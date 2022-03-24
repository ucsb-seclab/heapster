import claripy 

from heapster.identify_threats.simgrviz import SimgrViz
from heapster.identify_threats.heartbeat import HeartBeat
from heapster.identify_threats.SkipSVC import SkipSVC
from heapster.identify_threats.loop_handler import LoopHandler
from heapster.identify_threats.dfs import DFS

from angr import SimProcedure
from angr_taint_engine import TaintTracker
from angr.state_plugins import SimStatePlugin
from angr.exploration_techniques import ExplorationTechnique
from ..utils import *

# Keep track of gross approximation and other weird
# things 
class StateDirtyThings(SimStatePlugin):
    def __init__(self, peripherals_reads=None, svc_returns=None, mmio_access_cnt=0, svc_skipped_cnt=0, clone=None):
        self.mmio_access_cnt = mmio_access_cnt if clone is None else clone.mmio_access_cnt
        self.svc_skipped_cnt = svc_skipped_cnt if clone is None else clone.svc_skipped_cnt
        self.peripherals_reads = list() if clone is None else clone.peripherals_reads
        self.svc_returns = list() if clone is None else clone.svc_returns

    def merge(self, others, merge_conditions, common_ancestor=None): # pylint:disable=unused-argument
        return True

    @SimStatePlugin.memo
    def copy(self, _memo):
        return StateDirtyThings(clone=self)

class HeapTransitionTracker(SimStatePlugin):
    def __init__(self, heap_base=None, heap_grows=None, header_size=None, heap_attack=None, clone=None):
        SimStatePlugin.__init__(self)
        self.heap_base = heap_base if clone is None else clone.heap_base
        self.heap_grows = heap_grows if clone is None else clone.heap_grows
        self.header_size = header_size if clone is None else clone.header_size
        self.heap_attack = heap_attack if clone is None else clone.heap_attack
        
        # The first heap transition we need to see
        self.requested_heap_transition = self.heap_attack[0] if clone is None else clone.requested_heap_transition
        self.heap_ptr = self.heap_base if clone is None else clone.heap_base
        self.heap_attack_progress = 0 if clone is None else clone.heap_attack_progress

        # Wether a path is deviating from the transition we need to "prove".
        self.deviated = False if clone is None else clone.deviated

    def merge(self, others, merge_conditions, common_ancestor=None): # pylint:disable=unused-argument
        return True

    @SimStatePlugin.memo
    def copy(self, _memo):
        return HeapTransitionTracker(clone=self)

    def progress_transition(self):
        self.heap_attack_progress += 1
        self.requested_heap_transition = self.heap_attack[self.heap_attack_progress]

    def set_deviated(self):
        self.deviated = True

class HeapTransitionsExplorer(ExplorationTechnique):

    def __init__(self, heap_attack):
        super(HeapTransitionsExplorer, self).__init__()
        self.heap_attack = heap_attack

        self.attack_wip_states = []
        self.attack_completed_states = []

    def setup(self, simgr):
        return True

    def successors(self, simgr, state, **kwargs):
        succs = simgr.successors(state, **kwargs)
        new_succs = []

        for ss in succs.flat_successors:
            if ss.addr == 0xdeadbeef:
                if len(self.heap_attack) == state.heap_transition_tracker.heap_attack_progress:
                    self.attack_completed_states.append(ss.copy())
                elif state.heap_transition_tracker.heap_attack_progress != 0:
                    self.attack_wip_states.append(ss.copy())
            if not ss.heap_transition_tracker.deviated:
                new_succs.append(ss)

        succs.flat_successors = new_succs
        return succs

def get_init_state(project, hb_state, mem_dump_init):
    init_state = project.factory.entry_state(
                    add_options={
                                angr.options.CONCRETIZE_SYMBOLIC_FILE_READ_SIZES,
                                #angr.options.ZERO_FILL_UNCONSTRAINED_MEMORY,
                                #angr.options.ZERO_FILL_UNCONSTRAINED_REGISTERS,
                                },
                    remove_options={
                                angr.options.SIMPLIFY_EXPRS,
                                angr.options.LAZY_SOLVES
                                }
    )

    # Remove all tracking things, save time.
    for x in angr.options.refs:
        init_state.options.add(x)
        init_state.options.remove(x)

    init_state = init_memory_with_blob_mem(project, init_state, hb_state, mem_dump_init)
    init_state.regs.sp = int(hb_state["blob_stack_pointer"],16)

    return init_state

def dse_check_read(state):
    addr = state.inspect.mem_read_address
    val = state.inspect.mem_read_expr # I can set this to overwrite the return.
    
    #l.info('check_read: addr: %s' % addr)
    #l.info('check_read: val: %s' % val)

    if addr.symbolic:
        l.info("!!!Detected symbolic address reads at {}!!!".format(state.regs.pc))
    else:
        addr_concr = state.solver.eval(addr)
        # If we are reading from the mmio let's just return a symbolic variable.
        # This is needed because peripherals can evolve during times, and in 
        # situation like:
        #   while ( (MEMORY[0x40064006] & 0x20) == 0 )
        #   while ( (MEMORY[0x40064006] & 0x40) == 0 )
        # is necessary to return a fresh symbolic variables every time we access the 
        # peripherals memory.
        if addr_concr > 0x40000000 and addr_concr <= 0x50000000:
            sym_var_name = "peripherals_access_{}_{}".format(hex(addr_concr), state.state_dirty_things.mmio_access_cnt)
            state.state_dirty_things.peripherals_reads.append(sym_var_name)
            l.info("Detected access to peripherals, returning symb-value [{}].".format(sym_var_name))
            new_symb_var = claripy.BVS(sym_var_name, 4*8)
            state.inspect.mem_read_expr  = new_symb_var 
            state.memory.store(addr_concr, new_symb_var , disable_actions=True , inspect=False)
            state.state_dirty_things.mmio_access_cnt += 1 

def dse_check_write(state):
    
    addr = state.inspect.mem_write_address
    val = state.inspect.mem_write_expr

    #l.debug('check_write: addr: %s' % addr)
    #l.debug('check_write: val: %s' % val)

    if addr.symbolic:
        l.info("Detected symbolic writes at {}".format(state.regs.pc))
    else:
        addr_concr = state.solver.eval(addr)
        # TODO better checks to see if address is in boundaries or not! 
        # maybe we can even discard functions that are writing to crazy addresses!
        if addr_concr > last_ram_address(state.project):
            return

class MallocSimple(SimProcedure):
    def run(self):
        l.info("Calling malloc!!")
        current_ptr = self.state.heap_transition_tracker.heap_ptr
        next_ptr = self.state.heap_transition_tracker.heap_ptr + 0x10
        self.state.heap_transition_tracker.heap_ptr = next_ptr
        
        if "M-" in self.state.heap_transition_tracker.requested_heap_transition:
            self.state.heap_transition_tracker.progress_transition()
        else:
            self.state.heap_transition_tracker.set_deviated()
        
        return current_ptr

class FreeSimple(SimProcedure):
    def run(self):
        if "F-" in self.state.heap_transition_tracker.requested_heap_transition:
            self.state.heap_transition_tracker.progress_transition()
        else:
            self.state.heap_transition_tracker.set_deviated()
        

# Shortcut to make angr's noisy logging less noisy
def shut_up(thing):
    lol = logging.getLogger(thing)
    lol.setLevel("CRITICAL")

def dump_viz_graph(CURR_SIMGR):
    l.info("Dumping visualization graph if it exists")
    for et in CURR_SIMGR._techniques:
        if "SimgrViz" in str(et):
            break
    write_dot(et._simgrG,"/tmp/my_simgr.dot")


def stop_plz(state):
    import ipdb; ipdb.set_trace()
    
class HeapTransitionsHunter:
    
    def __init__(self, project, hb_state,
                       root_nodes_mmio_with_path_to_malloc, 
                       root_nodes_mmio_with_path_to_free):
        self.project = project 
        self.hb_state = hb_state
        self.heap_attack = hb_state["heap_attack"].split(";")
        self.malloc = int(hb_state["final_allocator"]["malloc"],16)
        self.free = int(hb_state["final_allocator"]["free"],16)
        self.root_nodes_mmio_with_path_to_malloc = root_nodes_mmio_with_path_to_malloc
        self.root_nodes_mmio_with_path_to_free = root_nodes_mmio_with_path_to_free
    
    def run(self):

        shut_up("angr.state_plugins.symbolic_memory")

        base_state = get_init_state(self.project, self.hb_state, self.hb_state["final_allocator"]["mem_dump_path"])

        # According to the transition we see at the beginning we start to explore 
        # from its correspondent root nodes
        if "F-" in self.heap_attack[0]:
            starting_funcs = self.root_nodes_mmio_with_path_to_free
        else:
            starting_funcs = self.root_nodes_mmio_with_path_to_malloc
        
        for func in starting_funcs:
            
            if func == 0x20f19:
                continue
            
            l.info("DSE is starting on {}".format(hex(func)))

            import ipdb; ipdb.set_trace()
            init_state = self.project.factory.call_state(addr=func, base_state = base_state, ret_addr=0xdeadbeef)
            init_state.register_plugin('heap_transition_tracker', HeapTransitionTracker(heap_base=self.hb_state["heap_base"],
                                                                                        heap_grows=self.hb_state["heap_grow_direction"],
                                                                                        header_size=self.hb_state["header_size"],
                                                                                        heap_attack=self.heap_attack))
            
            init_state.register_plugin('state_dirty_things', StateDirtyThings())

            init_state.inspect.b('mem_read' , angr.BP_BEFORE, action=dse_check_read)
            init_state.inspect.b('mem_write', angr.BP_BEFORE, action=dse_check_write)

            simgr = self.project.factory.simgr(init_state)
            simgr.use_technique(SkipSVC(self.project))
            heap_transition_explorer = HeapTransitionsExplorer(self.heap_attack)
            simgr.use_technique(heap_transition_explorer)
            simgr.use_technique(LoopHandler(cfg=self.project.cfg, bound=1))
            simgr.use_technique(DFS())

            # For debugging.
            simgr.use_technique(SimgrViz(self.project.cfg))
            simgr.use_technique(HeartBeat())

            self.project.hook(addr=self.malloc,
                                hook=MallocSimple())
            self.project.hook(addr=self.free,
                                hook=FreeSimple())

            l.info("Running DSE over function at {}".format(hex(func)))
            simgr.run()
            #dump_viz_graph(simgr)
            l.info("Finished executing function {}".format(hex(func)))

            if len(heap_transition_explorer.attack_completed_states) != 0:
                l.info("Completed the attack!!")
            elif len(heap_transition_explorer.attack_wip_states) != 0:
                l.info("Attack in progress, here the states:")
                for attack_state in heap_transition_explorer.attack_wip_states:
                    l.info("Attack at {}/{}. Currently looking for a {}".format(attack_state.heap_transition_tracker.heap_attack_progress),
                                                                                len(self.heap_attack, 
                                                                                attack_state.heap_transition_tracker.requested_heap_transition))
            else:
                l.info("No state progress the attack starting from {}".format(hex(func)))
            
            import ipdb; ipdb.set_trace()