import angr
import logging 
import time 

from configparser import ConfigParser
from pathlib import Path

# Fancy debug
from angrcli.interaction.explore import ExploreInteractive
import angrcli.plugins.ContextView
import angrcli.plugins.watches
import angr.analyses.reaching_definitions.dep_graph as dep_graph
from .exploration_techniques import HeartBeat, PointerSourceExecution, SimgrViz


# Inter-module ximports
from ..analyses.arguments_analyses import filter_unused_args
from ..analyses.pointers_source import DefsExplorer
from ..utils import *

# Logging
l = logging.getLogger("test_pointer_sources".ljust(23))
l.setLevel(logging.CRITICAL)

config = ConfigParser()
config.read((Path(__file__).parent.parent / "./heapster.ini").resolve())

# Globals 
OP_BEFORE = 0
OP_AFTER  = 1

'''
Use the Propagator to grab call values 
for function 'func'.
'''
def grab_args_values(project, func, args_dict, init_state):
    func_node = project.cfg.get_any_node(func.addr)
    call_site_dicts = {}
    
    for p in func_node.predecessors:
        callsite = project.factory.block(p.addr).instruction_addrs[-1]
        call_site_dicts[callsite] = {}
        
        function_p = p.function_address
        function_p_func = project.kb.functions[function_p]
        prop = project.analyses.Propagator(func=function_p_func, func_graph=function_p_func.graph, base_state=init_state)
        
        found_repl = False
        for r in prop.replacements:
            if r.block_addr == p.block.addr:
                found_repl = True
                #l.info("Found replacements for {}".format(p))
                break
        if not found_repl:
            l.debug("No replacements for predecessor at {}".format(p))
            continue

        replacements_values = prop.replacements[r]
        args_curr_dict = {}
        for a in args_dict.keys():
            target_offset = reg_to_offset(project, a)
            for v in replacements_values.keys():
                if type(v) != angr.analyses.propagator.engine_vex.VEXReg:
                    continue
                if v.offset == target_offset and type(replacements_values[v]) == int:
                    args_curr_dict[a] = replacements_values[v]
                    #args_dict[a].add(replacements_values[v])
        
        call_site_dicts[callsite] = args_curr_dict
    
    return call_site_dicts

'''
Generate call tests by plugging a value 
for every register for a particular 
function.
'''
def generate_ps_call_tests(all_args, callsite_info):
    assert(len(callsite_info) != 0)
    call_tests = []
    for k, regsv in callsite_info.items():
        tmp_all_args = all_args.copy()
        regsv_c = regsv.copy()
        for x in regsv.keys():
            tmp_all_args.remove(x)
        if len(tmp_all_args) == 0:
            call_tests.append(regsv_c)
        else:
            # We are missing some regs, plug default value as for now.
            for missing_r in tmp_all_args:
                # 8 is just a random value to avoid to plug 0
                # and miss the malloc behavior.
                regsv_c[missing_r] = 8
            call_tests.append(regsv_c)
    
    # Adding bunch of more back up tests
    new_test = {}
    for rk in all_args:
        new_test[rk] = 0x4
    call_tests.append(new_test)

    return call_tests

'''
Check if return value of a 
particular function is valid or not.
'''
def check_malloc_retval(value, heap_start, heap_end):
    def is_retval_valid(value):
        wrong_results = [0,-1,0xffffffff]
        if value in wrong_results:
            return False 
        else:
            return True
    def is_retval_heap_mem(value):
        if value >= heap_start and value <= heap_end:
            return True
        else:
            return False
    return is_retval_valid(value) and is_retval_heap_mem(value)


def dse_it(project, state):
    debug = False
    cli_debug = False

    sm = project.factory.simgr(state)

    dfs = angr.exploration_techniques.DFS()
    #ls = angr.exploration_techniques.LoopSeer(project.cfg, bound=100, limit_concrete_loops=True)
    ed = ExplosionDetector(threshold=1000)
    def timeout():
        l.warning("Timeout during DSE has been reached.")
        ed.timed_out.set()
        ed.timed_out_bool = True
    ps_exec = PointerSourceExecution()
    
    #simgr_viz = SimgrViz(project.cfg)

    #sm.use_technique(ls)
    sm.use_technique(dfs)
    sm.use_technique(ed)
    sm.use_technique(ps_exec)
    #sm.use_technique(simgr_viz)
    sm.use_technique(HeartBeat(beat_interval=1))

    timer = Timer(int(config["identify_hml"]["dse_timeout"]), timeout)
        
    timer.start()
    sm.run() # Run it! 
    timer.cancel()
    
    # If this timed-out let's just skip 
    # it next time.
    if ed.timed_out_bool:
        return None 

    #if debug:
    #    import ipdb; ipdb.set_trace()
    return ps_exec.last_state


def dse_check_read(state):
    addr = state.inspect.mem_read_address
    val = state.inspect.mem_read_expr # I can set this to overwrite the return.
    
    #l.info('check_read: addr: %s' % addr)
    #l.info('check_read: val: %s' % val)
    global mmio_access_cnt

    if addr.symbolic:
        l.debug("[!]Detected symbolic address reads at {}!!!".format(state.regs.pc))
        state.globals["symbolic_writes"].append((state.regs.pc,addr))
        return
    else:
        addr_concr = state.solver.eval(addr)
        state.globals["mem_reads_at"].add(addr_concr)
        # If we are reading from the mmio let's just return a symbolic variable.
        # This is needed because peripherals can evolve during times, and in 
        # situation like:
        #   while ( (MEMORY[0x40064006] & 0x20) == 0 )
        #   while ( (MEMORY[0x40064006] & 0x40) == 0 )
        # is necessary to return a fresh symbolic variables every time we access the 
        # peripherals memory.
        read_where = state.project.loader.find_object_containing(addr_concr)
        if read_where and "mmio" in read_where.binary_basename:
            sym_var_name = "peripherals_access_{}_{}".format(hex(addr_concr), mmio_access_cnt)
            new_symb_var = claripy.BVS(sym_var_name, 4*8)
            state.inspect.mem_read_expr  = new_symb_var 
            state.memory.store(addr_concr, new_symb_var , disable_actions=True , inspect=False)
            mmio_access_cnt += 1
            l.debug("[!]Detected access to peripherals, returning symb-value [{}].".format(sym_var_name))
            state.globals["symbolic_writes"].append((state.regs.pc,addr))

def dse_check_write(state):
    addr = state.inspect.mem_write_address
    val = state.inspect.mem_write_expr
    if not addr.symbolic:
        addr_concr = state.solver.eval(addr)
        state.globals["mem_writes_at"].add(addr_concr)

def dse_check_read(state):
    addr = state.inspect.mem_read_address
    val = state.inspect.mem_read_expr # I can set this to overwrite the return.
    if not addr.symbolic:
        addr_concr = state.solver.eval(addr)
        state.globals["mem_reads_at"].add(addr_concr)

'''
Call malloc with specific argument and starting 
from a specific base.
'''
def call_malloc(project, hb_state, func_addr, args, base_state, track_memory_ops=False, zero_fill_state=True):

    l.debug("Call malloc {} with args {}".format(hex(func_addr), args))
    
    cs = project.factory.call_state(func_addr, base_state=base_state, ret_addr=0xdeadbeef)
    
    # Just to make sure.
    cs.regs.lr = 0xdeadbeef
    cs.callstack.ret_addr = 0xdeadbeef
    cs.callstack.return_address = 0xdeadbeef
    
    # Add and remove options
    if zero_fill_state:
        cs.options.add(angr.options.ZERO_FILL_UNCONSTRAINED_MEMORY)
        cs.options.add(angr.options.ZERO_FILL_UNCONSTRAINED_REGISTERS)
    else:
        # Just to make sure, add and remove options.
        cs.options.add(angr.options.ZERO_FILL_UNCONSTRAINED_MEMORY)
        cs.options.add(angr.options.ZERO_FILL_UNCONSTRAINED_REGISTERS)
        cs.options.remove(angr.options.ZERO_FILL_UNCONSTRAINED_MEMORY)
        cs.options.remove(angr.options.ZERO_FILL_UNCONSTRAINED_REGISTERS)
    
    cs.options.add(angr.options.SIMPLIFY_EXPRS)
    cs.options.remove(angr.options.SIMPLIFY_EXPRS)
    cs.options.add(angr.options.LAZY_SOLVES)
    cs.options.remove(angr.options.LAZY_SOLVES)
    
    for x in angr.options.refs:
        cs.options.add(x)
        cs.options.remove(x)

    cs.regs.sp = project.arch.initial_sp

    # Init sets of reads and writes performed by the EP
    if track_memory_ops:
        cs.inspect.b('mem_write', when=angr.BP_AFTER, action=dse_check_write)
        cs.inspect.b('mem_read', when=angr.BP_AFTER, action=dse_check_read)
        cs.globals["mem_writes_at"] = set()
        cs.globals["mem_reads_at"] = set()

    for regk, regv in args.items():
        arg_val = base_state.solver.BVV(regv, project.arch.bits)
        #l.info("Setting {} with {}".format(regk, regv))
        setattr(cs.regs, regk, arg_val)
        
    next_state = dse_it(project, cs)

    if not next_state or next_state.solver.eval(next_state.regs.pc) != 0xdeadbeef:
        return None
    return next_state

def malloc_calls_first_test(project, hb_state, maybe_malloc, call_test, last_state, zero_fill_state=True):
    malloc_values = []

    # Call malloc 3 times.
    for _ in range(0,3):
        # 1st call
        next_state = call_malloc(project, hb_state, maybe_malloc.addr, call_test, last_state, zero_fill_state=zero_fill_state)
        if next_state == None:
            l.info("Test of {} with call_test {} failed because can't reach end of func".format(hex(maybe_malloc.addr), call_test))
            return False 
        malloced_address_val = next_state.solver.eval(getattr(next_state.regs, maybe_malloc.calling_convention.RETURN_VAL.reg_name))
        l.info("malloc at {} returned {}".format(hex(maybe_malloc.addr), hex(malloced_address_val)))
        
        if not check_malloc_retval(malloced_address_val, project.heap_start, project.heap_end): 
            return False
        
        malloc_values.append(malloced_address_val)
        last_state = next_state

    # All addresses must be unique.
    if len(set(malloc_values)) < len(malloc_values):
        l.info("Test of {} with call_test {} failed because not unique addresses {}".format(hex(maybe_malloc.addr), call_test, malloc_values))
        return False
    else:
        return True

'''
func is an Int representing the address of the function.
'''
def ret_value_deps(project, func):
    
    l.info("Studying return value of {}".format(hex(func)))
    func_deps = set()

    # Observations points are the last instruction of basic blocks that are endpoints.
    overall_defs = set()
    observation_points = []
    func_td = project.cfg.functions.get_by_addr(func)
    offset, size = project.arch.registers[func_td.calling_convention.RETURN_VAL.reg_name]

    assert(offset == 8) # R0

    for endpoint_type, endpoint_blocknodes in func_td.endpoints_with_type.items():
        for eb in endpoint_blocknodes:
            if endpoint_type == 'return':
                observation_points.append(("insn", project.factory.block(addr=eb.addr, opt_level=1).instruction_addrs[-1], 
                                        OP_BEFORE))
            elif endpoint_type == 'transition':
                # If we have a direct transition to another function let's add a fake definition
                # for the return value of the current function to the destination func.
                endpoint_cfg_node = project.cfg.get_any_node(eb.addr)
                endpoint_succ = endpoint_cfg_node.successors
                if len(endpoint_succ) == 0:
                    continue
                func_retval = hex(endpoint_succ[0].addr)
                l.debug("[CL] Transition endpoint, adding a fake definition for r0 as retval of {}".format(func_retval))
                overall_defs.add(("retval", func_retval, eb.addr))
    try:
        rd = project.analyses.ReachingDefinitions(subject=func_td, 
                                                  func_graph=func_td.graph,
                                                  cc = func_td.calling_convention,
                                                  observation_points= observation_points,
                                                  dep_graph = dep_graph.DepGraph()
                                                  )
    except Exception as e:
        l.debug("Exception in RD")
        return None

    defsExplorer = DefsExplorer(project, rd.dep_graph)

    # Sanity check.
    assert(len(rd.observed_results.values()) == len(observation_points))
    
    # Cycle all over the observed_results for the ret-value and
    # walk the definition backward.
    for observed_result in rd.observed_results.items():
        reg_defs = observed_result[1].register_definitions.get_objects_by_offset(offset)
        #assert(len(reg_defs) != 0)
        for reg_def in reg_defs:
            reg_seen_defs = defsExplorer.resolve_use_def(reg_def)
            for definition in reg_seen_defs:
                overall_defs.add(definition)

    # Analyze the observed definitions of the return argument.
    for definition in overall_defs:
        if definition[0] == "retval" and definition[1] != None:
            # It's not always guaranteed that the retval tag of a definition has the
            # func addr, in those casese we call it a day (definition[1] will be None).
            l.debug("[CL] Definition is coming from retval of func {}".format(definition[1]))
            func_deps.add(definition[1])
        elif definition[0] == "param":
            continue
        else:
            pass
    
    return func_deps

def is_ps_working(project, hb_state, ps, base_state, zero_fill_state=True):
    assert(type(ps) == int)

    l.info("[+]    Starting to test ps {}".format(hex(ps)))

    # Who can influence the ret-value?
    retval_deps = ret_value_deps(project, ps)
    l.debug("[+]    Retval of {} depends from {}".format(hex(ps), retval_deps))

    # Get info about prototype
    l.debug("[+]    Recovering prototype of {}".format(hex(ps)))
    ps_func = project.cfg.functions.get(ps,None)
    assert(ps_func)
    ps_args = filter_unused_args(project, ps_func)
    ps_args_dict_values = {}

    for x in ps_args:
        ps_args_dict_values[x] = set()
    
    # Get value at the callsite of the pointer generator 
    ps_args_dict_values = grab_args_values(project, ps_func, ps_args_dict_values, base_state)
    
    # Get the call tests 
    l.debug("[+]     Generating call tests for {}".format(hex(ps)))
    call_tests = generate_ps_call_tests(ps_args, ps_args_dict_values)

    last_state = base_state.copy()
    malloc_first_test_succeed = False
    working_ct = None 

    # Reduce the number of tests
    call_tests = call_tests[:2]
    
    # Perform call tests 
    for ct in call_tests:
        result = malloc_calls_first_test(project, hb_state, ps_func, ct, last_state, zero_fill_state)
        if not result:
            l.debug("[+]     Call test {} failed, trying another one".format(ct))
        else:
            malloc_first_test_succeed = True
            working_ct = ct
            break

    if malloc_first_test_succeed:
        l.debug("[+]     Evidence for malloc found in pointer source func {} with call test {}".format(hex(ps), working_ct))
        return True, working_ct
    else:
        l.debug("[+]     No evidence for malloc found in pointer source func {}".format(hex(ps)))
        return False, None


def is_ps_working_no_ep(project, hb_state, ps, base_state, working_call_test, rh_mem_writes_at, rh_mem_reads_at):
    assert(type(ps) == int)

    l.info("[+]    Starting to test ps {}".format(hex(ps)))
    last_state = call_malloc(project, hb_state, ps, working_call_test, base_state, track_memory_ops=True)
    assert(last_state != None)

    ps_reads_at = last_state.globals["mem_reads_at"]

    # If RH writes stuff and PS read it then the PS needs the RH.
    l.info("[+]    Checking RH and pointer source dependency")
    return rh_mem_writes_at.isdisjoint(ps_reads_at), working_call_test
