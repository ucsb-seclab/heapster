import angr
import logging 

from configparser import ConfigParser
from pathlib import Path

from angr_taint_engine import *
from angr.state_plugins import SimStatePlugin, inspect
from .exploration_techniques import HeartBeat, EpExecution, SkipSVC
from ..utils import *

l = logging.getLogger("execute_entry_point".ljust(23))
l.setLevel(logging.INFO)

config = ConfigParser()
config.read((Path(__file__).parent.parent / "./heapster.ini").resolve())

# Global counter of accesses to peripherlas memory.
mmio_access_cnt = 0

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
    
    def _inside_stack(addr):
        blob_stack_pointer = int(state.project.hb_state['blob_stack_pointer'],16)
        stack_max_size = int(config["init_firmware"]["stack_max_size"])
        if addr_concr <= blob_stack_pointer and addr_concr >= blob_stack_pointer - stack_max_size:
            return True
        else:
            return False

    addr = state.inspect.mem_write_address
    val = state.inspect.mem_write_expr

    #l.debug('check_write: addr: %s' % addr)
    #l.debug('check_write: val: %s' % val)

    if addr.symbolic:
        l.debug("Detected symbolic writes at {}".format(state.regs.pc))
        state.globals["symbolic_writes"].append((state.regs.pc,addr,val))
    else:
        addr_concr = state.solver.eval(addr)
        state.globals["mem_writes_at"].add(addr_concr)
        # TODO better checks to see if address is in boundaries or not! 
        # maybe we can even discard functions that are writing to crazy addresses!
        if addr_concr > last_ram_address(state.project):
            return

        # TODO also terminate if accesses peripherals 

        #if  project.loader.find_object_containing(addr)
        # Keep all the writes that do not belong to the stack!
        #if addr_concr > int(hb_state['blob_stack_pointer'],16) or not _inside_stack(addr_concr): 
        #    val_concr = state.solver.eval(val)
        #    state.globals["concrete_writes"][addr_concr] = val_concr


def config_simstate(state):
    # Hackish way to make sure we remove specific options.
    state.options.add(angr.options.ZERO_FILL_UNCONSTRAINED_MEMORY)
    state.options.remove(angr.options.ZERO_FILL_UNCONSTRAINED_MEMORY)
    state.options.add(angr.options.SIMPLIFY_EXPRS)
    state.options.remove(angr.options.SIMPLIFY_EXPRS)
    state.options.add(angr.options.LAZY_SOLVES)
    state.options.remove(angr.options.LAZY_SOLVES)
    state.options.add(angr.options.COW_STATES)
    state.options.remove(angr.options.COW_STATES)
    for x in angr.options.refs:
        state.options.add(x)
        state.options.remove(x)

    # We want these options.
    state.options.add(angr.options.ZERO_FILL_UNCONSTRAINED_MEMORY)
    state.options.add(angr.options.ZERO_FILL_UNCONSTRAINED_REGISTERS)


    #state.options.add(angr.options.BYPASS_UNSUPPORTED_SYSCALL)

def execute_ep(project, hb_state, func_target, init_state=None, timeout_value=0): 
    l.info("[+] Attempting to execute function at {}".format(hex(func_target)))
    
    try:
        f = project.kb.functions[func_target]
    except:
        l.exception("[!]  Error finding function info for {}. Skipping.".format(hex(func_target)))
        return None

    # Default state if not provided!
    if not init_state:
        init_state = project.factory.call_state(func_target, ret_addr=0xdeadbeef)
        config_simstate(init_state)

    # Just to make sure.
    init_state.regs.lr = 0xdeadbeef
    init_state.callstack.ret_addr = 0xdeadbeef
    init_state.callstack.return_address = 0xdeadbeef

    # Fix the sp to the original value 
    init_state.regs.sp = project.arch.initial_sp

    # Init array to detect symbolic writes.
    init_state.globals["symbolic_writes"] = []

    # Init sets of reads and writes performed by the EP
    init_state.globals["mem_writes_at"] = set()
    init_state.globals["mem_reads_at"] = set()


    sm = project.factory.simgr(init_state)
    
    # Use LoopsSeer to stop symbolic loops, fully execute concrete ones.
    ls = angr.exploration_techniques.LoopSeer(project.cfg, bound=0, limit_concrete_loops=False)
    
    # Use TaintTracker ET to skip every call.
    def my_follow_call_policy(*args, **kwargs):
        return False

    # Just use this to avoid to follow function calls.
    tt = TaintTracker(interfunction_level=0, precise_argument_check=False, taint_deref_values=False,
                    smart_call=True, should_follow_call=my_follow_call_policy)
    tt._N = 9999999
    
    # Hooks to inspect memory writes and reads.
    tt.add_callback(dse_check_write, 'mem_write', inspect.BP_BEFORE)
    tt.add_callback(dse_check_read,  'mem_read', inspect.BP_AFTER)

    ed = ExplosionDetector(threshold=int(config["init_firmware"]["dse_oep_max_states"]))
    
    # DSE in DFS
    dfs = angr.exploration_techniques.DFS()

    # Governing the termination of the EP
    ep_exec = EpExecution()

    # Handling SVC
    skipsvc = SkipSVC()

    # Plug in techniques.
    sm.use_technique(ls)
    sm.use_technique(tt)
    sm.use_technique(ed)
    sm.use_technique(dfs)
    sm.use_technique(skipsvc)
    sm.use_technique(ep_exec)
    sm.use_technique(HeartBeat(beat_interval=1))

    def timeout():
        l.warning("[!] Timeout during DSE has been reached.")
        ep_exec.timed_out.set()
        ep_exec.timed_out_bool = True
    
    timer = Timer(int(config["init_firmware"]["dse_oep_timeout"]), timeout)
    l.info("[+]  Starting DSE [timeout: {} secs]".format(int(config["init_firmware"]["dse_oep_timeout"])))

    timer.start()
    sm.run() # Run it!
    timer.cancel()

    # If the execution was not ended gracefully, something went 
    # terribly wrong, let's return None in these cases.
    if not ep_exec.end_execution:
        l.info("[+]  Unexpected termination of execution. Check errored states.")
    elif ep_exec.end_execution_reason[0] == "END_EXECUTION_RETURNS":
        l.info("[+]  Finished to execute func {}".format(hex(func_target)))
        if ep_exec.last_state.addr == 0x0:
            l.info("[!]   Last state addr is 0x0. Proceeding nonetheless.")
    elif ep_exec.end_execution_reason[0] == "END_EXECUTION_CALLOUT":
        l.info("[!]  Reached callout {} during RH execution".format(hex(ep_exec.last_state.addr)))
    elif ep_exec.end_execution_reason[0] == "END_EXECUTION_BAD_LOOP":
        l.info("[!]  Ended in infinite loop!")
    elif ep_exec.end_execution_reason[0] == "END_EXECUTION_TIMEOUT":
        l.info("[!]  Timeout expired during ResetHandler execution")
    elif ep_exec.end_execution_reason[0] == "END_EXECUTION_OUT_OF_ROM":
        l.info("[!]  Execution out of ROM")
    elif ep_exec.end_execution_reason[0] == "END_EXECUTION_SVC_UNSUPPORTED":
        l.info("[!]  Execution terminated because of unsupported SVC")
    elif ep_exec.end_execution_reason[0] == "END_EXECUTION_NO_MORE_ACTIVE":
        l.info("[![  Execution terminated because no more successors")
    else:
        l.critical("Unexpected end of execution. Stopping here.")
        import ipdb; ipdb.set_trace()
        assert(False)

    def wipe_bps(x):
        return True
    
    # Remove hooks from this state.
    ep_exec.last_state.inspect.remove_breakpoint('mem_read' , filter_func=wipe_bps)
    ep_exec.last_state.inspect.remove_breakpoint('mem_write', filter_func=wipe_bps)

    return ep_exec.last_state