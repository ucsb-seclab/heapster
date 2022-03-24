
import angr
import logging 

from configparser import ConfigParser
from pathlib import Path

from angr_taint_engine import *
from angr.state_plugins import SimStatePlugin, inspect
from .exploration_techniques import HeartBeat, HeapInitExecution, SkipSVC

from ..utils import * 

l = logging.getLogger("execute_heap_init".ljust(23))
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
        l.debug("!!!Detected symbolic address reads at {}!!!".format(state.regs.pc))
        state.globals["symbolic_writes"].append((state.regs.pc,addr))
        return
    else:
        addr_concr = state.solver.eval(addr)
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
            l.debug("Detected access to peripherals, returning symb-value [{}].".format(sym_var_name))
            #state.globals["symbolic_writes"].append((state.regs.pc,addr))



def dse_check_read_only_peripherals(state):
    addr = state.inspect.mem_read_address
    val = state.inspect.mem_read_expr # I can set this to overwrite the return.
    
    #l.info('check_read: addr: %s' % addr)
    #l.info('check_read: val: %s' % val)
    global mmio_access_cnt

    if addr.concrete:
        addr_concr = state.solver.eval(addr)
        if addr_concr == 0xcafebabe:
            import ipdb; ipdb.set_trace()

    if addr.symbolic:
        l.debug("!!!Detected symbolic address reads at {}!!!".format(state.regs.pc))
        state.inspect.mem_read_address = 0xcafebabe
        state.inspect.mem_read_expr = 0x0
        state.memory.store(0xcafebabe, 0x0 , disable_actions=True , inspect=False)
    else:
        addr_concr = state.solver.eval(addr)
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
            l.debug("Detected access to peripherals, returning symb-value [{}].".format(sym_var_name))
            #state.globals["symbolic_writes"].append((state.regs.pc,addr))



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

def execute_hi(project, hb_state, func_target, 
                        pointer_sources,
                        already_executed_initializers, 
                        init_state=None, 
                        timeout_value=0): 
    #l.info("[+]    Attempting to force execution at function {}".format(hex(func_target)))
    
    try:
        f = project.kb.functions[func_target]
    except:
        l.exception("[!]    Error finding function info for {}. Aborting emulation.".format(hex(func_target)))
        return None

    #endpoint = get_func_endpoint(project, f)

    # Default state if not provided!
    if not init_state:
        init_state = project.factory.call_state(func_target, ret_addr=0xdeadbeef)
        config_simstate(init_state)

    init_state.regs.sp = project.arch.initial_sp
    
    # Just to make sure.
    init_state.regs.lr = 0xdeadbeef
    init_state.callstack.ret_addr = 0xdeadbeef
    init_state.callstack.return_address = 0xdeadbeef

    init_state.globals["symbolic_writes"] = []

    sm = project.factory.simgr(init_state)
    
    # Use LoopsSeer to stop symbolic loops.
    ls = angr.exploration_techniques.LoopSeer(project.cfg, bound=0, limit_concrete_loops=False)
    
    # Policy to follow calls during execution.
    def my_follow_call_policy(*args, **kwargs):
        def _is_symbolic(state, arg):
            l.debug("[+]     Checking if arg are symbolic")
            reg_val = getattr(state.regs, arg)
            if reg_val.symbolic:
                return True
            else:
                return False
        state = args[0]
        state_addr = state.solver.eval(state.regs.pc)
        function = state.project.kb.functions.get(state_addr, None)
        if function:
            if not function.calling_convention:
                return False
            cc_args = function.calling_convention.args
            if cc_args:
                # Check if all of them are SimRegArg.
                for sim_arg in cc_args:
                    if type(sim_arg) != angr.calling_conventions.SimRegArg:
                        return False
                if any([_is_symbolic(state, sim_arg.reg_name) for sim_arg in cc_args]):
                        l.debug("[+]     Skipping call to {} because symbolic args".format(state_addr))
                        return False
                else:
                    l.debug("[+]     All concrete values for call to {}, following.".format(hex(state_addr)))
                    already_executed_initializers.add(state_addr)
                    return True 
            elif len(cc_args) == 0:
                l.debug("[+]     Function call to {} is void, following.".format(hex(state_addr)))
                # Well, a 0 args function should be followed.
                already_executed_initializers.add(state_addr)
                return True
            else:
                # Something wrong
                l.debug("[+]     Function call to {} has no CC, skipping.".format(hex(state_addr)))
                return False
        else:
            # Can not retrieve function, do no follow.
            l.debug("[+]     Function call {} not a function?".format(hex(state_addr)))
            return False 

    tt = TaintTracker(interfunction_level=10, precise_argument_check=False, taint_deref_values=False,
                    smart_call=True, should_follow_call=my_follow_call_policy)
    tt._N = 9999999
    tt.add_callback(dse_check_write, 'mem_write', inspect.BP_BEFORE)
    tt.add_callback(dse_check_read, 'mem_read', inspect.BP_AFTER)

    ed = ExplosionDetector(threshold=int(config["init_firmware"]["dse_oep_max_states"]))
    dfs = angr.exploration_techniques.DFS()
    hi_execution = HeapInitExecution(ps_addrs=[int(x,16) for x in pointer_sources])
    skipsvc = SkipSVC()

    def timeout():
        l.warning("[+]    Global timeout fired DSE of heap init has been reached.")
        hi_execution.timed_out.set()
        hi_execution.timed_out_bool = True
        hi_execution.end_execution_reason = ("END_EXECUTION_TIMEOUT", None)
    
    global_timer = MyTimer(3600, timeout)

    # Plug the exploration techniques.
    sm.use_technique(ls)
    sm.use_technique(tt)
    sm.use_technique(ed)
    sm.use_technique(dfs)
    sm.use_technique(skipsvc)
    sm.use_technique(hi_execution)
    sm.use_technique(HeartBeat(beat_interval=1, 
                               app_timer=global_timer))

    l.debug("[+]    Starting DSE of the function at {}".format(hex(func_target)))
    
    global_timer.start()
    sm.run() # Run it! 
    global_timer.cancel()

    # If the execution was not ended gracefully, something went 
    # terribly wrong, let's return None in these cases.
    if not hi_execution.end_execution or hi_execution.end_execution_reason == None:
        l.info("[!]    Unexpected termination of execution. Check errored states.")
        hi_execution.func_timer.cancel()
    elif hi_execution.end_execution_reason[0] == "END_EXECUTION_RETURNS":
        l.info("[+]    Finished to execute func {}".format(hex(func_target)))
        if hi_execution.last_state.addr == 0x0:
            l.info("[!]   Last state addr is 0x0. Proceeding nonetheless.")
    elif hi_execution.end_execution_reason[0] == "END_EXECUTION_CALLOUT":
        l.info("[+]    Reached callout {} during heap init execution".format(hex(hi_execution.last_state.addr)))
    elif hi_execution.end_execution_reason[0] == "END_EXECUTION_BAD_LOOP":
        l.info("[!]    Ended in infinite loop!")
    elif hi_execution.end_execution_reason[0] == "END_EXECUTION_PS_ADDR_LIMIT":
        l.info("[!]    Hit a pointer source multiple times during execution of heap init!")
    elif hi_execution.end_execution_reason[0] == "END_EXECUTION_SYMBOLIC_WRITES":
        l.info("[!]    Detected symbolic write, returing latest available state ({}).".format(hi_execution.last_state))
    elif hi_execution.end_execution_reason[0] == "END_EXECUTION_TIMEOUT":
        l.info("[!]    Timeout expired during heap init execution")
    elif hi_execution.end_execution_reason[0] == "END_EXECUTION_OUT_OF_ROM":
        l.info("[!]    Execution out of ROM [couldn't restore to callee]")
    elif hi_execution.end_execution_reason[0] == "END_EXECUTION_NO_MORE_ACTIVE":
        l.info("[!]    Execution has no more active states")
    elif hi_execution.end_execution_reason[0] == "END_EXECUTION_SVC_UNSUPPORTED":
        l.info("[!]    Execution terminated because of unsupported SVC")
    else:
        l.critical("IPDB!!!!!")
        import ipdb; ipdb.set_trace()
        assert(False)

    def wipe_bps(x):
        return True
    
    # Remove hooks from this state.
    if hi_execution.last_state:
        hi_execution.last_state.inspect.remove_breakpoint('mem_read' , filter_func=wipe_bps)
        hi_execution.last_state.inspect.remove_breakpoint('mem_write', filter_func=wipe_bps)
    
    return hi_execution.last_state



'''
Be less strict when executing the heap init
specified from users.
'''
def execute_forced_hi(project, hb_state, func_target, 
                        pointer_sources,
                        init_state=None, 
                        timeout_value=0): 
    #l.info("[+]    Attempting to force execution at function {}".format(hex(func_target)))
    
    try:
        f = project.kb.functions[func_target]
    except:
        l.exception("[!]    Error finding function info for {}. Aborting emulation.".format(hex(func_target)))
        return None

    #endpoint = get_func_endpoint(project, f)

    # Default state if not provided!
    if not init_state:
        init_state = project.factory.call_state(func_target, ret_addr=0xdeadbeef)
        config_simstate(init_state)

    init_state.regs.sp = project.arch.initial_sp
    
    # Just to make sure.
    init_state.regs.lr = 0xdeadbeef
    init_state.callstack.ret_addr = 0xdeadbeef
    init_state.callstack.return_address = 0xdeadbeef

    init_state.globals["symbolic_writes"] = []

    sm = project.factory.simgr(init_state)
    
    # Use LoopsSeer to stop symbolic loops.
    ls = angr.exploration_techniques.LoopSeer(project.cfg, bound=0, limit_concrete_loops=False)
    
    # Policy to follow calls during execution.
    def my_follow_call_policy(*args, **kwargs):
        def _is_symbolic(state, arg):
            l.debug("[+]     Checking if arg are symbolic")
            reg_val = getattr(state.regs, arg)
            if reg_val.symbolic:
                return True
            else:
                return False
        state = args[0]
        state_addr = state.solver.eval(state.regs.pc)
        function = state.project.kb.functions.get(state_addr, None)
        if function:
            cc_args = function.calling_convention.args
            if cc_args:
                # Check if all of them are SimRegArg.
                for sim_arg in cc_args:
                    if type(sim_arg) != angr.calling_conventions.SimRegArg:
                        return False
                if any([_is_symbolic(state, sim_arg.reg_name) for sim_arg in cc_args]):
                        l.debug("[+]     Skipping call to {} because symbolic args".format(state_addr))
                        return False
                else:
                    l.debug("[+]     All concrete values for call to {}, following.".format(hex(state_addr)))
                    return True 
            elif len(cc_args) == 0:
                l.debug("[+]     Function call to {} is void, following.".format(hex(state_addr)))
                return True
            else:
                # Something wrong
                l.debug("[+]     Function call to {} has no CC, skipping.".format(hex(state_addr)))
                return False
        else:
            # Can not retrieve function, do no follow.
            l.debug("[+]     Function call {} not a function?".format(hex(state_addr)))
            return False 

    tt = TaintTracker(interfunction_level=10, precise_argument_check=False, taint_deref_values=False,
                    smart_call=True, should_follow_call=my_follow_call_policy)
    tt._N = 9999999
    #tt.add_callback(dse_check_write, 'mem_write', inspect.BP_BEFORE)
    tt.add_callback(dse_check_read_only_peripherals, 'mem_read', inspect.BP_BEFORE)

    ed = ExplosionDetector(threshold=int(config["init_firmware"]["dse_oep_max_states"]))
    dfs = angr.exploration_techniques.DFS()
    hi_execution = HeapInitExecution(ps_addrs=[int(x,16) for x in pointer_sources])
    skipsvc = SkipSVC()

    def timeout():
        l.warning("[+]    Global timeout fired DSE of heap init has been reached.")
        hi_execution.timed_out.set()
        hi_execution.timed_out_bool = True
        hi_execution.end_execution_reason = ("END_EXECUTION_TIMEOUT", None)
    
    global_timer = MyTimer(3600, timeout)

    # Plug the exploration techniques.
    sm.use_technique(ls)
    sm.use_technique(tt)
    sm.use_technique(ed)
    sm.use_technique(dfs)
    sm.use_technique(skipsvc)
    sm.use_technique(hi_execution)
    sm.use_technique(HeartBeat(beat_interval=1, 
                               app_timer=global_timer))

    l.debug("[+]    Starting DSE of the function at {}".format(hex(func_target)))
    
    global_timer.start()
    sm.run() # Run it! 
    global_timer.cancel()

    # If the execution was not ended gracefully, something went 
    # terribly wrong, let's return None in these cases.
    if not hi_execution.end_execution or hi_execution.end_execution_reason == None:
        l.info("[!]    Unexpected termination of execution. Check errored states.")
        hi_execution.func_timer.cancel()
    elif hi_execution.end_execution_reason[0] == "END_EXECUTION_RETURNS":
        l.info("[+]    Finished to execute func {}".format(hex(func_target)))
        if hi_execution.last_state.addr == 0x0:
            l.info("[!]   Last state addr is 0x0. Proceeding nonetheless.")
    elif hi_execution.end_execution_reason[0] == "END_EXECUTION_CALLOUT":
        l.info("[+]    Reached callout {} during heap init execution".format(hex(hi_execution.last_state.addr)))
    elif hi_execution.end_execution_reason[0] == "END_EXECUTION_BAD_LOOP":
        l.info("[!]    Ended in infinite loop!")
    elif hi_execution.end_execution_reason[0] == "END_EXECUTION_PS_ADDR_LIMIT":
        l.info("[!]    Hit a pointer source multiple times during execution of heap init!")
    elif hi_execution.end_execution_reason[0] == "END_EXECUTION_SYMBOLIC_WRITES":
        l.info("[!]    Detected symbolic write, returing latest available state ({}).".format(hi_execution.last_state))
    elif hi_execution.end_execution_reason[0] == "END_EXECUTION_TIMEOUT":
        l.info("[!]    Timeout expired during heap init execution")
    elif hi_execution.end_execution_reason[0] == "END_EXECUTION_OUT_OF_ROM":
        l.info("[!]    Execution out of ROM [couldn't restore to callee]")
    elif hi_execution.end_execution_reason[0] == "END_EXECUTION_NO_MORE_ACTIVE":
        l.info("[!]    Execution has no more active states")
    elif hi_execution.end_execution_reason[0] == "END_EXECUTION_SVC_UNSUPPORTED":
        l.info("[!]    Execution terminated because of unsupported SVC")
    else:
        l.critical("IPDB!!!!!")
        import ipdb; ipdb.set_trace()
        assert(False)

    def wipe_bps(x):
        return True
    
    # Remove hooks from this state.
    if hi_execution.last_state:
        hi_execution.last_state.inspect.remove_breakpoint('mem_read' , filter_func=wipe_bps)
        hi_execution.last_state.inspect.remove_breakpoint('mem_write', filter_func=wipe_bps)
    
    return hi_execution.last_state