import logging 
import json 
import operator

from configparser import ConfigParser
from pathlib import Path

from .execute_pointer_sources import call_malloc
from .exploration_techniques import FreeExecution, HeartBeat

from ..analyses.arguments_analyses import filter_unused_args
from ..utils import *

from angrcli.interaction.explore import ExploreInteractive
import angrcli.plugins.ContextView
import angrcli.plugins.watches

l = logging.getLogger("execute_free     ")
l.setLevel(logging.INFO)

config = ConfigParser()
config.read((Path(__file__).parent.parent / "./heapster.ini").resolve())


def dse_it(state, hooks):

    sm = state.project.factory.simgr(state)

    dfs = angr.exploration_techniques.DFS()
    ed = ExplosionDetector(threshold=int(config["fix_hml"]["dse_max_states"]))
    free_exec = FreeExecution(current_hooks=hooks)
    
    sm.use_technique(dfs)
    sm.use_technique(ed)
    sm.use_technique(free_exec)
    sm.use_technique(HeartBeat())

    def timeout():
        l.debug("Timeout during DSE has been reached.")
        ed.timed_out.set()
    timer = Timer(int(config["fix_hml"]["dse_timeout"]), timeout)

    l.info("[+]   Starting timer [{} seconds]".format(config["fix_hml"]["dse_timeout"]))
    timer.start()
    start_time = time.time()
    sm.run() # Run it! 
    timer.cancel()
    end_time = time.time()

    # Calculate delta of latest function if didn't end properly.
    if free_exec.current_function in free_exec.executed_funcs.keys():
        free_exec.executed_funcs[free_exec.current_function] += (end_time - start_time)

    # Stop exploration has been forced from timeout, something went wrong.
    if ed.timed_out_bool:
        l.info("[!]   Exploration timeout is expired!")
        # If we timeout we try to skip the function in which we spent the most time.
        func_to_skip = max(free_exec.executed_funcs.items(), key=operator.itemgetter(1))[0]
        l.info("[+]   Spent {} in func {}. Hooking it next time.".format(free_exec.executed_funcs[func_to_skip], hex(func_to_skip)))
        if func_to_skip == state.project.kb.functions[state.addr].addr:
            l.fatal("[!] We should skip the entire free. This can't be done, something is wrong. Aborting.")
            assert(False)
        return False, func_to_skip

    return True, free_exec.last_state

def call_free(base_state, hb_state, chunk_to_free):
    l.debug("Deallocating chunk {}".format(hex(chunk_to_free)))
    project = base_state.project

    free_addr = int(hb_state["final_allocator"]["free"], 16)
    free = project.kb.functions[free_addr]

    free_prototype = json.loads(hb_state["free_prototype"])
    free_param = [] 
    free_prototype_args = []
    free_cc_args = free.calling_convention.args

    for f_arg_key, f_arg_val in free_prototype.items():
        if f_arg_key == 'ret':
            continue
        else:
            free_prototype_args.append(f_arg_val)

    cs = project.factory.call_state(free.addr,  base_state=base_state, ret_addr=0xdeadbeef)
    cs.regs.sp = project.arch.initial_sp

    # Just to make sure 
    setattr(cs.regs, "lr", 0xdeadbeef)
    cs.callstack.ret_addr = 0xdeadbeef
    cs.callstack_return_address = 0xdeadbeef

    # Setup parameter for free.
    for f_arg, f_cc_reg in zip(free_prototype_args, free_cc_args):
        if f_arg != "ptr_to_free":
            arg_val = hb_state["free_unknown_arguments_vals"][f_cc_reg.reg_name][0]
        else:
            arg_val = cs.solver.BVV(chunk_to_free, project.arch.bits)
        setattr(cs.regs, f_cc_reg.reg_name, arg_val) 

    # Emulate until we can hit the end of the function.
    success = False
    hooks = set()
    attempt = 0
    while success == False:
        l.info("[+]  Attempt {}. Executing free with {} hooks.".format(attempt + 1, len(hooks)))
        for j,h in enumerate(hooks):
            l.info("[+]   Hook-{}: {}".format(j, hex(h)))
        success, result = dse_it(cs, hooks)
        if success == False:
            l.debug("[+]   Skipping function {} next time".format(hex(result)))
            # result is the function we need to skip next time.
            hooks.add(result)
        else:
            if result != None and result.solver.eval(result.regs.pc) == 0xdeadbeef:
                l.info("[+]  ✓ Successfully executed free.")
            else:
                l.debug("[!] ✗ Free could not reach end of execution.")
                l.debug("[!] This can be a fatal error or simply due to hooks inserted in the algorithm.")
                l.debug("Current hooks {}".format(hooks))
                
            # result is the final state at this point.
            return result, hooks
        attempt += 1