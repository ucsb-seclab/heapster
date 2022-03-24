import angr
import logging
import json 
import operator

from configparser import ConfigParser
from pathlib import Path

from angrcli.interaction.explore import ExploreInteractive
import angrcli.plugins.ContextView
import angrcli.plugins.watches

import angr.analyses.reaching_definitions.dep_graph as dep_graph

from ..analyses.arguments_analyses import filter_unused_args
from ..analyses.pointers_source import DefsExplorer
from ..utils import *

from .exploration_techniques import PointerSourceExecution, HeartBeat

# Logging
l = logging.getLogger("execute_pointer_sources")
l.setLevel(logging.INFO)

config = ConfigParser()
config.read((Path(__file__).parent.parent / "./heapster.ini").resolve())


def dse_it(state, hooks):

    sm = state.project.factory.simgr(state)

    dfs = angr.exploration_techniques.DFS()
    ed = ExplosionDetector(threshold=int(config["fix_hml"]["dse_max_states"]))
    ps_exec = PointerSourceExecution(current_hooks=hooks)
    
    sm.use_technique(dfs)
    sm.use_technique(ed)
    sm.use_technique(ps_exec)
    sm.use_technique(HeartBeat())

    def timeout():
        l.warning("Timeout during DSE has been reached.")
        ed.timed_out.set()
    timer = Timer(int(config["fix_hml"]["dse_timeout"]), timeout)

    timer.start()
    start_time = time.time()
    sm.run() # Run it! 
    timer.cancel()
    end_time = time.time()
    if ps_exec.current_function in ps_exec.executed_funcs.keys():
        ps_exec.executed_funcs[ps_exec.current_function] += (end_time - start_time)

    # Stop exploration has been forced from timeout, something went wrong.
    if ed.timed_out_bool:
        l.debug("[!]Exploration timeout is expired")
        # If we timeout we try to skip the function in which we spent the most time.
        func_to_skip = max(ps_exec.executed_funcs.items(), key=operator.itemgetter(1))[0]
        l.info("[+]  Spent {} in func {}".format(ps_exec.executed_funcs[func_to_skip], hex(func_to_skip)))
        if func_to_skip == state.project.kb.functions[state.addr].addr:
            l.fatal("[!] We should skip the entire malloc. This can't be done, something is wrong. Aborting.")
            assert(False)
        return False, func_to_skip

    return True, ps_exec.last_state


'''
Call malloc given a state.
'''
def call_malloc(base_state, hb_state, requested_size):
    l.debug("Trying to allocate chunk of {} size".format(requested_size))
    project = base_state.project

    malloc_addr = int(hb_state["final_allocator"]["malloc"], 16)
    malloc = project.kb.functions[malloc_addr]
    malloc_prototype = json.loads(hb_state["malloc_prototype"])
    malloc_param = [] 
    malloc_prototype_args = []
    malloc_cc_args = malloc.calling_convention.args

    for m_arg_key, m_arg_val in malloc_prototype.items():
        if m_arg_key == 'ret':
            continue
        else:
            malloc_prototype_args.append(m_arg_val)

    cs = project.factory.call_state(malloc.addr, base_state=base_state, ret_addr=0xdeadbeef)
    
    # Just to make sure 
    setattr(cs.regs, "lr", 0xdeadbeef)
    cs.callstack.ret_addr = 0xdeadbeef
    cs.callstack_return_address = 0xdeadbeef

    # Setup args for malloc.
    for m_arg, m_cc_reg in zip(malloc_prototype_args, malloc_cc_args):
        if m_arg != "size":
            arg_val = hb_state["malloc_unknown_arguments_vals"][m_cc_reg.reg_name][0]
        else:
            arg_val = cs.solver.BVV(requested_size, project.arch.bits)
        setattr(cs.regs, m_cc_reg.reg_name, arg_val)
        l.debug("Setting reg {} with value {}".format(m_cc_reg.reg_name, arg_val))
    
    # Emulate until we can hit the end of the function.
    success = False
    hooks = set()
    while success == False:
        if len(hooks) != 0:
            l.info("Executing malloc with hooks:")
            for hi, h in enumerate(hooks):
                l.info("  🎣 Hook{} - {}".format(hi, hex(h)))
        success, result = dse_it(cs, hooks)
        if success == False:
            l.info("Skipping function {} next time".format(hex(result)))
            # result is the function we need to skip next time.
            hooks.add(result)
        else:
            if result.solver.eval(result.regs.pc) == 0xdeadbeef:
                l.debug("Successfully executed malloc.")
                # result is the final state at this point.
            else:
                l.debug("Malloc could not reach end of execution.")
                l.debug("This can be a fatal error or simply due to hooks inserted in the algorithm.")
                l.debug("Current hooks {}".format(hooks))
                # result is the final state at this point.
            return result, hooks