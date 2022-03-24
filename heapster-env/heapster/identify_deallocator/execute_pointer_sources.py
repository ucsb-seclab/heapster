import angr
import logging

from configparser import ConfigParser
from pathlib import Path

from angrcli.interaction.explore import ExploreInteractive
import angrcli.plugins.ContextView
import angrcli.plugins.watches

import angr.analyses.reaching_definitions.dep_graph as dep_graph

from ..analyses.arguments_analyses import filter_unused_args
from ..analyses.pointers_source import DefsExplorer
from ..utils import *

from .exploration_techniques import PointerSourceExecution

# Logging
l = logging.getLogger("execute_pointer_sources")
l.setLevel(logging.CRITICAL)

config = ConfigParser()
config.read((Path(__file__).parent.parent / "./heapster.ini").resolve())

# Globals
OP_BEFORE = 0
OP_AFTER  = 1


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
                assert(len(endpoint_succ) == 1)
                func_retval = hex(endpoint_succ[0].addr)
                l.info("[CL] Transition endpoint, adding a fake definition for r0 as retval of {}".format(func_retval))
                overall_defs.add(("retval", func_retval, eb.addr))
    try:
        rd = project.analyses.ReachingDefinitions(subject=func_td, 
                                                  func_graph=func_td.graph,
                                                  cc = func_td.calling_convention,
                                                  observation_points= observation_points,
                                                  dep_graph = dep_graph.DepGraph()
                                                  )
    except Exception as e:
        print(e)
        l.info("Exception in RD")
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
            l.info("[CL] Definition is coming from retval of func {}".format(definition[1]))
            func_deps.add(definition[1])
        elif definition[0] == "param":
            continue
        else:
            pass
    
    return func_deps


def dse_it(project, state):
    debug = False
    cli_debug = False

    sm = project.factory.simgr(state)

    dfs = angr.exploration_techniques.DFS()
    ls = angr.exploration_techniques.LoopSeer(project.cfg, bound=0, limit_concrete_loops=False)
    ed = ExplosionDetector(threshold=1000)
    ps_exec = PointerSourceExecution()

    sm.use_technique(dfs)
    sm.use_technique(ls)
    sm.use_technique(ed)
    sm.use_technique(ps_exec)

    def timeout():
        l.warning("Timeout during DSE has been reached.")
        ed.timed_out.set()
        ed.timed_out_bool = True

    timer = Timer(int(config["identify_hml"]["dse_timeout"]), timeout)
    timer.start()
    sm.run() # Run it! 
    timer.cancel()
    
    if ed.timed_out_bool:
        return None

    return ps_exec.last_state


'''
Grabbing values of calls at callsite.
This also substitues the extra_call_args_analysis.
'''
def grab_args_values(func, args_dict, init_state):
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
This is basically checking if at all callsites 
we have a value for all the registers we are supposed 
to fill to call this function.
If a register is missing we are filling that entry with a 
default value of 0. An improvement can be to use values of 
other callsites.
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
                regsv_c[missing_r] = 0
            call_tests.append(regsv_c)
    
    # Adding bunch of more back up tests
    new_test = {}
    for rk in all_args:
        new_test[rk] = 0x4
    call_tests.append(new_test)

    return call_tests

'''
Call malloc with specific argument and starting 
from a specific base.
'''
def call_malloc(project, func_addr, args, base_state):

    l.debug("Call malloc {} with args {}".format(hex(func_addr), args))
    
    cs = project.factory.call_state(func_addr, base_state=base_state, ret_addr=0xdeadbeef)
    # Just to make sure.
    cs.regs.lr = 0xdeadbeef
    cs.callstack.ret_addr = 0xdeadbeef
    cs.callstack.return_address = 0xdeadbeef

    for regk, regv in args.items():
        arg_val = base_state.solver.BVV(regv, project.arch.bits)
        #l.info("Setting {} with {}".format(regk, regv))
        setattr(cs.regs, regk, arg_val)
        
    next_state = dse_it(project, cs)
    if not next_state or next_state.solver.eval(next_state.regs.pc) != 0xdeadbeef:
        return None
    return next_state


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

'''
When running this test we expect the function to behave
like malloc since we filter before.
'''
def malloc_calls_second_test(project, maybe_malloc, call_test, last_state):
    l.debug("Allocating using {}, call_test {}".format(hex(maybe_malloc.addr), call_test))
    malloc_values = []
    
    for _ in range(0,3):
        next_state = call_malloc(project, maybe_malloc.addr, call_test, last_state)
        if next_state == None:
            return None, None
        malloced_address_val = next_state.solver.eval(getattr(next_state.regs, maybe_malloc.calling_convention.RETURN_VAL.reg_name))
        if not check_malloc_retval(malloced_address_val, project.heap_start, project.heap_end): return None, None
        malloc_values.append(malloced_address_val)
        last_state = next_state

    # Values must be different
    if len(set(malloc_values)) < len(malloc_values):
        #l.debug("Test of {} with call_test {} failed because not unique addresses {}".format(hex(maybe_malloc.addr), call_test, malloc_values))
        return None, None

    return malloc_values, last_state