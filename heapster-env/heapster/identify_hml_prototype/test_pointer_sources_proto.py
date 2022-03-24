import angr
import logging 

from configparser import ConfigParser
from pathlib import Path

# Fancy debug
from angrcli.interaction.explore import ExploreInteractive
import angrcli.plugins.ContextView
import angrcli.plugins.watches
import angr.analyses.reaching_definitions.dep_graph as dep_graph

# Inter-module ximports
from ..analyses.arguments_analyses import filter_unused_args
from ..analyses.pointers_source import DefsExplorer
from ..utils import *

from .exploration_techniques import PointerSourceExecution, HeartBeat 
# Logging
l = logging.getLogger("heapster.get_hml_prototype.test_pointer_sources_proto")
#l.setLevel(logging.DEBUG)

config = ConfigParser()
config.read((Path(__file__).parent.parent / "./heapster.ini").resolve())

# Globals 
OP_BEFORE = 0
OP_AFTER  = 1

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

'''
DSE starting from a particular state.
'''
def dse_it(project, state):
    debug = False
    cli_debug = False

    sm = project.factory.simgr(state)

    dfs = angr.exploration_techniques.DFS()
    ls = angr.exploration_techniques.LoopSeer(project.cfg, bound=100, limit_concrete_loops=True)
    ed = ExplosionDetector(threshold=1000)
    ps_exec = PointerSourceExecution()
    
    def timeout():
        l.warning("Timeout during DSE has been reached.")
        ed.timed_out.set()
        ed.timed_out_bool = True

    sm.use_technique(dfs)
    sm.use_technique(ls)
    sm.use_technique(ed)
    sm.use_technique(ps_exec)

    timer = Timer(int(config["identify_hml"]["dse_timeout"]), timeout)
    timer.start()
    sm.run() # Run it! 
    timer.cancel()
    
    # If this timed-out let's just skip 
    # it next time.
    if ed.timed_out_bool:
        return None 

    return ps_exec.last_state

'''
Call malloc with specific argument and starting 
from a specific base.
'''
def call_malloc(project, func_addr, args, base_state):

    l.debug("Call malloc {} with args {}".format(hex(func_addr), args))
    
    cs = project.factory.call_state(func_addr, base_state=base_state, ret_addr=0xdeadbeef)
    
    # Just to make sure
    setattr(cs.regs, "lr", 0xdeadbeef)
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

def malloc_calls_first_test(project, maybe_malloc, call_test, last_state):
    malloc_values = []

    # Call malloc 3 times.
    for _ in range(0,3):
        # 1st call
        next_state = call_malloc(project, maybe_malloc.addr, call_test, last_state)
        if next_state == None:
            l.info("Test of {} with call_test {} failed because can't reach end of func".format(hex(maybe_malloc.addr), call_test))
            return False, None, None
        malloced_address_val = next_state.solver.eval(getattr(next_state.regs, maybe_malloc.calling_convention.RETURN_VAL.reg_name))
        l.info("malloc at {} returned {}".format(hex(maybe_malloc.addr), hex(malloced_address_val)))
        if not check_malloc_retval(malloced_address_val, project.heap_start, project.heap_end): return False, None, None
        malloc_values.append(malloced_address_val)
        last_state = next_state

    # All addresses must be unique.
    if len(set(malloc_values)) < len(malloc_values):
        l.info("Test of {} with call_test {} failed because not unique addresses {}".format(hex(maybe_malloc.addr), call_test, malloc_values))
        return False, None, None
    else:
        return True, malloc_values, last_state


'''
func is an Int representing the address of the function.
'''
def ret_args_deps(project, func, op, reg_target):
    
    l.info("Studying params dependencies for op at".format(hex(op)))
    func_deps = set()

    # Observations points are the last instruction of basic blocks that are endpoints.
    overall_defs = set()
    observation_points = [("insn", op, OP_BEFORE)]
    func_td = project.cfg.functions.get_by_addr(func)
    offset, size = project.arch.registers[reg_target]

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
            func_deps.add(definition)
        elif definition[0] == "param":
            func_deps.add(definition)
        else:
            pass
    return func_deps

def is_ps_working(project, ps, base_state, call_tests):
    assert(type(ps) == int)

    l.info("Starting to test ps {}".format(hex(ps)))

    # Get info about prototype
    ps_func = project.cfg.functions.get(ps,None)
    assert(ps_func)

    # Get the call tests 
    last_state = base_state.copy()
    malloc_first_test_succeed = False
    working_ct = None 

    # Perform call tests 
    for ct in call_tests:
        result, malloc_addresses, last_state = malloc_calls_first_test(project, ps_func, ct, last_state)
        if not result:
            l.debug("Call test {} failed, trying another one".format(ct))
        else:
            malloc_first_test_succeed = True
            working_ct = ct
            break

    if malloc_first_test_succeed:
        return True, malloc_addresses, last_state
    else:
        return False, None, None


def grab_args_values(project, func, op, arg_name, init_state):
    func_node = project.cfg.get_any_node(func.addr)
    block_target = block_from_addr_ins(project, op)

    call_site_dicts = {}
    call_site_dicts[op] = {}
    prop = project.analyses.Propagator(func=func, func_graph=func.graph, base_state=init_state)
    
    found_repl = False
    for r in prop.replacements:
        if r.block_addr == block_target:
            found_repl = True
            #l.info("Found replacements for {}".format(p))
            break
        
    replacements_values = prop.replacements[r]
    arg_values = []
    target_offset = reg_to_offset(project, arg_name)
    for v in replacements_values.keys():
        if type(v) != angr.analyses.propagator.engine_vex.VEXReg:
            continue
        if v.offset == target_offset:
            arg_values.extend(replacements_values[v])
            #args_dict[a].add(replacements_values[v])

    return arg_values


def is_pf_working(project, func_addr, base_state, to_free, call_test):
    cs = project.factory.call_state(func_addr, base_state=base_state, ret_addr=0xdeadbeef)
    
    plugged_addr_to_free = False
    
    for regk, regv in call_test.items():
        if regv == "TOP" or regv == "None":
            plugged_addr_to_free = True
            regv = to_free
            l.debug("Plugging address to free at {}".format(regk))
        elif type(regv) != int:
            regv = 0

        arg_val = base_state.solver.BVV(regv, project.arch.bits)
        #l.info("Setting {} with {}".format(regk, regv))
        setattr(cs.regs, regk, arg_val)
    
    last_free_state = dse_it(project, cs)
    if last_free_state.solver.eval(last_free_state.regs.pc) != 0xdeadbeef:
        return None
    
    return last_free_state