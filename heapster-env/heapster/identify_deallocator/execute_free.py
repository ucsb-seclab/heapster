import logging 

from configparser import ConfigParser
from pathlib import Path

from .execute_pointer_sources import call_malloc
from .exploration_techniques import FreeExecution, HeartBeat, SkipSVC

from ..analyses.arguments_analyses import filter_unused_args
from ..utils import *

from angrcli.interaction.explore import ExploreInteractive
import angrcli.plugins.ContextView
import angrcli.plugins.watches


l = logging.getLogger("execute_free".ljust(20))
l.setLevel(logging.CRITICAL)

config = ConfigParser()
config.read((Path(__file__).parent.parent / "./heapster.ini").resolve())

pf_info_objs = {}
to_skip_pf = set()
successfull_free = set()

class PossibleFreeInfo():
    def __init__(self, addr, tests, used_args):
        self._addr = addr
        self._tests = tests
        self._used_args = used_args
        self._used_ct = None

'''
Grabbing values of calls at callsite.
This also substitues the extra_call_args_analysis.
'''
def grab_args_values_pf(project, func, args_dict, init_state):
    func_node = project.cfg.get_any_node(func.addr)
    call_site_dicts = {}
    
    if len(func_node.predecessors) == 0:
        l.debug("No predecessor for func {}".format(func.addr))

    for p in func_node.predecessors:
        callsite = project.factory.block(p.addr).instruction_addrs[-1]
        call_site_dicts[callsite] = {}
        
        function_p = p.function_address
        function_p_func = project.kb.functions[function_p]
        
        try:
            prop = project.analyses.Propagator(func=function_p_func, func_graph=function_p_func.graph, base_state=init_state)
        except Exception:
            l.info("Exception during Propagator analysis, skipping this function")
            continue
            
        found_repl = False
        for r in prop.replacements:
            if r.block_addr == p.block.addr:
                found_repl = True
                l.debug("Found replacements for {}".format(p))
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
                if v.offset == target_offset:
                    args_curr_dict[a] = replacements_values[v]
                    #args_dict[a].add(replacements_values[v])
        
        call_site_dicts[callsite] = args_curr_dict
    
    return call_site_dicts

def generate_pf_call_tests(pf_func, all_args, callsite_info):
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
                regsv_c[missing_r] = 'TOP'
            call_tests.append(regsv_c)
    
    sanitized_call_tests = []
    for ct in call_tests:
        clean_ct = {}
        for reg_name, reg_val in ct.items():
            if type(reg_val) == int:
                clean_ct[reg_name] = reg_val
            else:
                clean_ct[reg_name] = str(reg_val)

        sanitized_call_tests.append(clean_ct)


    # To correct possible Propagator bugs we 
    # inject a fake test with at least a TOP per
    # argument 

    # Adding bunch of more back up tests
    #new_test = {}
    #for rk in all_args:
    #    new_test[rk] = 0x4
    #call_tests.append(new_test)

    return sanitized_call_tests

def dse_it(project, state):
    debug = False
    cli_debug = False

    sm = project.factory.simgr(state)

    dfs = angr.exploration_techniques.DFS()
    ls = angr.exploration_techniques.LoopSeer(project.cfg, bound=0, limit_concrete_loops=False)
    ed = ExplosionDetector(threshold=1000)
    free_exec = FreeExecution()
    skipsvc = SkipSVC()

    def timeout():
        l.debug("Timeout during DSE has been reached.")
        ed.timed_out.set()
        ed.timed_out_bool = True

    sm.use_technique(dfs)
    sm.use_technique(ls)
    sm.use_technique(ed)
    sm.use_technique(skipsvc)
    sm.use_technique(free_exec)
    sm.use_technique(HeartBeat(beat_interval=1))

    timer = Timer(int(config["identify_hml"]["dse_timeout"]), timeout)
    timer.start()
    sm.run() # Run it! 
    timer.cancel()

    # If the execution was not ended gracefully, something went 
    # terribly wrong, let's return None in these cases.
    if not free_exec.end_execution:
        return None

    # If this timed-out let's just skip 
    # it next time.
    if ed.timed_out_bool:
        state_addr = state.solver.eval(state.regs.pc)
        #l.debug("Adding {} to skip because of timeout".format(hex(state_addr)))
        #to_skip_pf.add(state_addr)

    return free_exec.last_state
    
'''
Call free with specific argument and starting 
from a specific base.
We substitute TOP with the address to free.
'''
def call_free(project, func_addr, ct, to_free, base_state):
    cs = project.factory.call_state(func_addr, base_state=base_state, ret_addr=0xdeadbeef)
    cs.regs.sp = project.arch.initial_sp

    # Just to make sure.
    cs.regs.lr = 0xdeadbeef
    cs.callstack.ret_addr = 0xdeadbeef
    cs.callstack.return_address = 0xdeadbeef
    
    plugged_addr_to_free = False
    for regk, regv in ct.items():
        if regv == "TOP" or regv == "None":
            plugged_addr_to_free = True
            regv = to_free
            l.debug("Plugging address to free at {}".format(regk))
        elif type(regv) != int:
            regv = 0

        arg_val = base_state.solver.BVV(regv, project.arch.bits)
        #l.info("Setting {} with {}".format(regk, regv))
        setattr(cs.regs, regk, arg_val)
    
    if not plugged_addr_to_free:
        l.debug("[!]Could not plug address to free using test {}, aborting this function {}".format(ct, hex(func_addr)))
        return None 

    next_state = dse_it(project, cs)

    if not next_state or next_state.solver.eval(next_state.regs.pc) != 0xdeadbeef:
        l.debug("Execution of free {} didn't reach end of function".format(hex(func_addr)))
        return None
    return next_state


def possible_free_alfa_test(project, ps, last_malloc_state, pf, allocated_chunks,
                            all_free_evidence):
    assert(type(pf) == int)
    assert(type(ps._addr) == int)
    assert(type(ps._hi) == int)

    # Some optimization stuff.
    #if not first_run_of_free:
    #    if pf in seen_pf and pf not in successfull_free:
    #        l.warning("Skipping this pf {} because in seen_pf and not successfull".format(hex(pf)))
    #        return
    # Avoid to execute failing functions.
    
    if pf in to_skip_pf:
        l.warning("[!]   Skipping this pf {} because in skip_pf".format(hex(pf)))
        return
    
    # Get info about prototype
    l.debug("Recovering prototype of {}".format(hex(pf)))
    pf_func = project.cfg.functions.get(pf,None)
    assert(pf_func)

    if not pf_info_objs.get(pf, None):
        l.debug("Collecting unused args for function {}".format(hex(pf)))
        pf_args = filter_unused_args(project, pf_func)
    else:
        pf_args = pf_info_objs[pf]._used_args

    pf_args_dict_values = {}
    
    if len(pf_args) == 0:
        l.debug("No usable args for {}".format(hex(pf)))
        return 

    for x in pf_args:
        pf_args_dict_values[x] = set()

    if not pf_info_objs.get(pf, None):
        l.debug("Generating call tests for {}".format(hex(pf)))
        pf_args_dict_values = grab_args_values_pf(project, pf_func, pf_args_dict_values, last_malloc_state)
        call_tests = generate_pf_call_tests(pf_func, pf_args, pf_args_dict_values)
        # Cache this result so we don't have to run it again later.
        pf_info_objs[pf] = PossibleFreeInfo(pf, call_tests, pf_args)
    else:
        # Let's just re-use the test that was succesfull before.
        if not pf_info_objs[pf]._used_ct:
            call_tests = pf_info_objs[pf]._tests
        else:
            call_tests = [pf_info_objs[pf]._used_ct]

    # If we found free evidence or not.
    free_evidence = False 

    # Limit the number of performed tests
    # Just take the first 5 as for now.
    call_tests = call_tests[:5]

    abort_free = set()
    # Perform call tests 
    for ict, ct in enumerate(call_tests):
        # We are done when we spot a free_evidence! 
        if free_evidence or pf in abort_free:
            break
        
        last_state = last_malloc_state.copy()
        chunk_freed = 0
        # Try to free all the previously allocated chunks
        for chunk_to_free in allocated_chunks:
            l.debug("Calling free {} of {}".format(hex(pf), hex(chunk_to_free)))
            next_state = call_free(project, pf_func.addr, ct, chunk_to_free, last_state)

            # Something wrong if state is None or state finished in to_skip_pf (i.e., Timeout
            if not next_state or pf_func.addr in to_skip_pf:
                l.debug("Calling free {} with test {} failed, trying another one".format(hex(pf), ct))
                break
            else:
                chunk_freed += 1
                last_state = next_state.copy()

        # We successfully run free() 3 times 
        if chunk_freed == 3:
            next_state = call_malloc(project, ps._addr, ps._call_args, last_state)
            if next_state == None:
                l.info("[!]   ✗ Malloc {} failed to re-allocate. Skipping this free {}".format(hex(ps._addr), hex(pf_func.addr)))
                abort_free.add(pf)
                break
            malloced_address_val = next_state.solver.eval(getattr(next_state.regs, "r0"))
            if malloced_address_val in allocated_chunks:
                success_log = "[+]   ✓ Evidence for free at {}".format(hex(pf_func.addr))
                success_log = f'{bcolors.YELLOWBG}{success_log}{bcolors.ENDC}'
                l.info(success_log)
                l.debug("Malloc returned {} in previously allocated addresses!".format(hex(malloced_address_val)))
                pf_info_objs[pf]._used_ct = ct
                all_free_evidence.append((ps._addr, pf, ps._hi, ps._mem_dump, ps._call_args, ct))
                successfull_free.add(pf)
                free_evidence = True
            else:
                l.info("[!]   ✗ No evidence of free procedure at {} [re-allocation didn't work]".format(hex(pf_func.addr)))
                l.debug("[!]   ✗ Malloc returned {} not in previously allocated addresses".format(hex(malloced_address_val)))
        else:
            l.info("[!]   ✗ No evidence of free procedure at {} [free didn't work]".format(hex(pf_func.addr)))