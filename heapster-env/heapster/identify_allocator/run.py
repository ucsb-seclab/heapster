# Packages import
import angr
import argparse
import json 
import logging
import networkx
import os
import pickle
pickle._HAVE_PICKLE_BUFFER = False
import shutil
import sys
sys.setrecursionlimit(10**9) 

# Packages from
from datetime import date, datetime
from configparser import ConfigParser 
from pathlib import Path
from threading import Event, Timer
from cle.backends import NamedRegion

# Intra-module imports
from .execute_entry_point import execute_ep
from .execute_heap_init import execute_hi
from .filter_heap_init import *
from .filter_pointer_sources import filter_p_sources
from .test_pointer_sources import ret_value_deps, is_ps_working, is_ps_working_no_ep

# Inter-module imports
from ..analyses.global_accesses import *
from ..utils import *

# Logger-vodoo
l = logging.getLogger("identify_allocator".ljust(23))
l.setLevel(logging.INFO)

symb_logger = logging.getLogger("angr.state_plugins.symbolic_memory")
symb_logger.setLevel(logging.CRITICAL)
tt_logger = logging.getLogger("heapster.taint_tracking")
tt_logger.setLevel(logging.CRITICAL)



# Config
config = ConfigParser()
config.read((Path(__file__).parent.parent / "./heapster.ini").resolve())

def parse_opts():
    o = argparse.ArgumentParser()
    o.add_argument("--resume", default=None)
    #o.add_argument("--malloc", default=None)
    #o.add_argument("--free", default=None)
    group_entry_point = o.add_mutually_exclusive_group()
    group_entry_point.add_argument('-sbe', '--skip-entry-point-execution', action='store_true', default=False)
    group_entry_point.add_argument('-bep', '--blob-entry-point', default=None)
    opts = o.parse_args()
    return opts

def config_script(project, opts, hb_state):
    # Option to overwrite the entry point to execute.
    if opts.blob_entry_point:
        entry_point = opts.blob_entry_point
    else:
        entry_point = int(hb_state["blob_entry_point"], 16)
    return entry_point

'''
Return a set of addresses representing 
all the global variables that are accessed 
by tons of functions (threshold X)
'''
def grab_false_globals(project):
    globals_dict = {}
    # Count the number of accessglobalses to a variable to filter heap globals.
    for f in project.kb.functions:
        full_func_accesses = get_globals_accesses(project, f, filter_writes=False, full=True)
        curr_func_mem_accesses = set()
        for mem_access in full_func_accesses:
            if mem_access.dst:
                if globals_dict.get(mem_access.dst,None) and mem_access.dst not in curr_func_mem_accesses:
                    globals_dict[mem_access.dst]+=1
                else:
                    curr_func_mem_accesses.add(mem_access.dst)
                    globals_dict[mem_access.dst] = 1

    # Filter out the heap_globals that have too many accesses.
    false_globals = set()
    for k,v in globals_dict.items():
        if v > int(config["identify_hml"]["false_heap_globals_max"],10):
            false_globals.add(k)
    return false_globals

'''
Dump the memory backend of a state.
'''
def dump_memory(project, hb_state, wps):
    ps = wps.addr
    hi = wps.heap_init_func
    mem = wps.memory_dump

    mem_dump_name = hb_state["hb_folder"] + "/" + hex(ps) + "_" + hex(hi) + "_mem_dump.mem"
    l.debug("Dumping mem object {} as {}".format(mem, mem_dump_name))
    with open(mem_dump_name, "wb") as mem_state:
        pickle.dump(mem, mem_state)
    return mem_dump_name


def shut_up(thing):
    lol = logging.getLogger(thing)
    lol.setLevel("CRITICAL")

def config_logger():
    shut_up("angr.analyses.reaching_definitions.engine_vex")
    shut_up("angr.analyses.variable_recovery.variable_recovery_fast")
    shut_up("pyvex.lifting.gym.arm_spotter")
    shut_up("angr.analyses.loopfinder")
    shut_up("angr.analyses.propagator.engine_vex.SimEnginePropagatorVEX")
    shut_up("angr.analyses.reaching_definitions.reaching_definitions")
    shut_up("angr.state_plugins.symbolic_memory")
    shut_up("angr.storage.memory")
    shut_up("angr.analyses.calling_convention")
    shut_up("angr.analyses.variable_recovery.engine_vex.SimEngineVRVEX")
    shut_up("angr.analyses.variable_recovery.engine_base")
    shut_up("angr.project")

'''
Dump info into the hb_state file.
'''
def dump_hb_state(project, hb_state, working_ps):
    # The previous part can be heavily improved by using Unicorn and Symbion.
    l.info("[+]This is the list of working ps and heap init:")
    for wps in working_ps:
        needed_heap_init = hex(wps.heap_init_func) if wps.needs_unpack_data else "None"
        l.info("[+] PointerSource: {} | HeapInit: {}".format(hex(wps.addr), needed_heap_init))

    hb_state["working_pointer_sources"] = []
    l.debug("Dumping initialized states")
    for wps in working_ps:
        working_ps = {}
        working_ps["ps_addr"] = wps.addr
        working_ps["ps_ct"] = wps.call_test
        working_ps["hi_addr"] = wps.heap_init_func
        dump_name = dump_memory(project, hb_state, wps)
        working_ps["dump_name"] = dump_name
        working_ps["needs_unpacked_data"] = wps.needs_unpack_data
        hb_state["working_pointer_sources"].append(working_ps)

    # Dumping hb_state
    with open(hb_state_file, 'w') as fp:
        json.dump(hb_state, fp)

class WorkingPS:
    def __init__(self, addr:int, call_test:dict, heap_init_func_addr:int, memory_dump, needs_unpack_data:bool):
        self.addr = addr
        self.call_test = call_test
        self.heap_init_func = heap_init_func_addr
        self.memory_dump = memory_dump
        self.needs_unpack_data = needs_unpack_data

if __name__ == "__main__":
    opts = parse_opts()
    hb_state_file = opts.resume

    config_logger()

    if os.path.exists(hb_state_file) and os.path.isfile(hb_state_file):
        with open(hb_state_file, "r") as hb_file:
            hb_state = json.load(hb_file)
    else:
        l.fatal("No file at {}. Aborting.".format(hb_state_file))
        sys.exit(-1)

    l.info("[+]Loading project")
    project, bin_cfg = load_artifact(hb_state)
    project.hb_state = hb_state

    l.info("[+]Running CompleteCallingConventions analysis (might take a while)")
    project.analyses.CompleteCallingConventions(recover_variables=True, 
                                                force=True, 
                                                analyze_callsites=True)

    entry_point = config_script(project, opts, hb_state)
    
    l.info("[+]Identifying allocator started")
    # Limit memory to 70GB
    # Will throw a MemoryError exception 
    limit_memory(70000000000)
    
    # DSE of the entry point of the blob to unpack global variables.
    unpacked_state = None
    if not opts.skip_entry_point_execution:
        l.info("[+]Trying to execute ResetHandler at {}".format(hex(entry_point)))
        unpacked_state = execute_ep(project, hb_state, entry_point)
    else:
        l.info("[!]Skipping entry-point execution like requested.")

    # The base state that we used for symb-execution is either a 
    # blank state or the unpacked state.
    last_state = None
    if unpacked_state:
        last_state = unpacked_state.copy()
    else:
        blank_state = project.factory.blank_state()
        last_state = blank_state

    # Before even starting let's see if 
    # the pointer sources work.
    pointer_sources = hb_state["pointer_sources"]

    # Quick filter them before.
    #  -> Removing pointer sources with no xrefs (i.e., malloc has to be called at least one time)
    #  -> Removing pointer sources with 0 args (i.e., malloc has to have at least one arg)
    filtered_pointer_sources = filter_p_sources(project, pointer_sources)
    l.info("[+]Pointer source filtering removed {} functions".format(len(pointer_sources) - len(filtered_pointer_sources)))
    l.info("[+]Starting to test {} pointer sources".format(len(filtered_pointer_sources)))
    working_ps = []

    for j,p in enumerate(filtered_pointer_sources):
        l.info("[+] Testing {} | {}/{}".format(hex(p), j+1, len(filtered_pointer_sources)))
        blank_state = project.factory.blank_state()
        
        if unpacked_state:
            l.debug("[+] Testing if {} behaves like allocator <<after>> ResetHandler execution".format(hex(p)))
            res, ct_1 = is_ps_working(project, hb_state, p, last_state)
            if res:
                l.info("[+]  ✓ {} behaves like allocator <<after>> ResetHandler execution".format(hex(p)))
                # Does PS also works without the unpacked state of the ResetHandler?
                l.debug("[+] Testing if {} behaves like allocator <<without>> ResetHandler execution".format(hex(p)))
                res, ct_2 = is_ps_working(project, hb_state, p, blank_state, zero_fill_state=False)
                if res:
                    l.debug("[+] Checking RH and {} memory dependency".format(format(hex(p))))
                    # Second check, does the pointer source read any address written by the RH?
                    # If YES, we assume it needs it, otherwise it really works by itself!
                    if is_ps_working_no_ep(project, hb_state, p, blank_state, ct_2,
                                                                 unpacked_state.globals["mem_writes_at"],
                                                                 unpacked_state.globals["mem_reads_at"]
                                                                 ):
                        l.info("[+]  ✓ {} behaves like allocator <<without>> ResetHandler execution".format(hex(p)))
                        working_ps.append(WorkingPS(p, ct_2, entry_point, last_state.memory.mem, False))
                    else:
                        # Nice try, but you need the RH.
                        l.info("[+]  ✗ {} does NOT behave like allocator <<without>> ResetHandler execution [spotted memory dependency]".format(hex(p)))
                        working_ps.append(WorkingPS(p, ct_2, entry_point, last_state.memory.mem, True))
                else:
                    # PS definitely needs the RH.
                    l.info("[+]  ✗ {} does NOT behave like allocator <<without>> ResetHandler execution [execution failed]".format(hex(p)))
                    working_ps.append(WorkingPS(p, ct_1, entry_point, last_state.memory.mem, True))
            else:
                l.info("[+] ✗ {} does NOT behave like allocator.".format(hex(p)))
        else:
            # Let's see if any pointer source works without the execution of the ResetHandler.
            l.info("[+]Testing if {} behaves like allocator <<without>> ResetHandler execution".format(hex(p)))
            res, ct = is_ps_working(project, hb_state, p, blank_state)
            if res:
                l.info("[+] ✓ {} behaves like allocator <<without>> ResetHandler execution".format(hex(p)))
                working_ps.append(WorkingPS(p, ct, entry_point, last_state.memory.mem, False))
            else:
                l.info("[+] ✗ {} does NOT behave like allocator.".format(hex(p)))

    # OPTIMIZATION
    # If I get an allocator let's call it a day
    if len(working_ps) != 0:
        l.info("[+]The following functions seem already to work as allocators. Stopping here.")
        for i,ps in enumerate(working_ps):
            success_log = "[+] ✓ Function {}: {}".format(i+1, hex(ps.addr))
            success_log = f'{bcolors.YELLOWBG}{success_log}{bcolors.ENDC}'
            l.info(success_log)
        dump_hb_state(project, hb_state, working_ps)
        sys.exit(0) # we are done.
    else:
        l.info("[!] ✗ No pointer source is behaving like an allocator. Looking for heap initializers")
    
    ###########################
    # FILTERING POINTER SOURCES
    # TO REDUCE THE SEARCH-SPACE.
    ###########################

    # Let's remove unnecessary global vars.
    # Here we want to filter out the heap_globals that have too many accesses
    # from too many functions. 
    # false globals are used later in the algorithm.
    # The intuition is that these are probably globals not related to malloc/free.
    false_globals = grab_false_globals(project)

    # First, we want to filter all the pointer sources and the 
    # entry point (i.e., they are not heap initializers for sure).
    filter_out = [int(x,16) for x in pointer_sources]
    filter_out.append(entry_point)
    filtered_funcs = [ x for x in project.kb.functions if x not in filter_out ]
    
    # Then, we filter all the functions that has no xrefs, 
    # the intuition is that heap init should be called.
    # WARNING: this can generate *false positive*.
    #filtered_funcs = filter_by_zero_refs(project, filtered_funcs)

    # Filter all the functions that has too many xrefs.
    # Intuition: heap init should theoretically have only 1.
    # we leave some delta for flexibility.
    filtered_funcs = filter_by_xrefs_chain(project, filtered_funcs, int(config["init_firmware"]["max_heap_init_xrefs"]))
    
    # Filter all the functions that are not void.
    # Intuition: a heap initializer shouldn't have arguments.
    # WARNING: this can generate *false positives*.
    filtered_funcs = filter_by_no_args(project, filtered_funcs)

    ##########################
    # START THE ALLOCATOR HUNT 
    ##########################

    # OPTIMIZATION 1 
    # Cache of final states of executed
    # candidate heap init. 
    heap_init_states_cache = {}

    # OPTIMIZATION 2 
    # Cache of heap init that failed to 
    # execute.
    heap_init_fail = set()

    # Some auxiliary variables.
    already_init = set()
    tested_psx = set()
    successfully_executed_initializers = set()

    # Test only the filtered pointer sources.
    # (i.e., at least one xrefs, at least one arg!)
    for psx_index, psx in enumerate(filtered_pointer_sources):
        if psx in tested_psx:
            # if we have already tested it, skip it.
            # This checke is here because we dynamically discover new 
            # pointer sources by looking at the function called internally by 
            # a target pointer source (i.e., the current psx).
            # e.g. malloc() is calling internally a _malloc_internal().
            continue
        else:
            # Register the current one as tested
            tested_psx.add(psx)

        l.info("[+]Testing pointer source {} [{}\{}]".format(hex(psx), psx_index+1, len(filtered_pointer_sources)))
        # Keep a list of already executed heap init
        # this is relative to a specific psx.
        already_executed_initializers = set()
        l.info("[+] Trying to initialize pointer source {}".format(hex(psx)))
        
        # Recursively retrieve all the global variables accessed by this psx.
        psx_globals = get_globals_accesses(project, psx, filter_writes=False)
        # Do the same for every function called by this psx.
        psx_calls = get_calls_r(project, psx)
        for x in psx_calls:
            if x not in already_init:
                already_init.add(x)
                psx_globals.update(get_globals_accesses(project,x))

        # Remove the false globals by the set of accessed global vars.
        psx_globals = psx_globals.difference(false_globals)
        if len(psx_globals) == 0:
            # No globals, no party, try with another psx.
            l.info("[!] Zero global variables found starting from ps {}".format(hex(psx)))
            continue 

        ########################################### 
        # LOOKING FOR HEAP INIT FOR THIS ALLOCATOR
        ###########################################

        potential_heap_initializers = set()

        # (1) Filter all successors of the psx (the correspondant heap init must be before the psx)
        filtered_potential_heap_init = filter_ps_successors(project, psx_calls, filtered_funcs)
        l.info("[+] Filtered potential heap init are [{}]".format(len(filtered_potential_heap_init)))

        # (2) Order them by number of calls and filter functions with too many.
        # Intuition: a heap init shouldn't be called an enormous amount of times.
        filtered_potential_heap_init = order_by_number_of_calls(project, filtered_potential_heap_init, 
                                                                         int(config["init_firmware"]["max_calls_heap_init"]))
        
        # Keep only the functions that are accessing globals also 
        # accessed by the pointer source.
        # Intuition: heap init and allocator should have global vars in common.
        # NOTE: Only considering memory reads for this.
        full_func_accesses = set()
        for f in filtered_potential_heap_init:
            full_func_accesses.update(get_globals_accesses(project, f, filter_writes=False, full=False))
            for faux in get_calls_r(project, f):
                full_func_accesses.update(get_globals_accesses(project, faux, filter_writes=False, full=False))
            for mem_access in full_func_accesses:
                if mem_access in psx_globals:
                    potential_heap_initializers.add(f)
        l.info("[+] Filtered potential heap by shared globals are [{}]".format( len(potential_heap_initializers)))

        if len(potential_heap_initializers) == 0:
            # If there are no heap init and this psx didn't work initially (i.e., after the execution of RH)
            # then we have to discard it. Let's go to the next.
            l.info("[!] No potential heap initializers for {}".format(hex(psx)))
            continue 
        
        # Boolean guard to detect when ps is working.
        ps_works = False

        # Now we have a set of potential_heap_initializers.
        # Let's see which is the pairs (psx, heap_init) that will make
        # psx behaving like an allocator!

        # Test the heap initializer and see if pointer source works.
        for f_index, f in enumerate(potential_heap_initializers):

            l.info("[+]  Testing heap init at {} | allocator [{}/{}] - heap_init [{}/{}]".format(
                                                                                                hex(f),
                                                                                                psx_index+1,
                                                                                                len(filtered_pointer_sources),
                                                                                                f_index+1, 
                                                                                                len(potential_heap_initializers), 
                                                                                                ))

            if ps_works:
                # we are done here!
                l.info("[+]   Function {} behaves like an allocator.".format(hex(psx)))
                break

            # Do not re-executed failed heap-init.
            # INTUITION: if something goes wrong during the execution of this 
            # function, is very likely this function is not the heap init.
            # Let's avoid to re-execute it in the future.
            if f in heap_init_fail:
                l.fatal("[!]   {} tested before and failed. Skipping it.".format(hex(f)))
                continue
            
            # If we have already executed this heap init candidate
            # let's extract it from the cache, otherwise, we need to execute it.
            if not heap_init_states_cache.get(hex(f), None):
                l.debug("[+]   Cannot find cached state for heap init at {}. Creating fresh state.".format(hex(f)))
                if unpacked_state:
                    last_state = unpacked_state.copy()
                else:
                    last_state = project.factory.blank_state()

                if f in already_executed_initializers:
                    l.debug("[!]   Skipping heap init {} because already executed".format(hex(f)))
                    continue
                else:
                    # Register this as already executed. 
                    already_executed_initializers.add(f)
                
                # Retrieve the function.
                f_func = project.kb.functions[f]
                l.info("[+]   Emulating heap initializer {}".format(hex(f)))

                # Run it!
                next_state = execute_hi(project, 
                                        hb_state, 
                                        f, 
                                        pointer_sources,
                                        already_executed_initializers
                                        )
                
                if not next_state:
                    l.info("[!]   Heap init {} failed to execute!. Skipping it in the future.".format(hex(f)))
                    heap_init_fail.add(f)
                    continue
            else:
                l.debug("[+]   States Cache <<HIT>> for heap init at {}. Using it!".format(hex(f)))
                next_state = heap_init_states_cache[hex(f)]

            if len(next_state.globals["symbolic_writes"]) == 0:
                successfully_executed_initializers.add(f)
                heap_init_states_cache[hex(f)] = next_state.copy()
                l.info("[+]   Check if pointer source {} works".format(hex(psx)))
                res, ct = is_ps_working(project, hb_state, psx, next_state)
                if res:
                    success_log = "[+]   ✓ Pointer source {} is working with heap init {}.".format(hex(psx), hex(f))
                    success_log = f'{bcolors.YELLOWBG}{success_log}{bcolors.ENDC}'
                    l.info(success_log)
                    
                    # Set this to true, we found the heap init that make this ps work! 
                    ps_works = True 

                    hi_init_state = next_state.copy()

                    # Saving the info of working pointer source. 
                    working_ps.append(WorkingPS(psx, ct, f, hi_init_state.memory.mem, True))

                    # If the main pointer source works, we want to check
                    # if any function inside was actually the real allocator.
                    
                    # Collect the static definitions for the return value of this 
                    # function.
                    retval_deps = ret_value_deps(project, psx)
                    
                    while len(retval_deps) != 0:
                        faux = int(retval_deps.pop(),16)
                        l.info("[+]    Testing interal function {}".format(hex(faux)))

                        # Check if we have already tested this function.
                        if faux in tested_psx:
                            l.info("[!]    Function already tested. Skipping.")
                            continue

                        faux_func = bin_cfg.functions.get(faux, None) 
                        if not faux_func:
                            l.debug("[!]    Could not find a function definition at {}. Skipping it.".format(hex(faux)))
                            continue
                    
                        # Check it 
                        res, ct = is_ps_working(project, hb_state, faux, hi_init_state)
                        if res:
                            l.info("[+]    ✓ Pointer source (aux) {} is working with heap init {}.".format(hex(faux), hex(f)))
                            hi_init_state = next_state.copy()
                            working_ps.append(WorkingPS(faux, ct, f, hi_init_state.memory.mem, True))
                            retval_deps.update(ret_value_deps(project, faux))
                            tested_psx.add(faux)
                else:
                    l.info("[+]   ✗ Pointer source does not work. Continuing.")
            else:
                l.info("[!]   Discarding {} because of symbolic writes".format(hex(f)))
                heap_init_fail.add(f)

    dump_hb_state(project, hb_state, working_ps)
