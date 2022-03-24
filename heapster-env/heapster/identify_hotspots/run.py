import angr 
import argparse
import datetime
import json
import os
import operator
import sys
sys.setrecursionlimit(10**9) 

import itertools
import logging
import random

import time 

from datetime import datetime
from configparser import ConfigParser 
from pathlib import Path
from ..utils import * 

from .execute_pointer_sources import call_malloc
from .execute_free import call_free

# Fancy debugging.
from angrcli.interaction.explore import ExploreInteractive
import angrcli.plugins.ContextView
import angrcli.plugins.watches

from threading import Event, Timer


l = logging.getLogger("identify_hotspots")
l.setLevel(logging.INFO)

# Parse heapster global .ini conf
config = ConfigParser()
config.read((Path(__file__).parent.parent / "./heapster.ini").resolve())

def parse_opts():
    o = argparse.ArgumentParser()
    o.add_argument("--resume", default=None)
    opts = o.parse_args()
    return opts

def config_script(project, opts, hb_state):
    final_pair = hb_state["final_allocator"]
    malloc = int(final_pair["malloc"],16)
    free = int(final_pair["free"],16)
    mem_dump_path = final_pair["mem_dump_path"]
    return malloc, free, mem_dump_path


'''
Create state ready to execute with blob
unpacked memory.
'''
def get_init_state(project, hb_state, mem_dump_init):
    init_state = project.factory.entry_state(
                    add_options={
                                angr.options.CONCRETIZE_SYMBOLIC_FILE_READ_SIZES,
                                angr.options.ZERO_FILL_UNCONSTRAINED_MEMORY,
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

def check_malloc_result(value):
    l.debug("Malloc returned {}".format(hex(value)))
    wrong_results = [0,-1,0xffffffff]
    if value in wrong_results :
        l.warning("Malloc possibly returned an error code: {}. This is not good.".format(value))
        guard_malloc_error = True
        return False
    return True

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
    shut_up("angr.project")
    shut_up("angr.analyses.variable_recovery.engine_base")


'''
NOTE: 
This script is meant to find hotstops during the execution 
of malloc/free (wasting tons of times or getting stuck because 
of pheriperals). We are going to replace those functiont
with a skip() SimProc later.

NOTE:
The previous identification of malloc (identify_allocator) relies on the fact that we
are re-using args found at the callsite (so they should be right to make malloc works).
Here we want to exercise malloc with different params (also weird one) to see how it behaves.
(HeapHopper can be configured with values that are not expected by this allocator and we need to
unstuck it if necessary).
'''
if __name__ == "__main__":
    opts = parse_opts()
    hb_state_file = opts.resume

    if os.path.exists(hb_state_file) and os.path.isfile(hb_state_file):
        with open(hb_state_file, "r") as hb_file:
            hb_state = json.load(hb_file)
    else:
        l.fatal("[!]No file at {}. Aborting.".format(hb_state_file))
        sys.exit(-1)

    config_logger()

    l.info("[+]Loading project")
    project, bin_cfg = load_artifact(hb_state)
    project.hb_state = hb_state

    l.info("[+]Running CompleteCallingConventions analysis (might take a while)")
    project.analyses.CompleteCallingConventions(recover_variables=True, 
                                                force=True, 
                                                analyze_callsites=True)
        
    malloc, free, mem_dump_path = config_script(project, opts, hb_state)
    malloc = bin_cfg.functions.get(malloc,None)
    free = bin_cfg.functions.get(free,None)
    assert(malloc)
    assert(free)

    curr_allocated_chunks = []
    old_allocated_chunks  = []
    malloc_hooks = []
    free_hooks = []

    l.info("[+]Identifying HotSpots started!")
    # Limit memory to 70GB
    # Will throw a MemoryError exception 
    limit_memory(70000000000)
    
    init_state = get_init_state(project, hb_state, mem_dump_path)

    # Allocating some chunk.
    l.info("[+]Calling bunch of malloc using allocator {}".format(hex(malloc.addr)))
    malloc_sizes_list = config["fix_hml"]["malloc_emulation_def_req_sizes"].split(",")
    malloc_sizes_list = [int(x) for x in malloc_sizes_list]

    malloc_addresses = [] 
    last_state = init_state

    for call_n in range(0,10):
        l.info("[+] Calling malloc [{}/{}]".format(call_n+1, 10))
        malloc_size = random.choice(malloc_sizes_list)
        l.info("[+]  Trying allocator with size [{}]".format(malloc_size))
        next_state, hooks = call_malloc(last_state, hb_state, malloc_size)
        malloced_address = getattr(next_state.regs, malloc.calling_convention.RETURN_VAL.reg_name)
        malloced_address_val = next_state.solver.eval(malloced_address)
        l.info("[+]  Call returned address at {}".format(hex(malloced_address_val)))
        
        if not check_malloc_result(malloced_address_val):
            l.info("[!]   Returned address at {} is invalid!".format(hex(malloced_address_val)))
            if not hb_state.get("wrong_pairs", None):
                hb_state["wrong_pairs"] = []
            
            wrong_pair_signature = hex(malloc.addr) + "-" + hex(free.addr)

            if wrong_pair_signature not in hb_state["wrong_pairs"]:
                l.info("[!]   Adding this pair {}-{} to the wrong pair".format(hex(malloc.addr), 
                                                                             hex(free.addr)))
                hb_state["wrong_pairs"].append(wrong_pair_signature)
                with open(hb_state_file, 'w') as fp:
                    json.dump(hb_state, fp)

            l.fatal("[+]Change the selected final allocator in hb_state.json before re-starting this script")
            raise Exception

        # Update the function we need to hook.
        for h in hooks:
            if h not in malloc_hooks:
                malloc_hooks.append(h)

        malloc_addresses.append(malloced_address_val)
        last_state = next_state

    # Deallocate all the previous chunk.
    for call_free_i in range(0,10):
        l.info("[+] Calling free [{}/{}]".format(call_free_i+1, 10))
        next_state, hooks = call_free(last_state, hb_state, malloc_addresses[call_free_i])
        # Update the function we need to hook.
        for h in hooks:
            if h not in free_hooks:
                free_hooks.append(h)
        last_state = next_state
    
    ####################
    # Just another test
    ####################

    malloc_size = int(config["fix_hml"]["malloc_emulation_def_req_size"])
    l.info("[+] Trying allocator with size [{}]".format(malloc_size))
    next_state, hooks = call_malloc(last_state, hb_state, malloc_size)
    malloced_address = getattr(next_state.regs, malloc.calling_convention.RETURN_VAL.reg_name)
    malloced_address_val = next_state.solver.eval(malloced_address)
    if not check_malloc_result(malloced_address_val):
        if not hb_state.get("wrong_pairs", None):
            hb_state["wrong_pairs"] = []
        
        wrong_pair_signature = hex(malloc.addr) + "-" + hex(free.addr)

        if wrong_pair_signature not in hb_state["wrong_pairs"]:
            l.info("[!]Adding this pair {}-{} to the wrong pair".format(hex(malloc.addr), hex(free.addr)))
            hb_state["wrong_pairs"].append(wrong_pair_signature)
            with open(hb_state_file, 'w') as fp:
                json.dump(hb_state, fp)

        l.fatal("[+]Change the selected final allocator in hb_state.json before re-starting this script")
        raise Exception

    if malloced_address_val in malloc_addresses:
        all_right_log = "[+] ✓ Last malloc returns a previously allocated chunk."
        all_right_log = f'{bcolors.YELLOWBG}{all_right_log}{bcolors.ENDC}'
        l.info(all_right_log)
    else:
        bad_log = "[!] ✗ Last malloc returns a chunk not in the previously allocated one. This might be wrong."
        bad_log = f'{bcolors.REDBG}{bad_log}{bcolors.ENDC}'
        l.info(bad_log)

    # Update the function we need to hook.
    for h in hooks:
        if h not in malloc_hooks:
            malloc_hooks.append(h)

    ###############################
    # Try malloc with faulty values
    ###############################
    l.info("[+]Trying allocator with faulty values")

    # Faulty malloc 
    malloc_size = -1
    l.info("[+] Trying allocator with 0xffffffff")
    next_state, hooks = call_malloc(last_state, hb_state, malloc_size)
    malloced_address = getattr(next_state.regs, malloc.calling_convention.RETURN_VAL.reg_name)
    malloced_address_val = next_state.solver.eval(malloced_address)
    l.info("[+] Faulty malloc returned {}".format(hex(malloced_address_val)))
    last_state = next_state
    
    # Update the function we need to hook.
    for h in hooks:
        if h not in malloc_hooks:
            malloc_hooks.append(h)

    ###############################
    # Try free with faulty values
    ###############################
    l.info("[+]Trying deallocator with faulty values")
    
    # Faulty frees
    l.info("[+] Trying deallocator with 0xffffffff")
    next_state, hooks = call_free(last_state, hb_state, 0xffffffff)

    # Update the function we need to hook.
    for h in hooks:
        if h not in free_hooks:
            free_hooks.append(h)

    l.info("[+] Trying deallocator with 0x0")
    next_state, hooks = call_free(last_state, hb_state, 0x0)
    if not next_state:
        l.info("[!] Next state is None. This may cause problem later. Proceeding.")

    # Update the function we need to hook.
    for h in hooks:
        if h not in free_hooks:
            free_hooks.append(h)

    if len(malloc_hooks) > 0:
        l.info("[+]The following hooks need to be used for malloc() during DSE:")
        for hix, h in enumerate(malloc_hooks):
            l.info("[+] MallocHook-{}: {}".format(hix+1, hex(h)))
    else:
        l.info("[+]No MallocHook needed for DSE")

    if len(free_hooks) > 0:
        l.info("[+]The following hooks need to be used for free() during DSE:")
        for hix, h in enumerate(free_hooks):
            l.info("[+] FreeHook-{}: {}".format(hix+1, hex(h)))
    else:
        l.info("[+]No FreeHook needed for DSE")

    hb_state["malloc_to_hook_funcs"] = malloc_hooks
    hb_state["free_to_hook_funcs"] = free_hooks

    with open(hb_state_file, 'w') as fp:
        json.dump(hb_state, fp)
