import angr 
import argparse
import datetime
import json
import networkx as nx
import os
import sys
sys.setrecursionlimit(10**9) 

import itertools
import logging
import networkx 

from datetime import datetime
from configparser import ConfigParser 
from pathlib import Path

# Fancy debug
from angrcli.interaction.explore import ExploreInteractive
import angrcli.plugins.ContextView
import angrcli.plugins.watches

# Intra-module imports
from .filter_free import filter_not_free
from .execute_pointer_sources import malloc_calls_second_test
from .execute_free import possible_free_alfa_test

# Inter-module imports
from ..utils import * 

l = logging.getLogger("identify_deallocator")
l.setLevel(logging.INFO)

# Parse heapster global .ini conf
config = ConfigParser()
config.read((Path(__file__).parent.parent / "./heapster.ini").resolve())

def parse_opts():
    o = argparse.ArgumentParser()
    o.add_argument("--debug", action='store_true')
    o.add_argument("--resume", default=None)
    o.add_argument("--source-sink", action='store_true', default=False)
    opts = o.parse_args()
    return opts

class PointerSource:
    def __init__(self, addr, args, ret_val_deps):
        self._addr = addr
        self._args = args
        self._ret_val_deps = ret_val_deps

def classify_alloc_free_pairs(all_free_evidence):
    all_allocators   = set([x[0] for x in all_free_evidence])
    all_deallocators = set([ x[1] for x in all_free_evidence])
    curr_best_alloc   = set()
    curr_best_dealloc = set()

    best_pairs = []

    for a in all_allocators:
        
        all_calls = get_calls_r(project, a)
        if a in all_calls:
            all_calls.remove(a) # remove the current allocator...

        # Take the 'deepest' allocator that had a malloc-free behavior.
        if len(all_calls.intersection(all_allocators)) == 0:
            curr_best_alloc.add(a)
    l.debug("Curr best alloc: {}".format(curr_best_alloc))

    for d in all_deallocators:
        all_calls = get_calls_r(project, d)
        if d in all_calls:
            all_calls.remove(d) # remove the current deallocator...

        # Take the 'deepest' deallocator that had a malloc-free behavior.
        if len(all_calls.intersection(all_deallocators)) == 0:
            curr_best_dealloc.add(d)
    l.debug("Curr best dealloc: {}".format(curr_best_dealloc))

    for x in all_free_evidence:
        if x[0] in curr_best_alloc and x[1] in curr_best_dealloc:
            l.debug("Best pair!")
            best_pairs.append(x)
    
    return best_pairs


tested_deallocators = []
all_free_evidence = []

class PointerSourceInfo():
    def __init__(self, addr, heap_initializer, call_args, mem_dump_path):
        self._addr = addr
        self._hi = heap_initializer
        self._call_args = call_args
        self._mem_dump = mem_dump_path


def get_init_state(project, hb_state, mem_dump_init):
    init_state = project.factory.entry_state(
                    add_options={
                                angr.options.ZERO_FILL_UNCONSTRAINED_MEMORY,
                                angr.options.ZERO_FILL_UNCONSTRAINED_REGISTERS,
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
    init_state.regs.sp = project.arch.initial_sp

    return init_state

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

if __name__ == "__main__":
    opts = parse_opts()
    hb_state_file = opts.resume

    if os.path.exists(hb_state_file) and os.path.isfile(hb_state_file):
        with open(hb_state_file, "r") as hb_file:
            hb_state = json.load(hb_file)
    else:
        l.fatal("No file at {}. Aborting.".format(hb_state_file))
        sys.exit(-1)

    config_logger()

    l.info("[+]Loading project")
    project, bin_cfg = load_artifact(hb_state)
    project.hb_state = hb_state

    l.info("[+]Running CompleteCallingConventions analysis (might take a while)")
    project.analyses.CompleteCallingConventions(recover_variables=True, 
                                                force=True, 
                                                analyze_callsites=True)
    
    l.info("[+]Identifying de-allocator started!")
    # Limit memory to 70GB
    # Will throw a MemoryError exception 
    limit_memory(70000000000)
    
    #########################
    # PRE-FILTERING FUNCTIONS
    #########################
    
    # Running some pre-filter to reduce the search-space
    # (see details in the module filter_free.py)
    l.info("[+]Pre-filtering space of possible free")
    possible_free = filter_not_free(project, hb_state)
    l.info("[+]Search space reduced to {} possible functions (starting from {})".format(len(possible_free), 
                                                                                        len(project.kb.functions)))
    
    # Try to pair all the pointer sources that were working before
    # with a deallocator.
    working_pointer_sources = hb_state["working_pointer_sources"]
        
    for iwp,wps in enumerate(working_pointer_sources):
        alloc = wps['ps_addr']
        call_test = wps['ps_ct']
        hi = wps['hi_addr']
        mem_dump_init = wps['dump_name']

        if call_test is None:
            l.info('[!]Skipping invalid call-test for allocator {}'.format(hex(alloc)))
            continue 

        l.info("[+]Testing working allocator at {} [{}/{}]".format(hex(alloc),iwp+1, len(working_pointer_sources)))

        # just an aux class to keep info
        ps_info_obj = PointerSourceInfo(alloc, hi, call_test, mem_dump_init)
        
        last_state = get_init_state(project, hb_state, mem_dump_init)

        alloc_func = project.kb.functions[alloc]

        malloc_values, last_state = malloc_calls_second_test(project, alloc_func, call_test, last_state)
        
        if not malloc_values or not last_state:
            l.fatal("[!]  Allocator {} does not work as expected. Skipping it.".format(hex(alloc)))
            continue
        l.info("[+]  Calls to allocator returned following chunks:")
        for ix,x in enumerate(malloc_values):
            l.info("[+]   Chunk{}: {}".format(ix+1, hex(x)))

        for j, pf in enumerate(possible_free):
            l.info("[+]  Trying deallocator candidate {} [[alloc: {}/{}| dealloc: {}/{}]".format(hex(pf), 
                                                                                                 iwp+1, 
                                                                                                 len(working_pointer_sources), 
                                                                                                 j+1, 
                                                                                                 len(possible_free)))
            possible_free_alfa_test(project, ps_info_obj, last_state, pf, malloc_values, all_free_evidence)

    last_nodes_free_evidence = set()

    if len(all_free_evidence) != 0:
        l.info("[+]Found {} HML pairs".format(len(all_free_evidence)))
        for p in all_free_evidence:
            l.info("[+] Malloc {} | Free {}".format(hex(p[0]), hex(p[1])))
        
        l.info("[+]Identifying the best HML pair")
        
        # Try to reduce the HML candidates by analyzing their hierarchy
        # relations (i.e., who is calling who.)
        best_pairs = classify_alloc_free_pairs(all_free_evidence)
        hb_state["best_hml_pairs"] = []
        
        for ib, b in enumerate(best_pairs):
            hml_pair = {}
            l.info("[+]HML-{}: Malloc {} | Heap Init {} | Free {}".format(ib+1, 
                                                                          hex(b[0]), 
                                                                          hex(b[2]), 
                                                                          hex(b[1])))
            hml_pair["malloc"] = hex(b[0])
            hml_pair["free"] = hex(b[1])
            hml_pair["hi"] = hex(b[2])
            hml_pair["mem_dump_path"] = b[3]
            hml_pair["malloc_ct"] = b[4]
            hml_pair["free_ct"] = b[5]
            hb_state["best_hml_pairs"].append(hml_pair)
            # Dumping hb_state
            with open(hb_state_file, 'w') as fp:
                json.dump(hb_state, fp) 
    else:
        l.info("[!]No valid HML pair found.")
