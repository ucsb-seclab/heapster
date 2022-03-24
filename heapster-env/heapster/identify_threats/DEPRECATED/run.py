
import argparse
from .threat_explorer_static_blob import StaticHeapTransitionsHunterBlob


import json
import logging
import networkx as nx
import os
import sys

from .mmio_finder import MMIOFinder
from ..utils import *

l = logging.getLogger("heapster.identify_threats")
l.setLevel(logging.INFO)

def auto_int(x):
    return int(x, 0)

def parse_opts():
    o = argparse.ArgumentParser()
    o.add_argument("--resume", default=None)
    opts = o.parse_args()
    return opts


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
    shut_up("pyvex.lifting.gym.arm_spotter")
    shut_up("angr.analyses.variable_recovery.variable_recovery_fast")
    shut_up("angr.analyses.calling_convention")
    shut_up("pyvex.lifting.gym.arm_spotter")

if __name__ == "__main__":
    opts = parse_opts()
    hb_state_file = opts.resume

    if os.path.exists(hb_state_file) and os.path.isfile(hb_state_file):
        with open(hb_state_file, "r") as hb_file:
            hb_state = json.load(hb_file)
    else:
        l.fatal("No file at {}. Aborting.".format(hb_state_file))
        sys.exit(-1)

    l.info("[+] Analyzing blob [{}]".format(hb_state["blob_name"]))
    project, bin_cfg = load_artifact(hb_state)
    l.info("[!] Project loaded")

    l.info("[+]Running CompleteCallingConventions analysis (might take a while)")
    project.analyses.CompleteCallingConventions(recover_variables=True, 
                                                force=True, 
                                                analyze_callsites=True)

    config_logger()

    # Step 1: 
    # Collect functions that read data from MMIO
    mmiofinder = MMIOFinder(project, hb_state)
    mmiofinder.run()
    mmio_read_functions = mmiofinder.mmio_read_functions
    if len(mmio_read_functions) == 0:
        l.critical("No function reads input from MMIO. Aborting.")
        sys.exit(0)

    # Step 2: 
    # Keep MMIO functions that are root nodes
    root_nodes = [ n for n, in_degree in project.kb.callgraph.in_degree() if in_degree == 0]
    root_nodes_mmio = [ n for n in root_nodes if n in mmio_read_functions]

    # Step 3:
    # Let's verify that there is at least a path from root_nodes_mmio to the 
    # malloc and free
    final_pair = hb_state["final_allocator"]
    malloc = int(final_pair["malloc"],16)
    free = int(final_pair["free"],16)
    
    # These are the root nodes with a static path to malloc we can start to investigate dynamically.
    '''
    root_nodes_mmio_with_path_to_malloc = []
    root_nodes_mmio_with_path_to_free = []
    
    malloc_paths = {}
    free_paths = {}
    for rnm in root_nodes_mmio:
        malloc_callgraph_paths = list(nx.all_simple_paths(project.kb.callgraph, source=rnm, target=malloc))
        l.info("Function {} has {} paths to malloc".format(hex(rnm), len(malloc_callgraph_paths)))
        if len(list(malloc_callgraph_paths)) != 0: 
            malloc_paths[rnm] = malloc_callgraph_paths
            root_nodes_mmio_with_path_to_malloc.append(rnm)
        
        free_callgraph_paths = list(nx.all_simple_paths(project.kb.callgraph, source=rnm, target=free))
        l.info("Function {} has {} paths to free".format(hex(rnm), len(free_callgraph_paths)))
        if len(list(free_callgraph_paths)) != 0: 
            free_paths[rnm] = free_callgraph_paths
            root_nodes_mmio_with_path_to_free.append(rnm)

    if len(root_nodes_mmio_with_path_to_malloc) == 0 or len(root_nodes_mmio_with_path_to_free) == 0:
        l.critical("No root nodes with mmio reading is leading to malloc/free. Aborting.")
        sys.exit(0)
    '''
    
    ht_hunter = StaticHeapTransitionsHunterBlob(project, hb_state, mmio_read_functions)
    is_blob_vulnerable = ht_hunter.run()


    hb_state["blob_vulnerable"] = is_blob_vulnerable

    # Dumping hb_state
    with open(hb_state_file, 'w') as fp:
        json.dump(hb_state, fp)
