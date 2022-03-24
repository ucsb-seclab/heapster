
import argparse
from .threat_checker import ThreatChecker


import json
import logging
import networkx as nx
import os
import sys

from .mmio_finder import MMIOFinder
from ..utils import *

l = logging.getLogger("heapster.threat_checker    ")
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

    # Config
    config_logger()

    if os.path.exists(hb_state_file) and os.path.isfile(hb_state_file):
        with open(hb_state_file, "r") as hb_file:
            hb_state = json.load(hb_file)
    else:
        l.fatal("No file at {}. Aborting.".format(hb_state_file))
        sys.exit(-1)

    l.info("[+] Analyzing blob [{}]".format(hb_state["blob_name"]))
    project, bin_cfg = load_artifact(hb_state)
    l.info("[!] Project loaded")

    l.info("[+] Running CompleteCallingConventions analysis (might take a while)")
    project.analyses.CompleteCallingConventions(recover_variables=True, 
                                                force=True, 
                                                analyze_callsites=True)

    l.info("[+] ⚔️  ThreatChecker started!")

    # Step 1: 
    # Collect functions that read data from MMIO
    mmiofinder = MMIOFinder(project, hb_state)
    mmiofinder.run()
    mmio_read_functions = mmiofinder.mmio_read_functions
    if len(mmio_read_functions) == 0:
        l.critical("No function reads input from MMIO. Aborting.")
        sys.exit(0)
    
    l.info("[+] Function with MMIO operations")
    for x in mmio_read_functions:
        l.info("[+] {}".format(hex(x)))
    
    # Step 2: 
    # Keep MMIO functions that are root nodes
    root_nodes = [ n for n, in_degree in project.kb.callgraph.in_degree() if in_degree == 0]
    root_nodes_mmio = [ n for n in root_nodes if n in mmio_read_functions]

    final_pair = hb_state["final_allocator"]
    malloc = int(final_pair["malloc"],16)
    free = int(final_pair["free"],16)
    
    # Step 3:
    # Run the threat checker to see if there exists a static flow 
    # between a writing basic function and a malloc reachable from MMIO.
    ht_hunter = ThreatChecker(project, hb_state, mmio_read_functions)
    threat_properties = ht_hunter.run()

    ## Register results.
    hb_state["threat_properties"] = threat_properties

    #if is_blob_vulnerable:
    #    success_log = "[+] ✓ Blob is vulnerable"
    #    success_log = f'{bcolors.YELLOWBG}{success_log}{bcolors.ENDC}'
    #    l.info(success_log)
    #else:
    #    l.info("[!] ✗ Blob is not vulnerable")

    l.info("[+] Collected properties are:")
    for i,p in enumerate(threat_properties):
        l.info("[+] ⚔️  {}".format(p))

    # Dumping hb_state
    with open(hb_state_file, 'w') as fp:
        json.dump(hb_state, fp)


    # JUST TO CATCH OUTPUT, REMOVE ME
    #print(threat_properties)