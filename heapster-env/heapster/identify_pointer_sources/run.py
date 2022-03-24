import angr 
import argparse
import datetime
import json
import os
import sys
sys.setrecursionlimit(10**9) 
import angr.analyses.reaching_definitions.dep_graph as dep_graph

import logging

from datetime import datetime
from configparser import ConfigParser 
from pathlib import Path

from ..utils import * 
from ..analyses.pointers_source import PointerSourceAnalysis

l = logging.getLogger("identify_pointer_sources   ")
l.setLevel(logging.INFO)

# Parse heapster global .ini conf
config = ConfigParser()
config.read((Path(__file__).parent / "./heapster.ini").resolve())

# Observation point position
OP_BEFORE = 0
OP_AFTER  = 1

def parse_opts():
    o = argparse.ArgumentParser()
    group_blob_type = o.add_mutually_exclusive_group()
    o.add_argument("--debug", action='store_true')
    o.add_argument("--extra-basic-function", action='append', default=[])
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
    shut_up("angr.analyses.variable_recovery.engine_vex.SimEngineVRVEX")
    shut_up("angr.analyses.calling_convention")
    shut_up("angr.analyses.variable_recovery.engine_base")


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

    l.info("[+]Identifying Pointer Sources Started!")
    # Limit memory to 70GB
    # Will throw a MemoryError exception 
    limit_memory(70000000000)
    
    basic_functions = hb_state['bf_candidates']
    extra_num = 0
    for extra_bf_addr in opts.extra_basic_function:
        if check_existance(bin_cfg, extra_bf_addr):
            basic_functions.append({"name": "ExtraBasicFunction{}".format(extra_num), 
                                    "addr": [extra_bf_addr]})

    pointerSourceAnalysis = PointerSourceAnalysis(project, bin_cfg)

    discovery_contributions = {}
    for bf_candidate in basic_functions:
        bf_name  = bf_candidate["name"]
        bf_addrs = bf_candidate["addr"]
        bf_ptr_args = bf_candidate["pointer_regs"]

        discovery_contributions[bf_name] = []

        for bf_addr in bf_addrs:
            l.info("[+]Analyzing basic function {} candidate at {}".format(bf_name, hex(bf_addr)))
            # Getting all the XRefs
            bf_node = bin_cfg.model.get_any_node(bf_addr)
            xrefs = bf_node.predecessors
            
            # Grab addresses of the functions that have an XRefs to the current basic function
            bf_funcs_preds = list(set([x.function_address for x in xrefs]))

            # Parsing the XRefs given the function where they belong.
            # func_predecessors_dict will contain:
            # [ "func_address_X": [xref1, xref2], "func_address_Y": [xref3] ]
            # This is basically saying: func_X has 2 XRefs to the basic function: "xref1" and "xref2".
            func_predecessors_dict = {}
            for bf_func_pred_addr in bf_funcs_preds:
                func_predecessors_dict[str(bf_func_pred_addr)] = []
            for x in xrefs:
                func_predecessors_dict[str(x.function_address)].append(x)
            
            for bf_func_pred_addr, xrefs in func_predecessors_dict.items():
                bf_func_pred_addr = int(bf_func_pred_addr)
                bf_func_pred = bin_cfg.functions.get_by_addr(bf_func_pred_addr)
                l.info("[+] Now analyzing predecessor func at {}".format(hex(bf_func_pred_addr)))
                l.info("[+] XRefs are:")
                for x_index, x in enumerate(xrefs):
                    l.info("[+]  XRefs-{}: {}".format(x_index, x))

                observation_points = []
                
                for xref in xrefs:
                    call_to_xref_address = project.factory.block(xref.addr).instruction_addrs[-1]
                    observation_points.append(call_to_xref_address)

                # Run analysis for every xref to the basic function
                for op in observation_points:
                    pointerSourceAnalysis.run(bf_func_pred, op, bf_ptr_args)
        
        # Keep track of the pointer sources discovered by this basic function.
        discovery_contributions[bf_name] = [hex(x) for x in pointerSourceAnalysis.partial_pointer_sources]
        pointerSourceAnalysis.partial_pointer_sources = set()
    
    # Dump the state.
    hb_state["identify_pointers_timestamp"] = datetime.now().strftime('%Y-%m-%dT%H:%M:%S.%f%z')
    hb_state["pointer_sources"]    =  [hex(x) for x in pointerSourceAnalysis.pointer_sources]
    hb_state["calls_analyzed"]     =  [hex(x) for x in pointerSourceAnalysis.seen_func_calls]
    hb_state["caller_analyzed"]    =  [hex(x) for x in pointerSourceAnalysis.seen_func_callers]
    hb_state["discovery_contributions"] = discovery_contributions

    with open(hb_state_file, 'w') as fp:
        json.dump(hb_state, fp)