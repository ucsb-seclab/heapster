import angr 
import argparse
import datetime
import json
import os
import sys
sys.setrecursionlimit(10**9) 

import logging

from datetime import datetime
from configparser import ConfigParser 
from pathlib import Path

from .basic_function_models import *
from ..utils import * 

sys.setrecursionlimit(10000)

l = logging.getLogger("identify_basic_functions")
l.setLevel(logging.DEBUG)

# Parse heapster global .ini conf
config = ConfigParser()
config.read((Path(__file__).parent / "./heapster.ini").resolve())


def parse_opts():
    o = argparse.ArgumentParser()
    group_blob_type = o.add_mutually_exclusive_group()
    o.add_argument("--debug", action='store_true')
    o.add_argument('-bf', '--basic-function', action='append')
    o.add_argument("--resume", default=None)
    opts = o.parse_args()
    return opts

def check_supported(bfs):
    to_identify = []
    for f_name in bfs:
        if f_name == "memcpy":
            to_identify.append(IdentifiableMemcpy())
            to_identify.append(IdentifiableReverseMemcpy())
        elif f_name == "memset":
            to_identify.append(IdentifiableMemset())
            to_identify.append(IdentifiableReverseMemset())
            #to_identify.append(IdentifiableSimpleMemset())
        elif f_name == "memcmp":
            to_identify.append(IdentifiableMemcmp())
        elif f_name == "strlen":
            to_identify.append(IdentifiableStrlen())
        elif f_name == "strncat":
            to_identify.append(IdentifiableStrncat())
        elif f_name == "strcat":
            to_identify.append(IdentifiableStrcat())
        elif f_name == "strncpy":
            to_identify.append(IdentifiableStrncpy())
        else:
            l.warning("Function {} not supported".format(f_name))
    return to_identify

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
    to_identify = check_supported(opts.basic_function)
    assert(len(to_identify) != 0)

    if os.path.exists(hb_state_file) and os.path.isfile(hb_state_file):
        with open(hb_state_file, "r") as hb_file:
            hb_state = json.load(hb_file)
    
    config_logger()

    l.info("[+]Loading project")
    project, bin_cfg = load_artifact(hb_state)
    project.hb_state = hb_state

    l.info("[+]Running CompleteCallingConventions analysis (might take a while)")
    project.analyses.CompleteCallingConventions(recover_variables=True, 
                                                force=True, 
                                                analyze_callsites=True)

    l.info("[+]Identifying Basic Functions Started!")

    # Limit memory to 70GB
    # Will throw a MemoryError exception 
    limit_memory(70000000000)

    l.info("[+]Pre-processing of all the functions detected to reduce the search space.")
        
    # Some preliminary filters to cut down the number of functions to analyze.
    filters = [standard_function_filter(),basic_block_filter(), byte_size_filter_max(), callless_filter(), only_jmp_ins_filter()]
    filtered = []
    for f in bin_cfg.functions.values():
        for filt in filters:
            if not filt(f):
                break
        else:
            filtered.append(f)

    l.info("[+]Prefiltering resulted in {}/{} functions".format(len(filtered), len(bin_cfg.functions)))
    hb_state["bf_candidates"] = []

    for t in to_identify:
        l.info("[+]Trying to identify {} in the blob".format(t))
        ident = MyIdentifier(project, filtered, to_identify=[t])
        ident.run()

        for guessed_func, results in ident.identified.items():
            candidate_entry = {}
            candidate_entry["name"] = str(guessed_func)
            candidate_entry["pointer_regs"] = []
            candidate_entry["addr"] = []

            for f, i in results.items():
                if not i:
                    continue
                #l.info(f.name)
                candidate_entry["addr"].append(f.addr)
                for arg in f.arguments:
                    try:
                        wpw = arg.was_pointer_wrapper
                    except AttributeError:
                        continue
                    if wpw:
                        if arg.reg_name not in candidate_entry["pointer_regs"]: 
                            candidate_entry["pointer_regs"].append(arg.reg_name)
                success_log = "[+] ✓ Identified {} at {}".format(candidate_entry["name"], hex(f.addr))
                success_log = f'{bcolors.YELLOWBG}{success_log}{bcolors.ENDC}'
                l.info(success_log)
            
            hb_state["bf_candidates"].append(candidate_entry)
    
    hb_state["find_bf_timestamp"] = datetime.now().strftime('%Y-%m-%dT%H:%M:%S.%f%z')

    with open(hb_state_file, 'w') as fp:
        json.dump(hb_state, fp)
    
