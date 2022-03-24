import angr
import argparse
import json 
import logging
import os
import pickle
pickle._HAVE_PICKLE_BUFFER = False

import shutil
import sys
sys.setrecursionlimit(10**9) 
import yaml 

from datetime import date, datetime
from cle.backends import NamedRegion
from configparser import ConfigParser 
from pathlib import Path
from . import loader

l = logging.getLogger("heapster.load_firmware")
l.setLevel(logging.DEBUG)

# Parse heapster global .ini conf
config = ConfigParser()
config.read((Path(__file__).parent.parent / "./heapster.ini").resolve())

def auto_int(x):
    return int(x, 0)

def parse_opts():
    o = argparse.ArgumentParser()
    group_blob_type = o.add_mutually_exclusive_group()
    o.add_argument("--debug", action='store_true')
    o.add_argument("--fw-conf", default=None)
    o.add_argument("binary")
    
    opts = o.parse_args()
    return opts

def make_heapster_environment(blob_path):
    if os.path.exists(blob_path) and os.path.isfile(blob_path):
        dir_name = os.path.dirname(blob_path)
        blob_name = os.path.basename(blob_path)
        hb_project_folder = os.path.join(dir_name, config["global"]["hb_folder_project_name"])

        if os.path.exists(hb_project_folder):
            l.info("Heapbuster working space exists, press ANY key to proceed.")
            choice = input()
            shutil.rmtree(hb_project_folder)

        os.mkdir(os.path.join(dir_name,config["global"]['hb_folder_project_name']))

        l.info("Opening {}".format(blob_path))

        proj_dump_file = os.path.join(dir_name,"{}/{}.proj".format(config["global"]["hb_folder_project_name"], blob_name))
        blob_unpacked_state_dump_file  = os.path.join(dir_name,"{}/{}.unpacked_state".format(config["global"]["hb_folder_project_name"], blob_name))
        hb_state_file  = os.path.join(hb_project_folder,config["global"]["hb_project_file"])

        return dir_name, blob_name, hb_project_folder, proj_dump_file, hb_state_file
    else:
        l.fatal("No blob at {}".format(blob_path))
        sys.exit(0)

def check_heap_range(project, heap_start, heap_end):
    if project.loader.find_object_containing(heap_start) and project.loader.find_object_containing(heap_end):
        return True
    else:
        return False 

# Shortcut to make angr's noisy logging less noisy
def shut_up(thing):
    lol = logging.getLogger(thing)
    lol.setLevel("CRITICAL")

def config_logger():
    shut_up("angr.analyses.cfg.cfg_fast")
    shut_up("angr.analyses.cfg.cfg_base")
    shut_up("pyvex.lifting.gym.arm_spotter")
    shut_up("angr.state_plugins.symbolic_memory")
    shut_up("angr.analyses.propagator.engine_vex.SimEnginePropagatorVEX")
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

    blob_path = opts.binary
    fw_config_path = opts.fw_conf
    
    config_logger()

    if fw_config_path is None or not os.path.isfile(fw_config_path):
        l.critical("Invalid fw_config file!")
        sys.exit(0)
    if blob_path is None or not os.path.isfile(blob_path):
        l.critical("Invalid blob file!")
        sys.exit(0)

    dir_name, blob_name, hb_project_folder, proj_dump_file, hb_state_file = make_heapster_environment(blob_path)

    with open(fw_config_path, 'r') as fw_conf:
        fw_config = yaml.load(fw_conf, Loader=yaml.SafeLoader)
    
    # Load it!
    p = loader.load_it(blob_path, fw_config)
    p.cfg = loader.cfg_it(p, fw_config)
    
    l.info("Dumping project")
    with open(proj_dump_file, "wb") as proj_file:
        pickle.dump(p,proj_file)

    # Dumping hb state info.
    hb_state = {}
    hb_state["timestamp"] = datetime.now().strftime('%Y-%m-%dT%H:%M:%S.%f%z')
    hb_state["dir_name"] = dir_name
    hb_state["blob_name"] = blob_name
    hb_state["hb_folder"] = hb_project_folder
    hb_state["blob_project"] = proj_dump_file
    hb_state["base_address"] = p.loader.main_object.mapped_base
    hb_state["blob_entry_point"] = hex(p.entry)
    hb_state["blob_stack_pointer"] = hex(p.arch.initial_sp)
    hb_state["num_of_functions"] = len(p.kb.functions)
    
    with open(hb_state_file, 'w') as fp:
        json.dump(hb_state, fp)

    if fw_config["dump-funcs"]:
        funcs_file = hb_project_folder + "/blob.funcs" 
        l.info("Dumping function at {}".format(funcs_file))
        with open(funcs_file, "w") as blob_func_file:
            blob_func_file.write(hex(p.loader.main_object.mapped_base) + "\n")
            for f in p.kb.functions:
                blob_func_file.write(hex(f) + "\n")
    
    l.info("Heapbuster project created")
