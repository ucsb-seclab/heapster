
import argparse
from .threat_explorer_static3 import StaticHeapTransitionsHunter3
import angr 

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
    o.add_argument("--debug", action='store_true', default=False)
    o.add_argument("--elf", default=None)
    opts = o.parse_args()
    return opts


if __name__ == "__main__":
    opts = parse_opts()
    elf_file = opts.elf

    if not os.path.exists(elf_file):
        l.fatal("No file at {}. Aborting.".format(hb_state_file))
        sys.exit(-1)

    l.info("Loading Project")

    project = angr.Project(elf_file, load_options={'auto_load_libs':False}, arch="ARMCortexM")


    cfg = project.analyses.CFG(resolve_indirect_jumps=True, 
                                cross_references=True, 
                                force_complete_scan=False, 
                                function_prologues=True,
                                show_progressbar=True,
                                normalize=True, 
                                symbols=True, 
                                start_at_entry=True)
    
    project.cfg = cfg
    project.analyses.CompleteCallingConventions(recover_variables=True,
                                                analyze_callsites=True,
                                                force=True)

    root_nodes = [project.loader.main_object.get_symbol('main').rebased_addr]
    l.info("Root nodes at {}".format([hex(x) for x in root_nodes]))

    malloc = project.loader.main_object.get_symbol('malloc').rebased_addr
    l.info("Malloc at {}".format(hex(malloc)))

    free = project.loader.main_object.get_symbol('free').rebased_addr
    l.info("Free at {}".format(hex(free)))

    myread = project.loader.main_object.get_symbol('myread').rebased_addr
    l.info("Read at {}".format(hex(myread)))

    ht_hunter = StaticHeapTransitionsHunter3(project, malloc, free, myread, root_nodes)
    ht_hunter.run()