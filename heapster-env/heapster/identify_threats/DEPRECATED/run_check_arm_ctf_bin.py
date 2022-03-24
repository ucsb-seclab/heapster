# -*- coding: utf-8 -*-

import argparse
from .threat_explorer_static5 import StaticHeapTransitionsHunter5
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

    project = angr.Project(elf_file, load_options={'auto_load_libs':True})


    cfg = project.analyses.CFG(resolve_indirect_jumps=True, 
                                cross_references=True, 
                                force_complete_scan=False, 
                                function_prologues=True,
                                show_progressbar=True,
                                normalize=True, 
                                symbols=True, 
                                start_at_entry=True)
    
   

    project.cfg = cfg

    # NOTE: you cannot de-activate this.
    project.analyses.CompleteCallingConventions(recover_variables=True,
                                                analyze_callsites=True,
                                                force=True)

    # ACCESS SYMBOLS THROUGH THE PLT 
    #root_nodes = [project.loader.main_object.get_symbol('main').rebased_addr]
    root_nodes = []
    for x in project.cfg.functions.values():
        if x.name == "main":
            root_nodes.append(x.addr)
            break
            
    l.info("Root nodes at {}".format([hex(x) for x in root_nodes]))

    malloc = 0x0
    for k,v in project.loader.main_object.plt.items():
        if k == "malloc":
            malloc = v
    
    l.info("Malloc at {}".format(hex(malloc)))

    free = 0x0
    for k,v in project.loader.main_object.plt.items():
        if k == "free":
            free = v
    
    l.info("Free at {}".format(hex(free)))

    basic_functions_addrs = []
    # assuming amd64 calling convention (rdi, rsi ...)
    for k,v in project.loader.main_object.plt.items():
        if k == "read":
            basic_functions_addrs.append(("read", v, ["r1"]))
        elif k == "memset":
            basic_functions_addrs.append(("memset", v, ["r0"]))
        elif k == "memcpy":
            basic_functions_addrs.append(("memcpy", v, ["r0"]))
        elif k == "strcpy":
            basic_functions_addrs.append(("strcpy", v, ["r0"]))
        elif k == "strlen":
            basic_functions_addrs.append(("strlen", v, ["r0"]))

    #myread = 0x400bc8 
    l.info("WBF at {}".format(basic_functions_addrs))

    if malloc == 0x0:
        print("No malloc!!!")
        sys.exit(0)

    ht_hunter = StaticHeapTransitionsHunter5(project, malloc, free, basic_functions_addrs, root_nodes)
    ht_hunter.run()