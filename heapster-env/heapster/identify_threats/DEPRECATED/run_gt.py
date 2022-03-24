# -*- coding: utf-8 -*-

import argparse
from .threat_explorer_static_gt import StaticHeapTransitionsHunterGT
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

# Helpful dict to keep track of the calling convention
# of different architecture.
# WARNING: registers are in order! 
ARCH_ARG_REGISTERS = {}
ARCH_ARG_REGISTERS["ARM32"] = ["r0", "r1", "r2", "r3"]
ARCH_ARG_REGISTERS["ARM64"] = ["x0", "x1", "x2", "x3"]
ARCH_ARG_REGISTERS["AMD64"] = ["rdi", "rsi", "rdx", "rcx"]


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
    shut_up("angr.analyses.xrefs.SimEngineXRefsVEX")
    shut_up("cle.backends.elf.relocation")
    shut_up("cle.loader")
    shut_up("angr.analyses.cfg.cfg_fast")
    shut_up("angr.analyses.cfg.cfg_base")
    shut_up("claripy.vsa.strided_interval")


'''
Script to validate the ground-truth binaries 
for the heap-transitions analysis.
'''
if __name__ == "__main__":
    opts = parse_opts()
    elf_file = opts.elf

    if not os.path.exists(elf_file):
        l.fatal("No file at {}. Aborting.".format(hb_state_file))
        sys.exit(-1)

    config_logger()

    l.info("[+] Loading Project")

    project = angr.Project(elf_file, load_options={'auto_load_libs':True})
    l.info("[+] Project Arch is {} {} bits".format(project.arch.name, project.arch.bits))

    funcs_cc = {}
    if "ARM" in project.arch.name and project.arch.bits == 32:
        cc_regs = ARCH_ARG_REGISTERS["ARM32"]
        for j, cc_reg in enumerate(cc_regs):
            cckey = "arg{}".format(j)
            funcs_cc[cckey] = cc_reg
    elif "ARM" in project.arch.name and project.arch.bits == 64:
        cc_regs = ARCH_ARG_REGISTERS["ARM64"]
        for j, cc_reg in enumerate(cc_regs):
            cckey = "arg{}".format(j)
            funcs_cc[cckey] = cc_reg
    elif "AMD64" in project.arch.name:
        cc_regs = ARCH_ARG_REGISTERS["AMD64"]
        for j, cc_reg in enumerate(cc_regs):
            cckey = "arg{}".format(j)
            funcs_cc[cckey] = cc_reg
    else:
        l.critical("[!] Arch not supported")
        import ipdb; ipdb.set_trace()

    l.info("[+] Building binary CFG (may take a while)")
    
    cfg = project.analyses.CFG(resolve_indirect_jumps=True, 
                                cross_references=True, 
                                force_complete_scan=False, 
                                function_prologues=True,
                                show_progressbar=False,
                                normalize=True, 
                                symbols=True, 
                                start_at_entry=True)

    project.cfg = cfg

    # Activating this on ELF binaries is making angr explode very often. 
    #project.analyses.CompleteCallingConventions(recover_variables=True,
    #                                            analyze_callsites=True,
    #                                            force=True)

    # Get the function that represents the main
    root_nodes = []
    for x in project.cfg.functions.values():
        if x.name == "main":
            root_nodes.append(x.addr)
            break
    
    # Main corresponds to the MMIO nodes later.
    l.info("[+] Root nodes at {}".format([hex(x) for x in root_nodes]))

    for k,v in project.loader.main_object.plt.items():
        if k == "malloc":
            malloc = v

    l.info("[+] Malloc at {}".format(hex(malloc)))

    free = 0x0
    for k,v in project.loader.main_object.plt.items():
        if k == "free":
            free = v
    
    l.info("[+] Free at {}".format(hex(free)))

    basic_functions_addrs = []

    for k,v in project.loader.main_object.plt.items():
        if k == "read":
            basic_functions_addrs.append(("read", v, [funcs_cc["arg1"]]))
        elif k == "__read_chk":
            basic_functions_addrs.append(("__read_chk", v, [funcs_cc["arg0"]]))
        elif k == "memset":
            basic_functions_addrs.append(("memset", v, [funcs_cc["arg0"]]))
        elif k == "memcpy":
            basic_functions_addrs.append(("memcpy", v, [funcs_cc["arg0"], funcs_cc["arg1"] ]))
        elif k == "strcpy":
            basic_functions_addrs.append(("strcpy", v, [funcs_cc["arg0"], funcs_cc["arg1"] ]))
        elif k == "strlen":
            basic_functions_addrs.append(("strlen", v, [funcs_cc["arg0"]]))

    l.info("[+] Writing Basic Function at {}".format(basic_functions_addrs))

    ht_hunter = StaticHeapTransitionsHunterGT(project, funcs_cc, malloc, free, basic_functions_addrs, root_nodes)
    ht_hunter.run()