import angr
import claripy
import json
import sys
sys.setrecursionlimit(10**9) 

import threading

#import dive

#from pyvex.lifting.gym import ARMSpotter
from multiprocessing.pool import Pool as Pool
from threading import Timer
import logging
import gc
import argparse
import networkx as nx
from ..utils import *

l = logging.getLogger("heapster.identify_threats.mmio_finder")
l.setLevel(logging.CRITICAL)

# TODO: Make this configurable from the commandline
MMIO_RANGES_DEFAULT = [(0x40000000, 0x60000000)]

# Shortcut to make angr's noisy logging less noisy
def shut_up(thing):
    lol = logging.getLogger(thing)
    lol.setLevel("CRITICAL")

class MMIOFinder:
    def __init__(self, project, hb_state, mmio_ranges=[]):
        self.project = project
        self.hb_state = hb_state
        
        if mmio_ranges == []:
            self.mmio_ranges = MMIO_RANGES_DEFAULT
        else:
            self.mmio_ranges = mmio_ranges

        # Results here.
        self.mmio_read_functions = []

    def run(self):
        results = []

        N = len(self.project.kb.functions.keys())
        try:
            func_addrs = self.project.kb.functions.keys()
            for n,f in enumerate(func_addrs):
                results.append(self.mmio_detector(self.project, f, n, len(func_addrs)))
        except KeyboardInterrupt:
            pass
        
        #j = 0 
        #for r in results:
        #    if r[1]:
        #        j += 1 
        #        print("[{}] Function {} reads from MMIO".format(j, hex(r[0])))
        
        self.mmio_read_functions = list(set([x[0] for x in results if x[1]]))


    def is_mmio_address(self, addr):
        for s, e in self.mmio_ranges:
            if s <= addr < e:
                return True
        return False

    def mmio_detector(self, p, f_addr, n_funcs=0, tot_funcs=0):
        mmio_read = threading.Event()

        l.warning("Analyzing %#08x (%d / %d)" % (f_addr, n_funcs, tot_funcs))

        # TODO write a new analysis instead of modifying the existent Propagator....
        prop = self.project.analyses.Propagator(func=self.project.kb.functions[f_addr], base_state=p.factory.call_state(f_addr))
        
        mem_accesses = list()
        
        '''
        if prop.replacements:
            for block in prop.replacements.keys():
                block_addr = block.block_addr
                block_replacements = prop.replacements[block]
                for br_type, br_value in block_replacements.items():
                    if "VEXMemVar" in str(type(br_type)) and type(br_type.addr) is int:
                        mem_accesses.append(br_type.addr)
        '''

        mem_accesses = prop.mem_accesses
        
        for addr in mem_accesses:
            if self.is_mmio_address(addr):
                mmio_read.set()
                break

        if mmio_read.is_set():
            l.info("Function {} reads from MMIO ({})!".format(hex(f_addr), hex(addr)))

        return f_addr, mmio_read.is_set()