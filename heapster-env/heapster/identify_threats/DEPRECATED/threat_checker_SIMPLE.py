

import logging
import json 
import angr.analyses.reaching_definitions.dep_graph as dep_graph

from .analyses import SourceSinkAnalysis
from ..utils import *

l = logging.getLogger("heapster.threat_checker")
l.setLevel("INFO")


def shut_up(thing):
    lol = logging.getLogger(thing)
    lol.setLevel("CRITICAL")

'''
This is the threat identifier when using a firmware blob + hb_state  
as target.
'''
class ThreatChecker:
    
    def __init__(self, project, hb_state, mmio_nodes):

        self.project = project 
        self.hb_state = hb_state
        self.malloc = int(hb_state["final_allocator"]["malloc"],16)
        self.free = int(hb_state["final_allocator"]["free"],16)
        self.mmio_nodes = mmio_nodes
        self.external_data_sources = set()

        self.writing_bf_funcs = ["memcpy", "memset", "strncpy", "strcpy", "strcat", "strncat"]

        self.exploitability_metadata = []

    def get_xrefs_chain(self, target):
        curr_func_cfg_node = self.project.cfg.get_node(target)
        
        # this will contains the address of all the calls to malloc
        # that can be reached from a mmio node.
        calls_to_malloc_from_mmio = set()

        for p in curr_func_cfg_node.predecessors:
            curr_func_cfg_node = self.project.cfg.get_node(p.function_address)
            all_func_xrefs = set()
            all_func_xrefs.add(p)
            worklist = set()

            for pp in curr_func_cfg_node.predecessors:
                worklist.add((pp.function_address, pp.addr))
                all_func_xrefs.add(pp)
                while len(worklist) != 0:
                    w = worklist.pop()
                    func_addr = w[0]
                    curr_func_cfg_node = self.project.cfg.get_node(func_addr)
                    for ppp in curr_func_cfg_node.predecessors:
                        if ppp not in all_func_xrefs:
                            worklist.add((ppp.function_address, ppp.addr))
                            all_func_xrefs.add(ppp)

            # Check if any of the xrefs is a mmio_node
            for a in all_func_xrefs:
                if a.function_address in self.mmio_nodes:
                    calls_to_malloc_from_mmio.add(p)
        
        if len(calls_to_malloc_from_mmio) != 0:
            l.debug("[+] Can reach function {} from an MMIO node!".format(hex(target)))
            l.debug("[+] Reachable calls: {}".format([hex(x.addr) for x in calls_to_malloc_from_mmio]))
            return True, calls_to_malloc_from_mmio
        else:
            l.debug("[!] Cannot reach function {} from MMIO node".format(hex(target)))
            return False, None
    
    def is_writing_bf(self, curr_bf_name):
        for wbf in self.writing_bf_funcs:
            if wbf in curr_bf_name.lower():
                return True
        return False 

    def run(self):
        
        # Is this blob possibly vulnerable? 
        vulnerable = False 

        shut_up("heapster.source_sink_analysis")

        if self.malloc != 0x0:
            result_xrefs_chain, calls_to_malloc_from_mmio = self.get_xrefs_chain(self.malloc)
            if result_xrefs_chain:
                calls_to_malloc_from_mmio = list(calls_to_malloc_from_mmio)
                success_log = "[+] ✓ Can call malloc from mmio node [mmio-malloc]"
                l.info(success_log)

        if calls_to_malloc_from_mmio is None:
            l.info("[!] ✗ Cannot reach malloc from a mmio functon!")
        else:
            l.info("[+] Checking source sink of writing basic functions and mmio-malloc calls")
            valid_codelocs_source_sink = [ self.project.factory.block(addr=x.addr, opt_level=1).instruction_addrs[-1] for x in calls_to_malloc_from_mmio]

            found_malloc_wbf_path = False
            basic_functions = self.hb_state['bf_candidates']
            for bf_candidate in basic_functions:
                bf_name  = bf_candidate["name"].lower()
                bf_addrs = bf_candidate["addr"]
                bf_ptr_args = bf_candidate["pointer_regs"]

                wbf_to_check = False
                for wbf in self.writing_bf_funcs:
                    if wbf in bf_name:
                        wbf_to_check = True
                        break
                if not wbf_to_check:
                    continue # go to next bf 
                else:
                    for bf_idx, bf_addr in enumerate(bf_addrs):
                        l.info("[+]  Sink target: {}".format(bf_name))
                        l.info("[+]    🏃 Running...")
                        ssa = SourceSinkAnalysis(self.project, 
                                                self.project.cfg, 
                                                self.project.kb.functions[self.malloc],
                                                self.project.kb.functions[bf_addr],
                                                bf_ptr_args,
                                                scope=1, # just put a value !-0, doesn't matter what.
                                                valid_source = valid_codelocs_source_sink
                                                )
                        ssa.run()
                
                        if len(ssa.observed_source_sink) != 0:
                            success_log = "[+] ✓ Found source-sink relation between malloc and writing basic function"
                            l.info(success_log)
                            self.exploitability_metadata.append("PATH_TO_WRITE_BF_FROM_MALLOC_RET")
                            found_malloc_wbf_path = True 
                            break

        VULNERABLE = True 
        if len(self.exploitability_metadata) == 0:
            return not VULNERABLE 
        else:
            return VULNERABLE
