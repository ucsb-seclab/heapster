

import logging
import json 

from ..analyses.source_sink import SourceSinkAnalysis

l = logging.getLogger("StaticHeapTransitionsHunter")
l.setLevel("INFO")


def shut_up(thing):
    lol = logging.getLogger(thing)
    lol.setLevel("CRITICAL")

class StaticHeapTransitionsHunter:
    
    def __init__(self, project, hb_state, mmio_nodes):

        self.project = project 
        self.hb_state = hb_state
        self.malloc = int(hb_state["final_allocator"]["malloc"],16)
        self.free = int(hb_state["final_allocator"]["free"],16)
        self.mmio_nodes = mmio_nodes

        self.writing_funcs = ["memcpy", "memset", "strncpy", "strcpy", "strcat", "strncat"]

        self.exploitability_metadata = []

    def get_xrefs_chain(self, target):
        curr_func_cfg_node = self.project.cfg.get_any_node(target)
        
        caller_bbl = None

        all_func_xrefs = set()
        worklist = set()

        for p in curr_func_cfg_node.predecessors:
            worklist.add((p.function_address, p.addr))
            all_func_xrefs.add(p)
        
        while len(worklist) != 0:
            w = worklist.pop()
            func_addr = w[0]
            curr_func_cfg_node = self.project.cfg.get_any_node(func_addr)
            for p in curr_func_cfg_node.predecessors:
                if p not in all_func_xrefs:
                    worklist.add((p.function_address, p.addr))
                    all_func_xrefs.add(p)

        for a in all_func_xrefs:
            if a.function_address in self.mmio_nodes:
                l.info("Can reach function {} from an MMIO node!".format(hex(target)))
                return True
        
        l.info("Cannot reach function {} from MMIO node".format(hex(target)))
        return False
        

    def run(self):
        # base_state = get_init_state(self.project, self.hb_state, self.hb_state["final_allocator"]["mem_dump_path"])
        # We are going to rank the exploitability using different features that we collect in a static way:
        #
        # 1- PATH_TO_MALLOC_FROM_MMIO: does it exist a path from a mmio function to malloc? 
        # 2- CONNECTION_MALLOC_FREE: does it exist a path where malloc's return value flows into free? 
        # 3- ARB_FREE: does it exist a path where free is called with an argument not immediately returned by a call to malloc? 
        # 4- PATH_TO_WRITE_BF_FROM_MALLOC_RET: does it exist a path in which return value of malloc is consumed by a BF that writes data?
        # 
        # OTHERS?
        # 5- ARBITRARY SIZE MALLOC OR ALL CONSTANTS? 
        # 6- 
        # ========================
        # Exploitation Primitives
        # =========================
        # FAKE-FREE: YES if ARB_FREE 
        # DOUBLE_FREE: YES if PATH_TO_MALLOC_FROM_MMIO AND ARB_FREE
        # HEAP-OVERFLOW: YES if PATH_TO_MALLOC_FROM_MMIO and PATH_TO_WRITE_BF_FROM_MALLOC_RET
        # UAF: YES if PATH_TO_MALLOC_FROM_MMIO AND (CONNECTION_MALLOC_FREE OR ARB_FREE) AND PATH_TO_WRITE_BF_FROM_MALLOC_RET
        
        shut_up("heapster.source_sink_analysis")
        
        if self.get_xrefs_chain(self.malloc):
            self.exploitability_metadata.append("PATH_TO_MALLOC_FROM_MMIO")

        l.info("Starting inter-functional RD analysis for free parameter!")

        curr_func_cfg_node = self.project.cfg.get_any_node(self.free)
        #scope_functions = [ x.function_address for x in curr_func_cfg_node.predecessors] 

        # Which are the parameter of free? 
        free_proto = self.hb_state["free_prototype"]
        free_proto = json.loads(free_proto)

        target_free_arg = None
        for k,v in free_proto.items():
            if v == "ptr_to_free":
                if k == "arg_0":
                    target_free_arg = "r0"
                elif k == "arg_1":
                    target_free_arg = "r1"
                elif k == "arg_2":
                    target_free_arg = "r2"
                elif k == "arg_3":
                    target_free_arg = "r3"
                elif k == "arg_4":
                    target_free_arg = "r4"
                elif k == "arg_5":
                    target_free_arg = "r5"
                else:
                    l.critical("Check free prototype please...")
                    import ipdb; ipdb.set_trace()

        ssa = SourceSinkAnalysis(self.project, 
                                    self.project.cfg, 
                                    self.project.kb.functions[self.malloc],
                                    self.project.kb.functions[self.free],
                                    [target_free_arg],
                                    scope=1, # just put a value !-0, doesn't matter what.
                                )
        ssa.run()

        # FIXME this can generate some false positives?
        if len(ssa.observed_arb_param) != 0:
            self.exploitability_metadata.append("ARB_FREE")
        
        if len(ssa.observed_source_sink) != 0:
            self.exploitability_metadata.append("CONNECTION_MALLOC_FREE")
        
        # Check where malloc ret val flows 
        bfs = self.hb_state.get("discovery_contributions", None)
        if bfs is None:
            l.info("Skipping check for PATH_TO_WRITE_BF_FROM_MALLOC_RET because we don't have discovery_contributions info.")
        else:
            # Get all the BF that made us discover malloc! 
            bfs_malloc = [ k.lower() for k,v in bfs.items() if hex(self.malloc) in bfs[k]]
            found_wbfs_malloc = False
            for bf_name in bfs_malloc:
                for wbf in self.writing_funcs:
                    if wbf in bf_name:
                        found_wbfs_malloc = True
            
            if found_wbfs_malloc:
                self.exploitability_metadata.append("PATH_TO_WRITE_BF_FROM_MALLOC_RET")
        

        l.info("Report for exploitability:")
        exploitability_report = []

        # FAKE-FREE: YES if ARB_FREE 
        # DOUBLE_FREE: YES if PATH_TO_MALLOC_FROM_MMIO AND ARB_FREE
        # HEAP-OVERFLOW: YES if PATH_TO_MALLOC_FROM_MMIO and PATH_TO_WRITE_BF_FROM_MALLOC_RET
        # UAF: YES if PATH_TO_MALLOC_FROM_MMIO AND (CONNECTION_MALLOC_FREE OR ARB_FREE) AND PATH_TO_WRITE_BF_FROM_MALLOC_RET

        if "ARB_FREE" in self.exploitability_metadata:
            exploitability_report.append("FAKE-FREE")
        if "PATH_TO_MALLOC_FROM_MMIO" in self.exploitability_metadata and "ARB_FREE" in self.exploitability_metadata:
            exploitability_report.append("DOUBLE_FREE")
        if "PATH_TO_MALLOC_FROM_MMIO" in self.exploitability_metadata and "PATH_TO_WRITE_BF_FROM_MALLOC_RET" in self.exploitability_metadata:
            exploitability_report.append("HEAP-OVERFLOW")
        if "PATH_TO_MALLOC_FROM_MMIO" in self.exploitability_metadata and \
                            ("CONNECTION_MALLOC_FREE" in self.exploitability_metadata or "ARB_FREE" in self.exploitability_metadata) and \
                                     "PATH_TO_WRITE_BF_FROM_MALLOC_RET" in self.exploitability_metadata:
            exploitability_report.append("UAF")

        print(exploitability_report)

