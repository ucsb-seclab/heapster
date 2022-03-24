

import logging
import json 

from .analyses import SourceSinkAnalysis

l = logging.getLogger("StaticHeapTransitionsHunterGT")
l.setLevel("INFO")


def shut_up(thing):
    lol = logging.getLogger(thing)
    lol.setLevel("CRITICAL")

'''
This is the threat identifier when using random CTF 
challenges as target.
'''
class StaticHeapTransitionsHunterGT:
    
    def __init__(self, project, funcs_cc, malloc, free, basic_functions_addrs, mmio_nodes):

        self.project = project 
        self.malloc = malloc
        self.free = free
        self.funcs_cc = funcs_cc
        self.basic_functions_addrs = basic_functions_addrs
        self.mmio_nodes = mmio_nodes

        self.writing_bf_funcs = ["memcpy", "memset", "strncpy", "strcpy", "strcat", "strncat"]

        # Functions containing calls to these procedures are considered returing
        # user input. ( affected by false positive if the return value is not affected by user and
        # from false negative if we are missing some functions)
        self.user_sources = ["strtoul", "getchar", "scanf", "strtoul", 
                             "read", "gets", "fgets", "fgetc",
                             "fscanf", "strtoull"]
        
        self.valid_user_sources = {}
        self.user_sources_callers = []

        self.exploitability_metadata = []

        # Store here calls to function that get user data
        # This is mainly to compensate bad RD over AMD64 and 
        # the missing tag of function call argument for specific functions.
        # NOTE: here I store the calls to
        self.critical_codelocs = []

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
                l.info("Testing {}".format(hex(a.function_address)))
                if a.function_address in self.mmio_nodes:
                    calls_to_malloc_from_mmio.add(p)
        
        if len(calls_to_malloc_from_mmio) != 0:
            l.info("Can reach function {} from an MMIO node!".format(hex(target)))
            l.info("    Reachable calls: {}".format([hex(x.addr) for x in calls_to_malloc_from_mmio]))
            return True, calls_to_malloc_from_mmio
        else:
            l.info("Cannot reach function {} from MMIO node".format(hex(target)))
            return False, None

    def guess_external_source(self):
        for fus in self.user_sources:
            for k,v in self.project.loader.main_object.plt.items():
                if k == fus:
                    self.valid_user_sources[fus] = v
                    break
        l.info("[+] Found the following user source functions in the binary:")
        for fus_name, fus_addr in self.valid_user_sources.items():
            l.info("[+]  {}@{}".format(fus_name, hex(fus_addr)))

        

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
        
        #shut_up("heapster.source_sink_analysis")
        
        self.guess_external_source()

        if self.malloc != 0x0:
            result_xrefs_chain, calls_to_malloc_from_mmio = self.get_xrefs_chain(self.malloc)
            if result_xrefs_chain:
                calls_to_malloc_from_mmio = list(calls_to_malloc_from_mmio)
                self.exploitability_metadata.append("PATH_TO_MALLOC_FROM_MMIO")


        if self.free != 0x0:
            result_xrefs_chain, calls_to_free_from_mmio = self.get_xrefs_chain(self.free)
            if result_xrefs_chain:
                l.info("Can reach call to free using {}".format(calls_to_free_from_mmio))
                self.exploitability_metadata.append("PATH_TO_FREE_FROM_MMIO")

        if calls_to_malloc_from_mmio is None:
            l.info("Cannot reach malloc from a MMIO functon!")
        else:

            valid_codelocs_source_sink = [ self.project.factory.block(addr=x.addr, opt_level=1).instruction_addrs[-1] for x in calls_to_malloc_from_mmio]

            if self.free != 0x0:
                
                l.info("Starting inter-functional RD analysis for free parameter!")

                curr_func_cfg_node = self.project.cfg.get_any_node(self.free)
                #scope_functions = [ x.function_address for x in curr_func_cfg_node.predecessors] 

                # Which are the parameter of free.
                # If we use challenges it is usually the standard prototype.
                target_free_arg = self.funcs_cc["arg0"]
                
                ssa = SourceSinkAnalysis(self.project, 
                                            self.project.cfg, 
                                            self.project.kb.functions[self.malloc],
                                            self.project.kb.functions[self.free],
                                            [target_free_arg],
                                            scope=1, # just put a value != 0, doesn't matter what.
                                            valid_source = valid_codelocs_source_sink,
                                        )
                ssa.run()
                
                # FIXME this can generate some false positives?
                #if len(ssa.observed_arb_param) != 0:
                #    self.exploitability_metadata.append("ARB_FREE")
                
                # source sink only at codelocation where malloc is called from mmio functions!
                if len(ssa.observed_source_sink) != 0:
                    self.exploitability_metadata.append("CONNECTION_MALLOC_FREE")
                
            if calls_to_free_from_mmio and self.malloc != 0x0:
                valid_codelocs_free = [ self.project.factory.block(addr=x.addr, opt_level=1).instruction_addrs[-1] for x in calls_to_free_from_mmio]
                l.info("[+] Valid codeloc for free are:")
                for vi, vf in enumerate(valid_codelocs_free):
                    l.info("[+]  Call-{} {}".format(vi+1, hex(vf)))

                l.info("[+] Starting inter-functional RD analysis for mmio-free parameter!")

                curr_func_cfg_node = self.project.cfg.get_any_node(self.free)
                #scope_functions = [ x.function_address for x in curr_func_cfg_node.predecessors] 

                # Which are the parameter of free.
                # If we use challenges it is usually the standard prototype.
                target_free_arg = self.funcs_cc["arg0"]
                
                for fus in self.valid_user_sources.values():
                    l.info("[+] Considering function user source {}".format(hex(fus)))
                    import ipdb; ipdb.set_trace()
                    ssa = SourceSinkAnalysis(self.project, 
                                                self.project.cfg, 
                                                self.project.kb.functions[fus],
                                                self.project.kb.functions[self.free],
                                                [target_free_arg],
                                                scope=1, # just put a value != 0, doesn't matter what.
                                                valid_sink = valid_codelocs_free
                                            )
                    ssa.run()
                
                # FIXME this can generate some false positives?
                if len(ssa.observed_source_sink) != 0:
                    l.info("[+] Observed param from {}".format(ssa.observed_source_sink))
                    self.exploitability_metadata.append("ARB_FREE")

                
                # Check where malloc ret val flows
                # the following analysis can be merged with the pointer sources one
                l.info("[+] Checking source sink of writing basic functions and malloc calls")
                found_malloc_wbf_path = False

                for bf_candidate in self.basic_functions_addrs:
                    bf_name  = bf_candidate[0]
                    bf_addr = bf_candidate[1]
                    bf_ptr_args = bf_candidate[2]

                    l.info("[+] Checking wbf: {} | addr: {} | arg: {}".format(bf_name, hex(bf_addr), bf_ptr_args))

                    if not self.project.kb.functions.get(bf_addr, None):
                        continue

                    ssa = SourceSinkAnalysis(self.project, 
                                            self.project.cfg, 
                                            self.project.kb.functions[self.malloc],
                                            self.project.kb.functions[bf_addr],
                                            bf_ptr_args,
                                            scope=1, # just put a value !=0 doesn't matter what.
                                            valid_source = valid_codelocs_source_sink
                                            )
                    ssa.run()
            
                    if len(ssa.observed_source_sink) != 0:
                        l.info("[+] ✓ Found source-sink relation between malloc and writing bf")
                        self.exploitability_metadata.append("PATH_TO_WRITE_BF_FROM_MALLOC_RET")
                        found_malloc_wbf_path = True 
                        break

                    if found_malloc_wbf_path:
                        break

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

        l.info(" {}".format(exploitability_report))

