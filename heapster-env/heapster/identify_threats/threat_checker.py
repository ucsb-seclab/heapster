

import logging
import json 
import angr.analyses.reaching_definitions.dep_graph as dep_graph

from .analyses import SourceSinkAnalysis, DefsExplorer
from ..utils import *

l = logging.getLogger("heapster.threat_checker    ")
l.setLevel("INFO")


def shut_up(thing):
    lol = logging.getLogger(thing)
    lol.setLevel("CRITICAL")


class ThreatChecker:
    
    def __init__(self, project, hb_state, mmio_nodes):

        self.project = project 
        self.hb_state = hb_state
        self.malloc = int(hb_state["final_allocator"]["malloc"],16)
        self.free = int(hb_state["final_allocator"]["free"],16)
        self.mmio_nodes = mmio_nodes
        self.external_data_sources = set()

        self.writing_bf_funcs = ["memcpy", "memset", "strncpy", "strncat"]

        self.exploitability_metadata = []

    # Just consider if <target> is reachable from a MMIO function.
    def get_xrefs_chain(self, target):
        curr_func_cfg_node = self.project.cfg.model.get_node(target)
        
        # this will contains the address of all the calls to malloc
        # that can be reached from a mmio node.
        calls_to_malloc_from_mmio = set()

        for p in curr_func_cfg_node.predecessors:
            curr_func_cfg_node = self.project.cfg.model.get_node(p.function_address)
            all_func_xrefs = set()
            all_func_xrefs.add(p)
            worklist = set()

            for pp in curr_func_cfg_node.predecessors:
                worklist.add((pp.function_address, pp.addr))
                all_func_xrefs.add(pp)
                while len(worklist) != 0:
                    w = worklist.pop()
                    func_addr = w[0]
                    curr_func_cfg_node = self.project.cfg.model.get_node(func_addr)
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
    
    # Grab MMIO function that actually returns data dependent from MMIO stuff.
    def guess_external_source(self):

        for mmio_func in self.mmio_nodes:
            func_td = self.project.cfg.functions[mmio_func]
            
            if func_td == None:
                continue
            
            func_node = self.project.cfg.model.get_any_node(func_td.addr)

            if func_node != None and len(func_node.predecessors) > 0:

                l.debug("[+] Studying return-value definition for MMIO-function {}".format(hex(mmio_func)))

                # Only if function has a return value...
                if func_td.calling_convention.ret_val != None:

                    offset, size = self.project.arch.registers[func_td.calling_convention.RETURN_VAL.reg_name]

                    # Observations points are the last instruction of basic blocks that are endpoints.
                    observation_points = []
                    for endpoint_type, endpoint_blocknodes in func_td.endpoints_with_type.items():
                        for eb in endpoint_blocknodes:
                            if endpoint_type == 'return':
                                if len(self.project.factory.block(addr=eb.addr, opt_level=1).instruction_addrs) == 0:
                                    continue
                                observation_points.append(("insn", self.project.factory.block(addr=eb.addr, opt_level=1).instruction_addrs[-1], 
                                                        0))
                    try:
                        l.debug("[+] Observation points are:")
                        for obx, ob in enumerate(observation_points):
                            l.debug("[+]  Ob-{} {}".format(obx+1, hex(ob[1])))

                        rd = self.project.analyses.ReachingDefinitions(subject=func_td, 
                                                                    func_graph=func_td.graph,
                                                                    cc = func_td.calling_convention,
                                                                    observation_points = observation_points,
                                                                    dep_graph = dep_graph.DepGraph()
                                                                    )
                    except Exception as e:
                        l.fatal("[!AC] Exception during RD execution")
                        print(e)
                        continue

                    defsExplorer = DefsExplorer(self.project, rd.dep_graph)
                    overall_defs = set()

                    # Sanity check.
                    if len(rd.observed_results.values()) != len(observation_points):
                        continue

                    # Cycle all over the observed_results for the ret-value and
                    # walk the definition backward.
                    for observed_result in rd.observed_results.items():
                        reg_defs = observed_result[1].register_definitions.get_objects_by_offset(offset)
                        for reg_def in reg_defs:
                            reg_seen_defs = defsExplorer.resolve_use_def(reg_def)
                            overall_defs = overall_defs.union(reg_seen_defs)

                    l.debug("[+] Definitions for ret-val are:")
                    for dix, d in enumerate(overall_defs):
                        l.debug("[+]  Def-{} {}".format(dix+1, d))
                        if d[0] == "mmio-mem-const":
                            self.external_data_sources.add(mmio_func)
    
    def run(self):

        shut_up("heapster.source_sink_analysis")
        
        # Grab mmio functions that return mmio-data to callers
        #self.guess_external_source()

        #l.info("[+] MMIO functions that return external data are:")
        #for j,fx in enumerate(self.external_data_sources):
        #    l.info("[+]  MMIO-Function-{} {}".format(j+1, hex(fx)))

        # WEAK: does it exist a path from MMIO function to malloc
        if self.malloc != 0x0:
            malloc_func_cfg_node = self.project.cfg.model.get_node(self.malloc)
            xrefs_malloc = len(malloc_func_cfg_node.predecessors)
            
            self.exploitability_metadata.append("MALLOC_XREFS: {}".format(xrefs_malloc))
            
            result_xrefs_chain, calls_to_malloc_from_mmio = self.get_xrefs_chain(self.malloc)
            if result_xrefs_chain:
                calls_to_malloc_from_mmio = list(calls_to_malloc_from_mmio)
                l.info("[+] ✓ Can call malloc from mmio node [mmio-malloc]")
                self.exploitability_metadata.append("MMIO_MALLOC")

        # WEAK: does it exist a path from MMIO function to free
        if self.free != 0x0:
            result_xrefs_chain, calls_to_free_from_mmio = self.get_xrefs_chain(self.free)
            if result_xrefs_chain:
                l.info("[+] ✓ Can call free from mmio node [mmio-free]")
                self.exploitability_metadata.append("MMIO_FREE")


        if calls_to_malloc_from_mmio is None:
            l.info("[!] ✗ Cannot reach malloc from a mmio functon.")
        else:
            curr_func_cfg_node = self.project.cfg.model.get_any_node(self.free)
            #scope_functions = [ x.function_address for x in curr_func_cfg_node.predecessors] 

            malloc_proto = self.hb_state["malloc_prototype"]
            malloc_proto = json.loads(malloc_proto)

            # Grab target size parameter 
            target_malloc_arg = None
            for k,v in malloc_proto.items():
                if v == "size":
                    if k == "arg_0":
                        target_malloc_arg = "r0"
                    elif k == "arg_1":
                        target_malloc_arg = "r1"
                    elif k == "arg_2":
                        target_malloc_arg = "r2"
                    elif k == "arg_3":
                        target_malloc_arg = "r3"
                    elif k == "arg_4":
                        target_malloc_arg = "r4"
                    elif k == "arg_5":
                        target_malloc_arg = "r5"
                    else:
                        l.critical("Check malloc prototype please...")
                        import ipdb; ipdb.set_trace()
                
            
            l.info("[+] Considering arg [{}] as requested size for malloc".format(target_malloc_arg))

            valid_codelocs_malloc = [ self.project.factory.block(addr=x.addr, opt_level=1).instruction_addrs[-1] for x in calls_to_malloc_from_mmio]
            l.info("[+] Valid codelocs for mmio-malloc are:")
            for vi, vf in enumerate(valid_codelocs_malloc):
                l.info("[+]  Call-{} {}".format(vi+1, hex(vf)))

            if self.malloc != 0x0:
                codeloc_malloc_var_size = []
                found_vuln = False

                for vcm in valid_codelocs_malloc:
                    if found_vuln:
                        break
                    l.info("[+] 🤔 Starting inter-functional RD analysis for mmio-malloc parameter [call-site malloc: {}]".format(hex(vcm)))
                    # Check if malloc parameter is derived from a MMIO function that returns MMIO data
                    for fedidx, feds in enumerate(self.mmio_nodes):
                        if found_vuln:
                            break
                        l.info("[+] SourceSink analysis [source (mmio-node) :{}]<->[sink (malloc) :{}] [{}/{}]".format(hex(feds), hex(self.malloc), fedidx+1, len(self.external_data_sources)))
                        if not self.project.kb.functions[feds]:
                            continue
                        ssa = SourceSinkAnalysis(self.project, 
                                                    self.project.cfg, 
                                                    self.project.kb.functions[feds], # Not really used here...
                                                    self.project.kb.functions[self.malloc],
                                                    [target_malloc_arg],
                                                    scope=1, # just put a value != 0, doesn't matter what.
                                                    valid_sink = [vcm], # only consider malloc callsites reachable from MMIO
                                                    stop_at_undef_arg = True
                                                )
                        ssa.run()

                        if len(ssa.observed_arb_param) != 0:
                            l.info("[!] 😨 Found a MMIO malloc with variable size!")
                            self.exploitability_metadata.append("MMIO_MALLOC_VARIABLE_SIZE_{}".format(hex(vcm)))
                            codeloc_malloc_var_size.append(vcm)

                        # We need codelocs of the basic function where the return of this mmio-malloc-var-size flows.
                        l.info("[+] 🤔 Checking source sink of writing basic functions and mmio-malloc-var-size calls")

                        found_malloc_wbf_path = False
                        
                        basic_functions = self.hb_state['bf_candidates']
                        for bf_candidate in basic_functions:
                            if found_vuln:
                                break
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
                                    if found_vuln:
                                        break
                                    bf_node = self.project.cfg.model.get_node(bf_addr)
                                    calls_to_bf = [ x.addr for x in bf_node.predecessors]
                                    valid_codelocs_bf = [ self.project.factory.block(addr=x, opt_level=1).instruction_addrs[-1] for x in calls_to_bf]

                                    for codeloc_idx,vbf in enumerate(valid_codelocs_bf):
                                        if found_vuln:
                                            break
                                        l.info("[+]  Sink target: [bf_name: {}] [bf_addr: {}] [sink_codeloc: {} | [{}/{}]".format(bf_name, 
                                                                                                                                  hex(bf_addr),
                                                                                                                                  hex(vbf),
                                                                                                                                  codeloc_idx, 
                                                                                                                                  len(valid_codelocs_bf),
                                                                                                                                  )
                                                                                                                                )
                                        l.info("[+]    🏃 Running... [10 mins timeout]")
                                        

                                        ssa = SourceSinkAnalysis(self.project, 
                                                                self.project.cfg, 
                                                                self.project.kb.functions[self.malloc],
                                                                self.project.kb.functions[bf_addr],
                                                                bf_ptr_args,
                                                                scope=1, # just put a value !-0, doesn't matter what.
                                                                valid_source = codeloc_malloc_var_size,
                                                                valid_sink = [vbf],
                                                                timer = 600
                                                                )
                                        ssa.run()
                                        ssa.timer.cancel()
                                        
                                        if len(ssa.observed_source_sink) != 0:
                                            success_log = "[+] ✓ Found source-sink relation between mmio-malloc-var-size and writing basic function at {}".format(hex(vbf))
                                            l.info(success_log)
                                            self.exploitability_metadata.append("MMIO_MALLOC_{}_VARIABLE_SIZE_TO_BF_CODELOC_{}".format(hex(vcm), hex(vbf)))
                                            
                                            # Now, is the size parameter also potentially unbounded? (i.e. not a constant)
                                            if bf_name == "identifiablememcpy" or bf_name == "identifiablereversememcpy":
                                                target_reg = "r2"
                                            elif bf_name == "identifiablememset":
                                                target_reg = "r2"
                                            elif bf_name == "identifiablereversememset":
                                                target_reg = "r1"
                                            elif bf_name == "identifiablestrncat":
                                                self.project.kb.functions[self.malloc], = "r2"
                                            elif bf_name == "identifiablestrncpy":
                                                target_reg = "r2"
                                            else:
                                                l.critical("[!] BF not supported. Aborting.")
                                                assert(False)
                                            
                                            l.info("[+]  🤔 Testing if argument {} of {} at {} can be undefined".format(target_reg, bf_name, hex(vbf)))
                                            l.info("[+]    🏃 Running... [10 mins timeout]")
                                            ssa = SourceSinkAnalysis(self.project, 
                                                                    self.project.cfg, 
                                                                    self.project.kb.functions[self.malloc], # this doesn't matter here
                                                                    self.project.kb.functions[bf_addr],
                                                                    [target_reg],
                                                                    scope=1, # just put a value !-0, doesn't matter what.
                                                                    valid_source = codeloc_malloc_var_size,
                                                                    valid_sink = [vbf],
                                                                    stop_at_undef_arg = True,
                                                                    timer = 600
                                                                    )
                                            ssa.run()
                                            ssa.timer.cancel()

                                            if len(ssa.observed_arb_param) != 0:
                                                success_log = "[+] 🤯 Found source-sink relation between mmio-malloc-var-size and writing basic function with undef size at {}".format(hex(vbf))
                                                l.info(success_log)
                                                self.exploitability_metadata.append("MMIO_MALLOC_{}_VARIABLE_SIZE_TO_BF_VAR_SIZE_CODELOC_{}".format(hex(vcm), hex(vbf)))

                                            found_vuln = True 
                                            break


        return self.exploitability_metadata

