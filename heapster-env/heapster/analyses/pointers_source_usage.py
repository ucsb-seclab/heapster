import angr
import angr.analyses.reaching_definitions.dep_graph as dep_graph
import logging
import networkx
import sys
import hashlib

from angr.engines.light import SpOffset, RegisterOffset
from angr.knowledge_plugins.key_definitions.atoms import Register, SpOffset, MemoryLocation
from angr.knowledge_plugins.key_definitions.undefined import undefined, Undefined
from angr.knowledge_plugins.key_definitions.definition import Definition, ParamTag, RetValueTag, InitValueTag
from angr.knowledge_plugins.key_definitions.dataset import DataSet

from heapster.utils import reg_to_offset, offset_to_reg

# Observation point position
OP_BEFORE = 0
OP_AFTER  = 1

l = logging.getLogger("heapster.identify_pointer_usage_sources")
l.setLevel(logging.DEBUG)

class PointerSourceUsageAnalysis():
    def __init__(self, project, bin_cfg, func_predecessors_dict):
        self.project = project
        self.bin_cfg = bin_cfg

        # Initial state.
        self.sources = func_predecessors_dict
        self.sources_funcs = [int(x,10) for x in self.sources.keys()]

        # Tie the knot.
        self.seen_calls = set()
        self.seen_callers = set()
        
        # The final result.
        self.usage_analysys_results = []
        
        # Diagnostic.
        self.seen_func_calls = set()
        self.rd_exceptions = []
        self.rd_zero_results = 0
        self.invalid_func_exceptions = []
        self.filtered_pointer_sources = set()

    def reset(self):
        self.seen_calls = set()
        self.seen_callers = set()
        self.source_pred = None
        self.source_xref = None
        self.sink_xref = None
        self.rd_exceptions = []
        self.rd_zero_results = 0
        self.invalid_func_exceptions = []
        self.filtered_pointer_sources = set()

    def run(self, target_function, observation_point, target_registers):
        calls_to_analyze = set()
        callers_to_analyze = set()
        try:
            rd = self.project.analyses.ReachingDefinitions(subject=target_function, 
                                                           func_graph=target_function.graph,
                                                           cc = target_function.calling_convention,
                                                           observation_points = [("insn", observation_point, OP_BEFORE )],
                                                           dep_graph = dep_graph.DepGraph()
                                                          )
        except Exception as e:
            print(e)
            self.rd_exceptions.append(e)
            return
        
        defsExplorer = DefsExplorer(self.project, rd.dep_graph)
        overall_defs = set()

        # Sanity check, 1 ob_point == 1 observed_results. 
        assert(len(rd.observed_results.values()) == 1)

        # Collect all the definitions for args.
        for arg in target_registers:
            reg_offset = reg_to_offset(self.project, arg)
            assert(reg_offset != -1)
            # We can have multiple definitions for a register reaching a given xref.
            reg_defs = rd.one_result.register_definitions.get_objects_by_offset(reg_offset)

            #assert(len(reg_defs) != 0)
            
            # Collapse all the definitions.
            for reg_def in reg_defs:
                reg_seen_defs = defsExplorer.resolve_use_def(reg_def)
                for definition in reg_seen_defs:
                    overall_defs.add(definition)

            # Check the definitions for a specific argument of this basic function.
            for definition in overall_defs:
                if definition[0] == "retval" and definition[1] != None:
                    l.info("Definition is coming from retval of func {}".format(definition[1]))
                    # Add caller, callee and location of the call.
                    calls_to_analyze.add((target_function, definition[1], definition[2]))
                elif definition[0] == "param":
                    l.info("Definition is coming from arg {} of func {}".format(definition[1], hex(target_function.addr)))
                    callers_to_analyze.add((hex(target_function.addr), definition[1]))
                else:
                    pass 

            if calls_to_analyze: self.analyze_call(calls_to_analyze)
            if callers_to_analyze: self.analyze_caller(callers_to_analyze)
    
    def _def_used_as_arg(self, rd_result, target_def, aaa):
        import ipdb; ipdb.set_trace()
        pass

    def analyze_call(self, funcs):
        worklist = funcs.copy()
        while len(worklist) != 0:
            current_target = worklist.pop()

            # Extract function information.
            current_caller = current_target[0]
            assert(type(current_caller) != str)
            current_callee = current_target[1]
            self.seen_func_calls.add(current_callee)
            assert(type(current_callee) == str)
            call_location = current_target[2]
            assert(type(call_location) == int)

            # Create the ID to avoid re-analyze function in the same context later.
            call_id = hashlib.md5((str(current_caller.addr)+str(current_callee)+str(call_location)).encode()).hexdigest()
            l.info("Analyzing this function {} with this caller {} at this location {}".format(current_callee, hex(current_caller.addr), hex(call_location)))

            if call_id not in self.seen_calls:
                self.seen_calls.add(call_id)
                try:
                    func_td = self.bin_cfg.functions.get_by_addr(int(current_callee,16))
                except Exception as e:
                    self.invalid_func_exceptions.append(e)
                    continue 
                
                # Sanity check.
                assert(type(func_td.calling_convention.RETURN_VAL) is angr.calling_conventions.SimRegArg)
                offset, size = self.project.arch.registers[func_td.calling_convention.RETURN_VAL.reg_name]
                assert(offset != -1)

                # Observations points are the last instruction of basic blocks that are endpoints.
                observation_points = [ ("insn", self.project.factory.block(addr=blocknode.addr, opt_level=1).instruction_addrs[-1], 
                                             OP_BEFORE) for blocknode in func_td.endpoints]

                try:
                    rd = self.project.analyses.ReachingDefinitions(subject=func_td, 
                                                                    func_graph=func_td.graph,
                                                                    cc = func_td.calling_convention,
                                                                    observation_points= observation_points,
                                                                    dep_graph = dep_graph.DepGraph()
                                                                    )
                except Exception as e:
                    self.rd_exceptions.append(e)
                    continue

                defsExplorer = DefsExplorer(self.project, rd.dep_graph)
                overall_defs = set()

                # Sanity check.
                assert(len(rd.observed_results.values()) == len(observation_points))
                
                # If this is the function containing the call to the basic function
                # we want to check for the usages of the register r0 to see if its 
                # definition has been used at the codeloc of the call to the source function.
                if func_td.addr in self.sources_funcs:
                    if self._def_used_as_arg(rd, func_td.calling_convention.RETURN_VAL.reg_name, "dummy"):
                        pass
                        #self.usage_analysys_results.append(())

                # Cycle all over the observed_results for the ret-value and
                # walk the definition backward.
                for observed_result in rd.observed_results.items():
                    reg_defs = observed_result[1].register_definitions.get_objects_by_offset(offset)
                    #assert(len(reg_defs) != 0)

                    for reg_def in reg_defs:
                        reg_seen_defs = defsExplorer.resolve_use_def(reg_def)
                        for definition in reg_seen_defs:
                            overall_defs.add(definition)

                # Analyze the observed definitions of the return argument.
                for definition in overall_defs:
                    if definition[0] == "retval":
                        # It's not always guaranteed that the retval tag of a definition has the
                        # func addr, in those casese we call it a day (definition[1] will be None).
                        l.info("Definition is coming from retval of func {}".format(definition[1]))
                        call_id = hashlib.md5((str(func_td.addr)+str(definition[1])+str(definition[2])).encode()).hexdigest()
                        if definition[1] and call_id not in self.seen_calls:
                            worklist.add((func_td, definition[1], definition[2]))

                    elif definition[0] == "param":
                        self.run(current_caller, call_location, [offset_to_reg(self.project, definition[1].reg_offset)])
                    else: 
                        # Found a constant/static definition
                        pass 

    def analyze_caller(self, funcs):
        l.debug("Analyzing callers: {}".format(funcs))
        worklist = funcs.copy()
        
        while len(worklist) != 0:
            current_function = worklist.pop()
            
            if current_function not in self.seen_callers:

                self.seen_callers.add(current_function)
                current_function_addr = int(current_function[0],16)
                current_function_arg = current_function[1] 
                assert(current_function_arg.reg_offset != -1)
                node = self.bin_cfg.model.get_any_node(current_function_addr)
                
                # Get all the XRefs
                func_predecessors = list(set([xref.function_address for xref in node.predecessors]))

                func_predecessors_dict = {}
                for pred_func_addr in func_predecessors:
                    func_predecessors_dict[str(pred_func_addr)] = []
                for xref in node.predecessors:
                    func_predecessors_dict[str(xref.function_address)].append(xref)
                l.info("Analyzing predecessors of {}".format(current_function[0]))

                for pred_function_addr, xrefs in func_predecessors_dict.items():
                    pred_function_addr = int(pred_function_addr)
                    l.info("Now analyzing predecessor func at {}".format(hex(pred_function_addr)))
                    l.info("XRefs are {}".format((xrefs)))

                    for xref in xrefs:
                        l.info("Analyzing XRefs at {}".format(hex(xref.addr)))
                        start_function = self.bin_cfg.functions.get_by_addr(pred_function_addr)
                        
                        # only one observation point!
                        call_to_xref_address = self.project.factory.block(xref.addr).instruction_addrs[-1]

                        try:
                            rd = self.project.analyses.ReachingDefinitions(subject=start_function, 
                                                                        func_graph=start_function.graph,
                                                                        cc = start_function.calling_convention,
                                                                        observation_points= [("insn", call_to_xref_address , 0)],
                                                                        dep_graph = dep_graph.DepGraph()
                                                                        )
                        except Exception as e:
                            self.rd_exceptions.append(e)
                            continue
                        
                        # Sanity check, 1 ob_point -> 1 observed_results! 
                        assert(len(rd.observed_results.values()) == 1)
                        param_defs = rd.one_result.register_definitions.get_objects_by_offset(current_function_arg.reg_offset)
                        #assert(len(param_defs)!=0)

                        if start_function.addr in self.sources_funcs:
                            if self._def_used_as_arg(rd, param_defs, call_to_xref_address):
                                pass
                                #self.usage_analysys_results.append(())

                        for param_def in param_defs:
                            defsExplorer = DefsExplorer(self.project, rd.dep_graph)
                            param_seen_defs = defsExplorer.resolve_use_def(param_def)
                            
                            for definition in param_seen_defs:
                                if definition[0] == "retval":
                                    call_func_address = definition[1]
                                    l.info("Definition is coming from retval of func {}".format(call_func_address))
                                    if call_func_address and call_func_address not in self.seen_calls: 
                                        self.analyze_call(set([(start_function, call_func_address, definition[2])]))
                                elif definition[0] == "param":
                                    new_caller = (hex(pred_function_addr), definition[1])
                                    l.info("Definition is coming from arg {} of func {}".format(definition[1], hex(pred_function_addr)))
                                    if new_caller not in self.seen_callers:
                                        self.analyze_caller(set([new_caller]))
                                    else:
                                        l.warning("Arg {} of func {} has already been analyzed. Skipping.".format(definition[1], hex(pred_function_addr)))
                                else:
                                    pass

# Utility class to walk back the definitions graph.
class DefsExplorer():
    def __init__(self, project, rd_ddg_graph):
        self.project = project
        self.rd_ddg_graph = rd_ddg_graph

    def resolve_use_def(self, reg_def):
        # Now we need to analyze the definition for this atom
        reg_seen_defs = set()
        defs_to_check = set()
        defs_to_check.add(reg_def)
    
        # Cache of all seen nodes (Tie the knot)
        seen_defs = set()

        while len(defs_to_check) != 0:
            current_def = defs_to_check.pop()
            seen_defs.add(current_def) 
            # Check if the current Definition has a tag 
            def_value = self.check_definition_tag(current_def)
            
            # If we have spot a tagged definition we are done
            # OBSERVATION 1: our tagged definitions have only one value in the DataSet: "Undefined"
            #                because they are either a fresh definition that overwrites everything (a retval) or
            #                an initial parameter (func args)
            if def_value:
                reg_seen_defs.add(def_value)
            else:
                dataset = current_def.data 
                # Boolean guard: do we have any undefined pointers? 
                undefined_pointers = False 
                
                # A value in DataSet can be "Int" or "Undefined"
                for data in dataset:
                    if type(data) == Undefined: undefined_pointers = True  

                # If we have undefined pointers (a.k.a. Top value) we need to process the predecessors.
                if undefined_pointers:
                    for pred in self.rd_ddg_graph.graph.predecessors(current_def):
                        if pred not in seen_defs:
                            defs_to_check.add(pred)
                else:
                     # This is a constant.
                    def_value = ("const", None)
                    reg_seen_defs.add(def_value)
        return reg_seen_defs

    def check_definition_tag(self, definition):
        if definition.tag:
            if type(definition.tag) == RetValueTag:
                # Metadata contains the callee address + where the call happens.
                return ("retval", definition.tag.metadata, definition.codeloc.ins_addr)
            elif type(definition.tag) == ParamTag:
                # The param is defined by the Atom of this definition.
                return ("param", definition.atom)
        else:
            return None