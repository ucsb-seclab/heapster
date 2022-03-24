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

l = logging.getLogger("heapster.source_sink_analysis")
l.setLevel(logging.CRITICAL)

'''
This analysis spot if there is a match between
the return value of the function 'source_func' and
one of the arguments of the function 'sink_func' 
in 'sink_target_registers'.

a = source_func(x)
[...]
sink_func(a,...)

Observed results are in observed_source_sink.

WARNING: This analysis does not give ALL the possible 
matches, but mostly at least ONE match if it exists.
This is to guarantee termination.
'''
class SourceSinkAnalysis():
    def __init__(self, project, bin_cfg, source_func, sink_func, sink_target_registers, scope=0, scope_function = None, valid_source= None, valid_sink=None):
        self.project = project
        self.bin_cfg = bin_cfg
        self.scope = scope
        self.scope_function  = scope_function

        # source sink valid only at specific codeloc!
        self.valid_source = [] if not valid_source else valid_source
        self.valid_sink = [] if not valid_sink else valid_sink

        # Source and Sink.
        self.source = source_func
        self.sink = sink_func
        self.sink_target_registers = sink_target_registers
        self.current_sink_target_register = None
        
        # Results here.
        self.observed_source_sink = set()
        self.stop_analysis = False
        self.observed_arb_param = set()

        # Tie the knot.
        self.seen_call_ids = set()
        self.seen_caller_ids = set()
        
        # Diagnostic.
        self.rd_exceptions = []
        self.invalid_func_exceptions = []
        self.start_sink = None

    def run(self):
        l.info("[S] Trying to find a match between {} retval and {} args".format(hex(self.source.addr), hex(self.sink.addr)))
        sink_node = self.bin_cfg.model.get_any_node(self.sink.addr)
        sink_node_preds = sink_node.predecessors # getting all the XRefs
        sink_cc =  self.project.kb.functions[self.sink.addr].calling_convention
        
        # Grab all functions that have an xrefs to the function
        sink_funcs_preds = list(set([x.function_address for x in sink_node_preds]))

        # Parsing the XRefs given the function where they belong.
        # func_predecessors_dict will contain:
        # [ "func_address_X": [xref1, xref2], "func_address_Y": [xref3] ]
        # This is basically saying: func X has two xrefs to the baic function: "xref1" and "xref2".
        sink_predecessors_dict = {}
        for sink_func_pred_addr in sink_funcs_preds:
            sink_predecessors_dict[str(sink_func_pred_addr)] = []
        for x in sink_node_preds:
            sink_predecessors_dict[str(x.function_address)].append(x)
    
        for sink_func_pred_addr, xrefs in sink_predecessors_dict.items():
            sink_func_pred_addr = int(sink_func_pred_addr)
            sink_func_pred = self.bin_cfg.functions.get_by_addr(sink_func_pred_addr)

            l.info("[S] Now analyzing predecessor func at {}".format(hex(sink_func_pred_addr)))
            l.info("[S] XRefs are {}".format((xrefs)))

            observation_points = []
            # Every xref to the sink in this predecessor is an observation point.
            for xref in xrefs:
                call_to_xref_address = self.project.factory.block(xref.addr).instruction_addrs[-1]
                l.info("[S] Call to xref at {}".format(hex(call_to_xref_address)))
                
                # We add this call if the valid_sink is not specified, OR, if the 
                # call is a valid sink.
                if self.valid_sink == [] or call_to_xref_address in self.valid_sink:
                    observation_points.append(call_to_xref_address)
                else:
                    l.critical("[!S]  Discarding call because not valid sink!")

            for op in observation_points:
                self.start_sink = op
                l.info("[S] Starting from xref at {}".format(hex(op)))
                self._run(sink_func_pred, op, self.sink_target_registers)


    def _run(self, target_function, observation_point, target_registers):
        
        if self.stop_analysis:
            return 

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
            l.critical("Exception in RD, skipping this callsite.")
            self.rd_exceptions.append(e)
            return
        
        defsExplorer = DefsExplorer(self.project, rd.dep_graph)
        overall_defs = set()

        # Sanity check, 1 ob_point <= 1 observed_results (0 is error). 
        if len(rd.observed_results.values()) != 1:
            l.critical("No observable results for this callsite")
            return 

        if rd.observed_results == {}:
            l.error("No result for analysis of function {} with obs-point at {}".format(hex(target_function.addr), observation_point))
            self.rd_zero_results += 1
            return 

        # Collect all the definitions for args.
        for sink_arg in target_registers:

            # Save the current sink argument under analysis.
            self.current_sink_target_register = sink_arg

            reg_offset = reg_to_offset(self.project, sink_arg)
            # We can have multiple definitions for a register reaching a given xref.
            reg_defs = rd.one_result.register_definitions.get_objects_by_offset(reg_offset)
            
            if len(reg_defs) == 0:
                l.warning("[!_S] No definition for register {}".format(sink_arg))
                l.warning("[!_S] Attempting to detect transition wrapper.")
                if self._is_wrapper(target_function):
                    l.info("[!_S] Detected wrapper of function {}".format(hex(target_function.addr)))
                    l.info("[!_S] Adding additional definitions to continue analysis at the callers.")
                    callers_to_analyze.add((hex(target_function.addr), Register(reg_offset,4)))
                else:
                    l.warning("[!_S]Could not detect wrapper, stopping research here at {}".format(hex(target_function.addr)))

            #assert(len(reg_defs) != 0)
            # Collapse all the definitions.
            overall_defs = set()
            for reg_def in reg_defs:
                reg_seen_defs = defsExplorer.resolve_use_def(reg_def)
                overall_defs = overall_defs.union(reg_seen_defs)

            # Check the definitions for a specific argument of this basic function.
            for definition in overall_defs:
                if definition[0] == "retval" and definition[1] != None:
                    l.info("[_S] Definition is coming from retval of func {}".format(definition[1]))
                    if int(definition[1],16) == self.source.addr:
                        l.info("[_S] Observed a flow from return value of {} to {}".format(hex(self.source.addr), hex(self.sink.addr)))
                        if self.valid_source != []:
                            if definition[2] in self.valid_source: 
                                self.observed_source_sink.add((definition[2], self.start_sink, self.current_sink_target_register))
                                #self.stop_analysis = True
                            else:
                                l.info("[CL] Flow not at the codeloc requested. Continue.")
                        else:
                            self.observed_source_sink.add((definition[2], self.start_sink, self.current_sink_target_register))
                    else:
                        # Add caller, callee and location of the call.
                        if self.scope != 0:
                            calls_to_analyze.add((target_function, definition[1], definition[2]))
                elif definition[0] == "param":
                    l.info("[_S] Definition is coming from arg {} of func {}".format(definition[1], hex(target_function.addr)))
                    if self.scope != 0:
                        callers_to_analyze.add((hex(target_function.addr), definition[1]))
                else:
                    l.info("[_S] Definition is coming from memory")
                    self.observed_arb_param.add(observation_point)
            
            if self.scope != 0:
                if calls_to_analyze: self.analyze_call(calls_to_analyze)
                if callers_to_analyze: self.analyze_caller(callers_to_analyze)
    
    def analyze_call(self, funcs):

        worklist = funcs.copy()
        while len(worklist) != 0 and not self.stop_analysis:
            current_target = worklist.pop()

            # Extract function information.
            current_caller = current_target[0]
            current_callee = current_target[1]
            call_location = current_target[2]

            # Create the ID to avoid re-analyze function in the same context later.
            call_id = hashlib.md5((str(current_caller.addr)+str(current_callee)+str(call_location)).encode()).hexdigest()
            l.info("[CL] Analyzing this function {} with this caller {} at this location {}".format(current_callee, hex(current_caller.addr), hex(call_location)))

            # If we already went through there, skip it.
            if call_id in self.seen_call_ids:
                l.info("[CL] Skipping call with already analyzed context")
                continue
            
            try:
                func_td = self.bin_cfg.functions.get_by_addr(int(current_callee,16))
            except Exception as e:
                l.fatal("[!CL] Invalid function detected")
                self.invalid_func_exceptions.append(e)
                continue 

            # Register call_id 
            self.seen_call_ids.add(call_id)
            
            # Sanity checks.
            if func_td.calling_convention == None:
                continue
            assert(type(func_td.calling_convention.RETURN_VAL) is angr.calling_conventions.SimRegArg)
            offset, size = self.project.arch.registers[func_td.calling_convention.RETURN_VAL.reg_name]

            overall_defs = set()
            # Observations points are the last instruction of basic blocks that are endpoints.
            observation_points = []
            for endpoint_type, endpoint_blocknodes in func_td.endpoints_with_type.items():
                for eb in endpoint_blocknodes:
                    if endpoint_type == 'return':
                        if len(self.project.factory.block(addr=eb.addr, opt_level=1).instruction_addrs) == 0:
                            continue
                        observation_points.append(("insn", self.project.factory.block(addr=eb.addr, opt_level=1).instruction_addrs[-1], 
                                                OP_BEFORE))
                    elif endpoint_type == 'transition':
                        # If we have a direct transition to another function let's add a fake definition
                        # for the return value of the current function to the destination func.
                        endpoint_cfg_node = self.project.cfg.get_any_node(eb.addr)
                        endpoint_succ = endpoint_cfg_node.successors
                        if len(endpoint_succ) != 1:
                            continue
                        l.warning("[!CL] Transition endpoint, adding a fake definition for r0 as retval of {}".format(hex(endpoint_succ[0].addr)))
                        overall_defs.add(("retval", hex(endpoint_succ[0].addr), eb.addr))
                    
            if len(observation_points) != 0:
                try:
                    rd = self.project.analyses.ReachingDefinitions(subject=func_td, 
                                                                    func_graph=func_td.graph,
                                                                    cc = func_td.calling_convention,
                                                                    observation_points= observation_points,
                                                                    dep_graph = dep_graph.DepGraph()
                                                                    )
                except Exception as e:
                    l.fatal("[!CL] RD got an exception")
                    self.rd_exceptions.append(e)
                    continue

                defsExplorer = DefsExplorer(self.project, rd.dep_graph)
                

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

            # Analyze the observed definitions of the return argument.
            for definition in overall_defs:
                if definition[0] == "retval":
                    # It's not always guaranteed that the retval tag of a definition has the
                    # func addr, in those casese we call it a day (definition[1] will be None).
                    l.info("[CL] Definition is coming from retval of func {}".format(definition[1]))
                    if definition[1] and int(definition[1],16) == self.source.addr:
                        l.info("[CL] Observed a flow from return value of {} to {}".format(hex(self.source.addr), hex(self.sink.addr)))
                        if self.valid_source != []:
                            if definition[2] in self.valid_source: 
                                self.observed_source_sink.add((definition[2], self.start_sink, self.current_sink_target_register))
                                #self.stop_analysis = True
                            else:
                                l.info("[CL] Flow not at the codeloc requested. Continue.")
                        else:
                            self.observed_source_sink.add((definition[2], self.start_sink, self.current_sink_target_register))
                    elif definition[1]:
                        worklist.add((func_td, definition[1], definition[2]))
                    else: pass
                elif definition[0] == "param":
                    l.info("[CL] Definition coming from parameter of the function itself.")
                    self._run(current_caller, call_location, [offset_to_reg(self.project, definition[1].reg_offset)])
                else: 
                    # Found a constant/static definition
                    l.info("[CL] Definition coming from constant.")

    def analyze_caller(self, funcs):
        l.debug("[AC] Analyzing callers: {}".format(funcs))
        worklist = funcs.copy()
        
        while len(worklist) != 0 and not self.stop_analysis:
            current_function = worklist.pop()
            current_function_addr = int(current_function[0],16)

            current_function_arg = current_function[1]
            # Sanity checks.
            if type(current_function_arg) != Register:
                l.warning("Current function arg is not a Register")
                continue 
            assert(current_function_arg.reg_offset != -1)

            # Create the ID to avoid re-analyze function in the same context later.
            caller_id = hashlib.md5((str(current_function_addr)+str(current_function_arg.reg_offset)).encode()).hexdigest()

            # If we already went through there, skip it.
            if caller_id in self.seen_caller_ids:
                l.info("[AC] Skipping caller with already analyzed context")
                continue

            # Register caller_id.
            self.seen_caller_ids.add(caller_id)

            # Procede to get the predecessors.
            node = self.bin_cfg.model.get_any_node(current_function_addr)
            # Get all the XRefs
            func_predecessors = list(set([xref.function_address for xref in node.predecessors]))

            func_predecessors_dict = {}
            for pred_func_addr in func_predecessors:
                func_predecessors_dict[str(pred_func_addr)] = []
            for xref in node.predecessors:
                func_predecessors_dict[str(xref.function_address)].append(xref)
            l.info("[AC] Analyzing predecessors of {}".format(current_function[0]))

            for pred_function_addr, xrefs in func_predecessors_dict.items():
                pred_function_addr = int(pred_function_addr)
                l.info("[AC] Now analyzing predecessor func at {}".format(hex(pred_function_addr)))
                l.info("[AC] XRefs are {}".format((xrefs)))
                
                for xref in xrefs:
                    l.info("[AC] Analyzing XRefs at {} | Target register {}".format(hex(xref.addr), offset_to_reg(self.project, current_function_arg.reg_offset)))
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
                        l.fatal("[!AC] Exception during RD execution")
                        self.rd_exceptions.append(e)
                        continue
                    
                    # Sanity check, 1 ob_point -> 1 observed_results! 
                    if len(rd.observed_results.values()) != 1:
                        l.info("[!]  Observed results are {}. Continuing.".format(len(rd.observed_results.values())))
                        continue 

                    param_defs = rd.one_result.register_definitions.get_objects_by_offset(current_function_arg.reg_offset)
                    
                    if len(param_defs) == 0:
                        l.warning("[!AC] No definition for register {}".format(current_function_arg.reg_offset))
                        l.warning("[!AC] Attempting to detect transition wrapper.")
                        if self._is_wrapper(start_function):
                            l.info("[!AC] Detected wrapper of function {} at {}".format(hex(current_function_addr), hex(start_function.addr)))
                            l.info("[!AC] Adding additional definitions to continue analysis at the callers.")
                            worklist.add((hex(start_function.addr), current_function_arg))
                        else:
                            l.warning("Could not detect wrapper, stopping research here at {}".format(hex(start_function.addr)))

                    for param_def in param_defs:
                        defsExplorer = DefsExplorer(self.project, rd.dep_graph)
                        param_seen_defs = defsExplorer.resolve_use_def(param_def)
                        
                        for definition in param_seen_defs:
                            if definition[0] == "retval":
                                call_func_address = definition[1]
                                l.info("[AC] Definition is coming from retval of func {}".format(call_func_address))
                                if definition[1] and definition[1] == self.source.addr:
                                    l.info("[AC] Observed a flow from return value of {} to {}".format(hex(self.source.addr), hex(self.sink.addr)))
                                    if self.valid_source != []:
                                        if definition[2] in self.valid_source: 
                                            self.observed_source_sink.add((definition[2], self.start_sink, self.current_sink_target_register))
                                            #self.stop_analysis = True
                                        else:
                                            l.info("Flow not at the codeloc requested. Continue.")
                                    else:
                                        self.observed_source_sink.add((definition[2], self.start_sink, self.current_sink_target_register))
                                else:
                                    if call_func_address:
                                        self.analyze_call(set([(start_function, call_func_address, definition[2])]))
                            elif definition[0] == "param":
                                new_caller = (hex(pred_function_addr), definition[1])
                                l.info("[AC] Definition is coming from arg {} of func {}".format(definition[1], hex(pred_function_addr)))
                                worklist.add(new_caller)
                            else:
                                # Found a constant/static definition
                                l.info("[AC] Definition coming from constant.")
                                self.observed_arb_param.add(call_to_xref_address)
    
    # TODO: improve this, otherwise false positives.
    def _is_wrapper(self, function):
        if len(list(function.blocks)) == 1:
            block = list(function.blocks)[0]
            if block.instructions == 1:
                if block.vex.jumpkind == 'Ijk_Boring':
                    return True
        if function.has_return:
            return True
        return False




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