import angr
import logging
import os 
import struct

import angr.analyses.reaching_definitions.dep_graph as dep_graph
import hashlib

from configparser import ConfigParser 
from pathlib import Path
from threading import Timer

from angr.engines.light import SpOffset, RegisterOffset
from angr.knowledge_plugins.key_definitions.atoms import Register, SpOffset, MemoryLocation
from angr.knowledge_plugins.key_definitions.undefined import undefined, Undefined
from angr.knowledge_plugins.key_definitions.definition import Definition, ParamTag, RetValueTag, InitValueTag
from angr.knowledge_plugins.key_definitions.dataset import DataSet

from angr_taint_engine import *
from heapster.utils import *

# Observation point position for RD.
OP_BEFORE = 0
OP_AFTER  = 1

# Parse heapster global .ini conf
config = ConfigParser()
config.read((Path(__file__).parent.parent.parent / "./heapster.ini").resolve())

l = logging.getLogger("heapster.arguments_analyses.arg_values_analysis")
l.setLevel(logging.CRITICAL)



'''
Analysis that tries to recover possible values 
for a given argument of a target function and registers.
'''
class ArgValuesAnalysis():
    def __init__(self, project, hb_state, mem_dump_init):
        self.project  = project
        self.bin_cfg  = project.cfg
        self.hb_state = hb_state
        self.mem_dump_init = mem_dump_init

        # Tie the knot.
        self.seen_calls = set()
        self.seen_callers = set()
        
        # The final result.
        self.caller_values = set()
        
        # Diagnostic.
        self.rd_exceptions = []
        self.rd_zero_results = 0
        self.invalid_func_exceptions = []
        self.filtered_pointer_sources = set()
    
    def reset(self):
        self.seen_calls = set()
        self.seen_callers = set()
        self.caller_values = set()
        self.rd_exceptions = []
        self.rd_zero_results = 0
        self.invalid_func_exceptions = []
        self.filtered_pointer_sources = set()

    def run(self, target_function, observation_point, target_register_name):
        calls_to_analyze = set()
        callers_to_analyze = set()

        try:
            l.debug("[S] Running reaching definition with op: {}".format(observation_point))
            rd = self.project.analyses.ReachingDefinitions(subject=target_function, 
                                                           func_graph=target_function.graph,
                                                           cc = target_function.calling_convention,
                                                           observation_points = [("insn", observation_point, OP_BEFORE )],
                                                           dep_graph = dep_graph.DepGraph()
                                                          )
        except Exception as e:
            l.fatal(e)
            self.rd_exceptions.append(e)
            return

        assert(len(rd.observed_results.values()) == 1)
        reg_offset = reg_to_offset(self.project, target_register_name)
        assert(reg_offset != -1)
        reg_defs = rd.one_result.register_definitions.get_objects_by_offset(reg_offset)

        for reg_def in reg_defs:
            defsExplorer = DefsExplorer(self.project, rd.dep_graph)
            reg_seen_defs = defsExplorer.resolve_use_def(reg_def)
            for definition in reg_seen_defs:
                if definition[0] == "retval" and definition[1] != None:
                    l.info("[S] Definition is coming from retval of func {}".format(definition[1]))
                    # Add caller, callee and location of the call.
                    calls_to_analyze.add((target_function, definition[1], definition[2]))
                elif definition[0] == "param":
                    l.info("[S] Definition is coming from arg {} of func {}".format(definition[1], hex(target_function.addr)))
                    callers_to_analyze.add((hex(target_function.addr), definition[1]))
                else:
                    # We hit a constant, let's emulate this to extract the values.
                    l.info("[S] Definition is coming from a static variable")
                    possible_values = self._grab_values(target_function, observation_point, target_register_name, self.mem_dump_init)
                    for x in possible_values:
                        if type(x) == int:
                            l.critical("Found integer value for caller at {}".format(hex(observation_point)))
                            self.caller_values.add(x)

            if calls_to_analyze: self.analyze_call(calls_to_analyze)
            if callers_to_analyze: self.analyze_caller(callers_to_analyze)
    
    def analyze_call(self, funcs):
        worklist = funcs.copy()
        while len(worklist) != 0:
            current_target = worklist.pop()

            # Extract function information.
            current_caller = current_target[0]
            assert(type(current_caller) != str)
            current_callee = current_target[1]
            assert(type(current_callee) == str)
            call_location = current_target[2]
            assert(type(call_location) == int)

            # Create the ID to avoid re-analyze function in the same context later.
            call_id = hashlib.md5((str(current_caller.addr)+str(current_callee)+str(call_location)).encode()).hexdigest()
            l.info("[CL] Analyzing this function {} with this caller {} at this location {}".format(current_callee, hex(current_caller.addr), hex(call_location)))

            if call_id not in self.seen_calls:
                self.seen_calls.add(call_id)
                try:
                    func_td = self.bin_cfg.functions.get_by_addr(int(current_callee,16))
                except Exception as e:
                    self.invalid_func_exceptions.append(e)
                    continue 
                
                # Sanity check.
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
                            observation_points.append(("insn", self.project.factory.block(addr=eb.addr, opt_level=1).instruction_addrs[-1], 
                                                    OP_BEFORE))
                        elif endpoint_type == 'transition':
                            # If we have a direct transition to another function let's add a fake definition
                            # for the return value of the current function to the destination func.
                            endpoint_cfg_node = self.project.cfg.get_any_node(eb.addr)
                            endpoint_succ = endpoint_cfg_node.successors
                            assert(len(endpoint_succ) == 1)
                            l.info("[CL] Transition endpoint, adding a fake definition for r0 as retval of {}".format(hex(endpoint_succ[0].addr)))
                            overall_defs.add(("retval", hex(endpoint_succ[0].addr), eb.addr))

                for op in observation_points:
                    try:
                        rd = self.project.analyses.ReachingDefinitions(subject=func_td, 
                                                                        func_graph=func_td.graph,
                                                                        cc = func_td.calling_convention,
                                                                        observation_points= op,
                                                                        dep_graph = dep_graph.DepGraph()
                                                                        )
                    except Exception as e:
                        self.rd_exceptions.append(e)
                        continue

                    defsExplorer = DefsExplorer(self.project, rd.dep_graph)
                    overall_defs = set()

                    # Sanity checks.
                    assert(len(rd.observed_results.values()) == len(observation_points))
                    reg_defs = rd.one_result.register_definitions.get_objects_by_offset(offset)
                    assert(len(reg_defs) != 0)
                    for reg_def in reg_defs:
                        reg_seen_defs = defsExplorer.resolve_use_def(reg_def)
                        # Analyze the observed definitions of the return argument.
                        for definition in reg_seen_defs:
                            if definition[0] == "retval":
                                # It's not always guaranteed that the retval tag of a definition has the
                                # func addr, in those casese we call it a day (definition[1] will be None).
                                l.info("[CL] Definition is coming from retval of func {}".format(definition[1]))
                                call_id = hashlib.md5((str(func_td.addr)+str(definition[1])+str(definition[2])).encode()).hexdigest()
                                if definition[1]:
                                    worklist.add((func_td, definition[1], definition[2])) 
                            elif definition[0] == "param":
                                self.run(current_caller, call_location, [offset_to_reg(self.project, definition[1].reg_offset)])
                            else: 
                                l.info("Definition is coming from a static variable")
                                possible_values = self._grab_values(func_td, op, func_td.calling_convention.RETURN_VAL.reg_name, self.mem_dump_init)
                                for x in possible_values:
                                    if type(x) == int:
                                        l.critical("Found integer value for caller at {}".format(hex(op)))
                                        self.caller_values.add(x)

    def analyze_caller(self, funcs):
        l.debug("Analyzing callers: {}".format(funcs))
        worklist = funcs.copy()
        
        while len(worklist) != 0:
            current_function = worklist.pop()
            
            if current_function not in self.seen_callers:
                self.seen_callers.add(current_function)
                current_function_addr = int(current_function[0],16)
                current_function_arg = current_function[1]
                l.debug("Current function_arg is {}".format(current_function_arg)) 
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
                                                                          observation_points= [("insn", call_to_xref_address , OP_BEFORE)],
                                                                          dep_graph = dep_graph.DepGraph()
                                                                          )
                        except Exception as e:
                            l.debug("Exception in RD engine, skip {}".format(hex(start_function.addr)))
                            self.rd_exceptions.append(e)
                            continue

                        # Sanity check, 1 ob_point -> 1 observed_results! 
                        assert(len(rd.observed_results.values()) == 1)
                        param_defs = rd.one_result.register_definitions.get_objects_by_offset(current_function_arg.reg_offset)
                        l.debug("Got {} param_defs for register {}".format(len(param_defs), offset_to_reg(self.project, current_function_arg.reg_offset)))

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
                                    l.info("Definition is coming from retval of func {}".format(call_func_address))
                                    if call_func_address and call_func_address not in self.seen_calls: 
                                        self.analyze_call(set([(start_function, call_func_address, definition[2])]))
                                elif definition[0] == "param":
                                    new_caller = (hex(pred_function_addr), definition[1])
                                    l.info("Definition is coming from arg {} of func {}".format(definition[1], hex(pred_function_addr)))
                                    if new_caller not in self.seen_callers:
                                        worklist.add(new_caller)
                                    else:
                                        l.warning("Arg {} of func {} has already been analyzed. Skipping.".format(definition[1], hex(pred_function_addr)))
                                else:
                                    l.info("Definition is coming from a static variable")
                                    possible_values = self._grab_values(start_function, call_to_xref_address, offset_to_reg(self.project, current_function_arg.reg_offset), self.mem_dump_init)
                                    for x in possible_values:
                                        if type(x) == int:
                                            l.critical("Found integer value for caller at {}".format(hex(call_to_xref_address)))
                                            self.caller_values.add(x)


    def _is_wrapper(self, function):
        if len(list(function.blocks)) == 1:
            block = list(function.blocks)[0]
            if block.instructions == 1:
                if block.vex.jumpkind == 'Ijk_Boring':
                    return True
        return False 


    def _grab_values(self, func, op, arg_name, init_state):
        l.info("Using Propagator analysis over func at {}, observation point is {}, arg is {}".format(hex(func.addr), hex(op), arg_name))
        func_node = self.project.cfg.get_any_node(func.addr)
        block_target = block_from_addr_ins(self.project, op)
        call_site_dicts = {}
        call_site_dicts[op] = {}
        arg_values = []
        if block_target:
            prop = self.project.analyses.Propagator(func=func, func_graph=func.graph, base_state=init_state)
            
            found_repl = False
            for r in prop.replacements:
                if r.block_addr == block_target.addr:
                    found_repl = True
                    #l.info("Found replacements for {}".format(p))
                    break
            if found_repl:
                replacements_values = prop.replacements[r]
                target_offset = reg_to_offset(self.project, arg_name)
                for v in replacements_values.keys():
                    if type(v) != angr.analyses.propagator.engine_vex.VEXReg:
                        continue
                    if v.offset == target_offset:
                        arg_values.append(replacements_values[v])
                        #args_dict[a].add(replacements_values[v])
        return arg_values

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
                assert(type(definition.tag.metadata) == str)
                return ("retval", definition.tag.metadata, definition.codeloc.ins_addr)
            elif type(definition.tag) == ParamTag:
                # The param is defined by the Atom of this definition.
                return ("param", definition.atom)
        else:
            return None