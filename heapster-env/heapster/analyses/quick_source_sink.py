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
l.setLevel(logging.DEBUG)

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
class QuickSourceSinkAnalysis():
    def __init__(self, project, bin_cfg, source_func, sink_func, scope_function, sink_target_registers):
        self.project = project
        self.bin_cfg = bin_cfg

        # Source and Sink.
        self.source = source_func
        self.sink = sink_func
        self.scope_function = scope_function
        self.sink_target_registers = sink_target_registers
        self.current_sink_target_register = None
        
        # Results here.
        self.observed_source_sink = set()
        self.stop_analysis = False
        
        # Diagnostic.
        self.rd_exceptions = []
        self.invalid_func_exceptions = []
        self.start_sink = None

    def run(self):
        l.info("[S] Trying to find a match between {} retval and {} args inside {}".format(hex(self.source.addr), hex(self.sink.addr), hex(self.scope_function)))
        sink_node = self.bin_cfg.model.get_any_node(self.sink.addr)
        sink_node_preds = sink_node.predecessors # getting all the XRefs
        sink_cc =  self.project.kb.functions[self.sink.addr].calling_convention
        
        # Grab all functions that have an xrefs to the function
        sink_funcs_preds = list(set([x.function_address for x in sink_node_preds]))
        assert(self.scope_function) in sink_funcs_preds
        
        # Restrict to only the function in the scope 
        sink_funcs_preds = [self.scope_function]

        # Parsing the XRefs given the function where they belong.
        # func_predecessors_dict will contain:
        # [ "func_address_X": [xref1, xref2], "func_address_Y": [xref3] ]
        # This is basically saying: func X has two xrefs to the baic function: "xref1" and "xref2".
        sink_predecessors_dict = {}
        for sink_func_pred_addr in sink_funcs_preds:
            sink_predecessors_dict[str(sink_func_pred_addr)] = []
        
        for x in sink_node_preds:
            if x.function_address == self.scope_function:
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
                observation_points.append(call_to_xref_address)
            
            for op in observation_points:
                self.start_sink = op
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
            print(e)
            self.rd_exceptions.append(e)
            return
        
        defsExplorer = DefsExplorer(self.project, rd.dep_graph)
        overall_defs = set()

        # Sanity check, 1 ob_point <= 1 observed_results (0 is error). 
        if len(rd.observed_results.values()) != 1:
            l.error("Something went wrong?")
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
                        self.observed_source_sink.add((definition[2], self.start_sink, self.current_sink_target_register))
                        self.stop_analysis = True
                elif definition[0] == "param":
                    l.info("[_S] Definition is coming from arg {} of func {}".format(definition[1], hex(target_function.addr)))
                else:
                    pass 

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