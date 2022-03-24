import angr
import logging
import os 
import struct

import angr.analyses.reaching_definitions.dep_graph as dep_graph

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

OP_BEFORE = 0
OP_AFTER  = 1


# Parse heapster global .ini conf
config = ConfigParser()
config.read((Path(__file__).parent.parent.parent / "./heapster.ini").resolve())

l = logging.getLogger("heapster.arguments_analyses.free_args_analysis")
#l.setLevel(logging.DEBUG)


def get_param_uses(rd, arg_reg_offest):
    for reg_def in rd.all_uses._uses_by_definition.keys():
        if type(reg_def.atom) == Register:
            if reg_def.atom.reg_offset == arg_reg_offest and reg_def.tag and type(reg_def.tag) == ParamTag:
                uses = rd.all_uses._uses_by_definition[reg_def]
                return uses
    return []

def get_args_uses(project, func):
    observation_points = [ ("insn", project.factory.block(addr=blocknode.addr, opt_level=1).instruction_addrs[-1], OP_BEFORE) for blocknode in func.endpoints]
    args_uses = {}

    try:
        rd = project.analyses.ReachingDefinitions(subject=func, 
                                                  func_graph=func.graph,
                                                  cc = func.calling_convention,
                                                  observation_points= observation_points,
                                                 )
    except Exception as e:
        l.critical("RD exception during unused_args_analysis")
        return []

    if rd.observed_results != {}:
        if func.calling_convention:
            for func_arg in func.calling_convention.args:
                if type(func_arg) != angr.calling_conventions.SimRegArg:
                    continue
                l.info("Analyzing arg {} of func at {}".format(func_arg.reg_name, hex(func.addr)))
                arg_reg_offest = reg_to_offset(project, func_arg.reg_name) 
                this_arg_uses = get_param_uses(rd, arg_reg_offest)
                args_uses[func_arg.reg_name] = len(this_arg_uses)

    return args_uses



'''
This analysis tries to understand which is the 
"ptr to free" argument given the free args.
Employs a constraints counting technique. 
'''
def dynamic_guess_requested_ptr_to_free_arg(project, hb_state, free, free_args, addr_to_free, base_state):
    ins_endpoints = []
    for fe in free.endpoints:
        ins_endpoints.append(project.factory.block(addr=fe.addr, opt_level=1).instruction_addrs[-1])
    l.info("Extracted the following endpoints in free: {}".format(ins_endpoints))
    
    # Every unconstrained access to memory or register will return 0.
    cs = project.factory.call_state(free.addr,
                add_options={
                            angr.options.ZERO_FILL_UNCONSTRAINED_MEMORY,
                            angr.options.ZERO_FILL_UNCONSTRAINED_REGISTERS,
                            },
                ret_addr=0xdeadbeef,
                base_state = base_state
        )
    cs.regs.sp = int(hb_state["blob_stack_pointer"],16)

    # Tainting arguments of malloc.
    cs.globals["tainted_args"] = []
    cst_counter_dict = {}
    arg_idx = 0 
    for arg_name, arg_value in free_args.items():
        new_sym_var = get_sym_val(name="taint_current_arg_{}".format(arg_idx), bits=(project.arch.bits))
        
        # Top or None becomes the address to free.
        if arg_value == "TOP" or arg_value == "None":
            arg_value = addr_to_free
        
        # Set the symbolic argument to the register.
        setattr(cs.regs, arg_name, new_sym_var)
        cs.globals["tainted_args"].append((arg_name, new_sym_var))
        cs.add_constraints(new_sym_var == arg_value)
        cst_counter_dict[arg_name] = 0
        arg_idx+=1

    # Emulating function.
    l.info("Exploring function {}".format(hex(free.addr)))
    ls = angr.exploration_techniques.LoopSeer(project.cfg, 
                                              bound=int(config["get_hml_prototype"]["find_free_size_concrete_loop_bound"]), 
                                              limit_concrete_loops=True)
    ed = ExplosionDetector(threshold=int(config["get_hml_prototype"]["find_free_size_max_states"]))
    sm = project.factory.simgr(cs)
    sm.use_technique(ls)
    sm.use_technique(ed)
    sm.use_technique(angr.exploration_techniques.DFS())

    # We don't need to follow calls for this.
    #def smartcall_policy(*args, **kwargs):
    #    return False
    #tt = TaintTracker(interfunction_level=0, precise_argument_check=False, taint_deref_values=False,
    #                smart_call=True, should_follow_call=smartcall_policy)
    #tt._N = 9999999
    #sm.use_technique(tt)

    def timeout():
        l.warning("Timeout during DSE has been reached.")
        ed.timed_out.set()
        ed.timed_out_bool = True
    
    # Storing results here.
    candidate_size_args = []
    while len(sm.active) > 0 and not ed.timed_out_bool:
        new_state = sm.active[0]
        
        l.info(new_state)
        new_state_pc = new_state.solver.eval(new_state.regs.pc)
        l.debug(sm)
        # When we hit the fake return address we have
        # finished execute malloc.
        if new_state_pc == 0xdeadbeef: 
            l.info("Hit the free() endpoint!")
            args_sym_vars = new_state.globals["tainted_args"]
            # Extracting all the sym vars inside the constraints
            sym_tags = []
            for cst in new_state.solver.constraints:
                for x in cst.recursive_leaf_asts:
                    if x.symbolic:
                        sym_tags.append(str(x))
            for sym_tag in sym_tags:
                for k,v in args_sym_vars:
                    if str(sym_tag) == str(v):
                        cst_counter_dict[k] = cst_counter_dict[k] + 1
        # Step by step.
        sm.step()

    hb_state["free_args_info_constraints_proto"] = {}
    hb_state["free_args_info_usages_proto"] = {}

    # Now we select the parameter for which we have observed the most 
    # constraints.
    if len(set(cst_counter_dict.values())) == 1:
        l.info("Cannot use constraints counting, no MAX. Backing up on usages")
        arg_uses = get_args_uses(project, free)

        for reg_name, uses in arg_uses.items():
            hb_state["free_args_info_usages_proto"][reg_name] = uses
        arg_name = max(arg_uses, key=arg_uses.get)
        l.info("arg with most uses is {}".format(arg_name))
    else:
        for arg_name, cst_numbers in cst_counter_dict.items():
            hb_state["free_args_info_constraints_proto"][arg_name] = cst_numbers
        
        arg_name = max(cst_counter_dict, key=cst_counter_dict.get)
        l.info("arg with most constraints is {}".format(arg_name))

    return arg_name