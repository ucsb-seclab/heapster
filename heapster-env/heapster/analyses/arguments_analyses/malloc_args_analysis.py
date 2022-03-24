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

# Parse heapster global .ini conf
config = ConfigParser()
config.read((Path(__file__).parent.parent.parent / "./heapster.ini").resolve())

l = logging.getLogger("malloc_args_analysis")
l.setLevel(logging.CRITICAL)

# Common malloc error values.
malloc_error_values = [0x0, 0xffffffff]

'''
This analysis tries to understand which is the 
"requested size" argument given the malloc args.
Employs a constraints counting technique. 
FIXME clean this code.
'''
def dynamic_guess_requested_size_arg(project, hb_state, malloc, malloc_args, base_state):
    ins_endpoints = []
    for fe in malloc.endpoints:
        ins_endpoints.append(project.factory.block(addr=fe.addr, opt_level=1).instruction_addrs[-1])
    l.debug("Extracted the following endpoints in malloc: {}".format(ins_endpoints))
    
    # Every unconstrained access to memory or register will return 0.
    cs = project.factory.call_state(malloc.addr,
                add_options={
                            angr.options.ZERO_FILL_UNCONSTRAINED_MEMORY,
                            angr.options.ZERO_FILL_UNCONSTRAINED_REGISTERS,
                            },
                ret_addr=0xdeadbeef,
                base_state=base_state
        )
    cs.regs.sp = int(hb_state["blob_stack_pointer"],16)


    # Tainting arguments of malloc.
    cs.globals["tainted_args"] = []
    cst_counter_dict = {}
    arg_idx = 0 
    for arg_name, arg_value in malloc_args.items():
        new_sym_var = get_sym_val(name="taint_current_arg_{}".format(arg_idx), bits=(project.arch.bits))
        # Set the symbolic argument to the register.
        setattr(cs.regs, arg_name, new_sym_var)
        cs.globals["tainted_args"].append((arg_name, new_sym_var))
        # Constraining the values to the one that were working originally 
        cs.add_constraints(new_sym_var == arg_value) 
        cst_counter_dict[arg_name] = 0
        arg_idx+=1

    # Emulating function.
    l.debug("Exploring function {}".format(hex(malloc.addr)))
    ls = angr.exploration_techniques.LoopSeer(project.cfg, 
                                              bound=int(config["get_hml_prototype"]["find_malloc_size_concrete_loop_bound"]), 
                                              limit_concrete_loops=True)
    ed = ExplosionDetector(threshold=int(config["get_hml_prototype"]["find_malloc_size_max_states"]))
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
            l.info("Hit the malloc() endpoint.")
            return_val = new_state.solver.eval(new_state.regs.r0)
            # Malloc executed successfully if we have a valid pointer.
            l.info("Malloc() execution returned {}".format(return_val))
            if return_val not in malloc_error_values:
                l.info("Malloc() executed with no error code.")
                args_sym_vars = new_state.globals["tainted_args"]
                # Extracting all the sym vars inside the constraints.
                sym_tags = []
                for cst in new_state.solver.constraints:
                    for x in cst.recursive_leaf_asts:
                        if x.symbolic:
                            # Really sorry for this. 
                            sym_tags.append(str(x))
                # Let's check all the sym_tag extracted.
                for sym_tag in sym_tags:
                    for k,v in args_sym_vars:
                        if str(sym_tag) == str(v):
                            # Increase number of constraints observed.
                            cst_counter_dict[k] += 1
        # Step by step.
        sm.step()


    hb_state["malloc_args_info_constraints_proto"] = {}
    hb_state["malloc_args_info_usages_proto"] = {}
    
    for arg_name, cst_numbers in cst_counter_dict.items():
        hb_state["malloc_args_info_constraints_proto"][arg_name] = cst_numbers

    # Now we select the parameter for which we have observed the most 
    # constraints.
    arg_name = max(cst_counter_dict, key=cst_counter_dict.get)
    l.info("arg with most constraints is {}".format(arg_name))
    return arg_name

