import angr 
import argparse
import datetime
import json
import os
import sys
sys.setrecursionlimit(10**9) 

import itertools
import logging

from datetime import datetime
from configparser import ConfigParser 
from pathlib import Path
from wrapt_timeout_decorator import *

# Intra-module imports
from .update_templates import update_template_malloc, update_template_free, update_template_fake_free, update_template_double_free
from .malloc_prototype import get_malloc_prototype
from .free_prototype import get_free_prototype
from .test_pointer_sources_proto import is_ps_working
from .filter_prototypes import malloc_no_size_argument

# Inter-module imports
from ..analyses.arguments_analyses import ArgValuesAnalysis, ArgInfo
from ..analyses.arguments_analyses import filter_unused_args, get_args_uses, dynamic_guess_requested_size_arg
from ..analyses.arguments_analyses import dynamic_guess_requested_ptr_to_free_arg

from ..utils import * 

l = logging.getLogger("identify_hml_prototype")
l.setLevel(logging.DEBUG)

# Parse heapster global .ini conf
config = ConfigParser()
config.read((Path(__file__).parent.parent / "./heapster.ini").resolve())

def parse_opts():
    o = argparse.ArgumentParser()
    o.add_argument("--resume", default=None)
    opts = o.parse_args()
    return opts

@timeout(2.5)
def decompile_with_timeout(target_func):
    project.analyses.Decompiler(target_func)


def decompile_with_no_timeout(target_func):
    project.analyses.Decompiler(target_func)


'''
Analyze the possible values of the arguments that are not classified
as 'requested size' for malloc and 'ptr_to_free' for free.

project: angr Project.
hb_state: the Heapbuster state.
target_arg_info:  target register under analysis.
mem_dump_init: init state for this allocator.
'''
def analyze_extra_args(project, hb_state, hml_pair, target_func, target_arg_info, mem_dump_init):

    l.info("[+] Analyzing extra args -->{}<-- of function {}".format(target_arg_info.name ,hex(target_func.addr)))
    weird_values = [0x0, 0xffffffff]
    
    argValueAnalysis = ArgValuesAnalysis(project, hb_state, mem_dump_init)
    
    # Getting all the XRefs to target.
    target_node = project.cfg.model.get_any_node(target_func.addr)
    target_node_preds = target_node.predecessors
    target_cc =  project.kb.functions[target_func.addr].calling_convention

    # Grab all functions that have an xrefs to the function.
    target_funcs_preds = list(set([x.function_address for x in target_node_preds]))

    # Parsing the XRefs given the function where they belong.
    # func_predecessors_dict will contain:
    # [ "func_address_X": [xref1, xref2], "func_address_Y": [xref3] ]
    # This is basically saying: func X has two xrefs to the baic function: "xref1" and "xref2".
    func_predecessors_dict = {}
    for target_func_pred_addr in target_funcs_preds:
        func_predecessors_dict[str(target_func_pred_addr)] = []
    for x in target_node_preds:
        func_predecessors_dict[str(x.function_address)].append(x)

    assert(not target_arg_info.is_size and not target_arg_info.is_ptr_to_free)

    possible_vals = set()

    # Let's go at every predecessors of func_target
    for target_func_pred_addr, xrefs in func_predecessors_dict.items():
        target_func_pred_addr = int(target_func_pred_addr)
        target_func_pred = project.cfg.functions.get_by_addr(target_func_pred_addr)
        l.debug("Now analyzing predecessor func at {}".format(hex(target_func_pred_addr)))
        l.debug("XRefs are {}".format((xrefs)))

        observation_points = []
        # Grab all the calls in the predecessors at the func_target.
        for xref in xrefs:
            call_to_xref_address = project.factory.block(xref.addr).instruction_addrs[-1]
            observation_points.append(call_to_xref_address)

        l.debug("Observation point are {}".format([hex(x) for x in observation_points]))
        
        for op in observation_points:
            l.info("[+]   Starting ArgValuesAnalysis at {}".format(hex(op)))
            argValueAnalysis.run(target_func_pred, op, target_arg_info.name)
            possible_vals.update(argValueAnalysis.caller_values)

    # Filter some possible erroneous values 
    target_arg_values = list(filter(lambda  x: x not in weird_values, possible_vals))
    
    # Some decompiler kung-fu if we failed.
    if len(target_arg_values) == 0:
        l.debug("arg {} of target has no possible values. Assigning default one.".format(target_arg_info.name))
        
        timeout_decompiling = False
        # Use the decompiler to guess the type and assign some values 
        try:
            decompile_with_no_timeout(target_func)
        except:
            timeout_decompiling = True 

        if timeout_decompiling:
            # Last resort, let's try to use the previous ct values and call it a day.
            if hml_pair["malloc"] == target_func.addr:
                malloc_ct = hml_pair["malloc_ct"]
                target_arg_ct_value = malloc_ct[target_arg_info.name]
                target_arg_values = [target_arg_ct_value]
            elif hml_pair["free"] == target_func.addr:
                free_ct = hml_pair["free_ct"]
                target_arg_ct_value = free_ct[target_arg_info.name]
                target_arg_values = [target_arg_ct_value]
        else:
            found_type = False
            for arg, arg_type in zip(target_func.calling_convention.args, target_func.prototype.args):
                if arg.reg_name == target_arg_info.name:
                    found_type = True
                    break

            assert(found_type)
            curr_arg_type = arg_type 
            if str(curr_arg_type) == "BOT" or "*" in str(curr_arg_type):
                l.debug("Guessing pointer type for {}".format(target_arg_info.name))
                target_arg_values = [get_available_address(project)]
                l.debug("Using these values {} for arg {}".format([hex(x) for x in target_arg_values], target_arg_info.name))
            elif "int" in str(curr_arg_type):
                l.debug("Guessing integer type for {}".format(target_arg_info.name))
                target_arg_values = [0x1,0x2,0x3]
                l.debug("Using these values {} for arg {}".format([hex(x) for x in target_arg_values], target_arg_info.name))
            else:
                l.fatal("Unsupported argument type for {}".format(target_arg_info.name))
                sys.exit(1)

    return set(target_arg_values)



def get_init_state(project, hb_state, mem_dump_init):
    init_state = project.factory.entry_state(
                    add_options={
                                angr.options.ZERO_FILL_UNCONSTRAINED_MEMORY,
                                angr.options.ZERO_FILL_UNCONSTRAINED_REGISTERS,
                                },
                    remove_options={
                                angr.options.SIMPLIFY_EXPRS,
                                angr.options.LAZY_SOLVES
                                }
    )
    init_state = init_memory_with_blob_mem(project, init_state, hb_state, mem_dump_init)
    init_state.regs.sp = project.arch.initial_sp

    return init_state


class AllocatorProtoInfo:
    def __init__(self, hml_pair, 
                       malloc_prototype, malloc_prototype_string, malloc_args_dict, unknown_malloc_arg_values, unknown_malloc_args_counter,
                       free_prototype, free_prototype_string, free_args_dict, unknown_free_arg_values, unknown_free_args_counter):
        self.hml_pair = hml_pair
        self.malloc_prototype = malloc_prototype
        self.malloc_prototype_string = malloc_prototype_string
        self.malloc_args_dict = malloc_args_dict
        self.unknown_malloc_arg_values = unknown_malloc_arg_values
        self.unknown_malloc_args_counter = unknown_malloc_args_counter
        self.free_prototype = free_prototype
        self.free_prototype_string = free_prototype_string
        self.free_args_dict = free_args_dict
        self.unknown_free_arg_values = unknown_free_arg_values
        self.unknown_free_args_counter = unknown_free_args_counter

def shut_up(thing):
    lol = logging.getLogger(thing)
    lol.setLevel("CRITICAL")

def config_logger():
    shut_up("angr.analyses.reaching_definitions.engine_vex")
    shut_up("angr.analyses.variable_recovery.variable_recovery_fast")
    shut_up("pyvex.lifting.gym.arm_spotter")
    shut_up("angr.analyses.loopfinder")
    shut_up("angr.analyses.propagator.engine_vex.SimEnginePropagatorVEX")
    shut_up("angr.analyses.reaching_definitions.reaching_definitions")
    shut_up("angr.state_plugins.symbolic_memory")
    shut_up("angr.storage.memory")
    shut_up("angr.analyses.calling_convention")
    shut_up("angr.analyses.variable_recovery.engine_vex.SimEngineVRVEX")
    shut_up("angr.analyses.reaching_definitions.engine_ail.SimEngineRDAIL")
    shut_up("angr.analyses.propagator.engine_ail.SimEnginePropagatorAIL")
    shut_up("ailment.converter")
    shut_up("angr.analyses.variable_recovery.engine_base")



if __name__ == "__main__":
    opts = parse_opts()
    hb_state_file = opts.resume

    if os.path.exists(hb_state_file) and os.path.isfile(hb_state_file):
        with open(hb_state_file, "r") as hb_file:
            hb_state = json.load(hb_file)
    else:
        l.fatal("No file at {}. Aborting.".format(hb_state_file))
        sys.exit(-1)

    config_logger()

    l.info("[+]Loading project")
    project, bin_cfg = load_artifact(hb_state)
    project.hb_state = hb_state

    l.info("[+]Running CompleteCallingConventions analysis (might take a while)")
    project.analyses.CompleteCallingConventions(recover_variables=True, 
                                                force=True, 
                                                analyze_callsites=True)

    # Storing results here
    malloc_args_dict = {}
    free_args_dict   = {}
    
    # A list of HML whose prototype is 
    # not supported (i.e., no size as argument is provided)
    weird_allocators = []

    # A list of working allocators whose prototype has 
    # been identified.
    working_allocators =  {}

    l.info("[+]Identifying HML prototype started!")
    # Limit memory to 70GB
    # Will throw a MemoryError exception 
    limit_memory(70000000000)

    for ihml_pair, hml_pair in enumerate(hb_state["best_hml_pairs"]):
        malloc = int(hml_pair["malloc"], 16)
        free = int(hml_pair["free"], 16)

        l.info("[+] Analyzing prototype of HML [alloc: {} - dealloc:{}] [{}/{}]".format(hex(malloc), 
                                                                                       hex(free),
                                                                                       ihml_pair+1,
                                                                                       len(hb_state["best_hml_pairs"])))

        # Wrong pairs is caching the HML pairs that 
        # we detected are not working in the next steps.
        # This is more an artifact related to the heapster pipeline
        # (i.e., we want to keep track which one didn't work and skip them)
        if hb_state.get("wrong_pairs", None):
            wrong_pairs = hb_state["wrong_pairs"]
        else:
            wrong_pairs = []

        malloc = bin_cfg.functions.get(malloc,None)
        free = bin_cfg.functions.get(free,None)
        
        if hex(malloc.addr) + "-" + hex(free.addr) in wrong_pairs:
            l.info("[!] Skipping wrong pair {}-{}".format(hex(malloc.addr), hex(free.addr)))
            continue
        
        heap_init = hml_pair["hi"]
        mem_dump_init_path = hml_pair["mem_dump_path"]
        working_malloc_ct = hml_pair["malloc_ct"]
        working_free_ct = hml_pair["free_ct"]
        
        # Some assertions 
        assert(malloc)
        assert(free)
        assert(len(working_malloc_ct)) != 0
        assert(len(working_free_ct)) != 0

        # Get the blob init state.
        base_state = get_init_state(project, hb_state, mem_dump_init_path)
        
        # Filter not supported prototypes.
        # Here we use a very naive heuristic to filter prototype which
        # callsites clearly don't use an integer as argument.
        if malloc_no_size_argument(project, hml_pair, base_state):
            l.info("[!] Filtering allocator because its prototype is not supported. Skipping it.")
            weird_allocators.append(hml_pair)
            continue
        
        ###############################
        # STUDYING ALLOCATOR PROTOTYPE
        ###############################

        # Passed the prototype filter, let's start to analyze it.
        malloc_args_dict = {}
        for reg_name in working_malloc_ct.keys():
            malloc_args_dict[reg_name] = ArgInfo(reg_name)
        
        # If we have only one argument for malloc we assume it is 
        # the requested size.
        unknown_malloc_arg_values = {}
        if len(malloc_args_dict) == 1:
            l.info("[+] Allocator has only one argument. Using that as [requested size]")
            malloc_args_dict["r0"].is_size = True
        else:
            l.info("[+] Allocator has multiple arguments. Using heuristics to spot [requested size]")
            # Study which arg is the 'requested_size'
            req_size_arg = dynamic_guess_requested_size_arg(project, hb_state, malloc, working_malloc_ct, base_state)
            assert(req_size_arg)
            malloc_args_dict[req_size_arg].is_size = True
            # For all the arguments that are not the requested size we need to grab some values.
            for marg_name, marg_info in malloc_args_dict.items():
                if not marg_info.is_size and not marg_info.is_ptr_to_free:
                    unknown_malloc_arg_values[marg_info.name] = set()
                    unknown_malloc_arg_values[marg_info.name] = analyze_extra_args(project, hb_state, hml_pair, malloc, marg_info, base_state)
                    l.debug("Unknown malloc arg values are: {}".format(unknown_malloc_arg_values[marg_info.name]))

        # Creation of the malloc prototype
        malloc_prototype, malloc_prototype_string, unknown_malloc_args_counter = get_malloc_prototype(malloc, malloc_args_dict)
        l.info("[+] Malloc prototype is {}".format(malloc_prototype_string))

        #################################
        # STUDYING DEALLOCATOR PROTOTYPE
        #################################

        free_args_dict = {}
        assert(len(working_free_ct)) != 0
        for reg_name in working_free_ct.keys():
            free_args_dict[reg_name] = ArgInfo(reg_name)

        # If we have only one argument for free we assume it is 
        # the ptr_to_free.
        unknown_free_arg_values = {}
        if len(free_args_dict) == 1:
            l.info("[+] Dellocator has only one argument. Using that as [ptr_to_free]")
            free_args_dict["r0"].is_ptr_to_free = True
        else:
            l.info("[+] Dellocator has multiple arguments. Using heuristics to spot [ptr_to_free size]")
            # Let's call malloc to allocate an address 
            ret, malloc_valid_addresses, last_malloc_success_state = is_ps_working(project, malloc.addr, base_state, [working_malloc_ct])
            if not malloc_valid_addresses or len(malloc_valid_addresses) == 0 :
                continue

            ptr_to_free_arg = dynamic_guess_requested_ptr_to_free_arg(project, hb_state, free, working_free_ct , malloc_valid_addresses[0], base_state)
            assert(ptr_to_free_arg)
            free_args_dict[ptr_to_free_arg].is_ptr_to_free = True

            # For all the arguments that are not the ptr_to_free we need to grab some values.
            for farg_name, farg_info in free_args_dict.items():
                if not farg_info.is_size and not farg_info.is_ptr_to_free:
                    unknown_free_arg_values[farg_info.name] = set()
                    unknown_free_arg_values[farg_info.name] = analyze_extra_args(project, hb_state, hml_pair, free, farg_info, base_state)
                    l.debug("Unknown free arg values are: {}".format(unknown_free_arg_values[farg_info.name]))

        free_prototype, free_prototype_string, unknown_free_args_counter = get_free_prototype(free, free_args_dict)
        l.info("[+] Free prototype is {}".format(free_prototype_string))


        allocatorProtoInfo = AllocatorProtoInfo(hml_pair, malloc_prototype, malloc_prototype_string, malloc_args_dict, 
                                                          unknown_malloc_arg_values, unknown_malloc_args_counter, 
                                                          free_prototype, free_prototype_string, free_args_dict, 
                                                          unknown_free_arg_values, unknown_free_args_counter)


        l.debug("Adding proto for {}-{}".format(hml_pair["malloc"], hml_pair["free"]))
        
        working_allocators[hml_pair["malloc"]] = allocatorProtoInfo
    
    #l.info("The following are the working allocators:")
    #for x in working_allocators.values():
    #    l.info(x.hml_pair)
    
    if len(working_allocators) > 1:
        l.debug("[!]Multiple working allocator")
    else:
        l.debug("[!]Only one working allocator has valid prototype.")
    
    if len(working_allocators) == 0:
        l.critical("[!]No valid prototype for HMLs detected")
        import sys; sys.exit(0) 

    # Just pick the first working allocator.
    # The other allocators will be selected during the heapster pipeline.
    # (i.e., if this doesn't work is going to finish inside the 'wrong_pairs')
    final_allocator = list(working_allocators.values())[0]

    hb_state['final_allocator'] = final_allocator.hml_pair

    prototype_malloc = "[+]Final Malloc prototype is {}".format(final_allocator.malloc_prototype_string)
    prototype_malloc = f'{bcolors.YELLOWBG}{prototype_malloc}{bcolors.ENDC}'
    prototype_free = "[+]Final Free prototype is {}".format(final_allocator.free_prototype_string)
    prototype_free = f'{bcolors.YELLOWBG}{prototype_free}{bcolors.ENDC}'

    #l.info("[+]Final Malloc prototype is {}".format(final_allocator.malloc_prototype))
    l.info(prototype_malloc)
    #l.info("[+]Free prototype is {}".format(final_allocator.free_prototype))
    l.info(prototype_free)

    ###################################################################
    # GENERATES TEMPLATE FOR HEAPHOPPER ANALYSIS (VERY UGLY CODE SORRY)
    ###################################################################

    # Generate the gen_zoo script for heaphopper given the information 
    # of the malloc/free prototypes.
    gen_zoo_path = (Path(__file__).parent.parent / "./data/gen_zoo.template").resolve() 
    with open(str(gen_zoo_path), "r") as gen_zoo:
        gen_zoo_template = gen_zoo.read()

    # Global prototypes.
    gen_zoo_template = gen_zoo_template.replace("XXX_MALLOC_PROTOTYPE_XXX", final_allocator.malloc_prototype_string)
    gen_zoo_template = gen_zoo_template.replace("XXX_FREE_PROTOTYPE_XXX", final_allocator.free_prototype_string)

    # Fixing the template with proper calls.
    gen_zoo_template, malloc_call      = update_template_malloc(gen_zoo_template, final_allocator.malloc_prototype)
    gen_zoo_template, free_call        = update_template_free(gen_zoo_template, final_allocator.free_prototype, final_allocator.free_args_dict)
    gen_zoo_template, fake_free_call   = update_template_fake_free(gen_zoo_template, final_allocator.free_prototype, final_allocator.free_args_dict)
    gen_zoo_template, double_free_call = update_template_double_free(gen_zoo_template, final_allocator.free_prototype, final_allocator.free_args_dict)

    # Save a backup in the firmware folder.
    with open(hb_state["hb_folder"] + "/gen_zoo.py", "w") as gen_zoo:
        l.info("[+]Dropping [gen_zoo.py] script at {}".format(hb_state["hb_folder"]))
        gen_zoo.write(gen_zoo_template)

    # Save information inside hb_state file.
    hb_state["malloc_prototype"] = json.dumps(final_allocator.malloc_prototype)
    hb_state["malloc_prototype_string"] = json.dumps(final_allocator.malloc_prototype_string)
    hb_state["free_prototype"] = json.dumps(final_allocator.free_prototype)
    hb_state["free_prototype_string"] = json.dumps(final_allocator.free_prototype_string)
    hb_state["malloc_call"] = malloc_call
    hb_state["free_call"] = free_call
    hb_state["fake_free_call"] =  fake_free_call
    hb_state["double_free_call"] = double_free_call
    hb_state["malloc_unknown_arguments"] = final_allocator.unknown_malloc_args_counter
    hb_state["malloc_unknown_arguments_vals"] = {}
    for reg, vals in final_allocator.unknown_malloc_arg_values.items():
        hb_state["malloc_unknown_arguments_vals"][reg] = list(vals)
    hb_state["free_unknown_arguments"] = final_allocator.unknown_free_args_counter
    hb_state["free_unknown_arguments_vals"] = {}
    for reg, vals in final_allocator.unknown_free_arg_values.items():
        hb_state["free_unknown_arguments_vals"][reg] = list(vals)

    with open(hb_state_file, 'w') as fp:
        json.dump(hb_state, fp)