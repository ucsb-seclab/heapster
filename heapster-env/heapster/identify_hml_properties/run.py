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

from ..utils import * 

from .exploration_techniques import HMLFuncExecution, HeartBeat 

# Fancy debugging.
from angrcli.interaction.explore import ExploreInteractive
import angrcli.plugins.ContextView
import angrcli.plugins.watches

l = logging.getLogger("identify_hml_properties")
l.setLevel(logging.INFO)

# Parse heapster global .ini conf
config = ConfigParser()
config.read((Path(__file__).parent.parent / "./heapster.ini").resolve())

def parse_opts():
    o = argparse.ArgumentParser()
    o.add_argument("--resume", default=None)
    opts = o.parse_args()
    return opts

def config_script(project, opts, hb_state):
    final_pair = hb_state["final_allocator"]
    malloc = int(final_pair["malloc"],16)
    free = int(final_pair["free"],16)
    mem_dump_path = final_pair["mem_dump_path"]
    return malloc, free, mem_dump_path

def dse_it(state):
    debug = False
    cli_debug = False

    sm = project.factory.simgr(state)

    dfs = angr.exploration_techniques.DFS()
    hml_func_exec = HMLFuncExecution()
    
    sm.use_technique(dfs)
    sm.use_technique(hml_func_exec)
    sm.use_technique(HeartBeat())
    
    sm.run() # Run it! 

    assert(hml_func_exec.end_execution_reason[0] == "END_EXECUTION_RETURNS")
    return hml_func_exec.last_state

'''
Create state ready to execute with blob
unpacked memory.
'''
def get_init_state(project, hb_state, mem_dump_path):
    init_state = project.factory.entry_state(
                    add_options={
                                angr.options.CONCRETIZE_SYMBOLIC_FILE_READ_SIZES,
                                angr.options.ZERO_FILL_UNCONSTRAINED_MEMORY,
                                #angr.options.ZERO_FILL_UNCONSTRAINED_REGISTERS,
                                },
                    remove_options={
                                angr.options.SIMPLIFY_EXPRS,
                                angr.options.LAZY_SOLVES
                                }
    )
    
    # Remove all tracking things, save time.
    for x in angr.options.refs:
        init_state.options.add(x)
        init_state.options.remove(x)

    init_state = init_memory_with_blob_mem(project, init_state, hb_state, mem_dump_path )

    return init_state

'''
Call malloc given a state.
'''
def call_malloc(base_state, requested_size):
    malloc_prototype = json.loads(hb_state["malloc_prototype"])
    malloc_param = [] 
    malloc_prototype_args = []
    malloc_cc_args = malloc.calling_convention.args

    for m_arg_key, m_arg_val in malloc_prototype.items():
        if m_arg_key == 'ret':
            continue
        else:
            malloc_prototype_args.append(m_arg_val)

    cs = project.factory.call_state(malloc.addr, base_state=base_state, ret_addr=0xdeadbeef)
    
    # Just to make sure 
    setattr(cs.regs, "lr", 0xdeadbeef)
    cs.callstack.ret_addr = 0xdeadbeef 
    cs.callstack.return_address = 0xdeadbeef 

    # Setup args for malloc.
    for m_arg, m_cc_reg in zip(malloc_prototype_args, malloc_cc_args):
        if m_arg != "size":
            arg_val = hb_state["malloc_unknown_arguments_vals"][m_cc_reg.reg_name][0]
        else:
            arg_val = init_state.solver.BVV(requested_size, project.arch.bits)
        setattr(cs.regs, m_cc_reg.reg_name, arg_val)
    # Emulate.
    next_state = dse_it(cs)
    assert(next_state.solver.eval(next_state.regs.pc) == 0xdeadbeef)
    return next_state

def call_free(base_state, chunk_to_free):
    l.debug("Deallocating chunk {}".format(hex(chunk_to_free)))
    free_prototype = json.loads(hb_state["free_prototype"])
    free_param = [] 
    free_prototype_args = []
    free_cc_args = free.calling_convention.args

    for f_arg_key, f_arg_val in free_prototype.items():
        if f_arg_key == 'ret':
            continue
        else:
            free_prototype_args.append(f_arg_val)

    cs = project.factory.call_state(free.addr,  base_state=base_state, ret_addr=0xdeadbeef)
    
    # Just to make sure 
    setattr(cs.regs, "lr", 0xdeadbeef)
    cs.callstack.ret_addr = 0xdeadbeef 
    cs.callstack.return_address = 0xdeadbeef 

    # Setup parameter for free.
    for f_arg, f_cc_reg in zip(free_prototype_args, free_cc_args):
        if f_arg != "ptr_to_free":
            arg_val = hb_state["free_unknown_arguments_vals"][f_cc_reg.reg_name][0]
        else:
            arg_val = init_state.solver.BVV(chunk_to_free, project.arch.bits)
        setattr(cs.regs, f_cc_reg.reg_name, arg_val) 
    # Emulate.
    next_state = dse_it(cs)
    assert(next_state.solver.eval(next_state.regs.pc) == 0xdeadbeef)
    return next_state

def check_malloc_result(value):
    wrong_results = [0,-1,0xffffffff]
    if value in wrong_results :
        l.warning("Malloc 1 possibly returned an error code: {}. This is not good.".format(value))
        guard_malloc_error = True
        
        hb_state["allocator_works"] = 0
        with open(hb_state_file, 'w') as fp:
            json.dump(hb_state, fp)
        
        sys.exit(-1)

def reg_metadata_access(state):
    addr = state.solver.eval(state.inspect.mem_read_address)
    l.debug("Free() hits memory breakpoint at {}".format(hex(addr)))
    state.globals["metadata_accesses"].append(addr)

def reg_metadata_access_write(state):
    addr = state.solver.eval(state.inspect.mem_write_address)
    l.debug("Free() hits memory breakpoint at {}".format(hex(addr)))
    state.globals["metadata_accesses"].append(addr)


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
    shut_up("angr.analyses.variable_recovery.engine_base")

def spawn_cli(state):
    e = ExploreInteractive(state.project, state)
    e.cmdloop()

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
    
    malloc, free, mem_dump_path = config_script(project, opts, hb_state)
    malloc = bin_cfg.functions.get(malloc,None)
    free = bin_cfg.functions.get(free,None)
    assert(malloc)
    assert(free)

    l.info("[+]Identifying HML Properties Started!")
    # Limit memory to 70GB
    # Will throw a MemoryError exception 
    limit_memory(70000000000)
    
    l.info("[+]Using allocator at  {}".format(hex(malloc.addr)))
    l.info("[+]Using deallocator at {}".format(hex(free.addr)))

    curr_allocated_chunks = []
    old_allocated_chunks  = []

    init_state = get_init_state(project, hb_state, mem_dump_path)

    # Hook the skip() SimProc as detected by identify_hotspots.
    if hb_state.get("malloc_to_hook_funcs", None):
        malloc_hook_funcs = hb_state["malloc_to_hook_funcs"]
        for h in malloc_hook_funcs:
            l.info("[+] Hooking function {} with Skip()".format(hex(h)))
            project.hook(addr=h, hook=skip())

    if hb_state.get("free_to_hook_funcs", None):
        free_hook_funcs = hb_state["free_to_hook_funcs"]
        for h in free_hook_funcs:
            l.info("[+] Hooking function {} with Skip()".format(hex(h)))
            project.hook(addr=h, hook=skip())

    l.info("[+] Calling allocator bunch of times")
    # Call malloc first time and check result.
    malloc_1_size = int(config["test_hml"]["malloc_emulation_def_req_size"])
    next_state = call_malloc(init_state, malloc_1_size)
    malloced_address_1 = getattr(next_state.regs, malloc.calling_convention.RETURN_VAL.reg_name)
    malloced_address_1_val = next_state.solver.eval(malloced_address_1)
    check_malloc_result(malloced_address_1_val)
    curr_allocated_chunks.append(malloced_address_1_val)

    l.info("[+] First chunk allocated at {}".format(hex(malloced_address_1_val)))

    # Call malloc a second time and check result.
    malloc_2_size = int(config["test_hml"]["malloc_emulation_def_req_size"])
    next_state = call_malloc(next_state, malloc_2_size)
    malloced_address_2 = getattr(next_state.regs, malloc.calling_convention.RETURN_VAL.reg_name)
    malloced_address_2_val = next_state.solver.eval(malloced_address_2)
    check_malloc_result(malloced_address_2_val)
    curr_allocated_chunks.append(malloced_address_2_val)

    l.info("[+] Second chunk allocated at {}".format(hex(malloced_address_2_val)))

    # Call bunch of malloc.
    for _ in range(0,11):
        next_state = call_malloc(next_state, int(config["test_hml"]["malloc_emulation_def_req_size"]))
        malloced_address_val = next_state.solver.eval(getattr(next_state.regs, malloc.calling_convention.RETURN_VAL.reg_name))
        check_malloc_result(malloced_address_val)
        curr_allocated_chunks.append(malloced_address_val)
    
    # Courtesy prints.
    for chunk_i, x in enumerate(curr_allocated_chunks):
        l.info("[+]  Chunk-{} allocated at {}".format(chunk_i+1, hex(x)))

    # Calculate heap base address.
    hb_state["heap_base"] = malloced_address_1_val - malloc_1_size
    l.info("[+]Guessing heap base address at {}".format(hex(hb_state["heap_base"])))

    # Check heap growing direction.
    if malloced_address_2_val - malloced_address_1_val > 0:
        # The heap grows towards higher addresses
        hb_state["heap_grow_direction"] = ">"
    else:
        # The heap grows towards lower addresses
        hb_state["heap_grow_direction"] = "<" 
    l.info("[+]Guessing growing direction: {}".format(hb_state["heap_grow_direction"]))
    
    l.info("[+]Guessing inline metadata")
    # Fill allocated chunks with some user data.
    data_malloc_1 = "A" * malloc_1_size
    next_state.memory.store(malloced_address_1_val, data_malloc_1 ,endness=project.arch.memory_endness)
    data_malloc_2 = "B" * malloc_2_size
    next_state.memory.store(malloced_address_2_val, data_malloc_2 ,endness=project.arch.memory_endness)
    
    # Keep track of accesses outside of user data.
    next_state.globals["metadata_accesses"] = []

    # Scan the memory backward  
    curr_addr = malloced_address_2_val
    while curr_addr != malloced_address_1_val:
        if hb_state["heap_grow_direction"] == ">":
            # Go to previous dword
            curr_addr = curr_addr - project.arch.bytes 
        else:
            # Go to the next dword
            curr_addr = curr_addr + project.arch.bytes
        mem_data = next_state.memory.load(curr_addr, endness=project.arch.memory_endness)
        mem_data = hex(next_state.solver.eval(mem_data))

        if "4141" not in mem_data:
            # No data in this dword, we place a SimInspect.
            l.info("[!] No previous chunk data at {}".format(hex(curr_addr)))
            next_state.inspect.b('mem_read', mem_read_address= curr_addr ,when=angr.BP_BEFORE, action=reg_metadata_access)
            next_state.inspect.b('mem_write', mem_write_address= curr_addr ,when=angr.BP_BEFORE, action=reg_metadata_access_write)
        else:
            # Spot the chunk data, probably no more metadata.
            l.info("[+] Spotted previous chunk data {} at {}".format(mem_data, hex(curr_addr)))
            break 
    
    # Run free on the second allocated chunk.
    next_state = call_free(next_state, malloced_address_2_val)
    curr_allocated_chunks.remove(malloced_address_2_val)
    old_allocated_chunks.append(malloced_address_2_val)

    if len(next_state.globals["metadata_accesses"]) != 0:
        l.info("[+] Metadata guess:")
        for windex, x in enumerate(set(next_state.globals["metadata_accesses"])):
            l.info("[+]  MetadataAddress-{}: {}".format(windex, hex(x)))
    else:
        l.info("[!]  No metadata has been found")
    
    # Guess the header_size and the mem2chunk_offset according to the
    # accesses observed during free execution.
    if len(next_state.globals["metadata_accesses"]) != 0:
        if hb_state["heap_grow_direction"] == ">":
            mem2chunk_offset = malloced_address_2_val - min(next_state.globals["metadata_accesses"])
            header_size =  malloced_address_2_val - min(next_state.globals["metadata_accesses"])
        else:
            mem2chunk_offset = max(next_state.globals["metadata_accesses"]) - malloced_address_2_val 
            header_size =  max(next_state.globals["metadata_accesses"]) - malloced_address_2_val 
    else:
        mem2chunk_offset = 0
        header_size = 0
        
    l.info("[+]Guessed mem2chunk offset is [{}]".format(mem2chunk_offset))
    l.info("[+]Guessed header_size is [{}]".format(mem2chunk_offset))
    hb_state["mem2chunk_offset"] = mem2chunk_offset
    hb_state["header_size"] = header_size

    l.info("[+]Sanity checks to verify HML operations")
    
    # Sanity checks.
    # Deallocate all the previous chunks and allocate a new one. 
    # The new chunk should be in the set of the previously allocated chunks.
    for chunk in curr_allocated_chunks:
        l.info("[+] Deallocating chunk at {}".format(hex(chunk)))
        next_state = call_free(next_state, chunk)
        old_allocated_chunks.append(chunk)

    next_state.inspect.remove_breakpoint("mem_read", filter_func= lambda x: x != None)
    next_state.inspect.remove_breakpoint("mem_write", filter_func= lambda x: x != None)

    l.info("[+] Allocating new chunk [expecting to get one recently freed]")
    final_state = call_malloc(next_state, int(config["test_hml"]["malloc_emulation_def_req_size"]))
    malloced_address_3_val = final_state.solver.eval( getattr(final_state.regs, malloc.calling_convention.RETURN_VAL.reg_name))

    if malloced_address_3_val in old_allocated_chunks:
        success_log = "[+] ✓ Last malloc() returned previously freed chunk ({})".format(hex(malloced_address_3_val))
        success_log = f'{bcolors.YELLOWBG}{success_log}{bcolors.ENDC}'
        l.info(success_log)
        hb_state["allocator_works"] = 1
    else:
        bad_log = "[!] ✗ Last malloc() returned something different than the prev [{}]".format(hex(malloced_address_3_val))
        bad_log = f'{bcolors.REDBG}{bad_log}{bcolors.ENDC}'
        l.info(bad_log)

        if not hb_state.get("wrong_pairs", None):
            hb_state["wrong_pairs"] = []
        
        wrong_pair_signature = hex(malloc.addr) + "-" + hex(free.addr)

        if wrong_pair_signature not in hb_state["wrong_pairs"]:
            l.info("[!] Adding this pair {}-{} to the wrong pair".format(hex(malloc.addr), hex(free.addr)))
            hb_state["wrong_pairs"].append(wrong_pair_signature)
        
        hb_state["allocator_works"] = 0
        l.fatal("[!] >>>Change the selected final allocator in hb_state.json before re-starting this script<<<")

        with open(hb_state_file, 'w') as fp:
            json.dump(hb_state, fp)

        raise Exception

    with open(hb_state_file, 'w') as fp:
        json.dump(hb_state, fp)



