import angr
import argparse
import logging
import json 
import os
import pickle
import sys
sys.setrecursionlimit(10**6) 
import yaml

from angr.procedures.stubs.format_parser import FormatParser
from angr.procedures.posix.read import read
from angr.procedures.libc.printf import printf
from cle.backends import NamedRegion

from datetime import date, datetime
from cle.backends import NamedRegion
from configparser import ConfigParser 
from pathlib import Path

from ..utils import * 

from .exploration_techniques import HMLFuncExecution, HeartBeat

# Fancy debug.
from angrcli.interaction.explore import ExploreInteractive
import angrcli.plugins.ContextView
import angrcli.plugins.watches 

l = logging.getLogger("verify_pov".ljust(15))
l.setLevel(logging.INFO)
logger = l

# Parse heapster global .ini conf
config = ConfigParser()
config.read((Path(__file__).parent.parent / "./heapster.ini").resolve())

global malloc_index
global malloc_dict

def parse_opts():
    o = argparse.ArgumentParser()
    o.add_argument("--resume", default=None)
    o.add_argument("--analysis-conf", default=None)
    o.add_argument("--pov", default=None)
    o.add_argument("--no-hooks", action='store_true')
    opts = o.parse_args()
    return opts

def config_script(project, opts, hb_state):
    final_pair = hb_state["final_allocator"]
    malloc = int(final_pair["malloc"],16)
    free = int(final_pair["free"],16)
    mem_dump_path = final_pair["mem_dump_path"]
    return malloc, free, mem_dump_path

'''
Create state ready to execute with blob
unpacked memory.
'''
def get_init_state(project, hb_state, mem_dump_init):
    init_state = project.factory.entry_state(
                    add_options={
                                angr.options.CONCRETIZE_SYMBOLIC_FILE_READ_SIZES,
                                angr.options.ZERO_FILL_UNCONSTRAINED_MEMORY,
                                angr.options.ZERO_FILL_UNCONSTRAINED_REGISTERS,
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

    init_state = init_memory_with_blob_mem(project, init_state, hb_state, mem_dump_init)
    init_state.regs.sp = project.arch.initial_sp
    
    return init_state

global malloc_index
global malloc_dict

'''
Hook to inspect a call to malloc
and its result.
'''
class MallocInspect(angr.SimProcedure):

    def run(self, malloc_addr=None):
        global malloc_dict
        global malloc_index

        # Let's extract the args according to the prototype of this malloc
        malloc_prototype = self.state.globals["malloc_prototype"]

        malloc_args = ()
        for arg_idx in range(0,len(malloc_prototype)):
            malloc_args = malloc_args + (self.arg(arg_idx), )
        
        # Extract which param is the size, we have tagged that in the dict. 
        # As for now it MUST be present (even if we HeapBuster has support 
        # for malloc with no args tho).
        size_idx = 0
        for malloc_arg_key, malloc_arg_value in malloc_prototype.items():
            if malloc_arg_key == 'ret':
                continue
            if malloc_arg_value == "size":
                break
            else:
                size_idx = size_idx + 1
        
        size = self.state.solver.min(malloc_args[size_idx])

        logger.info("[+] Calling malloc with size: {}".format(size))

        malloc_dict[malloc_index] = (None, size)

        self.call(malloc_addr, malloc_args, 'check_malloc')
    
    def check_malloc(self, malloc_addr=None): #pylint:disable=unused-argument    
        global malloc_dict
        global malloc_index

        malloc_error_codes = [ 0x0, 0xffffffff]

        reg_name = self.state.globals["malloc_prototype"]["ret"]
        if not reg_name:
            l.fatal("[!] No support for void malloc yet. Aborting.")
            sys.exit(-1)
        malloced_addr = getattr(self.state.regs, reg_name) 
        
        # If we have something symbolic in this run, something is
        # wrong.
        sols = self.state.solver.eval_upto(malloced_addr, 2)
        if len(sols) > 1:
            logger.warning("[?] Wait, something is symbolic, how?!")
            #import ipdb; ipdb.set_trace()
            sys.exit(-1)

        # Get min val
        val = sols[0]
        if val not in malloc_error_codes:
            logger.info("[+] Malloc returned concrete address: {}".format(hex(val)))
            self.state.add_constraints(malloced_addr == val)
            malloc_info = malloc_dict[malloc_index]
            malloc_info = (val, malloc_info[1])
            malloc_dict[malloc_index] = malloc_info

            malloc_index = malloc_index + 1 
            return val
        else:
            logger.warning("[!] Malloc failed (returned 0)")
            #import ipdb; ipdb.set_trace()
            self.state.globals["malloc_failed"] = True
            return val

'''
Hook to inspect a call to free and its 
result.
'''
class FreeInspect(angr.SimProcedure):

    def run(self, free_addr=None): # pylint: disable=arguments-differ

        global last_free_on
        global malloc_dict
        global malloc_index

        free_prototype = self.state.globals["free_prototype"]
        # Let's extract the args according to the prototype of this malloc
        free_args = ()
        for arg_idx in range(0, len(free_prototype)):
            free_args = free_args + (self.arg(arg_idx), )
        
        # Extract which param is the ptr_to_free, we have tagged that in the dict. 
        # As for now it MUST be present in tha args.
        size_idx = 0

        for free_arg_key, free_arg_value in free_prototype.items():
            if free_arg_key == 'ret':
                continue
            if free_arg_value == "ptr_to_free":
                break
            else:
                size_idx = size_idx + 1
        ptr =  free_args[size_idx]

        val = self.state.solver.min(ptr)
        last_free_on = val 

        logger.info("[+] Calling free over address: {}".format(hex(val)))
        # Call real function at <free_addr> and then call <check_free>
        self.call(free_addr, free_args, 'check_free')

    def check_free(self, free_addr=None): #pylint:disable=unused-argument
        global last_free_on
        global malloc_dict
        global malloc_index

        # Let's extract the args according to the prototype of this free
        free_args = ()
        free_prototype = self.state.globals["free_prototype"]
        for arg_idx in range(0,len(free_prototype)):
            free_args = free_args + (self.arg(arg_idx), )
        
        # Extract which param is the ptr_to_free, we have tagged that in the dict. 
        # As for now it MUST be present in tha args.
        ptr_to_free_idx = 0
        for free_arg in free_prototype.values():
            if free_arg == "ptr_to_free":
                break
            else:
                ptr_to_free_idx = ptr_to_free_idx + 1

        ptr =  self.state.solver.eval(free_args[ptr_to_free_idx])
        key_to_delete = -1 
        for malloc_key, malloc_info in malloc_dict.items():
            if malloc_info[0] == last_free_on:
                key_to_delete = malloc_key
        if key_to_delete != -1:
            del malloc_dict[key_to_delete]  # delete entry in the allocated 
        return

'''
Custom hook for printf.
'''
class myprintf(FormatParser):
    def run(self):
        stdout = self.state.posix.get_fd(1)
        if stdout is None:
            return -1

        # The format str is at index 0
        fmt_str = self._parse(0)
        out_str = fmt_str.replace(1, self.arg)
        print(self.state.solver.eval(out_str, cast_to=bytes))
        stdout.write_data(out_str, out_str.size() // 8)
        return out_str.size() // 8

'''
Check wether we have triggered an 
overlapping chunks vulnerability.
'''
def check_overlapping_chunks():
    global malloc_dict
    allocated_addresses = []
    for malloc_key, malloc_info in malloc_dict.items():
        for mem_addr in range(malloc_info[0], malloc_info[0]+malloc_info[1], 0x1):
            if mem_addr in allocated_addresses:
                logger.info("[!] Detected overlapping chunk at address <<{}>>".format(hex(mem_addr))) 
                return True
            else:
                allocated_addresses.append(mem_addr)
    return False   
'''
Check wether we have triggered 
an arbitrary write.
'''
def check_arbitrary_write(state):
    if len(state.globals["arb_write_happened"]) != 0:
        return True
    else:
        return False
'''
Check if a specific address is out of the heap.
'''
def out_of_heap(malloc_addr, heap_grows, heap_base):
    if heap_grows == ">":
        if malloc_addr < heap_base:
            return True
        else:
            return False
    if heap_grows == "<":
        if malloc_addr > heap_base:
            return True
        else:
            return False

'''
Check bad allocation.
'''
def check_bad_alloc(heap_grows, heap_base):
    for malloc_key, malloc_info in malloc_dict.items():
        if out_of_heap(malloc_info[0], heap_grows, heap_base):
            l.info("[!] Address at {} is out of heap [base: {}, growing dir: {}]".format(hex(malloc_info[0]), 
                                                                                        hex(heap_base), 
                                                                                        heap_grows))
            return True 
    return False 

'''
Callback to check arbitraryy writes.
'''
def register_arb_write(state):
    addr = state.solver.eval(state.inspect.mem_write_address)
    state.globals["arb_write_happened"].add(addr)


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

if __name__ == "__main__":
    
    global  malloc_index
    global  malloc_dict

    opts = parse_opts()
    hb_state_file = opts.resume
    if os.path.exists(hb_state_file) and os.path.isfile(hb_state_file):
        with open(hb_state_file, "r") as hb_file:
            hb_state = json.load(hb_file)
    else:
        l.fatal("No file at {}. Aborting.".format(hb_state_file))
        sys.exit(-1)

    l.info("[+]Verifying PoV started!")

    # Load the analysis configuration.
    if not os.path.exists(opts.analysis_conf) or not os.path.isfile(opts.analysis_conf):
        l.fatal("Can't load the HeapHopper analysis file")
        sys.exit(-1)
    with open(opts.analysis_conf, "r") as analysis_conf:
        analysis_config = yaml.load(analysis_conf, Loader=yaml.FullLoader)

    # Load the POV file.
    if not os.path.exists(opts.pov) or not os.path.isfile(opts.pov):
        l.fatal("[!]Can't load the POV file")
        sys.exit(-1)

    blob_proj, blob_bin_cfg = load_artifact(hb_state)

    malloc_address, free_address, mem_dump_path = config_script(blob_proj, opts, hb_state)

    allocator_path = analysis_config["allocator"]
    allocator_name = os.path.basename(allocator_path)

    libc_path = analysis_config["libc"]

    ram_object = None
    mmio_object = None
    
    for obj in blob_proj.loader.all_objects:
        if "ram" in obj.binary_basename:
            ram_object = obj
        elif "mmio" in obj.binary_basename:
            mmio_object = obj
    
    assert(ram_object)
    assert(mmio_object)

    l.info("[+]Creating Project")
    project = angr.Project(opts.pov, load_options={
                                                   'force_load_libs': [allocator_path, ram_object, mmio_object],
                                                   'lib_opts': { allocator_name: {
                                                                                 'base_addr': blob_proj.loader.min_addr, 
                                                                                 'backend': 'blob', 
                                                                                 'arch': blob_proj.arch.name,
                                                                                 'entry_point': blob_proj.entry
                                                                                 } 
                                                               }
                                                   }, 
                                     arch=blob_proj.arch.name)
    
    # Fixing the stack pointer to point to the blob one!
    blob_sp_pointer = hb_state["blob_stack_pointer"]
    project.arch.initial_sp = int(blob_sp_pointer,16)
    # Init blob memory.
    state = get_init_state(project, hb_state, mem_dump_path)
    
    logger.info("[+]PoC and Blob loaded")
    logger.info("[+] PoC Entry Point at [{}]".format(hex(project.entry)))
    logger.info("[+] PoC Arch [{}]".format(project.arch.name))
    logger.info("[+] PoC Initial Stack Pointer [{}]".format(hex(project.arch.initial_sp)))

    logger.info("[+] PoC Regions:")
    for o_idx, o in enumerate(project.loader.all_objects):
        logger.info("[+]  Region {}: {}".format(o_idx,o))

    write_target_var = project.loader.main_object.get_symbol('write_target')
    for i in range(0, write_target_var.size, project.arch.bytes):
        logger.debug("write_mem_element at {}".format(hex(write_target_var.rebased_addr + i)))

    state.globals["malloc_prototype"] = json.loads(hb_state["malloc_prototype"]) 
    state.globals["free_prototype"] = json.loads(hb_state["free_prototype"]) 

    # Hook procedures.
    malloc_main_bin = project.loader.main_object.get_symbol('malloc').rebased_addr
    free_main_bin = project.loader.main_object.get_symbol('free').rebased_addr
    myread_main_bin = project.loader.main_object.get_symbol('myread').rebased_addr
    myprint_main_bin = project.loader.main_object.get_symbol('myprintf').rebased_addr
    project.hook(addr=malloc_main_bin, hook=MallocInspect(malloc_addr=malloc_address))
    project.hook(addr=free_main_bin, hook=FreeInspect(free_addr=free_address))
    project.hook(addr=myread_main_bin, hook=read())
    project.hook(addr=myprint_main_bin, hook=myprintf())

    # Setup hooks if identify_hotspots got any.
    if not opts.no_hooks:
        # Hook the skip() SimProc as detected by fix_hml.
        if hb_state.get("malloc_to_hook_funcs", None):
            malloc_hook_funcs = hb_state["malloc_to_hook_funcs"]
            for h in malloc_hook_funcs:
                l.info("[+]Hooking function {} with skip()".format(hex(h)))
                project.hook(addr=h, hook=skip())

        if hb_state.get("free_to_hook_funcs", None):
            free_hook_funcs = hb_state["free_to_hook_funcs"]
            for h in free_hook_funcs:
                l.info("[+]Hooking function {} with skip()".format(hex(h)))
                project.hook(addr=h, hook=skip())


    state.globals["arb_write_happened"] = set()
    for i in range(0, write_target_var.size, project.arch.bytes):
        wt_address = write_target_var.rebased_addr + i
        state.inspect.b('mem_write', mem_write_address= wt_address ,when=angr.BP_BEFORE, action=register_arb_write)

    # Prepare SimulationManager
    sm = project.factory.simgr(thing=state)
    
    avoids = []
    winning_address = project.loader.main_object.get_symbol('winning').rebased_addr
    
    logger.info("[+]State is configured. Ready to execute.")
    malloc_index = 0 
    malloc_dict = {}
    debug = False
    debug_cli = False
    print_ctx = False

    ed = ExplosionDetector(threshold=1000)
    hml_func_exec = HMLFuncExecution()

    sm.use_technique(angr.exploration_techniques.DFS())
    sm.use_technique(angr.exploration_techniques.Explorer(find=winning_address, avoid=avoids))
    sm.use_technique(ed)
    sm.use_technique(hml_func_exec)
    sm.use_technique(HeartBeat(beat_interval=1))

    def timeout():
        l.warning("[!]Timeout during DSE has been reached.")
        ed.timed_out.set()
        ed.timed_out_bool = True

    # Since we are removing the "problematic" functions
    # it's better we put a timer of 5 minutes here.
    timer = Timer(300, timeout)
    
    stop = False 
    debug = False
    debug_cli = False    
    
    # Clean this one day....
    timer.start()
    while len(sm.active) > 0:
        new_state = sm.active[0]
        if debug:
            print(sm.active)
            if debug_cli:
                e = ExploreInteractive(proj, new_state)
                e.cmdloop()
                import ipdb; ipdb.set_trace()
        # Step by step.
        sm.step()

    timer.cancel()

    # Check if vulnerability has been triggered.
    if "arb_write" in opts.analysis_conf:
        vuln_name = "arb_write"
    elif "bad_alloc" in opts.analysis_conf:
        vuln_name = "bad_alloc"
    elif "overlap" in opts.analysis_conf:
        vuln_name = "overlap"

    if hml_func_exec.end_execution_reason and hml_func_exec.end_execution_reason[0] == "END_EXECUTION_MALLOC_RETURNED_ZERO":
        print("???CONCRETIZED POC IS NOT VULNERABLE BECAUSE MALLOC RETURNED ERROR CODE???")
        sys.exit(0)
    
    # THESE PRINTS ARE HERE TO DETECT THE OUTPUT FROM THE EXPERIMENTS SCRIPTS
    # (THEY CAN BE REMOVED WHEN USING THE TOOL BY ITSELF)
    if ed.timed_out_bool:
        print("???CONCRETIZED POC IS NOT VULNERABLE BECAUSE OF TIMEOUT???")
        sys.exit(0)
    else:
        if vuln_name == "overlap":
            if check_overlapping_chunks():
                print("!!!CONCRETIZED POC IS VULNERABLE TO OVERLAPPING CHUNK!!!")
            else:
                print("???CONCRETIZED POC IS NOT VULNERABLE TO OVERLAPPING CHUNK???")
        elif vuln_name == "arb_write":
            if check_arbitrary_write(new_state):
                print("!!!CONCRETIZED POC IS VULNERABLE TO ARBITRARY WRITE!!!")
                for addr in new_state.globals["arb_write_happened"]:
                    print("!!!ARB WRITE AT {}".format(hex(addr)))
            else:
                print("???CONCRETIZED POC IS NOT VULNERABLE TO ARBITRARY WRITE???")
        else:
            heap_grows = hb_state["heap_grow_direction"]
            heap_base = hb_state["heap_base"]
            if check_bad_alloc(heap_grows, heap_base):
                print("!!!CONCRETIZED POC IS VULNERABLE TO BAD ALLOC!!!")
            else:
                print("???CONCRETIZED POC IS NOT VULNERABLE TO BAD ALLOC???")
    
    logger.info("Done")