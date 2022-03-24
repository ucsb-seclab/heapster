# coding: utf-8
#!/usr/bin/env python
# ██░ ██ ▓█████ ▄▄▄       ██▓███   ▄▄▄▄    █    ██  ██████ ▄▄▄█████▓▓█████  ██▀███    ██████
#▓██░ ██▒▓█   ▀▒████▄    ▓██░  ██▒▓█████▄  ██  ▓██▒██    ▒ ▓  ██▒ ▓▒▓█   ▀ ▓██ ▒ ██▒▒██    ▒
#▒██▀▀██░▒███  ▒██  ▀█▄  ▓██░ ██▓▒▒██▒ ▄██▓██  ▒██░ ▓██▄   ▒ ▓██░ ▒░▒███   ▓██ ░▄█ ▒░ ▓██▄
#░▓█ ░██ ▒▓█  ▄░██▄▄▄▄██ ▒██▄█▓▒ ▒▒██░█▀  ▓▓█  ░██░ ▒   ██▒░ ▓██▓ ░ ▒▓█  ▄ ▒██▀▀█▄    ▒   ██▒
#░▓█▒░██▓░▒████▒▓█   ▓██▒▒██▒ ░  ░░▓█  ▀█▓▒▒█████▓▒██████▒▒  ▒██▒ ░ ░▒████▒░██▓ ▒██▒▒██████▒▒
# ▒ ░░▒░▒░░ ▒░ ░▒▒   ▓▒█░▒▓▒░ ░  ░░▒▓███▀▒░▒▓▒ ▒ ▒▒ ▒▓▒ ▒ ░  ▒ ░░   ░░ ▒░ ░░ ▒▓ ░▒▓░▒ ▒▓▒ ▒ ░
# ▒ ░▒░ ░ ░ ░  ░ ▒   ▒▒ ░░▒ ░     ▒░▒   ░ ░░▒░ ░ ░░ ░▒  ░ ░    ░     ░ ░  ░  ░▒ ░ ▒░░ ░▒  ░ ░
# ░  ░░ ░   ░    ░   ▒   ░░        ░    ░  ░░░ ░ ░░  ░  ░    ░         ░     ░░   ░ ░  ░  ░
# ░  ░  ░   ░  ░     ░  ░          ░         ░          ░              ░  ░   ░           ░
#
import logging
import IPython
import ana
import math
import re
import cle
import json
import angr
import claripy
import os
import pickle
import yaml
import time 

import sys
sys.setrecursionlimit(10**9)

from elftools.elf.elffile import ELFFile
from angr.procedures.posix.read import read
from angr.state_plugins import Flags, SimFile
from angr import SimHeapBrk
from cle.backends import NamedRegion
from ..heap_condition_tracker import HeapConditionTracker, MallocInspect, FreeInspect
from ..mem_limiter import MemLimiter
from ..vuln_checker import VulnChecker
from ..hh_executor import HHExecutor
from ..concretizer import Concretizer
from ..heartbeat import HeartBeat
from ..hhsimgrviz import HHSimgrViz
from ..skip_svc import SkipSVC
from ...utils.angr_tools import heardEnter, all_bytes, init_memory_with_blob_mem, skip
from ...utils.parse_config import parse_config
from ...utils.input import constrain_input
from threading import Event, Timer

# Fancy debug.
from angrcli.interaction.explore import ExploreInteractive
import angrcli.plugins.ContextView
import angrcli.plugins.watches 

logger = logging.getLogger('heap-tracer')
logging.getLogger("angr.sim_manager").setLevel(logging.CRITICAL)

# Global vars.
DESC_HEADER = 'Vuln description for binary'
DESC_SECTION_LINE = '=========================================='
MALLOC_LIST = []

def priority_key(state):
    return hash(tuple(state.history.bbl_addrs))

'''
Map addrs to source code using DWARF info
'''
def decode_file_line(dwarfinfo, address):
    # Go over all the line programs in the DWARF information, looking for
    # one that describes the given address.
    for CU in dwarfinfo.iter_CUs():
        # First, look at line programs to find the file/line for the address
        lineprog = dwarfinfo.line_program_for_CU(CU)
        prevstate = None
        for entry in lineprog.get_entries():
            # We're interested in those entries where a new state is assigned
            if entry.state is None or entry.state.end_sequence:
                continue
            # Looking for a range of addresses in two consecutive states that
            # contain the required address.
            if prevstate and prevstate.address <= address < entry.state.address:
                filename = lineprog['file_entry'][prevstate.file - 1].name
                line = prevstate.line
                return filename, line
            prevstate = entry.state
    return None, None


def get_last_line(win_addr, bin_file):
    with open(bin_file, 'rb') as bf:
        elffile = ELFFile(bf)

        if not elffile.has_dwarf_info():
            print('{} has no DWARF info'.format(bin_file))
            sys.exit(1)

        # get_dwarf_info returns a DWARFInfo context object, which is the
        # starting point for all DWARF-based processing in pyelftools.
        dwarfinfo = elffile.get_dwarf_info()
        file_name, line = decode_file_line(dwarfinfo, win_addr)
        return line


def get_win_addr(proj, addr_trace):
    heap_func = None
    addr_trace = addr_trace[:-1]  # discard last element
    for addr in addr_trace[::-1]:
        if proj.loader.main_object.contains_addr(addr):
            print("{} in the main binary".format(hex(addr)))
            if heap_func:
                print("Last heap func {} is at {}".format(hex(heap_func), hex(addr)))
                return addr, heap_func
            else:  # heap-func in plt first
                heap_func = addr
                print("Heap func at {}".format(hex(heap_func)))

        elif heap_func:
            # last main_object addr has to be right before heap_func call
            raise Exception("Couldn't find win addr")



# This method post processes a vulnerable state
#
# :proj is the project object.
# :num_results specifies how many solutions you want to get for symbolic results in the state (it's in the config)
# :state is the state to analyze
# :write_state is the vulnerable state belonging to the history of the `state`
# :var_dict is the dict returned by the setup_state (with all the info regarding globals and stuff).
# :fd is the memory corruption file descriptor (usually 3).
#
def process_state(proj, num_results, state, write_state, var_dict, fd):
    processed_states = []

    # Get solutions for all the data read from the mem_corruption file.
    aaa = all_bytes(state.posix.fd[fd].read_storage)
    input_opts = state.solver.eval_upto(aaa, num_results, cast_to=bytes)
    print("Concretizing input using s you have {}".format(input_opts))

    input_opts2 = write_state.solver.eval_upto(aaa, num_results, cast_to=bytes)
    print("Concretizing input using write_s you have {}".format(input_opts2))

    for input_opt in input_opts:
        s = state.copy()
        write_s = write_state.copy()
        s.add_constraints(all_bytes(s.posix.fd[fd].read_storage) == input_opt)
        write_s.add_constraints(all_bytes(write_s.posix.fd[fd].read_storage) == input_opt)

        # Get all the bytes read from the stdin
        stdin_bytes = all_bytes(state.posix.fd[0].read_storage)
        print("Concretizing input using s you have {}".format(stdin_bytes))
       
        stdin_bytes2 = all_bytes(write_s.posix.fd[0].read_storage)
        print("Concretizing input using write_s you have {}".format(stdin_bytes2))

        # If we did any read from the stdin (fd: 0)
        if stdin_bytes:
            stdin_bytes = [b[0] for b in stdin_bytes]
            stdin_stream = stdin_bytes[0]
            for b in stdin_bytes[1:]:
                stdin_stream = stdin_stream.concat(b)

            # stdin_stream is the BVV stream of all the bytes read from stdin (fd: 0)
            stdin_opt = state.solver.eval(stdin_stream, cast_to=bytes)
            print("Concretizing input using s you have {}".format(stdin_opt))

            stdin_opt2 = write_s.solver.eval(stdin_stream, cast_to=bytes)
            print("Concretizing input using write_s you have {}".format(stdin_opt2))

            # Constraining the stdin stream to specific value
            s.add_constraints(stdin_stream == stdin_opt)
            write_s.add_constraints(stdin_stream == stdin_opt)
        else:
            stdin_opt = []

        svars = []

        # check if we have a saved-state for the sym_data memory
        if 'sym_data_ptr' in var_dict and s.heaphopper.sym_data_states[var_dict['sym_data_ptr']]:
            sym_s = s.heaphopper.sym_data_states[var_dict['sym_data_ptr']].copy()
            sym_s.add_constraints(all_bytes(sym_s.posix.fd[fd].read_storage) == input_opt)
            if stdin_opt:
                sym_s.add_constraints(stdin_stream == stdin_opt)
        else:
            sym_s = s

        for svar in var_dict['sdata_vars']:
            #smem_orig = sym_s.memory.load(svar, proj.arch.bytes, endness='Iend_LE')
            #smem_final = write_s.memory.load(svar, proj.arch.bytes, endness='Iend_LE')
            # If the symbolic variable was overwritten, use the orig one
            #if smem_orig is not smem_final:
            #    sol = sym_s.solver.min(smem_orig)
            #    sym_s.add_constraints(smem_orig == sol)
            #else:
            sol = write_s.solver.min(svar)
            write_s.add_constraints(svar == sol)
            svars.append(sol)

        #for svar in var_dict['sdata_vars']:
        #    #smem_orig = sym_s.memory.load(svar, proj.arch.bytes, endness='Iend_LE')
        #    #smem_final = s.memory.load(svar, proj.arch.bytes, endness='Iend_LE')
        #    ## If the symbolic variable was overwritten, use the orig one
        #    #if smem_orig is not smem_final:
        #    #    sol = sym_s.solver.min(smem_orig)
        #    #    sym_s.add_constraints(smem_orig == sol)
        #    #else:
        #    #    sol = s.solver.min(smem_final)
        #    #    s.add_constraints(smem_final == sol)
        #    sol = write_s.solver.min(svar)
        #    write_s.add_constraints(svar == sol)
        #    svars.append(sol)

        header_var = s.memory.load(var_dict['header_size_addr'], proj.arch.bytes, endness="Iend_LE")
        header = s.solver.min(header_var)
        s.add_constraints(header_var == header)
        write_s.add_constraints(header_var == header)

        msizes = []
        #print("Using memory load to concretize malloc sizes")
        #for malloc_size in var_dict['malloc_size_addrs']:
        #    
        #    size_var = s.memory.load(malloc_size, proj.arch.bytes, endness="Iend_LE")
        #    sol = s.solver.min(size_var)
        #    sols = s.solver.eval_upto(size_var, 10)
        #    print(sols)
        #    
        #    print("Using s for {} I would have {}".format(size_var, sol))
        #    sol2 = write_s.solver.min(size_var)
        #    print("Using write_s for {} I would have {}".format(size_var, sol2))
        #    #msizes.append(sol)
        #    #s.add_constraints(size_var == sol)
        #    #write_s.add_constraints(size_var == sol)

        # SANITY TEST
        #lol = var_dict["malloc_size_bvs"][3]
        #num_csts = len(state.solver.constraints)
        #state.solver.eval_upto(lol,10)
        #print("Checking number of constraints")
        #assert(num_csts == len(state.solver.constraints))
        #print("Checking number of constraints OK")
        
        print("===================================")
        print("Using BVS concretize malloc sizes")
        for malloc_size in var_dict['malloc_size_bvs']:
            size_var = malloc_size
            sol = write_s.solver.min(size_var)
            print("size_var {} is {}".format(size_var, sol))
            msizes.append(sol)
            s.add_constraints(size_var == sol)
            write_s.add_constraints(size_var == sol)

        fsizes = []
        for fill_size in var_dict['fill_size_vars']:
            sol = s.solver.min(fill_size)
            fsizes.append(sol)
            s.add_constraints(fill_size == sol)
            write_s.add_constraints(fill_size == sol)

        osizes = []
        for overflow_size in var_dict['overflow_sizes']:
            sol = write_s.solver.min(overflow_size)
            osizes.append(sol)
            s.add_constraints(overflow_size == sol)
            write_s.add_constraints(overflow_size == sol)

        wt_mem = []
        for write_target in var_dict['wtarget_vars']:
            #wt_var = write_s.memory.load(write_target, proj.arch.bytes, endness="Iend_LE")
            wt_var = write_target
            sol = write_s.solver.min(wt_var)
            logger.info("Concretizing write target at {}".format(sol))
            wt_mem.append(sol)
            write_s.add_constraints(wt_var == sol)

        allocs = []
        for allocation in var_dict['allocs']:
            alloc_var = s.memory.load(allocation, proj.arch.bytes, endness="Iend_LE")
            sol = s.solver.min(alloc_var)
            allocs.append(sol)
            s.add_constraints(alloc_var == sol)
            write_s.add_constraints(alloc_var == sol)

        arb_offsets = []
        for arb_var in var_dict['arb_offset_vars']:
            arb_offset = s.memory.load(arb_var, proj.arch.bytes, endness="Iend_LE")
            sol = s.solver.min(arb_offset)
            arb_offsets.append(sol)
            s.add_constraints(arb_offset == sol)
            write_s.add_constraints(arb_offset == sol)

        bf_offsets = []
        for bf_var in var_dict['bf_offset_vars']:
            bf_offset = s.memory.load(bf_var, proj.arch.bytes, endness="Iend_LE")
            sol = s.solver.min(bf_offset)
            bf_offsets.append(sol)
            s.add_constraints(bf_offset == sol)
            write_s.add_constraints(bf_offset == sol)

        arb_write = {}
        if s.heaphopper.arb_write_info:
            arb_write = {k: write_s.solver.min(v) for k, v in list(s.heaphopper.arb_write_info.items())}

        # Let's also concretize the symbolic args of malloc and free
        malloc_sym_args = {}
        if var_dict.get('malloc_sym_args_vars', None):
            for malloc_id, malloc_args in var_dict['malloc_sym_args_vars'].items():
                malloc_sym_args[malloc_id] = [] 
                for m_arg in malloc_args:
                    sol = write_s.solver.min(m_arg)
                    malloc_sym_args[malloc_id].append(sol)
                    s.add_constraints(m_arg == sol)
                    write_s.add_constraints(m_arg == sol)
        
        free_sym_args = {}
        if var_dict.get('free_sym_args_vars', None):
            for free_id, free_args in var_dict['free_sym_args_vars'].items():
                free_sym_args[free_id] = [] 
                for f_arg in free_args:
                    sol = write_s.solver.min(f_arg)
                    free_sym_args[free_id].append(sol)
                    s.add_constraints(f_arg == sol)
                    write_s.add_constraints(f_arg == sol)

        processed_states.append(
            (input_opt, stdin_opt, svars, header, msizes, fsizes, osizes, wt_mem, allocs, arb_offsets,
             bf_offsets, arb_write, malloc_sym_args, free_sym_args))
        
    return processed_states


'''
Configure state and fill memory with symbolic variables
'''
def setup_state(state, proj, config):

    logger.info("Setupping HeapHopper initial state")

    # Inject symbolic controlled data into memory
    var_dict = dict()
    var_dict['global_vars'] = []
    var_dict['allocs'] = []

    # ctrl_data is where we store the pointers returned
    # by malloc, MAX 20 of them.
    for i in range(20):
        cdata = proj.loader.main_object.get_symbol('ctrl_data_{}'.format(i))
        # check if ctrl_data exists
        if not cdata:
            break
        
        # This must be removed otherwise I can change the addresses of the returned chunk 
        # this is not allowed...
        #var_dict['global_vars'].append(cdata.rebased_addr)
        logger.info("ctrl_data_{} at {}".format(i, hex(cdata.rebased_addr)))
        var_dict['allocs'].append(cdata.rebased_addr)

    # Set mem2chunk offset with the value specified
    # in the analysis confg file.
    # I have this info from the analysis of the data-structures used by
    # the specific heap implementation we are studying.
    # TODO Must be extracted from the binary.
    mem2chunk_var = proj.loader.main_object.get_symbol('mem2chunk_offset')
    var_dict['mem2chunk_addr'] = mem2chunk_var.rebased_addr
    mem2chunk = state.solver.BVV(value=config['mem2chunk_offset'], size=proj.arch.bits)
    logger.info("Storing mem2chunk_offset value {} at {}".format(mem2chunk, hex(mem2chunk_var.rebased_addr)))
    state.memory.store(var_dict['mem2chunk_addr'], mem2chunk, proj.arch.bytes, endness='Iend_LE')

    #########################################################
    # Inject symbolic data into memory that can't be resolved
    # this is an automatic way to declare symbolic stuff.
    #########################################################
    var_dict['sdata_addrs'] = []
    var_dict['sdata_vars'] = []
    sdata_var = proj.loader.main_object.get_symbol('sym_data')
    # check if sym_data exists
    if sdata_var:
        for i in range(0, config['sym_data_size'], proj.arch.bytes):
            smem_elem = state.solver.BVS('smem', proj.arch.bits)
            var_dict['sdata_vars'].append(smem_elem)
            logger.info("Storing sym_data value {} at {}".format(smem_elem, hex(sdata_var.rebased_addr + i)))
            state.memory.store(sdata_var.rebased_addr + i, smem_elem, proj.arch.bytes, endness='Iend_LE')
            var_dict['sdata_addrs'].append(sdata_var.rebased_addr + i)

        # create entry in sym_data state storage
        var_dict['sym_data_ptr'] = sdata_var.rebased_addr + config['mem2chunk_offset']
        state.heaphopper.sym_data_states[var_dict['sym_data_ptr']] = None
        # add sym_data_size to heap state
        state.heaphopper.sym_data_size = config['sym_data_size']
        # add global_ptr to global_vars:
        var_dict['global_vars'].append(sdata_var.rebased_addr)

    #########################################################
    # Setup write_target
    #########################################################
    var_dict['wtarget_addrs'] = []
    var_dict['wtarget_vars'] = []
    write_target_var = proj.loader.main_object.get_symbol('write_target')
    
    for i in range(0, write_target_var.size, proj.arch.bytes):
        write_mem_elem = state.solver.BVS('write_mem', proj.arch.bits)
        var_dict['wtarget_vars'].append(write_mem_elem)
        logger.info("Storing write_mem_element value {} at {}".format(write_mem_elem, hex(write_target_var.rebased_addr + i)))
        state.memory.store(write_target_var.rebased_addr + i, write_mem_elem, proj.arch.bytes, endness='Iend_LE')
        var_dict['wtarget_addrs'].append(write_target_var.rebased_addr + i)
        var_dict['global_vars'].append(write_target_var.rebased_addr + i)
    
    #########################################################
    # Set header size
    #########################################################
    header_size_var = proj.loader.main_object.get_symbol('header_size')
    var_dict['header_size_addr'] = header_size_var.rebased_addr
    header_size = state.solver.BVV(value=config['header_size'], size=proj.arch.bits)
    logger.info("Storing header_size value {} at {}".format(header_size, hex(var_dict['header_size_addr'])))
    state.memory.store(var_dict['header_size_addr'], header_size, proj.arch.bytes, endness='Iend_LE')

    #########################################################
    # Set malloc sizes
    #########################################################
    malloc_size_var = proj.loader.main_object.get_symbol('malloc_sizes')
    var_dict['malloc_size_addrs'] = [malloc_size_var.rebased_addr + i for i in range(0, malloc_size_var.size, proj.arch.bytes)]
    print(var_dict['malloc_size_addrs'])
    var_dict['malloc_size_bvs'] = []

    #if max(config['malloc_sizes']) != 0:
    #    bvs_size = int(math.ceil(math.log(max(config['malloc_sizes']), 2))) + 1
    #else:
    #    bvs_size = proj.arch.bytes
    #num_bytes = int(math.ceil(bvs_size / float(state.arch.byte_width)))
    #bit_diff = num_bytes * state.arch.byte_width - bvs_size

    for msize in var_dict['malloc_size_addrs']:
        if len(config['malloc_sizes']) > 1:
            malloc_var = state.solver.BVS('malloc_size', proj.arch.bits)

            # If we have more than one size for malloc we need to put constraints.
            constraint = claripy.Or(malloc_var == config['malloc_sizes'][0])
            for bin_size in config['malloc_sizes'][1:]:
                constraint = claripy.Or(malloc_var == bin_size, constraint)
            state.add_constraints(constraint)

        else:
            malloc_var = state.solver.BVV(config['malloc_sizes'][0], state.arch.bits)
        var_dict['malloc_size_bvs'].append(malloc_var)

        logger.info("Storing malloc_size value {} at {}".format(malloc_var, hex(msize)))
        state.memory.store(msize, claripy.BVV(0, proj.arch.bits), endness='Iend_LE')  # zero-fill first just in case
        state.memory.store(msize, malloc_var, endness='Iend_LE')

    #########################################################
    # Set fill sizes to initialize malloc chunks.
    #########################################################
    fill_size_var = proj.loader.main_object.get_symbol('fill_sizes')
    var_dict['fill_size_addrs'] = [fill_size_var.rebased_addr + i for i in range(0, fill_size_var.size, proj.arch.bytes)]
    var_dict['fill_size_vars'] = []
    if config['chunk_fill_size'] == 'zero':
        var_dict['fill_size_vars'] = [state.solver.BVV(0, proj.arch.bits)] * len(var_dict['fill_size_addrs'])
    if config['chunk_fill_size'] == 'header_size':
        var_dict['fill_size_vars'] = [header_size] * len(var_dict['fill_size_addrs'])
    if config['chunk_fill_size'] == 'chunk_size':
        var_dict['fill_size_vars'] = var_dict['malloc_size_bvs']
    if type(config['chunk_fill_size']) in (int, int):
        var_dict['fill_size_vars'] = [claripy.BVV(config['chunk_fill_size'], proj.arch.bits)] * len(var_dict['fill_size_addrs'])

    for fsize, fill_var in zip(var_dict['fill_size_addrs'], var_dict['fill_size_vars']):
        logger.info("Storing fill_size value {} at {}".format(fill_var, hex(fsize)))
        state.memory.store(fsize, claripy.BVV(0, proj.arch.bits), endness='Iend_LE')  # zero-fill first just in case
        state.memory.store(fsize, fill_var, endness='Iend_LE')

    #########################################################
    # Set overflow sizes. This control the sizes of the
    # injected buffer overflows.
    #########################################################
    overflow_size_var = proj.loader.main_object.get_symbol('overflow_sizes')
    overflow_size_offset = overflow_size_var.rebased_addr
    var_dict['overflow_sizes_addrs'] = [overflow_size_offset + i for i in range(0, overflow_size_var.size, proj.arch.bytes)]

    #if max(config['overflow_sizes']) != 0:
    #    bvs_size = int(math.ceil(math.log(max(config['overflow_sizes']), 2))) + 1
    #else:
    #    bvs_size = proj.arch.bytes
    #num_bytes = int(math.ceil(bvs_size / float(state.arch.byte_width)))
    #bit_diff = num_bytes * state.arch.byte_width - bvs_size

    var_dict['overflow_sizes'] = []
    for overflow_size_addr in var_dict['overflow_sizes_addrs']:
        if len(config['overflow_sizes']) > 1:
            overflow_var = state.solver.BVS('overflow_size', proj.arch.bits)
            constraint = claripy.Or(overflow_var == config['overflow_sizes'][0])
            for bin_size in config['overflow_sizes'][1:]:
                constraint = claripy.Or(overflow_var == bin_size, constraint)
            state.add_constraints(constraint)
        else:
            overflow_var = state.solver.BVV(config['overflow_sizes'][0], state.arch.bits)
        var_dict['overflow_sizes'].append(overflow_var)
        logger.info("Storing overflow_size value {} at {}".format(overflow_var, hex(overflow_size_addr)))
        state.memory.store(overflow_size_addr, overflow_var, endness='Iend_LE')

    #########################################################
    # Get arb_write_offsets
    # Isn't this the write_target?
    #########################################################
    var_dict['arb_offset_vars'] = []
    arb_write_var = proj.loader.main_object.get_symbol('arw_offsets')
    for i in range(0, arb_write_var.size, proj.arch.bytes):
        var_dict['arb_offset_vars'].append(arb_write_var.rebased_addr + i)

    #########################################################
    # Get bf_offsets
    # ?
    #########################################################
    var_dict['bf_offset_vars'] = []
    bf_var = proj.loader.main_object.get_symbol('bf_offsets')
    for i in range(0, bf_var.size, proj.arch.bytes):
        var_dict['bf_offset_vars'].append(bf_var.rebased_addr + i)

    #########################################################
    # Setup malloc unknown symbolic arguments
    #########################################################
    malloc_unk_args = config["malloc_unk_args"]

    if len(malloc_unk_args) != 0:
        malloc_sym_args_matrix = proj.loader.main_object.get_symbol('malloc_sym_args')
        var_dict['malloc_sym_args_matrix'] = [malloc_sym_args_matrix.rebased_addr + i for i in range(0, malloc_sym_args_matrix.size, proj.arch.bytes)]

        # This is the number of malloc we have in the poc
        num_malloc = len(var_dict['malloc_sym_args_matrix']) // len(malloc_unk_args)
        
        # Let's break down, for every malloc, the addresses that correspond to their 
        # symbolic args in the sym_args matrix.
        i = 0
        for malloc_idx in range(0, num_malloc):
            k = "malloc_{}_sym_args_addr".format(malloc_idx)
            num_addrs = len(var_dict['malloc_sym_args_matrix']) // num_malloc 
            var_dict[k] = var_dict['malloc_sym_args_matrix'][i:i+num_addrs]
            i = i + num_addrs
            
            var_dict["malloc_sym_args_vars"] = {}

        # Now it's time to declare symbolic variables and constraint them to 
        # the set of values specified in the config.xml
        for malloc_idx in range(0, num_malloc):
            
            args_addrs = var_dict["malloc_{}_sym_args_addr".format(malloc_idx)]
            
            var_dict["malloc_sym_args_vars"]["malloc_{}".format(malloc_idx)] = []

            for arg_addr, arg_info in zip(args_addrs, malloc_unk_args.items()):
                sym_var_name = 'malloc_{}_sym_{}_addr'.format(malloc_idx, arg_info[0])
                sym_var_arg = state.solver.BVS(sym_var_name, proj.arch.bits)
                var_dict["malloc_sym_args_vars"]["malloc_{}".format(malloc_idx)].append(sym_var_arg)
                
                # Extracting all the values associated to this parameter
                arg_values = arg_info[1]

                # If we have mere than one value for this symbolic arg malloc we need to put constraints.
                constraint = claripy.Or(sym_var_arg == arg_values[0])
                for arg_val in arg_values[1:]:
                    constraint = claripy.Or(sym_var_arg == arg_val, constraint)
                state.add_constraints(constraint)     

                logger.info("Storing {} at {}".format(sym_var_arg, hex(arg_addr)))
                state.memory.store(arg_addr, claripy.BVV(0, proj.arch.bits), endness='Iend_LE')  # zero-fill first just in case
                state.memory.store(arg_addr, sym_var_arg, endness='Iend_LE')


    #########################################################
    # Setup free unknown symbolic arguments
    #########################################################
    free_unk_args = config["free_unk_args"]
    if len(free_unk_args) != 0:
        free_sym_args_matrix = proj.loader.main_object.get_symbol('free_sym_args')
        var_dict['free_sym_args_matrix'] = [free_sym_args_matrix.rebased_addr + i for i in range(0, free_sym_args_matrix.size, proj.arch.bytes)]

        # This is the number of free we have in the poc
        num_free = len(var_dict['free_sym_args_matrix']) // len(free_unk_args)
        
        # Let's break down, for every free, the addresses that correspond to their 
        # symbolic args in the sym_args matrix.
        i = 0
        for free_idx in range(0, num_free):
            k = "free_{}_sym_args_addr".format(free_idx)
            num_addrs = len(var_dict['free_sym_args_matrix']) // num_free 
            var_dict[k] = var_dict['free_sym_args_matrix'][i:i+num_addrs]
            i = i + num_addrs
        
        # Now it's time to declare symbolic variables and constraint them to 
        # the set of values specified in the config.xml
        var_dict["free_sym_args_vars"] = {}
        for free_idx in range(0, num_free):
            args_addrs = var_dict["free_{}_sym_args_addr".format(free_idx)]
            
            var_dict["free_sym_args_vars"]["free_{}".format(free_idx)] = []

            for arg_addr, arg_info in zip(args_addrs, free_unk_args.items()):
                sym_var_name = 'free_{}_sym_{}_addr'.format(free_idx, arg_info[0])
                sym_var_arg = state.solver.BVS(sym_var_name, proj.arch.bits)

                var_dict["free_sym_args_vars"]["free_{}".format(free_idx)].append(sym_var_arg)
                arg_values = arg_info[1]

                # If we have mere than one value for this symbolic arg malloc we need to put constraints.
                constraint = claripy.Or(sym_var_arg == arg_values[0])
                for arg_val in arg_values[1:]:
                    constraint = claripy.Or(sym_var_arg == arg_val, constraint)
                state.add_constraints(constraint) 

                logger.info("Storing {} at {}".format(sym_var_arg, hex(arg_addr)))
                state.memory.store(arg_addr, claripy.BVV(0, proj.arch.bits), endness='Iend_LE')  # zero-fill first just in case
                state.memory.store(arg_addr, sym_var_arg, endness='Iend_LE')

    #########################################################
    # Get winning addr. To understand when to stop the
    # analysis.
    #########################################################
    var_dict['winning_addr'] = proj.loader.main_object.get_symbol('winning').rebased_addr

    return var_dict

class ExplosionDetector(angr.exploration_techniques.ExplorationTechnique):
    def __init__(self, stashes=('active', 'deferred', 'errored', 'cut'), threshold=100):
        super(ExplosionDetector, self).__init__()
        self._stashes = stashes
        self._threshold = threshold
        self.timed_out = Event()
        self.timed_out_bool = False 
        self.max_state_reached = False

    def step(self, simgr, stash='active', **kwargs):
        simgr = simgr.step(stash=stash, **kwargs)
        total = 0
        if len(simgr.unconstrained) > 0:
            logger.debug("Nuking unconstrained")
            #import IPython; IPython.embed()
            simgr.move(from_stash='unconstrained', to_stash='_Drop_unconstrained', filter_func=lambda _: True)
            #for st in self._stashes:
            #    simgr.move(from_stash=st, to_stash='_Drop', filter_func=lambda _: True)
            #    return simgr
        if self.timed_out.is_set():
            logger.critical("Timed out, %d states: %s" % (total, str(simgr)))
            self.timed_out_bool = True
            for st in self._stashes:
                if hasattr(simgr, st):
                    simgr.move(from_stash=st, to_stash='_Drop_timeout', filter_func=lambda _: True)
        for st in self._stashes:
            if hasattr(simgr, st):
                total += len(getattr(simgr, st))

        if total >= self._threshold:
            logger.critical("State explosion detected, over %d states: %s" % (total, str(simgr)))
            for st in self._stashes:
                if hasattr(simgr, st):
                    simgr.move(from_stash=st, to_stash='_Drop_state_explosion', filter_func=lambda _: True)
        return simgr




def trace(config_name, binary_name):
    # Some timing.
    exp_start_time = time.time()
    
    # Get config
    logger.warning("Config at {}".format(config_name))
    config = parse_config(config_name)

    # Set logging
    logger.info('Searching for vulns')
    logging.basicConfig()
    angr.manager.l.setLevel(config['log_level'])
    angr.exploration_techniques.spiller.l.setLevel(config['log_level'])
    cle.loader.l.setLevel(config['log_level'])
    logger.setLevel(config['log_level'])

    # The "libc" is the blob-as-a-lib
    libc_path = os.path.expanduser(config['libc'])
    libc_name = os.path.basename(libc_path)

    # The allocators funcs are in the blob-as-a-lib
    allocator_path = os.path.expanduser(config['allocator'])
    allocator_name = os.path.basename(allocator_path)

    # The heapster state
    hb_state_file = config["hb_state"]
    if os.path.exists(hb_state_file) and os.path.isfile(hb_state_file):
        with open(hb_state_file, "r") as hb_file:
            hb_state = json.load(hb_file)
    else:
        logger.fatal("Couldn't find the heapster state at {}! Aborting.".format(hb_state_file))
        sys.exit(-1)

    # The blob-project
    blob_proj_file_path =  hb_state['blob_project']
    
    hh_log_name = config['hb_logfile']
    hh_log = open(hh_log_name, 'a')

    logger.fatal("Loading project file at {}".format(blob_proj_file_path))
    if os.path.isfile(blob_proj_file_path):
        with open(blob_proj_file_path, "rb") as blob_proj_file:
            blob_proj = pickle.load(blob_proj_file)
    else:
        logger.fatal("Can't load blob project file, aborting.")
        sys.exit(-1)

    blob_bin_cfg = blob_proj.cfg
    mem_dump_path = hb_state["final_allocator"]["mem_dump_path"]

    # Creating main project of the POC to trace.
    # POC must be loaded with the same arch as the blob.
    
    # These 2 objects must be there if we correctly
    # created the blob project.
    ram_object = None
    mmio_object = None
    
    for obj in blob_proj.loader.all_objects:
        if "ram" in obj.binary_basename:
            ram_object = obj
        elif "mmio" in obj.binary_basename:
            mmio_object = obj
    
    assert(ram_object)
    assert(mmio_object)

    proj = angr.Project(binary_name, load_options={
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

    blob_sp_pointer = hb_state["blob_stack_pointer"]
    #logger.info("[+]Setting stack pointer at {}".format(blob_sp_pointer))
    proj.arch.initial_sp = int(blob_sp_pointer,16)
    logger.info("[+]PoC and Blob loaded inside HeapHopper")
    logger.info("[+] PoC Entry Point at [{}]".format(hex(proj.entry)))
    logger.info("[+] PoC Arch [{}]".format(proj.arch.name))
    logger.info("[+] PoC Initial Stack Pointer [{}]".format(hex(proj.arch.initial_sp)))

    logger.info("[+] PoC Regions:")
    for o_idx, o in enumerate(proj.loader.all_objects):
        logger.info("[+]  Region {}: {}".format(o_idx,o))

    # Find write_target
    write_target_var = proj.loader.main_object.get_symbol('write_target')
    # Get libc.
    libc = proj.loader.shared_objects[libc_name]
    # Get allocator.
    allocator = proj.loader.shared_objects[allocator_name]

    ###########################################################
    # Preparing the state options for heaphopper.
    ###########################################################
    added_options = set()
    # Maintain a mapping from symbolic variable name to which addresses it is present in.
    added_options.add(angr.options.REVERSE_MEMORY_NAME_MAP)
    # Make the value of memory read from an uninitialized address zero instead of an unconstrained symbol
    added_options.add(angr.options.ZERO_FILL_UNCONSTRAINED_MEMORY)
    # Return 0 any unspecified bytes in registers
    added_options.add(angr.options.ZERO_FILL_UNCONSTRAINED_REGISTERS)

    # Debug only.
    #added_options.add(angr.options.TRACK_MEMORY_ACTIONS)
    #added_options.add(angr.options.CONSTRAINT_TRACKING_IN_SOLVER)

    # Value-Set analysys stuff.
    if config['use_vsa']:
        added_options.add(angr.options.APPROXIMATE_SATISFIABILITY)  # vsa for satisfiability
        added_options.add(angr.options.APPROXIMATE_GUARDS)          # vsa for guards
        added_options.add(angr.options.APPROXIMATE_MEMORY_SIZES)    # vsa for mem_sizes
        added_options.add(angr.options.APPROXIMATE_MEMORY_INDICES)  # vsa for mem_indices

    # Simplifications are causing troubles, need to disable them.
    removed_options = set()
    removed_options.add(angr.options.SIMPLIFY_MEMORY_WRITES)
    removed_options.add(angr.options.SIMPLIFY_REGISTER_WRITES)
    removed_options.add(angr.options.SIMPLIFY_EXPRS)
    removed_options.add(angr.options.SIMPLIFY_MEMORY_READS)
    removed_options.add(angr.options.SIMPLIFY_REGISTER_READS)
    removed_options.add(angr.options.SIMPLIFY_REGISTER_WRITES)
    removed_options.add(angr.options.SIMPLIFY_CONSTRAINTS)

    # Here we should have an initialized state!
    # Now preparing it for HeapHopper.
    state = proj.factory.entry_state(add_options=added_options, remove_options=removed_options)

    state = init_memory_with_blob_mem(proj, state, hb_state, mem_dump_path)
    state.register_plugin('heaphopper', HeapConditionTracker(config=config,
                                                             wtarget=(write_target_var.rebased_addr,
                                                                      write_target_var.size),
                                                             libc=libc,
                                                             allocator=allocator,
                                                             malloc_prototype=config["malloc_prototype"],
                                                             free_prototype=config["free_prototype"],
                                                             heap_grows=hb_state["heap_grow_direction"]
                                                             ))

    heap_base = hb_state["heap_base"]
    logger.info("Heap base address is at {}".format(hex(heap_base)))
    state.heap.heap_base = heap_base
    state.heaphopper.set_level(config['log_level'])

    ###################################################################
    # Setup the state we are going to analyze
    # This is filling the placeholders vars in the generated zoo's POC.
    ###################################################################
    var_dict = setup_state(state, proj, config)

    # Set READS memory concretization strategies.
    state.memory.read_strategies = [
        #Concretization strategy that resolves an address into some limited number of solutions.
        angr.state_plugins.symbolic_memory.concretization_strategies.SimConcretizationStrategySolutions(config['read_concr_ss_sols']), 
        # Concretization strategy that constraints the address to controlled data.
        # Controlled data consists of symbolic data and the addresses given as arguments. memory.
        angr.state_plugins.symbolic_memory.concretization_strategies.SimConcretizationStrategyControlledData(config['read_concr_sc_sols'],
                                                                                                             var_dict[
                                                                                                               'global_vars']),
        # Concretization strategy that resolves an address into some limited number of solutions.
        # Always handles the concretization, but only returns a maximum of limit number of solutions.
        # Therefore, should only be used as the fallback strategy.
        angr.state_plugins.symbolic_memory.concretization_strategies.SimConcretizationStrategyEval(config['read_concr_se_sols'])
    ]

    # Set WRITES memory concretization strategies (See above for comments)
    state.memory.write_strategies = [
        angr.state_plugins.symbolic_memory.concretization_strategies.SimConcretizationStrategySolutions(config['write_concr_ss_sols']),
        angr.state_plugins.symbolic_memory.concretization_strategies.SimConcretizationStrategyControlledData(config['write_concr_sc_sols'],
                                                                                                             var_dict[
                                                                                                                 'global_vars']),
        angr.state_plugins.symbolic_memory.concretization_strategies.SimConcretizationStrategyEval(config['write_concr_se_sols'])
    ]

    ###################################################################
    # Hook malloc and free with the functions in the "blob-as-a-lib"
    # Basically the beginning of malloc/free are hooked with the malloc
    # free implementations inside the blob.
    ###################################################################

    # Address of malloc in the blob
    malloc_addr = config['malloc_addr']

    # Address of free in the blob
    free_addr = config['free_addr']

    # Hook malloc and free with implementations inside the blob and the myread
    # with a SimProc.
    malloc_main_bin = proj.loader.main_object.get_symbol('malloc').rebased_addr
    free_main_bin = proj.loader.main_object.get_symbol('free').rebased_addr
    myread_main_bin = proj.loader.main_object.get_symbol('myread').rebased_addr

    # Install SimProcedure used to inspect malloc/free before runnung them.
    # vulns is the array of vulnerability we are looking for.
    proj.hook(addr=malloc_main_bin,
              hook=MallocInspect(malloc_addr=malloc_addr, vulns=config['vulns'], ctrl_data=var_dict['allocs']))
    proj.hook(addr=free_main_bin,
              hook=FreeInspect(free_addr=free_addr, vulns=config['vulns'], sym_data=var_dict['sdata_addrs']))
    proj.hook(addr=myread_main_bin, hook=read())

    # Hook the skip() SimProc as detected by fix_hml.
    if hb_state.get("malloc_to_hook_funcs", None):
        malloc_hook_funcs = hb_state["malloc_to_hook_funcs"]
        for h in malloc_hook_funcs:
            logger.info("Plugging malloc hooks to project")
            proj.hook(addr=h, hook=skip())

    if hb_state.get("free_to_hook_funcs", None):
        free_hook_funcs = hb_state["free_to_hook_funcs"]
        for h in free_hook_funcs:
            logger.info("Plugging free hook at {} to project".format(hex(h)))
            proj.hook(addr=h, hook=skip())

    found_paths = []

    ##################################################################
    # Configure simgr for exploration!
    ##################################################################
    sm = proj.factory.simgr(thing=state)

    # ET that stops at the first vuln that we found.
    sm.use_technique(VulnChecker(config['mem_corruption_fd'], config['input_pre_constraint'], config['input_values'],
                                 config['stop_found'], config['filter_fake_frees']))

    # Some advanced configuration of the exploration technique.
    if config['use_mem_limiter']:
        # Just for safety
        sm.use_technique(MemLimiter(config['mem_limit'], config['drop_errored']))
    if config['use_dfs']:
        sm.use_technique(angr.exploration_techniques.DFS())
    if config['use_veritesting']:
        sm.use_technique(angr.exploration_techniques.Veritesting())
    if config['use_concretizer']:
        concr_addrs = var_dict['malloc_size_addrs'] + var_dict['allocs']
        sm.use_technique(Concretizer(concr_addrs))
    if config['spiller']:
        if config['dfs']:
            src_stash = 'deferred'
        else:
            src_stash = 'active'
        spill_conf = config['spiller_conf']
        ana_setup()
        spiller = angr.exploration_techniques.Spiller(
            src_stash=src_stash, min=spill_conf['min'], max=spill_conf['max'],
            staging_min=spill_conf['staging_min'], staging_max=spill_conf['staging_max'],
            priority_key=priority_key
        )
        sm.use_technique(spiller)
    if config['loopseer']:
        max_cycle = config['loopser_max_iterations'] # HACK: this is mostly to avoid infinite loops in assertions!
        # This can be improved by just focusing on the functions of interest (malloc/free and descendants)
        loopseer = angr.exploration_techniques.LoopSeer(blob_bin_cfg, bound=max_cycle, discard_stash="hangs")
        sm.use_technique(loopseer)
    if config['timeout']:
        max_states = config['max_states']
        ed = ExplosionDetector(threshold=max_states)
       
        # Defining the handle for the timeout
        def timeout():
            logger.warning("TIMEOUT")
            ed.timed_out.set()
            ed.timed_out_bool = True
            
        exploration_timer = Timer(config['max_sec'], timeout)
        sm.use_technique(ed)

    avoids = []
    sm.use_technique(angr.exploration_techniques.Explorer(find=(var_dict['winning_addr'],), avoid=avoids))

    # Create fd for memory corruption input
    name = b'memory_corruption'
    path = b'/tmp/%s' % name
    mem_corr_fd = config['mem_corruption_fd']

    f = SimFile(name, writable=False)
    f.set_state(state)
    state.fs.insert(path, f)
    real_fd = state.posix.open(path, flags=Flags.O_RDONLY, preferred_fd=mem_corr_fd)
    if mem_corr_fd != real_fd:
        raise Exception("Overflow fd already exists.")

    # constrain input
    if config['input_pre_constraint']:
        if 'overflow' in config['zoo_actions']:
            overflow_bytes = config['zoo_actions']['overflow'] * max(config['overflow_sizes'])
        else:
            overflow_bytes = 0

        if 'uaf' in config['zoo_actions']:
            uaf_bytes = config['zoo_actions']['uaf'] * config['header_size']
        else:
            uaf_bytes = 0

        if 'arb_relative_write' in config['zoo_actions']:
            arw_bytes = config['zoo_actions']['arb_relative'] * state.arch.byte_width * 2
        else:
            arw_bytes = 0

        num_bytes = overflow_bytes + uaf_bytes + arw_bytes
        input_bytes = state.posix.fd[mem_corr_fd].read_data(num_bytes)[0].chop(8)
        state.posix.fd[mem_corr_fd].seek(0)
        constrain_input(state, input_bytes, config['input_values'])

    logger.info("[+] State is configured. Ready to execute.")

    if config['timeout']:
        logger.info("[+] Starting HeapHopper with timeout [{}] secs".format(config['max_sec']))
        exploration_timer.start()
    
    sm.use_technique(SkipSVC())
    hh_exxecutor = HHExecutor()
    sm.use_technique(hh_exxecutor)
    #simgrviz = HHSimgrViz(hb_state=hb_state)
    #sm.use_technique(simgrviz)
    #sm.use_technique(HeartBeat(beat_interval=1))
    
    tracing_start_time = time.time()

    stop = False 
    while len(sm.active) > 0 and not stop:
        sm.step()
    
    logger.info("[+] HeapHopper terminated!")

    if config['timeout']:
        exploration_timer.cancel()
    
    if ed.timed_out_bool:
        hh_log.write("{} -> Reached a Timeout \n".format(binary_name))

    # All the found states that reached the winning function and are marked as 
    # vulnerable by heaphopper are moved to the vuln stash.
    sm.move(from_stash='found', to_stash='vuln', filter_func=lambda p: p.heaphopper.vulnerable)
    found_paths.extend(sm.vuln)

    if config['spiller']:
        ana_teardown()

    # Inside 'found_paths' I have all the paths that have reached the
    # winning address
    for path in found_paths:
        # The win_addr is the address where we have detected the vuln,
        # this has nothing to do with the winning function.
        win_addr, heap_func = get_win_addr(proj, path.history.bbl_addrs.hardcopy)
        win_addr = path.project.factory.block(win_addr).instruction_addrs[-1] # the win addr is the last address of the last basic_block.

        path.heaphopper.win_addr = win_addr
        # Collect the last line executed in the source file befre detecting
        # the vulnerability.
        if proj.loader.main_object.pic:
            win_addr = win_addr - proj.loader.main_object.min_addr
        last_line = get_last_line(win_addr, binary_name)
        path.heaphopper.last_line = last_line
        # Collect info of the location of the arbitrary write detected in
        # the heap implementation.
        if path.heaphopper.arb_write_info:
            path.heaphopper.arb_write_info['instr'] = proj.loader.find_object(allocator_name).addr_to_offset(
                path.heaphopper.arb_write_info['instr'])

    logger.info('Found {} vulns'.format(len(found_paths)))
    
    if len(found_paths) == 0:
        hh_log.write("{} -> No Vuln. These are the errored state:\n".format(binary_name))
        for err_state in sm.errored:
            logger.info(err_state)
            hh_log.write(str(err_state) + "\n")

    if len(found_paths) == 0:
        logger.info("These are the errored state:")
        for err_state in sm.errored:
            logger.info(err_state)

    print("END-METADATA-EXPERIMENTS") # HACK, will remove, just to parse the output.
    
    # If we have results let's save the report.
    if len(found_paths) > 0:
        print(found_paths)
        try:
            arb_writes = store_results(proj, config['num_results'], binary_name, found_paths, var_dict,
                                    config['mem_corruption_fd'])
        except Exception:
            print("Fatal error during store results")
            return 0
        if config['store_desc']:
            store_vuln_descs(proj, binary_name, found_paths, var_dict, arb_writes)
        
        hh_log.write("{} -> Found {} vulns | Vuln: {}\n".format(binary_name, len(found_paths), path.heaphopper.vuln_type))

        # This print is only useful to catch output from the heapster_exp_client, will remove it.
        print("FOUND-VULN: {}".format(path.heaphopper.vuln_type))
    
    # Need to log some stuff here 
    if "_Drop_unconstrained" in sm.stashes:
        hh_log.write("Simgr with {} _Drop_uncostrained\n".format(len(sm.stashes["_Drop_unconstrained"])))
        print("ERROR-TRACING: " + "_Drop_uncostrained\n")
    elif "_Drop_timeout" in sm.stashes:
        hh_log.write("Simgr with {} _Drop_timeout\n".format(len(sm.stashes["_Drop_timeout"])))
        print("ERROR-TRACING: " + "_Drop_timeout\n")
    elif "_Drop_state_explosion" in sm.stashes:
        hh_log.write("Simgr with {} _Drop_state_explosion\n".format(len(sm.stashes["_Drop_state_explosion"])))
        print("ERROR-TRACING: " + "_Drop_state_explosion\n")
    elif "out_of_memory" in sm.stashes:
        hh_log.write("Simgr with {} out_of_memory\n".format(len(sm.stashes["out_of_memory"])))
        print("ERROR-TRACING: " + "out_of_memory\n")
    elif len(sm.stashes["hangs"]) > 0:
        hh_log.write("Simgr with {} was spinning\n".format(len(sm.stashes["hangs"])))
        print("ERROR-TRACING: " + "hangs\n")

    now = time.time()
    hh_log.write("POC tracing total time {}\n".format(now - tracing_start_time))
    hh_log.write("Experiment total time {}\n".format(now - exp_start_time))
    
    print("POC-TRACING-TOTAL-TIME: {}\n".format(now - tracing_start_time))
    print("EXPERIMENT-TOTAL-TIME: {}\n".format(now - exp_start_time))
    
    hh_log.close()

    return 0

def store_vuln_descs(proj, desc_file, states, var_dict, arb_writes):
    global DESC_HEADER, DESC_SECTION_LINE

    logger.info('Creating vuln descriptions: {}-desc.yaml'.format(desc_file))
    

    # This file must be provided to HeapHopper when we start it.
    with open('{}.desc'.format(os.path.dirname(desc_file) + "/"+ os.path.basename(desc_file).replace(".bin","")), 'r') as f:
        bin_info = yaml.load(f, Loader=yaml.SafeLoader)
    '''
    bin_info['allocs'] -> list of (dst_symbol, size_symbol)
    bin_info['frees'] -> list of (dst_symbol)
    bin_info['reads'] -> list of (dst_symbol, size_symbol)
    bin_info['overflows'] -> list of (src_symbol, dst_symbol, size_symbol)
    bin_info['fake_frees'] -> list of fake_chunk_ptrs
    bin_info['double_frees'] -> list of double_frees
    bin_info['arb_relative_writes'] -> list of arb_relative_writes
    bin_info['single_bitflips'] -> list of single_bitflips
    bin_info['uafs'] -> list of use-after_frees
    '''
    descs = []
    for state_num, state in enumerate(states):
        desc = []
        desc.append('{} {}'.format(DESC_HEADER, desc_file))
        desc.append('CONSTRAINTS:')
        desc.append(DESC_SECTION_LINE)
        desc.append('\t- {} allocations:'.format(len(bin_info['allocs'])))
        # show mallocs:
        for msize, minfo in zip(var_dict['malloc_size_addrs'], bin_info['allocs']):
            size_val = state.solver.min(state.memory.load(msize, proj.arch.bytes, endness='Iend_LE'))
            desc.append('\t\t* {} byte allocation to {}'.format(size_val, minfo[0]))
        # show frees
        desc.append('\t- {} frees:'.format(len(bin_info['frees'])))
        for free in bin_info['frees']:
            desc.append('\t\t* free of {}'.format(free))
        # show overflows
        desc.append('\t- {} overflows:'.format(len(bin_info['overflows'])))
        for of, of_size in zip(bin_info['overflows'], var_dict['overflow_sizes_addrs']):
            size_val = state.solver.min(state.memory.load(of_size, proj.arch.bytes, endness='Iend_LE'))
            desc.append('\t\t* {} byte overflow from {} into {}'.format(size_val, of[0], of[1]))
        # show bad frees
        desc.append('\t- {} bad_frees:'.format(len(bin_info['fake_frees'])))
        for fake_free in bin_info['fake_frees']:
            desc.append('\t\t* free of fake_chunk {}'.format(fake_free))
        if state.heaphopper.double_free:
            desc.append('\t- {} double free(s)'.format(len(state.heaphopper.double_free)))
        # show arbitrary relative writes
        desc.append('\t- {} arb_relative_writes:'.format(len(bin_info['arb_relative_writes'])))
        for dst, offset in bin_info['arb_relative_writes']:
            desc.append('\t\t* arbitrary relative write to {} at offset {}'.format(dst, offset))
        # show single bitflips
        desc.append('\t- {} single_bitflips:'.format(len(bin_info['single_bitflips'])))
        for dst, offset, bit in bin_info['single_bitflips']:
            desc.append('\t\t* single bitflip to {} at offset {} on bit {}'.format(dst, offset, bit))
        # show single bitflips
        desc.append('\t- {} uafs:'.format(len(bin_info['uafs'])))
        for dst, size in bin_info['uafs']:
            desc.append('\t\t* use-after-free of {} with size of {}'.format(dst, size))
        # check controlled_data
        desc.append('\t- controlled_data:')
        stdin_bytes = all_bytes(state.posix.fd[0].read_storage)
        if stdin_bytes:
            stdin_bytes = [b[0] for b in stdin_bytes]
            stdin = stdin_bytes[0]
            for b in stdin_bytes[1:]:
                stdin = stdin.concat(b)
        constraint_vars = [list(c.variables) for c in state.solver.constraints]
        i = 0
        for read, fill_size in zip(bin_info['reads'], var_dict['fill_size_vars']):
            sol = state.solver.min(fill_size)
            for j in range(0, sol, proj.arch.bytes):
                i += j
                # We should never end up here if stdin doesn't exist
                curr_input = stdin.reversed[i + 7:i]
                input_vars = list(curr_input.variables)
                for input_var in input_vars:
                    if input_var in constraint_vars:
                        desc.append('\t\t* 8 byte of controlled data in the heap @ {}+{}'.format(read[0], i))

        desc.append('\t- symbolic_data:')
        for sdata in var_dict['sdata_addrs']:
            mem = state.memory.load(sdata, proj.arch.bytes, endness='Iend_LE')
            mem_vars = list(mem.variables)
            for mem_var in mem_vars:
                if mem_var in constraint_vars:
                    desc.append('\t\t* 8 byte of symbolic data in the bss @ {}'.format(sdata))

        desc.append('\n\nRESULT:')
        desc.append(DESC_SECTION_LINE)
        if state.heaphopper.vuln_type == 'malloc_non_heap':
            desc.append('\t- malloc returns a pointer to non-heap segment')
        if state.heaphopper.vuln_type == 'malloc_allocated':
            desc.append('\t- malloc returns a pointer to an already allocated heap region')
            # IPython.embed()
        if state.heaphopper.stack_trace:
            desc.append('\t- arbitrary write stack_trace:')
            for idx, addr in enumerate(state.heaphopper.stack_trace):
                desc.append('\t\t[{}] {}'.format(idx, hex(addr)))

        if state.heaphopper.vuln_type == 'arbitrary_write_malloc':
            desc.append('\t- arbitrary write in malloc')
            for idx, arb_write in enumerate(arb_writes[state_num]):
                desc.append(
                    '\t\t{0:d}: Instr: 0x{1:x}; TargetAddr: 0x{2:x}; Val: 0x{3:x}'.format(idx,
                                                                                          arb_write['instr'] & 0xffffff,
                                                                                          arb_write['addr'],
                                                                                          arb_write['val']))
        if state.heaphopper.vuln_type == 'restricted_write_malloc':
            desc.append('\t- restricted write in malloc')
            for idx, arb_write in enumerate(arb_writes[state_num]):
                desc.append(
                    '\t\t{0:d}: Instr: 0x{1:x}; TargetAddr: 0x{2:x}; Val: 0x{3:x}'.format(idx,
                                                                                          arb_write['instr'] & 0xffffff,
                                                                                          arb_write['addr'],
                                                                                          arb_write['val']))

        if state.heaphopper.vuln_type == 'arbitrary_write_free':
            desc.append('\t- arbitrary write in free:')
            for idx, arb_write in enumerate(arb_writes[state_num]):
                desc.append(
                    '\t\t{0:d}: Instr: 0x{1:x}; TargetAddr: 0x{2:x}; Val: 0x{3:x}'.format(idx,
                                                                                          arb_write['instr'] & 0xffffff,
                                                                                          arb_write['addr'],
                                                                                          arb_write['val']))

        if state.heaphopper.vuln_type == 'restricted_write_free':
            desc.append('\t- restricted write in free:')
            for idx, arb_write in enumerate(arb_writes[state_num]):
                desc.append(
                    '\t\t{0:d}: Instr: 0x{1:x}; TargetAddr: 0x{2:x}; Val: 0x{3:x}'.format(idx,
                                                                                          arb_write['instr'] & 0xffffff,
                                                                                          arb_write['addr'],
                                                                                          arb_write['val']))
        descs.append('\n'.join(desc))

        if "_write_" in state.heaphopper.vuln_type:
            desc.append('\t- metadata arbitrary write info:')
            seen_keys = ["instr", "addr",  "val"]
            for k,v in state.heaphopper.arb_write_info.items():
                if k not in seen_keys:
                    desc.append("\t\t {}: {}\n".format(k, v))

    desc_dict = {'file': desc_file, 'text': descs}
    with open("{}-desc.yaml".format(desc_file), 'w') as f:
        yaml.dump(desc_dict, f)


#  This method stores the results as yaml-file
#
# :proj is the project object.
# :states is a list of vulnerable states found by the analysis.
# :bin_file is the binary's name.
# :var_dict is the dict returned by the setup_state (with all the info regarding globals and stuff).
# :fd is the memory corruption file descriptor (usually 3).
#
def store_results(proj, num_results, bin_file, states, var_dict, fd):
    logger.info('Storing result infos to: {}-result.yaml'.format(bin_file))
    results = []
    arbitrary_writes = []

    # For every vulnerable state
    for i, state in enumerate(states):
        result = dict()
        result['file'] = bin_file
        result['path_id'] = i
        result['input_opts'] = []
        result['stdin_opts'] = []
        result['symbolic_data'] = []
        result['malloc_sizes'] = []
        result['fill_sizes'] = []
        result['header_sizes'] = []
        result['overflow_sizes'] = []
        result['write_targets'] = []
        result['mem2chunk_offset'] = state.solver.eval(state.memory.load(var_dict['mem2chunk_addr'], proj.arch.bytes,
                                                                                   endness='Iend_LE'))
        result['stack_trace'] = state.heaphopper.stack_trace
        result['last_line'] = state.heaphopper.last_line
        result['heap_base'] = state.heap.heap_base
        result['allocs'] = []
        result['arb_write_offsets'] = []
        result['bf_offsets'] = []
        result['vuln_type'] = state.heaphopper.vuln_type
        result['malloc_sym_args'] = [] 
        result['free_sym_args'] = []

        arbitrary_write = []
        
        processed_state = process_state(proj, num_results, state, state.heaphopper.vuln_state, var_dict, fd)

        for input_opt, stdin_opt, svars, header, msizes, fsizes, osizes, wtargets, allocs, arb_offsets, bf_offsets, arb_write, malloc_sym_args, free_sym_args in processed_state:
            result['input_opts'].append(input_opt)
            result['stdin_opts'].append(stdin_opt)
            result['symbolic_data'].append(svars)
            result['header_sizes'].append(header)
            result['malloc_sizes'].append(msizes)
            result['fill_sizes'].append(fsizes)
            result['overflow_sizes'].append(osizes)
            result['write_targets'].append(wtargets)
            result['allocs'].append(allocs)
            result['arb_write_offsets'].append(arb_offsets)
            result['bf_offsets'].append(bf_offsets)
            result['malloc_sym_args'].append(malloc_sym_args)
            result['free_sym_args'].append(free_sym_args)
            arbitrary_write.append(arb_write)
        results.append(result)
        arbitrary_writes.append(arbitrary_write)

    with open("{}-result.yaml".format(bin_file), 'w') as f:
        yaml.dump(results, f)

    return arbitrary_writes

