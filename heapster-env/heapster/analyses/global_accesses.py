
import angr
import logging

from angr.engines.light import SpOffset
from ..utils import *

l = logging.getLogger("heapster.analyses.global_accesses")
#l.setLevel(logging.DEBUG)

class MemoryOp():
    def __init__(self, machine_ins_addr=None, memop_type='', block_id=0, stmt_id=0, target=''):
        self.memop_type = memop_type  # this is "load" or "store"
        self.machine_ins_addr = machine_ins_addr
        self.block_id = block_id
        self.stmt_id = stmt_id

    def __str__(self):
        return "MemoryOp | type:{} | machine_ins_addr:{} |  block_id:{} | stmt_id:{} ".format(self.memop_type, hex(self.machine_ins_addr),
                                                                                              self.block_id, self.stmt_id)

'''
Get all the accesses to global variables
performed by a specific function.
This leverages the analysis GlobalAccessesAnalyzer.
:filter_writes: discard writes to global vars.
:not-filter_writes: keep also write accesses to global vars. 
:full: returns the dictionary containing all the info.
:not-full: return only the destination of a read/writes. 
'''
def get_globals_accesses(project, func, filter_writes=True, full=False):
    # Get globals accesses to variables
    globalAccessAnalyzer = GlobalAccessesAnalyzer(project, project.cfg.functions.get_by_addr(func), filter_writes=filter_writes)
    globalAccessAnalyzer.run()
    if not full:
        global_reads_accesses = globalAccessAnalyzer.mem_data_accesses
    else:
        global_reads_accesses = globalAccessAnalyzer.mem_data_accesses_full
    return global_reads_accesses

class GlobalAccessesAnalyzer():

    def __init__(self, project, target_func, filter_writes=True):
        self.project = project
        self.bin_cfg = project.cfg
        self.target_func = target_func
        self.mem_data_accesses_dict = {}
        self.mem_data_accesses = set()
        self.mem_data_accesses_full = set()
        self.filter_writes = filter_writes

    def _is_in_current_func_code(self, addr):
        if self.target_func.addr_to_instruction_addr(addr):
            return True
        else:
            return False

    def _is_ignored_offset(self, addr):
        if addr >= 0x0 and addr <= 0x100:
            return True 
        return False 

    def _filter_access(self, data_access):
        # We are only interested in reads over absolute addresses, filter the rest.
        if self.filter_writes and data_access.type_string == "write":
            return True
        # We don't want accesses to the stack, only reads to global variables to integer constants.
        elif type(data_access.dst) == SpOffset or type(data_access.dst) != int:
            return True
        if data_access.type_string == "offset" and self._is_ignored_offset(data_access.dst):
            return True 
        # We don't want accesses at the code of the current func.
        elif self._is_in_current_func_code(data_access.dst):
            return True
        else:
            return False
            
    def run(self):
        for block_original in self.target_func.blocks:
            func_target_cfg_node = self.bin_cfg.get_any_node(block_original.addr)
            if func_target_cfg_node:
                self.mem_data_accesses_dict[block_original.addr] = set()
                for data_access in func_target_cfg_node.get_data_references():
                    if not self._filter_access(data_access):
                        self.mem_data_accesses_dict[block_original.addr].add(data_access.dst)
                        self.mem_data_accesses.add(data_access.dst)
                        self.mem_data_accesses_full.add(data_access)
                    else:
                        continue
