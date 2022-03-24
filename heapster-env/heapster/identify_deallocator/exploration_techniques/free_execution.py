# pylint: disable=import-error, no-name-in-module
import angr
import hashlib
import os
import logging
import networkx
import time
import copy

from typing import List, Set, Dict, Tuple, Optional
from angr.exploration_techniques import ExplorationTechnique
from angr import SimState
from networkx.drawing.nx_agraph import write_dot
from threading import Event, Timer

l = logging.getLogger("FreeExecution")
l.setLevel(logging.CRITICAL)

global CURR_SIMGR
global CURR_PROJ
global CURR_STATE

# Find all the infinite loop.
def fast_infinite_loop_finder(p, func):
    la = p.analyses.LoopFinder(functions=[func])
    bad_loops = []
    for loop in la.loops:
        if not loop.break_edges:
            for node in loop.graph.nodes():
                if not isinstance(node, angr.codenode.BlockNode):
                    continue
                bad_loops.append(node.addr)
    return bad_loops

END_EXECUTION_RETURNS  = "END_EXECUTION_RETURNS"
END_EXECUTION_CALLOUT  = "END_EXECUTION_CALLOUT"
END_EXECUTION_BAD_LOOP = "END_EXECUTION_BAD_LOOP"
END_EXECUTION_SYMBOLIC_WRITES  = "END_EXECUTION_SYMBOLIC_WRITES"
END_EXECUTION_PS_ADDR = "END_EXECUTION_PS_ADDR"
END_EXECUTION_TIMEOUT = "END_EXECUTION_TIMEOUT"
END_EXECUTION_OUT_OF_ROM = "END_EXECUTION_OUT_OF_ROM"
END_EXECUTION_NO_MORE_ACTIVE = "END_EXECUTION_NO_MORE_ACTIVE"
END_EXECUTION_SVC_UNSUPPORTED = "END_EXECUTION_SVC_UNSUPPORTED"
END_EXECUTION_DECODING_ERROR = "END_EXECUTION_DECODING_ERROR"

class FreeExecution(ExplorationTechnique):

    def __init__(self):
        super(FreeExecution, self).__init__()

        self.end_execution = False
        # This is a tuple with reason and additional info depending 
        # on the reason why we terminate.
        self.end_execution_reason = None

        # Last state reached before the end of execution of this DSE.
        self.last_state = None

        # The callout sites of the target function.
        # block nodes at whose ends the function calls out to another non-returning function
        # If we hit that function, we assume we are jumping to main.
        self.callout_sites_addresses = []
        
        # Infinite loops locations.
        self.bad_loops = []

    def setup(self, simgr):
        init_state = simgr.active[0]
        func = init_state.project.kb.functions[init_state.addr]
        # Grab callout sites 
        self.callout_sites_addresses = [x.addr for x in func.callout_sites]
        # Grab infinite Loops
        self.bad_loops = fast_infinite_loop_finder(init_state.project,func)

        return True

    def check_end_of_function(self, state):
        if state.addr == 0xdeadbeef or state.addr == 0x0:
            # Did we reach the end, if yes, let's stop.
            # WHY:
            # Everything is concrete in this state, so we assume the first
            # state that reaches the end is equivalent to the concrete execution.
            # (There are imprecision of course, but it's the best we can do).
            l.debug("[+] Reached address 0xdeadbeef")
            self.end_execution = True
            self.last_state = state.copy()
            self.end_execution_reason = (END_EXECUTION_RETURNS, state.addr)
            return True
        else:
            return False

    def successors(self, simgr, state:SimState, **kwargs):
        
        l.debug("[+] State at {}".format(state))
        
        # Checkpoint
        self.last_state = state 
        self.check_end_of_function(state)

        succs = simgr.successors(state, **kwargs)

        if succs == None or len(succs.flat_successors) == 0:
            l.debug("[+]   Succs is None. Returning.")
            self.end_execution = True
            self.last_state = state.copy()
            self.end_execution_reason = (END_EXECUTION_NO_MORE_ACTIVE, state.addr)
            return succs


        if state.globals.get("svc_found", False):
            l.debug("[+]   SVC unsupported found. Returning.")
            self.end_execution = True
            self.last_state = state.copy()
            self.end_execution_reason = (END_EXECUTION_SVC_UNSUPPORTED, state.addr)
            succs.flat_successors = []
            succs.successors = []
            return succs

        for ss in succs.flat_successors:
            
            if self.check_end_of_function(ss):
                break

            exec_where = ss.project.loader.find_object_containing(ss.addr)
            if exec_where is None or "ram" in exec_where.binary_basename:
                try:
                    l.debug("[!]    Detected execution out of ROM. Returning immediately to caller [{}]".format(hex(ss.solver.eval(ss.regs.lr))))
                    ss.globals['out_of_rom'] = True
                except Exception as e:
                    l.debug("[!]    Could not restore to caller. Aborting.")
                    self.end_execution = True
                    self.last_state = ss.copy()
                    self.end_execution_reason = (END_EXECUTION_OUT_OF_ROM, ss.addr)
                    break

            if ss.globals.get("out_of_rom", None):
                ss.regs.pc = ss.callstack.current_return_target
                del(ss.globals["out_of_rom"])
                ss.history.jumpkind = "Ijk_FakeRet"

            if ss.addr in self.bad_loops:
                self.end_execution = True
                self.last_state = ss.copy()
                self.end_execution_reason = (END_EXECUTION_BAD_LOOP, ss.addr)
                break

        if self.end_execution:
            succs.flat_successors = []
            succs.successors = []
            return succs
        else: 
            return succs

