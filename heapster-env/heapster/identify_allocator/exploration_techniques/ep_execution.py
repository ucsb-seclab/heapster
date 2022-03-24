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

l = logging.getLogger("EpExecution".ljust(23))
l.setLevel(logging.DEBUG)

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
END_EXECUTION_NO_MORE_ACTIVE  = "END_EXECUTION_NO_MORE_ACTIVE"
END_EXECUTION_CALLOUT  = "END_EXECUTION_CALLOUT"
END_EXECUTION_BAD_LOOP = "END_EXECUTION_BAD_LOOP"
END_EXECUTION_TIMEOUT = "END_EXECUTION_TIMEOUT"
END_EXECUTION_STATE_EXPLOSION = "END_EXECUTION_STATE_EXPLOSION"
END_EXECUTION_OUT_OF_ROM = "END_EXECUTION_OUT_OF_ROM"
END_EXECUTION_SVC_UNSUPPORTED = "END_EXECUTION_SVC_UNSUPPORTED"
END_EXECUTION_DECODING_ERROR = "END_EXECUTION_DECODING_ERROR"

class EpExecution(ExplorationTechnique):

    def __init__(self):
        super(EpExecution, self).__init__()

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

        # For timeout.
        self.timed_out = Event()
        self.timed_out_bool = False

    def setup(self, simgr):
        init_state = simgr.active[0]
        func = init_state.project.kb.functions[init_state.addr]
        # Grab callout sites 
        self.callout_sites_addresses = [x.addr for x in func.callout_sites]
        # Grab infinite Loops
        self.bad_loops = fast_infinite_loop_finder(init_state.project,func)

        return True


    def successors(self, simgr, state:SimState, **kwargs):
        
        # Checkpoint 
        self.last_state = state

        if state.globals.get("out_of_rom", None):
            state.regs.pc = state.callstack.current_return_target
            del(state.globals["out_of_rom"])
            state.history.jumpkind = "Ijk_FakeRet"

        succs = simgr.successors(state, **kwargs)

        if succs == None or len(succs.flat_successors) == 0:
            l.debug("[+]   Succs is None. Returning.")
            self.end_execution = True
            self.last_state = state.copy()
            self.end_execution_reason = (END_EXECUTION_NO_MORE_ACTIVE, state.addr)
            return succs

        if state.globals.get("svc_found", False):
            l.debug("[!]   SVC unsupported found. Returning.")
            self.end_execution = True
            self.last_state = state.copy()
            self.end_execution_reason = (END_EXECUTION_SVC_UNSUPPORTED, state.addr)
            succs.flat_successors = []
            succs.successors = []
            return succs

        for ss in succs.flat_successors:

            if ss.addr == 0xdeadbeef or ss.addr == 0x0:
                # Did we reach the end of the EntryPoint, if yes, let's stop.
                # WHY:
                # Everything is concrete in this state, so we assume the first
                # state that reaches the end is equivalent to the concrete execution.
                # (There can be imprecisions of course, but it's the best we can do).
                l.debug("[+]   DSE reached end of function. Stopping.")
                self.end_execution = True
                self.last_state = ss.copy()
                self.end_execution_reason = (END_EXECUTION_RETURNS, ss.addr)
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

            if ss.addr in self.callout_sites_addresses:
                l.debug("[!]   DSE reached a callout. Stopping.")
                self.end_execution = True
                self.last_state = ss.copy()
                self.end_execution_reason = (END_EXECUTION_CALLOUT, ss.addr)
                break 

            if ss.addr in self.bad_loops:
                l.debug("[!]   DSE reached an infinite loop. Stopping.")
                self.end_execution = True
                self.last_state = ss.copy()
                self.end_execution_reason = (END_EXECUTION_BAD_LOOP, ss.addr)
                break

            if self.timed_out.is_set():
                l.debug("[!]   DSE Timed Out. Stopping")
                self.timed_out_bool = True
                self.end_execution = True
                self.last_state = ss.copy()
                self.end_execution_reason = (END_EXECUTION_TIMEOUT, ss.addr)
                break

        if self.end_execution:
            succs.flat_successors = []
            succs.successors = []
            return succs
        else: 
            return succs
