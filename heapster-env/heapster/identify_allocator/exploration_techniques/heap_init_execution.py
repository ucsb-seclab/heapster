# pylint: disable=import-error, no-name-in-module
import angr
import hashlib
import os
import logging
import networkx
import time
import threading
import copy

from typing import List, Set, Dict, Tuple, Optional
from angr.exploration_techniques import ExplorationTechnique
from angr import SimState
from networkx.drawing.nx_agraph import write_dot
from threading import Event, Timer

l = logging.getLogger("HeapInitExecution".ljust(23))
l.setLevel(logging.CRITICAL)


class MyTimer(threading.Timer):
    started_at = None
    def start(self):
        self.started_at = time.time()
        threading.Timer.start(self)
    def elapsed(self):
        return time.time() - self.started_at
    def remaining(self):
        return self.interval - self.elapsed()


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
END_EXECUTION_PS_ADDR_LIMIT = "END_EXECUTION_PS_ADDR_LIMIT"
END_EXECUTION_TIMEOUT = "END_EXECUTION_TIMEOUT"
END_EXECUTION_NO_MORE_ACTIVE = "END_EXECUTION_NO_MORE_ACTIVE"
END_EXECUTION_OUT_OF_ROM = "END_EXECUTION_OUT_OF_ROM"
END_EXECUTION_SVC_UNSUPPORTED = "END_EXECUTION_SVC_UNSUPPORTED"
END_EXECUTION_DECODING_ERROR = "END_EXECUTION_DECODING_ERROR"

'''
==================
DSE Configuration:
==================
1-  When spending more than 30 minutes inside the same function we
    terminate the analysis
2-  When reaching a callout, we terminate.
3-  When entering a 'bad_loop' we terminate.
4-  When reaching the execution of a pointer sources address, we terminate.
5-  We execute cooncrete loops to termination
6-  We terminate immediately symbolic loops
7-  Exploration technique used is DFS
8-  We follow only functions calls with concrete arguments or void (MAX deep 10)
9-  When detecting symbolic memory writes/reads (addr) we terminate.
10- IF execution lasts more than 1hr. stop it.
'''
class HeapInitExecution(ExplorationTechnique):

    def __init__(self, ps_addrs=[]):
        super(HeapInitExecution, self).__init__()

        self.ps_addrs = ps_addrs
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

        # For timeout
        self.func_timer = None
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

    def func_timeout(self):
        l.warning("[!] Function timeout fired")
        self.timed_out.set()
        self.timed_out_bool = True

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
        
        if state.globals.get("out_of_rom", None):
            state.regs.pc = state.callstack.current_return_target
            del(state.globals["out_of_rom"])
            state.history.jumpkind = "Ijk_FakeRet"

        l.debug("[+] State at {}".format(state))

        # Start the per-function timer.
        if not self.func_timer:
             self.func_timer = MyTimer(1800, self.func_timeout)
             self.func_timer.start()
        
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
            
            # NOTE: sometimes angr messes up the stack, we try 
            # to compensate by detecting the end of the function when 0x0 is
            # also reached.
            if self.check_end_of_function(ss):
                break

            exec_where = ss.project.loader.find_object_containing(ss.addr)

            # This if only if we are analyzing the syntetic example , otherwise, other line.
            #if exec_where is None or "ram" in exec_where.binary_basename or ss.addr == 0x8008afd:
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
                setattr(ss.regs, "pc", ss.solver.eval(state.regs.lr))
                del(ss.globals["out_of_rom"])
                l.debug("Setting PC to {}".format(ss.regs.pc))
                ss.history.jumpkind = "Ijk_FakeRet"
                ss.callstack.ret()

            current_function = ss.project.kb.functions.get(ss.addr, None)
            prev_function = None
            if ss.history:
                prev_function = ss.project.kb.functions.get(ss.history.addr, None)
            
            if current_function and prev_function and current_function.addr != prev_function.addr:
                self.func_timer.cancel()
                self.func_timer = MyTimer(1800, self.func_timeout)
                self.func_timer.start()

            if len(ss.globals["symbolic_writes"]) > 0:
                self.end_execution = True
                self.last_state = ss.copy()
                self.end_execution_reason = (END_EXECUTION_SYMBOLIC_WRITES, ss.addr)
                l.debug("[!]   Aborting execution because of symbolic writes.")
                break

            #if ss.addr in self.callout_sites_addresses:
            #    self.end_execution = True
            #    self.last_state = ss.copy()
            #    self.end_execution_reason = (END_EXECUTION_CALLOUT, ss.addr)
            #    break 

            if ss.addr in self.bad_loops:
                self.end_execution = True
                self.last_state = ss.copy()
                self.end_execution_reason = (END_EXECUTION_BAD_LOOP, ss.addr)
                break

            if ss.addr in self.ps_addrs:
                if ss.globals.get("calls_to_ps", 0) == 0:
                    ss.globals["calls_to_ps"] = 1
                else:
                    self.end_execution = True
                    self.last_state = ss.copy()
                    self.end_execution_reason = (END_EXECUTION_PS_ADDR_LIMIT, ss.addr)
                    break

            if self.timed_out.is_set():
                self.timed_out_bool = True
                self.end_execution = True
                self.last_state = ss.copy()
                self.end_execution_reason = (END_EXECUTION_TIMEOUT, ss.addr)
                break

        if self.end_execution:
            succs.flat_successors = []
            succs.successors = []
            self.func_timer.cancel()
            return succs
        else: 
            return succs

