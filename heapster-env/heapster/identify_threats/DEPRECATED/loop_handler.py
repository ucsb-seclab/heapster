from types import new_class
from heapster.utils import fast_infinite_loop_finder
import logging

from angr.exploration_techniques import ExplorationTechnique
from angr.analyses.loopfinder import Loop
from angr.state_plugins import SimStatePlugin

l = logging.getLogger("LoopHandler")
l.setLevel("CRITICAL")

# Keep track of gross approximation and other weird
# things 
class LoopData(SimStatePlugin):
    def __init__(self, current_active_loops=None, loop_trips=None, loop_watchdogs=None, clone=None):
        self.current_active_loops = list() if clone is None else clone.current_active_loops
        self.loop_trips = dict() if clone is None else clone.loop_trips
        self.loop_watchdogs = dict() if clone is None else clone.loop_watchdogs

    def merge(self, others, merge_conditions, common_ancestor=None): # pylint:disable=unused-argument
        return True

    @SimStatePlugin.memo
    def copy(self, _memo):
        return LoopData(clone=self)


class LoopHandler(ExplorationTechnique):

    def __init__(self, cfg=None, bound=None):
        super(LoopHandler, self).__init__()
        self.cfg = cfg
        self.bound = bound
        self.loops = {}

        self.loop_watchdogs = {}
    
    def setup(self, simgr):
        for s in simgr.active:
            s.register_plugin('loop_data', LoopData())

        loop_finder = self.project.analyses.LoopFinder(kb=self.cfg.kb, normalize=True)
        for loop in loop_finder.loops:
            if loop.entry_edges:
                entry = loop.entry_edges[0][1]
                self.loops[entry.addr] = loop
   
    def activate_loop(self, state):
        # If the address of the state is equal to the header of a detected loop 
        # and the loop is not already activated, we activate it.
        if state.addr in self.loops.keys() and state.addr not in state.loop_data.current_active_loops:
            l.info("Activating loop at {}".format(hex(state.addr)))
            state.loop_data.current_active_loops.append(self.loops[state.addr])
            state.loop_data.loop_trips[state.addr] = 0
         

    def loop_watchdog(self, state, next_state):
        if next_state.addr <= state.addr and next_state.history.jumpkind == "Ijk_Boring" and next_state.addr in state.history.bbl_addrs:
            
            if next_state.loop_data.loop_watchdogs.get(next_state.addr, None) is not None:
                next_state.loop_data.loop_watchdogs[next_state.addr] += 1
            else:
                next_state.loop_data.loop_watchdogs[next_state.addr] = 1
            return True
        else:
            return False

    def unstuck_loop(self, state, next_state):
        l.info("Gotta unstuck a loop")
        state_block = state.project.factory.block(addr=state.addr).vex
        possible_targets = []
        for addr, jmp in state_block.constant_jump_targets_and_jumpkinds.items():
            if jmp == 'Ijk_Boring' and addr != next_state.addr:
                possible_targets.append(addr)
        return possible_targets

    def check_loop_watchdog(self, state, next_state):
        if next_state.loop_data.loop_watchdogs[next_state.addr] > self.bound + 30:
            states = self.unstuck_loop(state, next_state)
            if len(states) != 0:
                return states, True
        else:
            return [next_state.addr], False

    def successors(self, simgr, state, **kwargs):
        
        succs = simgr.successors(state, **kwargs)

        new_succs = []
        discarded_succs = []

        for ss in succs.flat_successors:
            if self.loop_watchdog(state, ss):
                targets, result = self.check_loop_watchdog(state, ss)
                if result:
                    discarded_succs.append(ss)
                    for t in targets:
                        l.info("Watchdog kicking in, teleporting state at {}".format(hex(t)))
                        new_state = ss.copy()
                        setattr(new_state.regs, "pc", t)
                        new_succs.append(new_state)

        # we had active loops, what happen during the step? 
        if state.loop_data.current_active_loops != []:
            # last active loop is the current running one 
            current_loop = state.loop_data.current_active_loops[-1]
            break_nodes = [ x[0].addr for x in self.loops[current_loop.entry.addr].break_edges]
            continue_nodes = [x[0].addr for x in self.loops[current_loop.entry.addr].continue_edges]
            out_of_loop_nodes = [ x[1].addr for x in self.loops[current_loop.entry.addr].break_edges]

            for ss in succs.flat_successors:
                if ss.globals.get("tail_to_check", False):
                    
                    # Symbolic loop, the tail can go multiple places 
                    if len(succs.flat_successors) > 1:
                        # The loop took the tail out of the loop, terminate this loop!
                        if ss.addr in out_of_loop_nodes:
                            ss.loop_data.current_active_loops = ss.loop_data.current_active_loops[:-1]
                            ss.loop_data.loop_trips[current_loop.entry.addr] = 0
                        # The loop took the tail back to the header.
                        elif ss.addr == current_loop.entry.addr:
                            # The loop is symbolic, we want to terminate this ASAP.
                            # We do not add this state to the successors.
                            l.info("Discarding state at {} because of symbolic loop!".format(hex(ss.addr)))
                            discarded_succs.append(ss)
                        else:
                            # back to a node in the body of the loop
                            pass
                    else:
                        # The loop took the tail out of the loop, terminate this loop!
                        if ss.addr in out_of_loop_nodes:
                            ss.loop_data.current_active_loops = ss.loop_data.current_active_loops[:-1]
                            ss.loop_data.loop_trips[current_loop.entry.addr] = 0
                        # The loop took the tail back to the header.
                        elif ss.addr == current_loop.entry:
                            ss.loop_data.loop_trips[current_loop.entry.addr] += 1
                            if ss.loop_data.loop_trips[current_loop.entry.addr] > self.bound:
                                l.info("Reached bound for loop {}".format(current_loop))
                                # Forcing the termination of the loop.
                                discarded_succs.append(ss)
                                ss.loop_data.current_active_loops = ss.loop_data.current_active_loops[:-1]
                                ss.loop_data.loop_trips[current_loop.entry.addr] = 0
                                l.info("Forcing termination of bounded loop. New states are:")
                                for n in out_of_loop_nodes:
                                    new_state = ss.copy()
                                    setattr(new_state.regs, "pc", n)
                                    l.info("{}".format(new_state))
                                    new_succs.append(new_state)
                        else:
                            # back to a node in the body of the loop
                            pass
                    ss.globals['tail_to_check'] = False

                if ss not in discarded_succs:
                    new_succs.append(ss)

                # The loop can exit or not, we have to check at the next iteration if 
                # we need to increment the counter or not or breaking the loop.
                if ss.addr in break_nodes:
                    ss.globals['tail_to_check'] = True
                elif ss.addr in continue_nodes:
                    # in this case the loop is going back to the head for sure, we
                    # can increment the trip count here.
                    ss.loop_data.loop_trips[current_loop.entry.addr] += 1
                    if ss.loop_data.loop_trips[current_loop.entry.addr] > self.bound:
                        l.info("Reached bound for loop {}".format(current_loop))
                        # Forcing the termination of the loop.
                        discarded_succs.append(ss)
                        ss.loop_data.current_active_loops = ss.loop_data.current_active_loops[:-1]
                        ss.loop_data.loop_trips[current_loop.entry.addr] = 0
                        l.info("Forcing termination of bounded loop. New states are:")
                        for n in out_of_loop_nodes:
                            new_state = ss.copy()

                            setattr(new_state.regs, "pc", n)
                            l.info("{}".format(new_state))
                            new_succs.append(new_state)
                else:
                    # well, we are in the loop body, go ahead.
                    pass
        else:
            new_succs = succs.flat_successors 

        for ss in new_succs:
            if ss not in discarded_succs:
                self.activate_loop(ss)
        
        #if len(discarded_succs) != 0:
        #    import ipdb; ipdb.set_trace()
    
        succs.flat_successors = new_succs
        return succs

