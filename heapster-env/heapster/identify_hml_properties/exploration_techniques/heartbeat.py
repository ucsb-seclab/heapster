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


l = logging.getLogger("HeartBeat".ljust(23))
l.setLevel(logging.CRITICAL)

global CURR_SIMGR
global CURR_PROJ
global CURR_STATE


def dump_viz_graph(simgr=None):
    l.info("Dumping visualization graph if it exists")
    
    if simgr is None:
        simgr = CURR_SIMGR
    
    for et in simgr._techniques:
        if "SimgrViz" in str(et):
            break
    write_dot(et._simgrG,"/tmp/my_simgr.dot")

def spw_cli():
    global CURR_SIMGR
    global CURR_PROJ
    global CURR_STATE
    import angrcli.plugins.ContextView
    from angrcli.interaction.explore import ExploreInteractive
    e = ExploreInteractive(CURR_PROJ, CURR_STATE)
    e.cmdloop()


class HeartBeat(ExplorationTechnique):
    '''
    When plugging this Exploration technique we collect information
    regarding the SimStates generated by the Simgr.
    This is a DEBUG ONLY technique that should never be used in production.
    '''
    def __init__(self, beat_interval=1, app_timer=None):
        super(HeartBeat, self).__init__()
        self.stop_heart_beat_file = "/tmp/stop_heartbeat.txt"
        self.beat_interval = beat_interval
        self.beat_cnt = 0
        self.steps_cnt = 0

        # Any app timer we want to display
        self.app_timer = app_timer

    def setup(self, simgr):
        return True

    def successors(self, simgr, state:SimState, **kwargs):
        global CURR_SIMGR
        global CURR_PROJ
        global CURR_STATE

        beat_1_ts = time.time()

        #if state.addr == 0x7e55:
        #    CURR_SIMGR = simgr
        #    CURR_PROJ = state.project
        #    CURR_STATE = state
        #    spw_cli()

        succs = simgr.successors(state, **kwargs)
        beat_interval = time.time() - beat_1_ts

        if succs == None:
            return succs 
        
        for ss in succs.successors:
            ss.globals['step_time'] = str(beat_interval)
            ss.globals['unsat_succs'] = str(list(succs.unsat_successors))

        self.beat_cnt += 1
        self.steps_cnt += 1
        
        if self.beat_cnt == self.beat_interval:
            l.info("Exploration is alive <3. Step {}".format(self.steps_cnt)) 
            l.info("    Succs are: {}".format(succs))
            l.info("    Simgr is: {}".format(simgr))
            if self.app_timer:
                l.info("    Time remaining is: {}".format(self.app_timer.remaining()))
            self.beat_cnt = 0
            if os.path.isfile(self.stop_heart_beat_file):
                l.info("HeartBeat stopped, need help? </3")
                
                CURR_SIMGR = simgr
                CURR_PROJ = state.project
                CURR_STATE = state
                
                import ipdb; ipdb.set_trace()
                
                CURR_SIMGR = None
                CURR_PROJ = None
                CURR_STATE = None
        
        return succs