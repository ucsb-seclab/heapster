import angr
import claripy
import json
import sys
sys.setrecursionlimit(10**9) 

from angr_taint_engine import *
from .dfs import DFS
from .deadinator import TheDeadendinator

import logging
import argparse
import networkx as nx
from ..utils import *

l = logging.getLogger("heapster.identify_threats.path_builder")
l.setLevel(logging.INFO)


# Shortcut to make angr's noisy logging less noisy
def shut_up(thing):
    lol = logging.getLogger(thing)
    lol.setLevel("CRITICAL")

class PathBuilder:
    def __init__(self, project, hb_state):
        self.project = project
        self.hb_state = hb_state

    def get_bbl_addrs(self, curr_func, caller_func):
        curr_func_cfg_node = self.project.cfg.get_any_node(curr_func)
        valid_step = False
        caller_bbl = None
        for p in curr_func_cfg_node.predecessors:
            if p.function_address == caller_func:
                caller_bbl = p.addr
                valid_step = True
                break
        
        # We did not find a valid path to reach this...
        if not valid_step:
            return []
        
        func_caller = self.project.kb.functions[caller_func]
        func_caller_graph = func_caller.graph
        

    def get_paths(self, src=None, dst=None):
        if src == None or dst == None:
            return []
        
        # First let's see if the callgraph says it is feasible
        callgraph_paths = nx.all_simple_paths(self.project.kb.callgraph, source=src, target=dst)
        if callgraph_paths == []:
            return []
        
        for path_id,path in enumerate(callgraph_paths): 
            l.info("CALLGRAPH PATH FROM {} TO MALLOC: {}".format(hex(src), [hex(x) for x in path]))
            l.info("Trying to generate trace for path {}".format(path_id))
            callgraph_paths_rev = callgraph_paths.copy()[::-1]
            
            bbl_addrs = []
            for i in range(len(callgraph_paths_rev) - 1):
                curr_func, caller_func = callgraph_paths_rev[i], callgraph_paths_rev[i + 1]
                addrs = self.get_bbl_addrs(curr_func, caller_func)

            import ipdb; ipdb.set_trace()

        return []

