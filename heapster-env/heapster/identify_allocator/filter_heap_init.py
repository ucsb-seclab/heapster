
# Packages import
import logging 
import networkx

from configparser import ConfigParser
from pathlib import Path

# Inter-module imports
from ..utils import * 
from ..analyses.arguments_analyses import filter_unused_args

l = logging.getLogger("filter_heap_init".ljust(23))
l.setLevel(logging.CRITICAL)

config = ConfigParser()
config.read((Path(__file__).parent.parent / "./heapster.ini").resolve())

def filter_by_zero_refs(project, potential_heap_initializers):
    new_potential_heap_initializers = []
    for p in potential_heap_initializers:
        if get_refs_number(project, project.cfg, p) != 0:
            new_potential_heap_initializers.append(p)
    return new_potential_heap_initializers

'''
We walk back the xrefs chain starting from a particular
heap init.
The idea is that we should observe a "skinny" chain of 
functions back to the ResetHandler since an heap initializers 
is called early during the booting process.
'''
def filter_by_xrefs_chain(project, potential_heap_initializers, max_hi_refs):
    new_potential_heap_initializers = set()

    for p in potential_heap_initializers:
        xrefs_chain = set()
        xrefs_chain.add(p)
        already_tested = set()
        wrong_xref_chain = False
        
        # Check all the chain up to the top.
        while len(xrefs_chain) != 0:
            curr_f = xrefs_chain.pop()
            func_callers = get_function_callers(project, curr_f)
            already_tested.add(curr_f)
            if len(func_callers) > max_hi_refs:
                wrong_xref_chain = True
                break
            else:
                # Let's check the callers recursively.
                for f in func_callers:
                    if f not in already_tested:
                        xrefs_chain.add(f)

        if not wrong_xref_chain:
            new_potential_heap_initializers.add(p)
        else:
            l.debug("Filtered {} because wrong xref chain".format(hex(p)))
    return new_potential_heap_initializers


def filter_by_size(project, potential_heap_initializers):
    pass

'''
Heap initializers are generally void.
'''
def filter_by_no_args(project, potential_heap_initializers):
    new_potential_heap_initializers = set()
    for p in potential_heap_initializers:
        func = project.kb.functions[p]
        f_args = filter_unused_args(project, func)
        if len(f_args) == 0:
            new_potential_heap_initializers.add(p)
    return new_potential_heap_initializers

def filter_by_number_of_calls(project, potential_heap_initializers, max_calls):
    filtered_again_potential_heap_init = set()
    for ff in potential_heap_initializers:
        ff_calls = get_calls_r(project, ff)
        if len(ff_calls) < max_calls:
            filtered_again_potential_heap_init.add(ff)
    return filtered_again_potential_heap_init

'''
Remove all successors of a pointer souce from a set of 
candidate heap initializers.
Idea: heap init is not called by pointer source, and when
it is, is executed by the malloc during emulation later.
'''
def filter_ps_successors(project, ps_successors, potential_heap_initializers):
    tmp_intersection = ps_successors.intersection(potential_heap_initializers)
    l.info("Removing {} function from potential heap init since are successors of PS".format(len(tmp_intersection)))
    new_potential_heap_initializers = potential_heap_initializers.difference(tmp_intersection)
    return new_potential_heap_initializers

'''
Filter all functions in the callgraph 
that are topologically before the pointer_source.
[Now deactivated]
'''
def filter_by_topological_order(project, pointer_source, sub_graph):
    # Just collect them until we spot the pointer source
    filtered_again_potential_heap_init = set()
    for x in networkx.topological_sort(sub_graph):
        if x == pointer_source:
            return filtered_again_potential_heap_init
        else:
            filtered_again_potential_heap_init.add(x)
    return filtered_again_potential_heap_init

'''
Filter heap initialiizer with too many calls
(Threshold at X).
IDEA: An heap init does not have generally too many
calls.
'''
def order_by_number_of_calls(project, filtered_potential_heap_init, max_calls):
    phi_and_calls = []
    for f in filtered_potential_heap_init:
        phi_calls = len(get_calls_r(project, f))
        phi_and_calls.append((f, phi_calls))
    
    # Just a quick hack, filter out the one with too many calls 
    phi_and_calls.sort(key=lambda tup: tup[1])
    filtered_phi_and_calls = []
    for x in phi_and_calls:
        #if x[1] < max_calls:
        filtered_phi_and_calls.append(x)

    return [x[0] for x in filtered_phi_and_calls]