import logging 

from configparser import ConfigParser
from pathlib import Path

l = logging.getLogger("filter_free")
l.setLevel(logging.CRITICAL)

config = ConfigParser()
config.read((Path(__file__).parent.parent / "./heapster.ini").resolve())


def filter_void_free_and_no_preds(project, possible_free):
    # Filter out frees that has 0 arguments and no predecessors
    filtered_free = []
    filtered_cnt = 0 
    for f in possible_free:
        func = project.kb.functions[f]
        func_node = project.cfg.get_any_node(func.addr)
        if func.arguments and len(func.arguments) != 0 and len(func_node.predecessors) != 0:
            filtered_free.append(f) # Keep if it is not void
        else:
            filtered_cnt+=1
    l.info("[+] filter_void_free filtered {} functions from possible_free".format(filtered_cnt))
    return filtered_free

def filter_not_free(project, hb_state):
    possible_free = []
    filtered_cnt = 0 

    # Free doesn't return a pointer.
    pointer_sources = hb_state['pointer_sources']
    # Free doesn't return a pointer eventually used in a basic function.
    calls_analyzed = hb_state['calls_analyzed']
    # Free doesn't receive a pointer as argument that is passed to a basic function.
    callers_analyzed = hb_state['caller_analyzed']
    # Free is not the entry point 
    ep = hb_state['blob_entry_point']

    basic_functions = []
    for bf_candidate in hb_state['bf_candidates']:
        basic_functions = basic_functions + [hex(x) for x in bf_candidate["addr"] ]

    not_free = pointer_sources + calls_analyzed + callers_analyzed + basic_functions
    
    for func in project.kb.functions.values():
        if hex(func.addr) not in not_free:
            #l.debug("func {} not in not_free".format(hex(func.addr)))
            possible_free.append(func.addr)
        else:
            l.debug("[+] func {} filtered because in not_free".format(hex(func.addr)))
            filtered_cnt+=1
    l.info("[+] filter_not_free filtered {} functions from possible_free".format(filtered_cnt))

    return filter_void_free_and_no_preds(project, possible_free)
