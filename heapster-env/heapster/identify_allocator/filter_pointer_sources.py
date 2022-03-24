import logging 

from configparser import ConfigParser
from pathlib import Path

l = logging.getLogger("filter_pointer_sources".ljust(23))
l.setLevel(logging.CRITICAL)

config = ConfigParser()
config.read((Path(__file__).parent.parent / "./heapster.ini").resolve())

def filter_p_sources(project, p_generators):
    possible_malloc = []
    filtered_cnt = 0
    p_generators = [int(x,16) for x in p_generators]
    bin_cfg = project.cfg 

    for p in p_generators:
        pg = bin_cfg.functions.get_by_addr(p)
        pgcc = pg.calling_convention
        pgcfg = bin_cfg.model.get_any_node(p)
        # Filter functions that are not called by anyone (if any).
        if not pgcc or len(pgcfg.predecessors) == 0 or len(pg.arguments) == 0:
            filtered_cnt += 1
            continue
        else:
            possible_malloc.append(p)
    l.info("filter_p_generators filtered {} functions from possible_malloc".format(filtered_cnt))
    return possible_malloc