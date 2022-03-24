import select
import logging
import pickle
import sys

from angr import SimPacketsStream
from angr import SimProcedure

logger = logging.getLogger('heaphopper.angr_tools')
logger.setLevel(logging.INFO)

# Global to avoid unpickling every time.
mem_dumps_loaded = {}

def heardEnter():
    i, o, e = select.select([sys.stdin], [], [], 0.0001)
    for s in i:
        if s == sys.stdin:
            input = sys.stdin.readline()
            return True
    return False


def all_bytes(file):
    if type(file) == SimPacketsStream:
        # import IPython; IPython.embed()
        return file.content
    indexes = list(file.mem.keys())
    if len(indexes) == 0:
        return file.state.solver.BVV("")
    min_idx = min(indexes)
    max_idx = max(indexes)
    buff = [ ]
    for i in range(min_idx, max_idx+1):
        buff.append(file.load(i, 1))
    return file.state.solver.Concat(*buff)

'''
Super-duper angr black magic to 
merge two memory states and import 
the initialized state of the blob.
'''
def init_memory_with_blob_mem(project, state, hb_state, mem_dump_path):
    global mem_dumps_loaded
    
    dump_name = mem_dump_path.split("/")[-1]

    if mem_dumps_loaded.get(dump_name, None):
        blob_mem_init = mem_dumps_loaded[dump_name]
    else:
        with open(mem_dump_path, "rb") as state_dump_file:
            blob_mem_init = pickle.load(state_dump_file) 
    
    logger.info("Updating memory with following pages:")
    # p is the key of the dict 
    for pi, p in enumerate(blob_mem_init._pages):
        logger.info("  Page-{}: {}".format(pi, hex(p)))

    state.memory.mem._pages.update(blob_mem_init._pages)
    state.memory.mem._symbolic_addrs.update(blob_mem_init._symbolic_addrs)
    
    return state

'''
The skip SimProcedure that will skip 
the call to a function.
'''
class skip(SimProcedure):
    #pylint:disable=arguments-differ
    def run(self, *arg, **kwarg):
        logger.info("Skipping function {}".format(hex(self.state.addr)))
        return