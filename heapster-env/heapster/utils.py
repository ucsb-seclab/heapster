import angr
import sys 
import os 
import pickle
import threading 
import time 
import resource 
pickle._HAVE_PICKLE_BUFFER = False
import logging 

from networkx.drawing.nx_agraph import write_dot

from threading import Event, Timer
from angr.exploration_techniques import LengthLimiter, LoopSeer, ExplorationTechnique

l = logging.getLogger("heapster.utils")
l.setLevel(logging.CRITICAL)

# Global to avoid unpickling every time.
mem_dumps_loaded = {}

def limit_memory(maxsize):
    soft, hard = resource.getrlimit(resource.RLIMIT_AS)
    resource.setrlimit(resource.RLIMIT_AS, (maxsize, hard))

class MyTimer(threading.Timer):
    started_at = None
    def start(self):
        self.started_at = time.time()
        threading.Timer.start(self)
    def elapsed(self):
        return time.time() - self.started_at
    def remaining(self):
        return self.interval - self.elapsed()

class bcolors:
    HEADER = '\033[95m'
    OKBLUE = '\033[94m'
    OKGREEN = '\033[92m'
    WARNING = '\033[93m'
    FAIL = '\033[91m'
    ENDC = '\033[0m'
    BOLD = '\033[1m'
    UNDERLINE = '\033[4m'
    # Background colors:
    GREYBG = '\033[100m'
    REDBG = '\033[101m'
    GREENBG = '\033[102m'
    YELLOWBG = '\033[103m'
    BLUEBG = '\033[104m'
    PINKBG = '\033[105m'
    CYANBG = '\033[106m'

'''
Just safely load the project artifact 
'''
def load_artifact(hb_state):
    hb_folder      =  hb_state['hb_folder']
    proj_dump_file =  hb_state['blob_project']
    
    if "arm_firmware_firmxray" in proj_dump_file:
        l.critical("[+] CHANGING PATH ON-THE-FLY. REMOVE ME.")
        proj_dump_file = proj_dump_file.replace("arm_firmware_firmxray", "arm_firmware_firmxray_ALL")

    if os.path.isfile(proj_dump_file):
        with open(proj_dump_file, "rb") as proj_file:
            p = pickle.load(proj_file)
    else:
        l.fatal("Can't load Project file at {}, aborting.".format(proj_dump_file))
        sys.exit(-1)
    return p,p.cfg

'''
Get all the arguments of the function 'func'.
'''
def get_arg_locs(project, func, args):
    cc = project.factory.cc()
    locs = cc.arg_locs(is_fp=[False]*len(args))

    result_locs = []
    for i, a in enumerate(args):
        loc = func.arguments[i] if i < len(func.arguments) else locs[i]
        result_locs.append(loc)
    return result_locs

'''
Given the register of an offset, returns its name.
'''
def offset_to_reg(project, offset):
    return project.arch.register_names.get(offset, '')

'''
Given the name of a register, returns the offset.
'''
def reg_to_offset(project,reg_name):
    reg_value = project.arch.registers.get(reg_name, None)
    if reg_value:
        return reg_value[0]
    else:
        return -1

'''
Get number of Xrefs to a specific function.
'''
def get_refs_number(project, bin_cfg, function_address):
    node = bin_cfg.model.get_any_node(function_address)
    node_predecessors = node.predecessors # getting all the XRefs
    return len(node_predecessors)

'''
Get predecessors of a specific function.
'''
def get_refs(project, bin_cfg, function_address):
    node = bin_cfg.model.get_any_node(function_address)
    node_predecessors = node.predecessors # getting all the XRefs
    return node_predecessors

def block_from_addr_ins(project, ins_addr):
    floored_func = project.kb.functions.floor_func(ins_addr)
    if floored_func:
        for b in floored_func.blocks:
            if ins_addr in b.instruction_addrs:
                return b
    return None 


'''
Get an address that is not already mapped in the 
process address space.
'''
def get_available_address(project):
    # Get a free address that is not in the address space
    for x in range(0x10000, 0xc0000000, 0x100):
        if not project.loader.find_object_containing(x) and not project.loader.find_object_containing(x + 0x100):
            return x
    l.fatal("Could not find a free address")
    raise Exception

'''
Spot all the infinite loops 
in the blob.
'''
def fast_infinite_loop_finder(p):
    la = p.analyses.LoopFinder()
    bad_loops = []
    for loop in la.loops:
        if not loop.break_edges:
            for node in loop.graph.nodes():
                if not isinstance(node, angr.codenode.BlockNode):
                    continue
                bad_loops.append(node.addr)
    return bad_loops


def last_ram_address(project):
    for x in project.loader.all_objects:
        if "ram" in x.binary_basename or "ramdisk" in x.binary_basename:
            return x.max_addr
    l.critical("No ram associated to this blob. This might be a problem.")
    return project.loader.max_addr



'''
An helper exploration technique to handle explosions
during DSE.
'''
class ExplosionDetector(ExplorationTechnique):
    def __init__(self, stashes=('active', 'deferred', 'errored', 'cut'), threshold=100):
        super(ExplosionDetector, self).__init__()
        self._stashes = stashes
        self._threshold = threshold
        self.timed_out = Event()
        self.timed_out_bool = False

        self.memory_peak = -1

    def step(self, simgr, stash='active', **kwargs):
        simgr = simgr.step(stash=stash, **kwargs)
        total = 0
        if len(simgr.unconstrained) > 0:
            l.debug("Nuking unconstrained")
            simgr.move(from_stash='unconstrained', to_stash='_Drop', filter_func=lambda _: True)
        
        if self.timed_out.is_set():
            l.debug("Timed out, %d states: %s" % (total, str(simgr)))
            self.timed_out_bool = True
            for st in self._stashes:
                if hasattr(simgr, st):
                    simgr.move(from_stash=st, to_stash='_Timeout', filter_func=lambda _: True)
        
        for st in self._stashes:
            if hasattr(simgr, st):
                total += len(getattr(simgr, st))

        if total >= self._threshold:
            l.critical("State explosion detected, over %d states: %s" % (total, str(simgr)))
            for st in self._stashes:
                #for state in simgr.stashes[st]:
                #    state.globals["state_explosion"] = True
                if hasattr(simgr, st):
                    simgr.move(from_stash=st, to_stash='_Drop', filter_func=lambda _: True)

        return simgr

'''
The skip SimProcedure that will skip 
the call to a function.
'''
class skip(angr.SimProcedure):
    #pylint:disable=arguments-differ
    def run(self, *arg, **kwarg):
        l.info("Skipping function {}".format(hex(self.state.addr)))
        return

'''
Get the endnodes of a target function,
if no end-nodes can be detected, we use the latest node
of the graph.
'''
def get_func_endpoint(project, func_target):
    endpoint = None
    last_node = None
    if not func_target.endpoints:
        for n in func_target.nodes:
            last_node = n
        endpoint = last_node.addr
        l.warning("The function has no endpoints. Using last node address {} as educated guess.".format(hex(endpoint)))
    else:
        endpoint = project.factory.block(addr=func_target.endpoints[0].addr, opt_level=1).instruction_addrs[-1]
    return endpoint

'''
Recursively get all the calls performed by
a function using the callgraph.
'''
def get_calls_r(project, func):
    def _get_calls(project, f):
        calls = project.cfg.functions.callgraph.successors(f)
        for c in calls:
            if c not in all_calls:
                all_calls.add(c)
                _get_calls(project, c)
    all_calls = set()
    _get_calls(project, func)
    return all_calls

'''
Get all the calls performed by
a function using the callgraph.
(Stop at the first level)
'''
def get_calls(project, func):
    all_calls = set()
    calls = project.cfg.functions.callgraph.successors(func)
    for c in calls:
        all_calls.add(c)
    return all_calls

def get_callers(project, func):
    all_caller = set()
    callers = project.cfg.functions.callgraph.predecessors(func)
    for c in callers:
        all_caller.add(c)
    return all_caller

def get_function_callers(project, func):
    all_caller = set()
    assert(type(func) == int)
    node = project.cfg.model.get_any_node(func)
    func_predecessors = set([xref.function_address for xref in node.predecessors])
    return func_predecessors

'''
Check wether a function exists in the CFG
or not.
'''
def check_existance(cfg, function_addr):
    if cfg.functions.get(function_addr,None):
        return True
    else:
        l.warning("Function at {} doesn't exist in the CFG. Skipping it.".format(function_addr))
        return False

'''
Dump a networkx graph.
'''
def dump_graph(dir_name, name, graph):
    l.info("Dumping graph...")
    try:
        output_path = os.path.join(dir_name, "{}.graph".format(name))
        write_dot(graph,output_path)
    except Exception as e:
        l.error("Exception during graph dumping for {}".format(name))
        l.error(e)
        import ipdb; ipdb.set_trace()
        pass
    l.info("Dumped graph.")

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
    
    state.memory.mem._pages.update(blob_mem_init._pages)
    state.memory.mem._symbolic_addrs.update(blob_mem_init._symbolic_addrs)
    
    return state
