import os
import time
import angr
import random
import logging 

from tqdm import tqdm

l = logging.getLogger("exec_basic_function     ")
l.setLevel(logging.INFO)
'''
Abstraction for an identifiable function.
'''
class IdentifiableFunction(object):
    def can_be_consistent_with(self, project, func):
        raise NotImplementedError

    def get_queries(self):
        raise NotImplementedError

    def check_consistency(self, project, func, args, state):
        raise NotImplementedError

class StateSerializable:
    def place_into_state(self, state, loc):
        return NotImplementedError
    def retrieve_from_state(self, state, loc):
        return NotImplementedError

class PointerWrapper:
    def __init__(self, data, addr=None):
        self.addr = addr
        assert type(data) is bytes
        self.data = data

    '''
    Set this pointer into the given state at location
    'loc'.
    '''
    def place_into_state(self, state, loc):
        self.data.place_into_state(state, loc=self.addr)
        endness = state.arch.register_endness
        if type(loc) is str:
            state.registers.store(loc, self.addr, endness=endness)
        else:
            state.memory.store(loc, self.addr, endness=endness)

    '''
    Retrieve from loc and set the attributes.
    '''
    def retrieve_from_state(self, state, loc):
        endness = state.arch.register_endness
        if type(loc) is str:
            val = state.registers.load(loc, endness=endness)
        else:
            val = state.memory.load(loc, endness=endness)
        self.addr = state.solver.eval_one(val)
        self.data = self.data.retrieve_from_state(state, loc)
        return self
        
    def __repr__(self):
        return "PointerWrapper({}, addr={})".format(self.data, self.addr)

'''
Assign random addresses to the PointerWrapper.
'''
def assign_rand_addrs(args):
    addrs = {a.addr for a in args if type(a) is PointerWrapper}
    for a in args:
        if type(a) is not PointerWrapper or a.addr is not None:
            continue
        
        # Let's assign an address that we haven't used before to
        # this pointer wrapper.
        while True:
            addr = random.randint(1, 0xfffff) << 12
            if addr not in addrs:
                a.addr = addr
                addrs.add(addr)
                break

def red(s):
    return "\x1b[31m" + s + "\x1b[0m"
'''
This is the main class that is 
identifing the basic functions.
:param project is the angr project
:param to_identify is a list of IdentifiableFunction
       implementations.
'''
class MyIdentifier(object):
    def __init__(self, project, filtered_functions, to_identify):
        self.project = project
        self.to_identify = to_identify
        self.filtered_functions = filtered_functions
        self.identified = {i: dict() for i in self.to_identify}
    
    def run(self):
        heartbeat_delta = 1 if len(self.filtered_functions) // 4 < 0 else len(self.filtered_functions) // 4
        for f_num, f in enumerate(self.filtered_functions):
            if f_num % heartbeat_delta == 0:
                # print log every 10 funcs :)
                l.info("[+] Analyzing functions... Progress: [{}/{}]".format(f_num, len(self.filtered_functions)))
            self.identify_func(f)

    def identify_func(self, f):
        for identifiable in self.to_identify:
            # Check if the current function under analysis respect the first 
            # filter regardin this specific identifiable.
            if not identifiable.can_be_consistent_with(self.project, f):
                l.debug("Function {} doesn't respect consistency".format(hex(f.addr)))
                continue
            
            # Get the queries that we are going to use to setup
            # the state at the call site of the function we want to test.
            queries = identifiable.produce_queries()
            consistency_checks = []

            l.debug("Running [{}] queries against function [{}]".format(len(queries), hex(f.addr)))
            # Now let's run the queries!
            q_num = 1
            for q in queries:
                l.debug("Running query [{}/{}] against function [{}]".format(q_num, len(queries), hex(f.addr)))
                l.debug("Checking function {} against query {}".format(hex(f.addr), q))
                result = self.run_query(f, q)
                q_num += 1
                # Ok now after we have ran the thing we want to check the consistency
                # with the identifiable. 
                is_consistent = identifiable.check_consistency(self.project, f, result)
                if is_consistent is not None:
                    consistency_checks.append(is_consistent)
                    if not is_consistent:
                        l.debug("...Consistency check failed. Skipping function.")
                        break

            if not len(consistency_checks):
                continue
            
            if f in self.identified[identifiable]:
                if self.identified[identifiable][f] != all(consistent for consistent in consistency_checks):
                    l.fatal("DIFFERENT RUNS GAVE DIFFERENT RESULTS! HOW??????????")
                    import ipdb; ipdb.set_trace()
                    assert False
            self.identified[identifiable][f] = all(consistent for consistent in consistency_checks)

    '''
    Runs a specific query over a given function that we suspect 
    is an identifiable one.
    param :function is the function we suspect to be an identifiable 
    param :query is a set if query that we are going to use to test the function.
    '''
    def run_query(self, function, query):
        return run(self.project, function, query)

'''
Used to test a function against a set of queries.
'''
def run(project, func, args, max_steps=2000, max_secs=10):

    # Assign random addresses to the pointers wrapper.
    assign_rand_addrs(args)

    # Now let's create a call state over the function.
    state = project.factory.call_state(func.addr,
            add_options={angr.options.ZERO_FILL_UNCONSTRAINED_MEMORY, 
                         angr.options.ZERO_FILL_UNCONSTRAINED_REGISTERS, 
                         }
    )

    # This is containing the func args.
    locs = get_arg_locs(project, func, args)

    # Setup the state with the PointerWrapper args. 
    for arg_loc, a in zip(locs, args):
        if type(a) is PointerWrapper:
            arg_loc.was_pointer_wrapper = True
            val = a.addr
            state.memory.store(val, a.data)
        else:
            arg_loc.was_pointer_wrapper = False
            val = a
        arg_loc.set_value(state, val)
    
    # Create the simgr 
    sm = project.factory.simulation_manager(state)
    t = time.time()
    i = 0

    # We simulate the entire function til we have no more active states.
    while sm.active:
        if max_steps is not None and i > max_steps:
            return False, args, state, "Function exceeded max number of {} steps!".format(max_steps)
        if max_secs is not None and time.time() - t > max_secs:
            return False, args, state, "Function exceeded timeout of {} seconds!".format(max_secs)

        #?
        #if i and i % 100 == 0:
        #    print(i, sm)

        sm.step()
        i += 1

    l.debug(sm)
    if sm.errored:
        return False, args, sm.errored[0], repr(sm.errored[0])

    assert len(sm.deadended) == 1

    #print("Running function {} with arguments {} took {} seconds!".format(func.name, args, time.time() - t))
    #print("Running function {} with took {} seconds!".format(func.name, time.time() - t))
    return True, args, sm.deadended[0], ""

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

def rand_byte():
    if random.random() < 0.2:
        return b'\0'
    return bytes([random.randint(0, 255)])

def rand_bytes(n):
    return b''.join(rand_byte() for _ in range(n))
