# ██░ ██ ▓█████ ▄▄▄       ██▓███   ▄▄▄▄    █    ██  ██████ ▄▄▄█████▓▓█████  ██▀███    ██████ 
#▓██░ ██▒▓█   ▀▒████▄    ▓██░  ██▒▓█████▄  ██  ▓██▒██    ▒ ▓  ██▒ ▓▒▓█   ▀ ▓██ ▒ ██▒▒██    ▒ 
#▒██▀▀██░▒███  ▒██  ▀█▄  ▓██░ ██▓▒▒██▒ ▄██▓██  ▒██░ ▓██▄   ▒ ▓██░ ▒░▒███   ▓██ ░▄█ ▒░ ▓██▄   
#░▓█ ░██ ▒▓█  ▄░██▄▄▄▄██ ▒██▄█▓▒ ▒▒██░█▀  ▓▓█  ░██░ ▒   ██▒░ ▓██▓ ░ ▒▓█  ▄ ▒██▀▀█▄    ▒   ██▒
#░▓█▒░██▓░▒████▒▓█   ▓██▒▒██▒ ░  ░░▓█  ▀█▓▒▒█████▓▒██████▒▒  ▒██▒ ░ ░▒████▒░██▓ ▒██▒▒██████▒▒
# ▒ ░░▒░▒░░ ▒░ ░▒▒   ▓▒█░▒▓▒░ ░  ░░▒▓███▀▒░▒▓▒ ▒ ▒▒ ▒▓▒ ▒ ░  ▒ ░░   ░░ ▒░ ░░ ▒▓ ░▒▓░▒ ▒▓▒ ▒ ░
# ▒ ░▒░ ░ ░ ░  ░ ▒   ▒▒ ░░▒ ░     ▒░▒   ░ ░░▒░ ░ ░░ ░▒  ░ ░    ░     ░ ░  ░  ░▒ ░ ▒░░ ░▒  ░ ░
# ░  ░░ ░   ░    ░   ▒   ░░        ░    ░  ░░░ ░ ░░  ░  ░    ░         ░     ░░   ░ ░  ░  ░  
# ░  ░  ░   ░  ░     ░  ░          ░         ░          ░              ░  ░   ░           ░               


from angr import SimProcedure
from angr.state_plugins import SimStatePlugin, inspect
import claripy
import logging
import sys

logger = logging.getLogger('heaphopper.heap_condition_tracker')

class HeapConditionTracker(SimStatePlugin):
    def widen(self, _others):
        pass

    def __init__(self, config=None, libc=None, allocator=None, initialized=0, vulnerable=False, vuln_state=None, hangs=False, faulty=False,
                 vuln_type='', malloc_prototype=None, free_prototype=None, heap_grows=None, malloc_dict=None, free_dict=None, malloc_idx=0, free_idx=0,
                 write_bps=None, wtarget=None, req_size=None, arb_write_info=None, double_free=None, fake_frees=None, stack_trace=None,
                 ctrl_data_idx=0, curr_freed_chunk=None, sym_data_states=None, sym_data_size=None, **kwargs):  # pylint:disable=unused-argument
        super(HeapConditionTracker, self).__init__()
        self.config = config
        self.libc = libc
        self.allocator = allocator
        self.initialized = initialized
        self.vulnerable = vulnerable
        self.vuln_state = vuln_state
        self.hangs = hangs
        self.malloc_idx = malloc_idx
        self.free_idx = free_idx
        self.faulty = faulty
        self.vuln_type = vuln_type
        self.malloc_dict = dict() if malloc_dict is None else dict(malloc_dict)
        self.free_dict = dict() if free_dict is None else dict(free_dict)
        self.malloc_prototype = malloc_prototype
        self.free_prototype = free_prototype
        self.heap_grows = heap_grows
        self.double_free = list() if double_free is None else list(double_free)
        self.fake_frees = list() if fake_frees is None else list(fake_frees)
        self.write_bps = list() if write_bps is None else list(write_bps)
        self.wtarget = wtarget
        self.req_size = req_size
        self.arb_write_info = dict() if arb_write_info is None else dict(arb_write_info)
        self.stack_trace = list() if stack_trace is None else list(stack_trace)
        self.ctrl_data_idx = ctrl_data_idx
        self.curr_freed_chunk = curr_freed_chunk
        self.sym_data_states = dict() if sym_data_states is None else dict(sym_data_states)
        self.sym_data_size = sym_data_size

    def set_level(self, level): # pylint:disable=no-self-use
        logger.setLevel(level)

    @SimStatePlugin.memo
    def copy(self, _memo):
        return HeapConditionTracker(**self.__dict__)

    # we need that for veritesting
    def merge(self, others, merge_conditions, common_ancestor=None): # pylint:disable=unused-argument
        # TODO: Do better merging
        for o in others:
            self.vulnerable |= o.vulnerable

            self.hangs |= o.hangs

            if not self.vuln_type and o.vuln_type:
                self.vuln_type = o.vuln_type

            if not self.malloc_dict and o.malloc_dict:
                self.malloc_dict = dict(o.malloc_dict)

            if not self.free_dict and o.free_dict:
                self.free_dict = dict(o.free_dict)

            if not self.arb_write_info and o.arb_write_info:
                self.arb_write_info = dict(o.arb_write_info)

            if not self.write_bps and o.write_bps:
                self.write_bps = o.write_bps

            if not self.wtarget and o.wtarget:
                self.wtarget = o.wtarget

            if not self.req_size and o.req_size:
                self.req_size = o.req_size

            if not self.double_free and o.double_free:
                self.double_free = list(o.double_free)

            if not self.vuln_state and o.vuln_state:
                self.vuln_state = o.vuln_state.copy()

            if not self.fake_frees and o.fake_frees:
                self.fake_frees = list(o.fake_frees)

            if not self.stack_trace and o.stack_trace:
                self.stack_trace = list(o.stack_trace)

            if not self.ctrl_data_idx and o.ctrl_data_idx:
                self.ctrl_data_idx = o.ctrl_data_idx

            if o.initialized:
                self.initialized = o.initialized

            return True

'''
We define a pure Arbitrary Write (AW) as a
write-where-what in which we can write over ALL the 
write-targets space (since we are concretizing ) whataver 
value we want, if these two conditions are not met, this 
is a Restricted Write (RW)
'''
def check_arbitrary_write(state):

    arbitrary_where = True
    arbitrary_write_metadata = {}
    arbitrary_write_metadata["where_size"] = 0
    
    where_total_size = state.heaphopper.wtarget[1]
    
    # Get the length of the memory write (in bytes)
    write_size_val = state.solver.eval(state.inspect.mem_write_length)
    arbitrary_write_metadata["what_size"] = write_size_val 


    # Check if we can cover all the "WHERE"
    for wt_addr in range(state.heaphopper.wtarget[0], state.heaphopper.wtarget[0] + state.heaphopper.wtarget[1], 0x1):
        if not state.solver.satisfiable(extra_constraints=[state.inspect.mem_write_address == wt_addr]):
            arbitrary_where = False
        else:
            arbitrary_write_metadata["where_size"]+=1

    # If we can not cover the entire write targets space 
    # we consider this a restricted write, no matter which data
    # we can write.
    if arbitrary_write_metadata["where_size"] != where_total_size :
        logger.info("RW | {}".format(arbitrary_write_metadata))
        logger.info("Could not cover the entire writer target space ({})".format(where_total_size))
        arbitrary_write_metadata["restricted_where"] = True
        return "RW", arbitrary_write_metadata 
    
    # If we are here we have arbitrary where, let's check for arbitrary what.
    # if we the data being written is not symbolic we consider this restricted write.
    if not state.inspect.mem_write_expr.symbolic:
        arbitrary_write_metadata["what_not_symbolic"] = True
        arbitrary_write_metadata["what_concrete_value"] = state.solver.eval(state.inspect.mem_write_expr)
        logger.info("RW | {}".format(arbitrary_write_metadata))
        return "RW", arbitrary_write_metadata
    else:
        # Defensive code, just in case.
        if write_size_val == 1:
            sols = state.solver.eval_upto(state.inspect.mem_write_expr, 254)
            if len(sols) == 254:
                return "AW", arbitrary_write_metadata
        elif write_size_val == 4:
            logger.info("Testing for 254 solutions for what in AW")
            arbitrary_write_metadata["what_254"] = False
            sols = state.solver.eval_upto(state.inspect.mem_write_expr, 254)
            if len(sols) == 254:
                arbitrary_write_metadata["what_254"] = True
                logger.info("Testing for 512 solutions for what in AW")
                arbitrary_write_metadata["what_512"] = False
                sols = state.solver.eval_upto(state.inspect.mem_write_expr, 512)
                if len(sols) == 512:
                    logger.info("Testing for special solutions for what in AW")
                    arbitrary_write_metadata["what_512"] = True 
                    arbitrary_write_metadata["what_special_values"] = 0 
                    if state.solver.satisfiable(extra_constraints=[state.inspect.mem_write_expr == 0x41414141]):
                        arbitrary_write_metadata["what_special_values"] += 1
                        if state.solver.satisfiable(extra_constraints=[state.inspect.mem_write_expr == 0xdeadbeef]):
                            arbitrary_write_metadata["what_special_values"] += 1
                            return "AW", arbitrary_write_metadata
                        else:
                            return "RW", arbitrary_write_metadata
                    return "RW", arbitrary_write_metadata
            else:
                return "RW", arbitrary_write_metadata
        else:
            logger.info("FATAL, unexpected write length")
            assert(False)

'''
Used to check memory_writes of malloc and free! 
'''
def check_write(state):

    # If we found an arb_write we're done
    if state.heaphopper.vuln_type.startswith('arbitrary_write'):
        return

    # Check if we have an arbitrary_write
    addr = state.inspect.mem_write_address
    val = state.inspect.mem_write_expr

    #logger.debug('check_write: addr: %s' % addr)
    #logger.debug('check_write: val: %s' % val)

    # Constraints that describe the write target[0]
    constr = claripy.And(addr >= state.heaphopper.wtarget[0],
                        addr < state.heaphopper.wtarget[0] + state.heaphopper.wtarget[1])
    
    # can we solve for the addr pointing at the write_target?
    if state.solver.satisfiable(extra_constraints=[constr]):
        logger.debug('check_write: Found arbitrary write')
        state.add_constraints(constr)
        logger.info('arb write is writing at {}'.format(hex(state.solver.min(addr))))
        state.heaphopper.vuln_state = state.copy()

        if state.heaphopper.vuln_type !='':
            logger.info("We already have a vuln. Skipping.")
            return 

        arb_write_class, arb_write_metadata = check_arbitrary_write(state)
        if arb_write_class == "AW":
            state.heaphopper.vuln_type = 'arbitrary_write'
        else:
            state.heaphopper.vuln_type = 'restricted_write'
        
        state.heaphopper.arb_write_info = dict(instr=state.addr, addr=addr, val=val)
        state.heaphopper.arb_write_info.update(arb_write_metadata)
        state.heaphopper.stack_trace = get_libc_stack_trace(state)

def check_sym_data(state):
    # Check if we overwrite a sym_data structure passed to free
    addr = state.inspect.mem_write_address
    free_addr = state.heaphopper.curr_freed_chunk
    if free_addr in state.heaphopper.sym_data_states and not state.heaphopper.sym_data_states[free_addr]:
        #logger.debug('check_sym_data: curr_freed_chunk: 0x%x' % free_addr)
        #logger.debug('check_sym_data: addr: %s' % addr)
        constr = claripy.And(addr >= free_addr, addr < free_addr + state.heaphopper.sym_data_size)
        if not state.solver.symbolic(addr) and state.solver.satisfiable(extra_constraints=[constr]):
            #logger.debug('check_sym_data: Saving state')
            state.heaphopper.sym_data_states[free_addr] = state.copy()

def get_libc_stack_trace(state):
    backtrace = state.history.bbl_addrs.hardcopy[::-1]
    index = 0
    while state.heaphopper.allocator.contains_addr(backtrace[index]):
        index += 1
    return backtrace[:index]



class MallocInspect(SimProcedure):
    IS_FUNCTION = True
    local_vars = ()

    def run(self, malloc_addr=None, vulns=None, ctrl_data=None): # pylint: disable=arguments-differ,unused-argument
        # Let's extract the args according to the prototype of this malloc
        malloc_args = ()
        for arg_idx in range(0,len(self.state.heaphopper.malloc_prototype)):
            malloc_args = malloc_args + (self.arg(arg_idx), )
        
        # Extract which param is the size, we have tagged that in the dict. 
        # As for now it MUST be present (even if we HeapBuster has support 
        # for malloc with no args tho).
        size_idx = 0
        for malloc_arg_key, malloc_arg_value in self.state.heaphopper.malloc_prototype.items():
            if malloc_arg_key == 'ret':
                continue
            if malloc_arg_value == "size":
                break
            else:
                size_idx = size_idx + 1
        
        size = malloc_args[size_idx]

        # If looking for an arbitrary write we need to register a breakpoints on 
        # the memory writes performed by malloc!
        if 'arb_write' in vulns:
            self.state.heaphopper.write_bps.append(self.state.inspect.b('mem_write', when=inspect.BP_BEFORE,
                                                            action=check_write))
        self.state.heaphopper.req_size = size

        # call malloc at <malloc_addr> and when it returns 
        # continue at <check_malloc>
        logger.info("Calling malloc {} with size: {}".format(self.state.heaphopper.malloc_idx, size))
        self.call(malloc_addr, malloc_args, 'check_malloc')

    def check_malloc(self, malloc_addr=None, vulns=None, ctrl_data=None): #pylint:disable=unused-argument    
        
        malloc_error_codes = [ 0x0, 0xffffffff]

        # Check if the address is before/after the heap
        # base depending on the grow direction.
        def out_of_heap(state, address):
            if state.heaphopper.heap_grows == ">":
                if address < self.state.heap.heap_base:
                    return True
                else:
                    return False
            if state.heaphopper.heap_grows == "<":
                if address > self.state.heap.heap_base:
                    return True
                else:
                    return False

        # This is called after the real code of the malloc has been runned!
        # Clear breakpoints
        for bp in self.state.heaphopper.write_bps:
            self.state.inspect.remove_breakpoint('mem_write', bp=bp)
        
        self.state.heaphopper.write_bps = []

        # Check if malloc returns some bogus pointer
        # We need to extract this info accordingly to
        # where this malloc implementation is returning the result.
        # HACK: As for now I just support returning into a register!  
        reg_name = self.state.heaphopper.malloc_prototype["ret"]
        if not reg_name:
            l.fatal("No support for void malloc yet. Aborting.")
            sys.exit(-1)
        malloced_addr = getattr(self.state.regs, reg_name) 
        
        # The first address returned by malloc
        # will give us the heap-base.
        # This is needed to understand when we have a 
        # `bad_alloc`.
        if self.state.heaphopper.initialized == 0:
            self.state.heaphopper.initialized = 1
            sols = self.state.solver.eval_upto(malloced_addr, 2)
            if len(sols) > 1:
                logger.warning("First malloc has multiple solutions. Picking the first one.")
                
            #logger.info("Heap base address is {}".format(hex(sols[0])))
            #self.state.heap.heap_base = sols[0] 

        if 'arb_write' in vulns:
            # Remove breakpoint and check for arbitrary writes
            if self.state.heaphopper.vuln_type == 'arbitrary_write':
                logger.info('Found malloc arbitrary write')
                self.state.heaphopper.vulnerable = True
                self.state.heaphopper.vuln_type = 'arbitrary_write_malloc'

            if self.state.heaphopper.vuln_type == 'restricted_write':
                logger.info('Found malloc restricted write')
                self.state.heaphopper.vulnerable = True
                self.state.heaphopper.vuln_type = 'restricted_write_malloc'

        # Get ctrl_data ptr used as id
        dict_key = ctrl_data[self.state.heaphopper.ctrl_data_idx]
        self.state.heaphopper.ctrl_data_idx += 1

        # This might be better than checking for symbolic
        sols = self.state.solver.eval_upto(malloced_addr, 2)
        if len(sols) > 1:
            self.state.heaphopper.malloc_idx += 1
            return self.check_sym_malloc(malloced_addr, vulns, dict_key)

        # Get the only possible value. (len(sols) == 1) here)
        val = sols[0]
        logger.info("Malloc {} returned concrete address: {}".format(self.state.heaphopper.malloc_idx, hex(val)))
        self.state.heaphopper.malloc_idx += 1

        if val in malloc_error_codes:
            self.state.heaphopper.faulty = True
            return val
        
        self.state.add_constraints(malloced_addr == val)

        if self.state.heaphopper.vulnerable:
            return val

        if 'bad_alloc' in vulns and val in self.state.heaphopper.fake_frees:
            logger.info('Found allocation to fake freed address')
            self.state.add_constraints(malloced_addr == val)
            self.state.heaphopper.vulnerable = True
            self.state.heaphopper.vuln_type = 'malloc_non_heap'
            self.state.heaphopper.vuln_state = self.state.copy()

        elif 'bad_alloc' in vulns and out_of_heap(self.state, val) and val not in malloc_error_codes:
            logger.info('Found allocation on bogus non-heap address')
            #import ipdb; ipdb.set_trace()
            if self.state.heaphopper.heap_grows == ">": 
                self.state.add_constraints(malloced_addr < self.state.heap.heap_base)
            else:
                self.state.add_constraints(malloced_addr > self.state.heap.heap_base)
            val = self.state.solver.eval_upto(malloced_addr, 1)[0]
            self.state.add_constraints(malloced_addr == val)
            self.state.heaphopper.vulnerable = True
            self.state.heaphopper.vuln_type = 'malloc_non_heap'
            self.state.heaphopper.vuln_state = self.state.copy()

        elif 'overlap_alloc' in vulns and val not in self.state.heaphopper.double_free:
            if self.check_overlap(self.state.heaphopper.malloc_dict, malloced_addr, self.state.heaphopper.req_size):
                return val

        self.state.heaphopper.malloc_dict[dict_key] = (self.state.heaphopper.req_size, malloced_addr)

        # Remove from free dict if reallocated
        for key in list(self.state.heaphopper.free_dict.keys()):
            sol = self.state.solver.min(self.state.heaphopper.free_dict[key][1])
            if val == sol:
                self.state.heaphopper.free_dict.pop(key)
                break

        return val

    def check_sym_malloc(self, malloced_addr, vulns, dict_key):

        if self.state.heaphopper.vulnerable:
            return malloced_addr

        if 'bad_alloc' in vulns:
            if self.state.heaphopper.heap_grows == ">": 
                if self.state.solver.satisfiable(extra_constraints=[malloced_addr < self.state.heap.heap_base, malloced_addr != 0x0, malloced_addr != 0xffffffff]):
                    self.state.add_constraints(malloced_addr < self.state.heap.heap_base)
                    self.state.add_constraints(malloced_addr != 0x0)
                    self.state.add_constraints(malloced_addr != 0xffffffff)
                    val = self.state.solver.min(malloced_addr)
                    self.state.add_constraints(malloced_addr == val)
                    logger.info('Found allocation on bogus non-heap address at {}'.format(hex(val)))
                    self.state.heaphopper.vulnerable = True
                    self.state.heaphopper.vuln_type = 'malloc_non_heap'
                    self.state.heaphopper.vuln_state = self.state.copy()
                    return malloced_addr
            elif self.state.heaphopper.heap_grows == "<":
                if self.state.solver.satisfiable(extra_constraints=[malloced_addr > self.state.heap.heap_base, malloced_addr != 0x0, malloced_addr != 0xffffffff]):
                    self.state.add_constraints(malloced_addr > self.state.heap.heap_base)
                    self.state.add_constraints(malloced_addr != 0x0)
                    self.state.add_constraints(malloced_addr != 0xffffffff)
                    val = self.state.solver.min(malloced_addr)
                    self.state.add_constraints(malloced_addr == val)
                    logger.info('Found allocation on bogus non-heap address at {}'.format(hex(val)))
                    self.state.heaphopper.vulnerable = True
                    self.state.heaphopper.vuln_type = 'malloc_non_heap'
                    self.state.heaphopper.vuln_state = self.state.copy()
                    return malloced_addr    
            else:
                logger.fatal("No info regarding heap growing direction. FixMe.")
                import ipdb; ipdb.set_trace()

        #################################################################
        # Check overlaps
        #################################################################
        
        # if the ast grows to big, str(addr) is expensive
        logger.info("check_sym_malloc: addr.ast.depth = %d", malloced_addr.ast.depth)
        #logger.info("sym_malloc: {}".format(malloced_addr))
        if 'overlap_alloc' in vulns and (malloced_addr.ast.depth > 30 or str(malloced_addr) not in self.state.heaphopper.double_free):
            if self.check_overlap(self.state.heaphopper.malloc_dict, malloced_addr, self.state.heaphopper.req_size):
                
                # ADDED BY ME 
                val = self.state.solver.min(malloced_addr)

                # BUG? IF I ADD THIS CONSTRAINT HERE THE LOADED SIZE IS 16 WHEN I PROCESS THE STATE........
                #self.state.add_constraints(malloced_addr==val)
                
                #logger.info("Registering malloc with address {} and size {} at key {}".format(hex(val), self.state.heaphopper.req_size, hex(dict_key)))
                #self.state.heaphopper.malloc_dict[dict_key] = (self.state.heaphopper.req_size, malloced_addr)                        
                
                return malloced_addr

        # Register this malloc value in the dict
        #logger.info("Registering malloc with addresses {} and sizes {} at key {}".format( [hex(x) for x in self.state.solver.eval_upto(malloced_addr, 10)], 
        # self.state.solver.eval_upto(self.state.heaphopper.req_size, 10), hex(dict_key)))

        print("Registering malloc at dict_key {}".format(dict_key))
        self.state.heaphopper.malloc_dict[dict_key] = (self.state.heaphopper.req_size, malloced_addr)

        # Get the minimum value...
        val = self.state.solver.min(malloced_addr)
        print("Minimum value for symbolic malloc is {}".format(hex(val)))

        # Remove from free dict if reallocated
        for key in list(self.state.heaphopper.free_dict.keys()):
            sol = self.state.solver.min(self.state.heaphopper.free_dict[key][1])  # Why do we remove only the min solution? Does this make actually sense?
            if val == sol:
                self.state.heaphopper.free_dict.pop(key)
                break
        
        return malloced_addr

    '''
    Check overlapping chunks
    '''
    def check_overlap(self, malloc_dict, malloced_addr, req_size):
        
        for dst in list(malloc_dict.keys()):
            alloc = malloc_dict[dst][1]

            # Conditions for overlappability
            condition1 = self.state.solver.And(alloc < malloced_addr, alloc + malloc_dict[dst][0] > malloced_addr)
            condition2 = self.state.solver.And(alloc > malloced_addr, malloced_addr + req_size > alloc)
            
            # Check if this is satisfiable!
            if self.state.solver.satisfiable(extra_constraints=[condition1]):
                logger.info('Found overlapping allocation')
                self.state.add_constraints(condition1)
                req_size_value = self.state.solver.eval(req_size)
                #self.state.add_constraints(req_size == req_size_value)
                print("{} must be {}".format(req_size, req_size_value))
                self.state.heaphopper.vulnerable = True
                self.state.heaphopper.vuln_type = 'malloc_allocated'
                self.state.heaphopper.vuln_state = self.state.copy()
                #import ipdb; ipdb.set_trace()
                print("Alloc overlapped is {} with size {} and overlapping allocation is {} with size {}".format(hex(self.state.solver.min(alloc)), 
                                                                                                                 hex(self.state.solver.min(malloc_dict[dst][0])), 
                                                                                                                 hex(self.state.solver.min(malloced_addr)),
                                                                                                                 hex(self.state.solver.min(req_size))
                                                                                                                 )
                                                                                                                )
                return True
            
            if self.state.solver.satisfiable(extra_constraints=[condition2]):
                logger.info('Found overlapping allocation')
                self.state.add_constraints(condition2)
                req_size_value = self.state.solver.eval(req_size)
                #self.state.add_constraints(req_size == req_size_value)
                print("{} must be {}".format(req_size, req_size_value))
                self.state.heaphopper.vulnerable = True
                self.state.heaphopper.vuln_type = 'malloc_allocated'
                self.state.heaphopper.vuln_state = self.state.copy()
                #import ipdb; ipdb.set_trace()
                print("Alloc overlapped is {} with size {} and overlapping allocation is {} with size {}".format(hex(self.state.solver.min(alloc)), 
                                                                                                                 hex(self.state.solver.min(malloc_dict[dst][0])), 
                                                                                                                 hex(self.state.solver.min(malloced_addr)),
                                                                                                                 hex(self.state.solver.min(req_size))
                                                                                                                 )
                                                                                                                )
                return True
        
        return False


class FreeInspect(SimProcedure):
    IS_FUNCTION = True

    def _isallocated(self, val):
        found = False
        for key in list(self.state.heaphopper.malloc_dict.keys()):
            sol = self.state.solver.min(self.state.heaphopper.malloc_dict[key][1])
            if val == sol:
                logger.info("This addr is allocated!")
                found = True
        return found

    # TODO: this `run` must be fixed accordingly to the prototype of the free
    def run(self, free_addr=None, vulns=None, sym_data=None): # pylint: disable=arguments-differ

        # Let's extract the args according to the prototype of this malloc
        free_args = ()
        for arg_idx in range(0,len(self.state.heaphopper.free_prototype)):
            free_args = free_args + (self.arg(arg_idx), )
        
        # Extract which param is the ptr_to_free, we have tagged that in the dict. 
        # As for now it MUST be present in tha args.
        size_idx = 0

        for free_arg_key, free_arg_value in self.state.heaphopper.free_prototype.items():
            if free_arg_key == 'ret':
                continue
            if free_arg_value == "ptr_to_free":
                break
            else:
                size_idx = size_idx + 1

        ptr =  free_args[size_idx]
        val = self.state.solver.min(ptr)

        # register a fake free if ptr is in sym_data
        if val in sym_data and not self._isallocated(val):
            #logger.info("Registering a fake free at {}".format(hex(val)))
            self.state.heaphopper.fake_frees.append(val)
        else:
            found = False

            # Are we freeing an existing chunk?
            for key in list(self.state.heaphopper.malloc_dict.keys()):
                sol = self.state.solver.min(self.state.heaphopper.malloc_dict[key][1])
                
                # If we have a match we need to remove this from the malloc dict
                if val == sol:
                    #logger.info("Removing chunk in malloc dict at {}".format(hex(key)))
                    minfo = self.state.heaphopper.malloc_dict.pop(key)
                    self.state.heaphopper.free_dict[key] = minfo
                    found = True

            if not found:
                # Well, we are freeing something that was freed before!
                for key in list(self.state.heaphopper.free_dict.keys()):
                    sol = self.state.solver.min(self.state.heaphopper.free_dict[key][1])
                    if val == sol:
                        #logger.info("Freeing a free chunk. That's a double free.")
                        self.state.heaphopper.double_free.append(val)


        # If looking for an arbitrary write we need to register a breakpoints on 
        # the memory writes performed by free!        
        if 'arb_write' in vulns:
            self.state.heaphopper.write_bps.append(self.state.inspect.b('mem_write', when=inspect.BP_BEFORE,
                                                            action=check_write))

        if val in sym_data:
            self.state.heaphopper.write_bps.append(self.state.inspect.b('mem_write', when=inspect.BP_BEFORE,
                                                            action=check_sym_data))
        self.state.heaphopper.curr_freed_chunk = val
        
        logger.info("Calling free {} over address: {}".format(self.state.heaphopper.free_idx, hex(val)))
        
        # Call real function at <free_addr> and then call <check_free>
        self.call(free_addr, free_args, 'check_free')


    def check_free(self, free_addr=None, vulns=None, sym_data=None): #pylint:disable=unused-argument

        # Let's extract the args according to the prototype of this free
        free_args = ()
        for arg_idx in range(0,len(self.state.heaphopper.free_prototype)):
            free_args = free_args + (self.arg(arg_idx), )
        
        # Extract which param is the ptr_to_free, we have tagged that in the dict. 
        # As for now it MUST be present in tha args.
        size_idx = 0
        for free_arg in self.state.heaphopper.free_prototype.values():
            if free_arg == "ptr_to_free":
                break
            else:
                size_idx = size_idx + 1
        ptr =  free_args[size_idx]

        # Clear the chunk currently being freed
        self.state.curr_freed_chunk = None

        # Clear breakpoints
        for bp in self.state.heaphopper.write_bps:
            self.state.inspect.remove_breakpoint('mem_write', bp=bp)
        self.state.heaphopper.write_bps = []

        self.state.heaphopper.free_idx += 1

        # Don't track heap_init free
        #if self.state.heaphopper.initialized == 1:
        #    self.state.heaphopper.initialized = 2
        #    return

        # check non-heap:
        if 'bad_free' in vulns and self.state.solver.satisfiable(
                extra_constraints=[ptr < self.state.heap.heap_base]):
            logger.info('Found free of non-heap address')
            self.state.heaphopper.vulnerable = True
            self.state.heaphopper.vuln_type = 'free_non_heap'
            self.state.heaphopper.vuln_state = self.state.copy()
            return

        if 'double_free' in vulns:
            val = self.state.solver.min(ptr)
            if val in self.state.heaphopper.double_free:
                logger.info('Found double free')
                self.state.heaphopper.vulnerable = True
                self.state.heaphopper.vuln_state = self.state.copy()
                return

        if 'arb_write' not in vulns:
            return

        if self.state.heaphopper.vuln_type == 'arbitrary_write':
            logger.info('Found free arbitrary write')
            self.state.heaphopper.vulnerable = True
            self.state.heaphopper.vuln_type = 'arbitrary_write_free'

        if self.state.heaphopper.vuln_type == 'restricted_write':
            logger.info('Found free restricted write')
            self.state.heaphopper.vulnerable = True
            self.state.heaphopper.vuln_type = 'restricted_write_free'

        return