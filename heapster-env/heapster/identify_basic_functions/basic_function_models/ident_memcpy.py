
from .ident import *
from .basic_filters import *

class IdentifiableMemcpy(IdentifiableFunction):

    def can_be_consistent_with(self, project, func):
        filters = [callless_filter(), standard_function_filter(), basic_block_filter(30), byte_size_filter_max(500), only_jmp_ins_filter()]
        for f in filters:
            if not f(func):
                return False
        return True

    def produce_queries(self):
        return get_memcpy_evidence()

    def check_consistency(self, project, func, result):
        return consistent_with_memcpy(project, func, result)

    def __str__(self):
        return "IdentifiableMemcpy"

'''
Crafting evidences for memcpy.
'''
def get_memcpy_evidence():
    
    # Every test contains 3 args, 2 buffer and 1 size! 
    tests = []
    #tests += [ (PointerWrapper(b'\0' * 100), PointerWrapper(b'asdf\0asdf'), 9) ]
    tests += [ (PointerWrapper(b'asdf\0asdf'), PointerWrapper(b'\0' * 100), 9) ]
    tests += [ (PointerWrapper(b'asdf\0asdf'), PointerWrapper(b'wxyz\0wxyz'), 9) ]
    tests += [ (PointerWrapper(b'wxyz\0wxyz'), PointerWrapper(b'asdf\0asdf'), 9) ]
    
    #for i in range(3):
    #    length = random.randint(10, 100)
    #    tests += [ (PointerWrapper(rand_bytes(length)), PointerWrapper(rand_bytes(length)), length) ]
    return tests

'''
This is checking if the result of a run of a function
are compatible with the behavior of the memcpy.
'''
def consistent_with_memcpy(project, func, result):
    success, args, state, error_msg = result

    if len(args) < 3:
        return None

    if not (type(args[0]) is PointerWrapper and type(args[1]) is PointerWrapper and type(args[2]) is not PointerWrapper):
        return None

    if args[2] > 1000: # arbitrary limit where we start expecting to see errors
        return None

    if not success:
        return False
    
    # Starting the behavioral checks!
    # Basically here we want to check if the buffer given as test
    # has been copied over the other buffer without modification 
    # to the source buffer. This is probably very much memcpy.
    arg_locs = get_arg_locs(project, func, args)

    length = args[2]
    ptr_dst, orig_dst = args[0].addr, args[0].data[:length]
    ptr_src, orig_src = args[1].addr, args[1].data[:length]

    bv_dst = state.memory.load(ptr_dst, length)
    bv_src = state.memory.load(ptr_src, length)
    if bv_dst.symbolic or bv_src.symbolic:
        return False

    content_dst = state.solver.eval_one(bv_dst, cast_to=bytes)
    content_src = state.solver.eval_one(bv_src, cast_to=bytes)
    
    if content_dst != orig_src:
        return False

    if content_src != orig_src:
        return False
    
    return True