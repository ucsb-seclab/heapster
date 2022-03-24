
from .ident import *
from .basic_filters import *

class IdentifiableStrncat(IdentifiableFunction):

    def can_be_consistent_with(self, project, func):
        filters = [callless_filter(), standard_function_filter(), basic_block_filter(30), byte_size_filter_max(500), only_jmp_ins_filter()]
        for f in filters:
            if not f(func):
                return False
        return True

    def produce_queries(self):
        return get_strncat_evidence()

    def check_consistency(self, project, func, result):
        return consistent_with_strncat(project, func, result)

    def __str__(self):
        return "IdentifiableStrncat"

'''
Crafting evidences for strlen.
'''
def get_strncat_evidence():
    
    # Every test contains 3 args
    tests = []

    tests += [ (PointerWrapper(b'first_half\0'), PointerWrapper(b'second_half'),6)]
    tests += [ (PointerWrapper(b'abcd\0'), PointerWrapper(b'efgh'),3)]
    tests += [ (PointerWrapper(b'greed_is_\0'), PointerWrapper(b'goodlolololol'),4)]

    return tests

'''
This is checking if the result of a run of a function
are compatible with the behavior of the strncat.
'''
def consistent_with_strncat(project, func, result):
    success, args, state, error_msg = result

    if len(args) < 3:
        return None

    if type(args[0]) is not PointerWrapper or type(args[1]) is not PointerWrapper or type(args[2]) is PointerWrapper:
        return None

    if not success:
        return False
    
    # Starting the behavioral checks!
    arg_locs = get_arg_locs(project, func, args)
    
    length = args[2]
    ptr_dst, orig_dst = args[0].addr, args[0].data
    ptr_src, orig_src = args[1].addr, args[1].data[:length]

    bv_dst = state.memory.load(ptr_dst, len(orig_dst) + length)
    bv_src = state.memory.load(ptr_src, length)

    if bv_dst.symbolic or bv_src.symbolic:
        return False

    content_dst = state.solver.eval_one(bv_dst, cast_to=bytes)
    content_src = state.solver.eval_one(bv_src, cast_to=bytes)

    # NULL byte at dst is overwritten by POSIX standard 
    orig_dst = orig_dst[:-1]

    # Constructing the resulting string 
    resulting_string = orig_dst + orig_src + b'\0'

    if content_dst != resulting_string:
        return False 

    return True