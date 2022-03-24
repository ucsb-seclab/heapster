
from .ident import *
from .basic_filters import *

class IdentifiableStrncpy(IdentifiableFunction):

    def can_be_consistent_with(self, project, func):
        filters = [callless_filter(), standard_function_filter(), basic_block_filter(30), byte_size_filter_max(500), only_jmp_ins_filter()]
        for f in filters:
            if not f(func):
                return False
        return True

    def produce_queries(self):
        return get_strncpy_evidence()

    def check_consistency(self, project, func, result):
        return consistent_with_strncpy(project, func, result)

    def __str__(self):
        return "IdentifiableStrncpy"

'''
Crafting evidences for memcpy.
'''
def get_strncpy_evidence():
    
    # Every test contains 3 args, 2 buffer and 1 size! 
    tests = []
    #tests += [ (PointerWrapper(b'\0' * 100), PointerWrapper(b'asdf\0asdf'), 9) ]
    tests += [ (PointerWrapper(b'AAAAAAAAAA\0'), PointerWrapper(b'BBBB\0B'), 6) ] # results in BBBB00
    tests += [ (PointerWrapper(b'CCCC'), PointerWrapper(b'asdf\0'), 4) ]         # results in asdf
    tests += [ (PointerWrapper(b'CCCCCCCCCC\0'), PointerWrapper(b'asdf\0aaa'), 8) ]  # results in asdf0000
    return tests


def real_strncpy(a, b, size):
    final_string = ''
    got_null = False 
    for i in range(0,size):
        if b[i] != 0 and not got_null:
            final_string += chr(b[i])
        else:
            got_null = True
            final_string += chr(0)

    return final_string.encode("ascii")
'''
This is checking if the result of a run of a function
are compatible with the behavior of the memcpy.
'''
def consistent_with_strncpy(project, func, result):
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
    
    # src buffer is not modified
    if content_src != orig_src:
        return False
    
    expected_string = real_strncpy(content_dst, content_src, length)

    # Compute result of strncpy 
    if content_dst != expected_string:
        return False
    
    return True