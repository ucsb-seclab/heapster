
from .ident import *
from .basic_filters import *

class IdentifiableStrlen(IdentifiableFunction):

    def can_be_consistent_with(self, project, func):
        filters = [callless_filter(), standard_function_filter(), basic_block_filter(30), byte_size_filter_max(500), only_jmp_ins_filter()]
        for f in filters:
            if not f(func):
                return False
        return True

    def produce_queries(self):
        return get_strlen_evidence()

    def check_consistency(self, project, func, result):
        return consistent_with_strlen(project, func, result)

    def __str__(self):
        return "IdentifiableStrlen"

'''
Crafting evidences for strlen.
'''
def get_strlen_evidence():
    
    # Every test contains 1 arg 
    tests = []

    tests += [ (PointerWrapper(b'this_is_a_random_string\0'), ) ]
    tests += [ (PointerWrapper(b'a\0'), ) ]
    tests += [ (PointerWrapper(b'asidkj09ek90\0'), ) ]

    return tests

'''
This is checking if the result of a run of a function
are compatible with the behavior of the memcpy.
'''
def consistent_with_strlen(project, func, result):
    success, args, state, error_msg = result

    if len(args) < 1:
        return None

    if not type(args[0]) is PointerWrapper:
        return None

    if not success:
        return False
    
    # Starting the behavioral checks!
    # Basically here we want to check if the buffer given as test
    # has been copied over the other buffer without modification 
    # to the source buffer. This is probably very much memcpy.
    arg_locs = get_arg_locs(project, func, args)

    ptr_string, string_data = args[0].addr, args[0].data
    correct_string_len = len(string_data) - 1

    bv_dst = state.memory.load(ptr_string, correct_string_len+1)

    if bv_dst.symbolic:
        return False

    content_dst = state.solver.eval_one(bv_dst, cast_to=bytes)

    # String must be untouched!
    if content_dst != string_data:
        return False
    
    # r0 should hold the length of the string
    if state.solver.eval(state.regs.r0) != correct_string_len:
        return False

    return True