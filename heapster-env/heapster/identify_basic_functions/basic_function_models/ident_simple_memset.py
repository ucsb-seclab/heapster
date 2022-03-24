from .ident import *
from .basic_filters import *

class IdentifiableSimpleMemset(IdentifiableFunction):
    def can_be_consistent_with(self, project, func):
        filters = [callless_filter(), standard_function_filter(), basic_block_filter(30), byte_size_filter_max(500)]
        for f in filters:
            if not f(func):
                return False
        return True

    def produce_queries(self):
        queries = [
            (PointerWrapper(b"\0" * 100), 100),
            (PointerWrapper(b"\0" * 100), 100),
        ]
        for length in [2, 8]:
            canary = os.urandom(8)
            queries += [
                (PointerWrapper(rand_bytes(length) + canary), length),
                (PointerWrapper(rand_bytes(length) + canary), length),
            ]

        return queries

    def check_consistency(self, project, func, result):
        success, args, state, error_msg = result
        if not success:
            return None
        if len(args) < 2:
            return None

        if type(args[0]) is not PointerWrapper or type(args[1]) is PointerWrapper:
            return None

        if args[1] > 1000:
            return None # probably timed out, let's not say no

        arg_locs = get_arg_locs(project, func, args)

        length = args[1]
        ptr_dst, orig_dst = args[0].addr, args[0].data[:length]
        char_fill = 0x0 & 0xff

        bv_dst = state.memory.load(ptr_dst, length)
        if bv_dst.symbolic:
            return False
        
        content_dst = state.solver.eval_one(bv_dst, cast_to=bytes)
        if content_dst != bytes([char_fill] * length):
            return False

        return True

    def __str__(self):
        return "IdentifiableSimpleMemset"