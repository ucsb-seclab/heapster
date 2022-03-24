from .ident import *
from .basic_filters import *

class IdentifiableMemcmp(IdentifiableFunction):
    def can_be_consistent_with(self, project, func):
        filters = [callless_filter(), standard_function_filter(), basic_block_filter(30), byte_size_filter_max(500)]
        for f in filters:
            if not f(func):
                return False

        return True

        
    def produce_queries(self):
        queries = [
            (PointerWrapper(b"asdf"), PointerWrapper(b"asdf"), 4),      # =0
            (PointerWrapper(b"asdf"), PointerWrapper(b"bsdf"), 4),      # <0
            (PointerWrapper(b"bsdf"), PointerWrapper(b"asdf"), 4),      # >0
            (PointerWrapper(b"asdf"), PointerWrapper(b"asdz"), 4),      # <0
            (PointerWrapper(b"asdg"), PointerWrapper(b"asda"), 4),      # >0
            
            #(PointerWrapper(b"\0sdf"), PointerWrapper(b"\0sdf"), 4),   # =0
            #(PointerWrapper(b"\0sdg"), PointerWrapper(b"\0sdf"), 4),   # >0
            #(PointerWrapper(b"\0sdf"), PointerWrapper(b"\0sdg"), 4),   # <0
            #(PointerWrapper(b"\0sdf"), PointerWrapper(b"\0sdg"), 3),   # =0
            #(PointerWrapper(b"\0sdg"), PointerWrapper(b"\0sdf"), 3),   # =0
            #(PointerWrapper(b"\0sdf"), PointerWrapper(b"\0sdg"), 4),   # <0
        ]

        return queries

    def _real_memcmp(self, a, b, size):
        for i in range(size):
            if a[i] != b[i]:
                return a[i] - b[i]
        return 0

    def check_consistency(self, project, func, result):
        success, args, state, error_msg = result
        
        if not success:
            return None
        if len(args) < 3:
            return None

        if type(args[0]) is not PointerWrapper or type(args[1]) is not PointerWrapper or type(args[2]) is PointerWrapper:
            return None

        if args[2] > 1000:
            return None # probably timed out, let's not say no
        cc = project.factory.cc()
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
    
        if content_dst != orig_dst:
            return False

        if content_src != orig_src:
            return False

        retval = cc.return_val.get_value(state)
        res = state.solver.eval_one(retval)
        expres = self._real_memcmp(content_dst, content_src, length)
        return expres == res

    def __str__(self):
        return "IdentifiableMemcmp"