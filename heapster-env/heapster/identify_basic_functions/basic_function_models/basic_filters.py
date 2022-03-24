
def filter(f):
    def _wrapped(*args, **kwargs):
        def _f(func_to_analyze):
            return f(func_to_analyze, *args, **kwargs)
        return _f
    return _wrapped

'''
The number of calls in the function must be 0.
IDEA: We don't expect basic functions to make other calls
but they are usually self-contained.
'''
@filter
def callless_filter(f):
    return len(f.get_call_sites()) == 0

'''
The function has not already been hooked.
'''
@filter
def standard_function_filter(f):
    return not (f.is_simprocedure or f.is_plt or f.is_syscall)

'''
Just a filter on the number of basic blocks.
We don't expect these functions to be HUGE.
'''
@filter
def basic_block_filter(f, n_blocks=30):
    return len(list(f.blocks)) <= n_blocks

'''
Another filter based on the size of the function.
Again, we don't expect these functions to be HUGE.
'''
@filter
def byte_size_filter_max(f, n_bytes=500):
    return f.size <= n_bytes

'''
Another filter based on the size of the function.
'''
@filter
def byte_size_filter_min(f, n_bytes=10):
    return f.size > n_bytes


'''
Filter out jump out instructions
'''
@filter
def only_jmp_ins_filter(f):
    if len(f.block_addrs_set) == 1:
        for b in f.blocks:
            block = b
        if block.vex.jumpkind == 'Ijk_Boring':
            return False
    return True