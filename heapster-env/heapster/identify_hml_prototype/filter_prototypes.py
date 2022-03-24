
'''
Here we want to filter all the allocators 
for which we do not support their prototype.
'''

import logging
l = logging.getLogger("heapster.get_hml_prototype.filter_prototype")
l.setLevel(logging.DEBUG)

'''
We require the malloc to receive a size in input.
This for instance will filter out Balloc and similar.
'''
def malloc_no_size_argument(project, hml_pair, base_state):
    # Extract information 
    malloc = int(hml_pair["malloc"], 16)
    malloc = project.cfg.functions.get(malloc,None)
    working_malloc_ct = hml_pair["malloc_ct"]
    assert(malloc)

    possible_int_value = False
    for arg_name, arg_value in working_malloc_ct.items():
        # A reasonable MAX for an allocation in a firmware...
        if arg_value >= 0 and arg_value <= 10000:
            possible_int_value = True
    
    if possible_int_value:
        return False # We found an integer value, do not filter this malloc 
    else:
        return True  # We found only pointers, filter this malloc.






