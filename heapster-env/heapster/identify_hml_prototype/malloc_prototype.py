
import logging

'''
Get the prototype of malloc given the 
identified arguments.
'''
def get_malloc_prototype(malloc, malloc_args_dict):
    malloc_prototype = {}
    malloc_prototype_string = "unsigned int * malloc(" 
    for x in range(0, len(malloc_args_dict)):
        malloc_prototype_string = malloc_prototype_string + "ARG_{},".format(x)
    malloc_prototype_string = malloc_prototype_string[:-1] + ")"
    malloc_prototype["ret"] = malloc.calling_convention.return_val.reg_name

    i = 0
    unknown_malloc_args_counter = 0 
    for arg_k in sorted(malloc_args_dict):
        malloc_arg_info =  malloc_args_dict[arg_k]
        arg_name = "arg_{}".format(i)
        if malloc_arg_info.is_size == True:
            malloc_prototype[arg_name] = "size"
            malloc_prototype_string = malloc_prototype_string.replace("ARG_{}".format(i), "int size")
        else:
            malloc_prototype[arg_name] = arg_name
            malloc_prototype_string = malloc_prototype_string.replace("ARG_{}".format(i), "size_t {}".format(arg_name))
            unknown_malloc_args_counter += 1 
        i = i + 1
    
    return malloc_prototype, malloc_prototype_string, unknown_malloc_args_counter