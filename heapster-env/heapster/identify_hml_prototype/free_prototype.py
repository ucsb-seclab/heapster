
import logging

'''
Get the prototype of free given the 
identified arguments.
'''
def get_free_prototype(free, free_args_dict):
    free_prototype = {}
    free_prototype_string = "void free(" 
    for x in range(0, len(free_args_dict)):
        free_prototype_string = free_prototype_string + "ARG_{},".format(x)
    free_prototype_string = free_prototype_string[:-1] + ")"

    found_arg_ptr_to_free = False
    i = 0
    unknown_free_args_counter = 0 

    for arg_k in sorted(free_args_dict):
        free_arg_info = free_args_dict[arg_k]
        arg_name = "arg_{}".format(i)
        
        if free_arg_info.is_ptr_to_free == True:
            free_prototype[arg_name] = "ptr_to_free"
            free_prototype_string = free_prototype_string.replace("ARG_{}".format(i), "unsigned int * {}".format(arg_name))
            found_arg_ptr_to_free  = True
        else:
            free_prototype[arg_name] = arg_name
            free_prototype_string = free_prototype_string.replace("ARG_{}".format(i), "size_t {}".format(arg_name))
            unknown_free_args_counter += 1 
        i = i + 1

    return free_prototype, free_prototype_string, unknown_free_args_counter