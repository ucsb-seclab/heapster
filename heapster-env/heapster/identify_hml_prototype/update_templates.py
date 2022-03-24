
import logging 

l = logging.getLogger("heapster.get_hml_prototype.update_templates")
l.setLevel(logging.DEBUG)

'''
Update the gen_zoo template with the information regarding
malloc.
'''
def update_template_malloc(gen_zoo_template, malloc_prototype):
    param_idx = 0
    malloc_unk_args_cnt = 0
    malloc_call = "malloc(" 
    for malloc_param_key, malloc_param_value in malloc_prototype.items():
        if malloc_param_key == 'ret':
            continue
        # Every parameter that is not 'req_size' points to the sym_data.
        if param_idx != 0:
            malloc_call = malloc_call + ","
        if malloc_param_value != 'size':
            malloc_call = malloc_call + "malloc_sym_args[{}][{}]"
            malloc_unk_args_cnt+=1
        else:
            malloc_call = malloc_call + "malloc_sizes[{}]"
        param_idx = param_idx + 1
    malloc_call = malloc_call + ")"
    gen_zoo_template = gen_zoo_template.replace("XXX_MALLOC_CALL_XXX", malloc_call)
    return gen_zoo_template, malloc_call

'''
Update the gen_zoo template with the information regarding
free.
'''
def update_template_free(gen_zoo_template, free_prototype, free_args_dict):
    param_idx = 0
    free_unk_args_cnt = 0
    free_call = "free(" 
    for free_param_key, free_param_value in free_prototype.items():
        if free_param_key == 'ret':
            continue   
        # Every parameter that is not `ptr_to_free` points to the sym_data.
        if param_idx != 0:
            free_call = free_call + ","
        if free_param_value != 'ptr_to_free':
            # Get the information regarding this unknown param from
            # the free_args_dict.
            curr_arg_info = list(free_args_dict.values())[param_idx]
            free_call = free_call + "free_sym_args[{}][{}]"
            free_unk_args_cnt += 1
        else:
            free_call = free_call + "ctrl_data_{}.global_var"
        param_idx = param_idx + 1 
    free_call = free_call + ")"
    gen_zoo_template = gen_zoo_template.replace("XXX_FREE_CALL_XXX", free_call)
    return gen_zoo_template, free_call

'''
Update the gen_zoo template with the information regarding
fake free.
'''
def update_template_fake_free(gen_zoo_template, free_prototype, free_args_dict):
    # Handling fake free call
    param_idx = 0
    fake_free_call = "free(" 
    for free_param_key, free_param_value in free_prototype.items():
        if free_param_key == 'ret':
            continue
        # Every parameter that is not `ptr_to_free` points to the sym_data.
        if param_idx != 0:
            fake_free_call = fake_free_call + ","
        if free_param_value != 'ptr_to_free':
            # Get the information regarding this unknown param from
            # the free_args_dict.
            curr_arg_info = list(free_args_dict.values())[param_idx]
            fake_free_call = fake_free_call + "free_sym_args[{}][{}]"
        else:
            fake_free_call = fake_free_call + "((uint8_t *) &sym_data.data) + mem2chunk_offset"
        param_idx = param_idx + 1 
    fake_free_call = fake_free_call + ")"
    gen_zoo_template = gen_zoo_template.replace("XXX_FAKE_FREE_CALL_XXX", fake_free_call)
    return gen_zoo_template, fake_free_call

'''
Update the gen_zoo template with the information regarding
double free.
'''
def update_template_double_free(gen_zoo_template, free_prototype, free_args_dict):
    # Handling double free call
    param_idx = 0
    double_free_call = "free(" 
    for free_param_key, free_param_value in free_prototype.items():
        if free_param_key == 'ret':
            continue
        # Every parameter that is not `ptr_to_free` points to the sym_data.
        if param_idx != 0:
            double_free_call = double_free_call + ","
        if free_param_value != 'ptr_to_free':
            # Get the information regarding this unknown param from
            # the free_args_dict.
            curr_arg_info = list(free_args_dict.values())[param_idx]
            double_free_call = double_free_call + "free_sym_args[{}][{}]"
        else:
            double_free_call = double_free_call + "ctrl_data_{}.global_var"
        param_idx = param_idx + 1 
    double_free_call = double_free_call + ")"
    gen_zoo_template = gen_zoo_template.replace("XXX_DOUBLE_FREE_CALL_XXX", double_free_call)
    return gen_zoo_template, double_free_call