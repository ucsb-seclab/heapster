'''
Used to generated the config to generate the POCs
with HeapHopper.
'''

import os 
import sys 
import json
from datetime import date 

hh_analysis_original = "/root/.heapster-env-conf/hh_analysis_original.yaml"

if __name__ == "__main__":

    blob_absolute_path = sys.argv[1]

    if not os.path.isfile(blob_absolute_path):
        print("FATAL: Can't find file at {}".format(blob_absolute_path))
        sys.exit(1)

    dirname = os.path.dirname(blob_absolute_path)
    hb_state_dir = dirname + "/hb_analysis/"
    hb_state_path = hb_state_dir + "/hb_state.json"

    print("Opening {}".format(hb_state_path))
    with open(hb_state_path, "r") as hb_file:
        hb_state = json.load(hb_file)
    
    if not hb_state.get("final_allocator", None):
        print("No final allocator for {}".format(blob_absolute_path))
        sys.exit(1)

    with open(hh_analysis_original, "r") as hh_analysis_original_file:
        hh_original = hh_analysis_original_file.read()
    
    hb_folder = hb_state["hb_folder"]
    allocator = hb_state["dir_name"] + "/" + hb_state["blob_name"]
    libc = hb_state["dir_name"] + "/" + hb_state["blob_name"]
    header_size = hb_state["header_size"]
    mem2chunk_offset = hb_state["mem2chunk_offset"]
    malloc_addr = hb_state["final_allocator"]["malloc"]
    free_addr = hb_state["final_allocator"]["free"]
    malloc_prototype = hb_state["malloc_prototype"]
    malloc_prototype_string = hb_state["malloc_prototype_string"]
    free_prototype_string = hb_state["free_prototype_string"]
    free_prototype = hb_state["free_prototype"]
    malloc_unk_args = hb_state["malloc_unknown_arguments_vals"]
    free_unk_args = hb_state["free_unknown_arguments_vals"]

    hh_main_config_blob = hh_original.replace("<HB_STATE_PATH>", hb_folder + "/hb_state.json")
    hh_main_config_blob = hh_main_config_blob.replace("<ALLOCATOR_PATH>", allocator)
    hh_main_config_blob = hh_main_config_blob.replace("<LIBC_PATH>", libc)
    hh_main_config_blob = hh_main_config_blob.replace("<HEADER_SIZE>", str(header_size))
    hh_main_config_blob = hh_main_config_blob.replace("<MEM2CHUNK_OFFSET_SIZE>", str(mem2chunk_offset))
    hh_main_config_blob = hh_main_config_blob.replace("<MALLOC_ADDR>", malloc_addr)
    hh_main_config_blob = hh_main_config_blob.replace("<MALLOC_PROTOTYPE_DICT>", malloc_prototype)

    malloc_unk_args = str(malloc_unk_args)
    malloc_unk_args = malloc_unk_args.replace("r0", "arg_0")
    malloc_unk_args = malloc_unk_args.replace("r1", "arg_1")
    malloc_unk_args = malloc_unk_args.replace("r2", "arg_2")
    malloc_unk_args = malloc_unk_args.replace("r3", "arg_3")
    malloc_unk_args = malloc_unk_args.replace("r4", "arg_4")
    malloc_unk_args = malloc_unk_args.replace("r5", "arg_5")

    hh_main_config_blob = hh_main_config_blob.replace("<MALLOC_UNK_ARGS_DICT>", str(malloc_unk_args))
    hh_main_config_blob = hh_main_config_blob.replace("<MALLOC_PROTOTYPE_STRING>", malloc_prototype_string)
    hh_main_config_blob = hh_main_config_blob.replace("<FREE_ADDR>", free_addr)
    hh_main_config_blob = hh_main_config_blob.replace("<FREE_PROTOTYPE_DICT>", free_prototype)

    free_unk_args = str(free_unk_args)
    free_unk_args = free_unk_args.replace("r0", "arg_0")
    free_unk_args = free_unk_args.replace("r1", "arg_1")
    free_unk_args = free_unk_args.replace("r2", "arg_2")
    free_unk_args = free_unk_args.replace("r3", "arg_3")
    free_unk_args = free_unk_args.replace("r4", "arg_4")
    free_unk_args = free_unk_args.replace("r5", "arg_5")


    hh_main_config_blob = hh_main_config_blob.replace("<FREE_UNK_ARGS_DICT>", str(free_unk_args))
    hh_main_config_blob = hh_main_config_blob.replace("<FREE_PROTOTYPE_STRING>", free_prototype_string)

    new_hh_analysis_original = hb_folder + "/hh_analysis_template.yaml"

    with open(new_hh_analysis_original, "w") as hh_analysis_original_file:
        hh_analysis_original_file.write(hh_main_config_blob)
        hh_analysis_original_file.write("\n\n\n#Auto genereated on {}".format(date.today()))
    
    print("Generated heaphopper config file at {}".format(new_hh_analysis_original))