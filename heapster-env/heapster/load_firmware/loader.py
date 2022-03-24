import angr
import archinfo
import logging
import os
import claripy
import struct
import sys 

from cle.backends import NamedRegion
from angr.analyses.cfg import CFGUtils

l = logging.getLogger("heapster.load_firmware.loader")
l.setLevel(logging.INFO)

def check_heap_range(project, heap_start, heap_end):
    if project.loader.find_object_containing(heap_start) and project.loader.find_object_containing(heap_end-1):
        return True
    else:
        return False 

def get_stack_init_from_ivt(stream, offset_ivt=0):
    stream.seek(offset_ivt)
    try:
        maybe_sp = stream.read(4)
        maybe_sp = struct.unpack('<I', maybe_sp)[0]
        return maybe_sp
    except:
        l.exception("Something died")
        return None
    finally:
        stream.seek(0)

def get_ep_from_ivt(stream, offset_ivt=0):
    stream.seek(offset_ivt)
    try:
        _ = stream.read(4)
        ep = stream.read(4)
        ep = struct.unpack('<I', ep)[0]
        return ep
    except:
        l.exception("Something died")
        return None
    finally:
        stream.seek(0)

supported_archs = ["ARMCortexM"]

#fw_config["ram-regions"]
def get_regions(blob_regions, arch, new_regions, default_name):

    for i, rr in enumerate(new_regions):
        assert(rr[2] > rr[1])

        # Extract the name for this region
        if rr[0] != "":
            if rr[0] not in blob_regions.keys():
                region_name = rr[0]
            else:
                region_name = rr[0] + "_{}".format(i)
        else:
            region_name = "{}_{}".format(default_name, i)
        
        blob_regions[region_name] = {}

        # Is this backed by a binary or not?
        region_backer = None
        if rr[3] != "":
            if os.path.isfile(rr[3]):
                # Append the filename, this is handled by CLE.
                region_backer = rr[3]
                ramdisk_size = os.path.getsize(region_backer)
                if rr[2] - rr[1] > ramdisk_size:
                    l.critical("[!] The loaded ramdisk is smaller than the specified ram addresses!")
                    l.critical("[!] Ramdisk size: {} | Configured RAM: {}".format(ramdisk_size, rr[2]-rr[1]))
                # Options to load this
                blob_regions[region_name]["backer_type"] = "ramdisk"
                blob_regions[region_name]["backer_name"] = os.path.basename(region_backer)
                blob_regions[region_name]["backer"] = region_backer
                blob_regions[region_name]["lib_opts"] = {}
                blob_regions[region_name]["lib_opts"]["backend"] = "blob"
                blob_regions[region_name]["lib_opts"]["entry_point"] = 0x0
                blob_regions[region_name]["lib_opts"]["base_addr"] = rr[1]
                blob_regions[region_name]["lib_opts"]["arch"] = arch
            else:
                l.critical("[!]Not a valid file at {}".format(rr[3]))
                sys.exit(0)
        else:
            blob_regions[region_name]["backer"] = NamedRegion(region_name, rr[1], rr[2])
            blob_regions[region_name]["backer_type"] = "CLE_named_region"

    return blob_regions

def load_it(blob_path, fw_config):

    l.info("[+]Parsing Firmware config")

    if fw_config["arch"] not in supported_archs:
        l.critical("Arch {} not supported.")
        l.critical("    Currently supporting: {}".format(supported_archs))
        sys.exit(0)

    # Mapping RAM
    blob_regions = {}
    get_regions(blob_regions, fw_config["arch"], fw_config["ram-regions"], "ram")
    get_regions(blob_regions, fw_config["arch"], fw_config["mmio-regions"], "mmio")
    get_regions(blob_regions, fw_config["arch"], fw_config["scb-regions"], "scb")
    get_regions(blob_regions, fw_config["arch"], fw_config["extra-regions"], "extra-region")
    
    blob_entry_point = fw_config["entry-point"]
    if blob_entry_point == 0x0:
        if fw_config["has-ivt"]:
            l.info("[+]Trying to extract entry point from IVT table at offset +0x{}".format(fw_config["offset-ivt"]))
            blob_stream = open(blob_path, "rb") 
            ivt_entry_point = get_ep_from_ivt(blob_stream, fw_config["offset-ivt"])
            if ivt_entry_point:
                l.info("[+] Identified entry point of blob at {}".format(hex(ivt_entry_point)))
                blob_entry_point = ivt_entry_point
            else:
                l.critical("[!] Cannot retrieve entry point from IVT. Trying with 0x0.")
                blob_entry_point = 0x0

    l.info("[+]Creating Firmware Project")

    # Create project with information retrieved before.
    lib_opts = {os.path.basename(v["backer"]):v["lib_opts"] for (k,v) in blob_regions.items() 
                                                                if blob_regions[k]["backer_type"] == "ramdisk"}
    p = angr.Project(blob_path, main_opts={
                                           'base_addr': fw_config["base-address"], 
                                           'arch': fw_config["arch"], 
                                           'entry_point': blob_entry_point, 
                                           'backend': 'blob'
                                          },
                                load_options={
                                        'force_load_libs': [ x["backer"] for x in blob_regions.values()],
                                        'lib_opts': lib_opts
                                        }
                    )

    # Getting info on heap region 
    heap_region = fw_config["heap-region"][0]
    if check_heap_range(p, heap_region[0], heap_region[1]):
        p.heap_start = heap_region[0]
        p.heap_end = heap_region[1]
        l.info("[+]Considering addresses from {} to {} as possible heap region".format(hex(p.heap_start), hex(p.heap_end)))
    else:
        l.critical("!!!WARNING!!!: Heap region specified does not completely fall in mapped regions.")
        for o_idx, o in enumerate(p.loader.all_objects):
            l.critical("[!]Region {}: {}".format(o_idx,o))
        l.critical("[!]Heap boundaries: {}->{}".format(hex(heap_region[0]), hex(heap_region[1])))

    blob_stack_pointer = fw_config["stack-pointer"]
    if blob_stack_pointer != 0x0:
        p.arch.initial_sp = blob_stack_pointer
    else:
        if fw_config["has-ivt"]:
            blob_stream = open(blob_path, "rb")
            stack_ptr = get_stack_init_from_ivt(blob_stream, fw_config["offset-ivt"])
            if stack_ptr:
                p.arch.initial_sp = stack_ptr
            else:
                l.critical("Cannot retrieve stack value from IVT. Using beginning of RAM, this can be wrong.")
                p.arch.initial_sp = blob_ram_regions[0][0]
    
    # Fix stack pointer if it is odd number
    if p.arch.initial_sp % 2 == 1:
        l.info("[!]Correcting stack pointer initial value (odd).") 
        l.info("[!] Rounding {} to {}".format(hex(p.arch.initial_sp), 
                                              hex(p.arch.initial_sp & 0xfffffff8)))
        p.arch.initial_sp = p.arch.initial_sp & 0xfffffff8

    l.info("[+]Setting initial stack pointer at {}".format(hex(p.arch.initial_sp)))

    l.info("[+]Blob loaded.")
    for o_idx, o in enumerate(p.loader.all_objects):
        l.info("[+] Region {}: {}".format(o_idx,o))
    return p

def cfg_it(p, fw_config): 
    l.info("[+]Building CFG")
    regions = None if not fw_config["only-rom"] else [(p.loader.main_object.min_addr, p.loader.main_object.max_addr)]
    if regions:
        l.info("[+] Considering only the following regions for CFG building")
        for i,r in enumerate(regions): 
            l.info("[+]  Region {}: {} -> {}".format(i,hex(r[0]),hex(r[1])))

    cfg = p.analyses.CFG(resolve_indirect_jumps=True, 
                         cross_references=True, 
                         force_complete_scan=False, 
                         function_prologues=fw_config["function-prologues"],
                         show_progressbar=True,
                         normalize=True, 
                         symbols=True, 
                         start_at_entry=fw_config["start-at-entry"],
                         regions=regions
                         )
    if fw_config["complete-calling-convention"]:
        p.analyses.CompleteCallingConventions(recover_variables=True,
                                              analyze_callsites=True,
                                              force=True)
    return cfg

