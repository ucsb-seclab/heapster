import os 
import shutil
import sys 
import subprocess
import wget 

REMOTE_FW_IMAGES_REPO = "https://github.com/ucsb-seclab/monolithic-firmware-collection/"
REMOTE_FW_LOAD_CONFIG_REPO = "https://raw.githubusercontent.com/ucsb-seclab/heapster-dataset-metadata/master/fw-load-confs/wild/{}/{}/conf.yaml"
WILD_FW_FOLDER = "./"

# PLEASE READ THE README BEFORE! :)
# 
# YOU CAN FEED THESE KIND OF LINK TO THE SCRIPT IF THE FIRMWARE IS HOSTED SOMEWHERE 
# https://github.com/ucsb-seclab/monolithic-firmware-collection/blob/master/ARMCortex-M/D_FIRMXRAYS/nordic/105_V2.1.3_20170828.bin@5bee5a33aebff656bbf1d1f46865b382?raw=true
# Usage:
#       python get-fw.py <FIRMWARE_BIN_URI>
#
if __name__ == '__main__':
    firmware_uri = sys.argv[1]
    firmware_name = firmware_uri.split("/")[-1].replace("?raw=true",'')

    with open("./fw-tested.txt", "r") as f:
        fw_tested_list = [x.strip() for x in f.readlines()]
    
    # Ok, you want something we have actually tested, good.
    if firmware_name in fw_tested_list:
        fw_analysis_folder = os.path.join(WILD_FW_FOLDER, firmware_name)
        isExist = os.path.exists(fw_analysis_folder)

        # Create the analysis folder 
        if not isExist:
            os.makedirs(fw_analysis_folder)
        else:
            answer = input("\n[WARNING] The folder at {} exists, continue? [y/N]: ".format(fw_analysis_folder))
            if answer == "y" or answer == "Y":
                shutil.rmtree(fw_analysis_folder)
                os.makedirs(fw_analysis_folder)
            else:
                sys.exit(0)
        
        # Download it 
        try:
            wget.download(firmware_uri, out=fw_analysis_folder)
        except:
            # Remove created folder if something goes wrong
            print("\n[FATAL] Could not find file at {}".format(firmware_uri))
            shutil.rmtree(fw_analysis_folder)
            sys.exit(-1)
        
        # Download the load conf
        firmware_load_conf_uri_nordic = REMOTE_FW_LOAD_CONFIG_REPO.format("nordic", firmware_name)
        firmware_load_conf_uri_ti = REMOTE_FW_LOAD_CONFIG_REPO.format("ti", firmware_name)
        firmware_load_conf_uri_fitbit = REMOTE_FW_LOAD_CONFIG_REPO.format("fitbit", firmware_name)

        load_config_uris = [firmware_load_conf_uri_nordic,firmware_load_conf_uri_ti,firmware_load_conf_uri_fitbit]
        found=False
        for conf_uri in load_config_uris:
            try:
                wget.download(conf_uri, out=fw_analysis_folder)
                found = True
                break
            except:
                continue
        if not found:
            print("\n[FATAL] Could not find config for the tested firmware?! I tried: ")
            for x in load_config_uris:
                print("    {}".format(x))
            print("[FATAL] Please ping me at degrigis@ucsb.edu!")
            shutil.rmtree(fw_analysis_folder)
            sys.exit(-1)
        else:
            print("\n[INFO] Firmware ready to be analyzed in {}".format(fw_analysis_folder))
    else:
        print("[WARNING] You are about to download a firmware not tested in our dataset")
        print("[WARNING] Make sure to write a proper conf.yaml for loading and that is a CortexM image!")
        print("[WARNING] May the force be with you :-)")
        print("[WARNING]            @degrigis")

        fw_analysis_folder = os.path.join(WILD_FW_FOLDER, firmware_name)
        isExist = os.path.exists(fw_analysis_folder)

        # Create the analysis folder 
        if not isExist:
            os.makedirs(fw_analysis_folder)
        else:
            answer = input("\n[WARNING] The folder at {} exists, continue? [y/N]: ".format(fw_analysis_folder))
            if answer == "y" or answer == "Y":
                shutil.rmtree(fw_analysis_folder)
                os.makedirs(fw_analysis_folder)
            else:
                sys.exit(0)
        
        # Download it 
        try:
            wget.download(firmware_uri, out=fw_analysis_folder)
        except:
            # Remove created folder if something goes wrong
            print("\n[FATAL] Could not find file at {}".format(firmware_uri))
            shutil.rmtree(fw_analysis_folder)
            sys.exit(-1)\
        
        print("\n[INFO] Dropping generic loading config in the folder too")
        shutil.copyfile("./.conf.yaml", fw_analysis_folder+"/conf.yaml")

    

        

        
        




    

    
