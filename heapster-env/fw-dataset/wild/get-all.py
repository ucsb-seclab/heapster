import os 
import shutil
import sys 
import subprocess
import wget 

REMOTE_FW_IMAGES_REPO = "https://github.com/ucsb-seclab/monolithic-firmware-collection/"
REMOTE_FW_LOAD_CONFIG_REPO = "https://raw.githubusercontent.com/ucsb-seclab/heapster-dataset-metadata/master/fw-load-confs/wild/{}/{}/conf.yaml"

REMOTE_FW_IMAGES_REPO1 = "https://github.com/ucsb-seclab/monolithic-firmware-collection/blob/master/ARMCortex-M/D_FIRMXRAYS/nordic/{}?raw=true"
REMOTE_FW_IMAGES_REPO2=  "https://github.com/ucsb-seclab/monolithic-firmware-collection/blob/master/ARMCortex-M/D_FIRMXRAYS/ti/{}?raw=true"
REMOTE_FW_IMAGES_REPO3=  "https://github.com/ucsb-seclab/monolithic-firmware-collection/blob/master/ARMCortex-M/D_FITBIT/ti/{}?raw=true"

REMOTE_FW_IMAGES_WILD = [REMOTE_FW_IMAGES_REPO1,REMOTE_FW_IMAGES_REPO2,REMOTE_FW_IMAGES_REPO3]

WILD_FW_FOLDER = "./"

# This script downloads the entire Heapster's dataset in ./wild
if __name__ == '__main__':

    with open("./fw-tested.txt", "r") as f:
        fw_tested_list = [x.strip() for x in f.readlines()]
    
    print("You are about to download the entire dataset! :)")

    # Ok, you want something we have actually tested, good.
    for firmware_name in fw_tested_list:
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
        
        for URI in REMOTE_FW_IMAGES_WILD:
            firmware_uri = URI.format(firmware_name)
            
            found = False
            # Download it 
            try:
                wget.download(firmware_uri, out=fw_analysis_folder)
                found = True
            except:
                continue
            
            if not found:
                # Remove created folder if something goes wrong
                print("\n[FATAL] Could not find file at {}".format(firmware_uri))
                shutil.rmtree(fw_analysis_folder)
                break  # Go to next firmware 
            else:
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
                    break
                else:
                    print("\n[INFO] Firmware {} ready to be analyzed in {}".format(firmware_name, fw_analysis_folder))

    

        

        
        




    

    
