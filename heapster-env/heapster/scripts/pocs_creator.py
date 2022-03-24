import os 
import sys
import requests
import shutil 
import subprocess
import yaml
import hashlib

from models import *

from sqlalchemy import create_engine
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker


# CONFIG 
hb_file = ["hb_state.json", "XXX.proj", "hh_analysis_template.yaml", "gen_zoo.py"]

deep_level_start = 2 
deep_level_max = 8

# generic config for heaphopper
heaphopper_base_config_path = "/root/heapster/heapster/data/hh_global_analysis_template.yaml"
# where to put experiments artifact
heapster_exps_folder = "/root/heapster/heaphopper_analyses/"
# heaphopper gen_zoo.py folder
heapster_gen_script_path = "/root/heapster/heaphopper/heaphopper/gen/gen_zoo.py"
# list of all exploit primitives
exploit_primitives = ["<OVERFLOW>", "<FAKE_FREE>", "<DOUBLE_FREE>", "<ARB_RELATIVE_WRITE>", "<UAF>", "<SINGLE_BITFLIP>"]
exploit_primitives_active = ["<OVERFLOW>", "<FAKE_FREE>", "<DOUBLE_FREE>", "<UAF>"]

# list of vulns to prove
vulns = ["bad_alloc", "overlap_alloc", "arb_write"]
hh_blob_configs_names = ["analysis_arb_write.yaml", "analysis_bad_alloc.yaml", "analysis_overlap_alloc.yaml", "analysis_arb_write_full.yaml"]

#heaphopper commands
heaphopper_gen_zoo  = "python3 /root/heapster/heaphopper/heaphopper_client.py gen -c <HH_GLOBAL_CONFIG>"

# Connect and create the fuzzer database if it doesn't exist.
def connect_to_db(curr_exp_topdir, blob_name):
    db_name = curr_exp_topdir + "/heapster_exps_" + blob_name + ".db"
    if not os.path.isfile(db_name):
        db_file = open(db_name, "w")
        db_file.close()
        db_engine = create_engine('sqlite:///{}'.format(db_name))
        Base.metadata.create_all(db_engine)
    else:
        db_engine = create_engine('sqlite:///{}'.format(db_name))
    
    DBSession = sessionmaker(bind=db_engine)
    db_session = DBSession()

    return db_session


def register_experiment(analysis_config_path, poc_path, db_session):
    string_id = analysis_config_path + poc_path
    exp_id = hashlib.md5(string_id.encode('utf-8')).hexdigest()

    new_experiment = Experiment(id=exp_id,
                                fuzzer_id=None,
                                poc_path=poc_path,
                                poc_tracing_total_time=None,
                                exp_total_time=None,
                                vuln='',
                                errors='')
    
    db_session.add(new_experiment)
    db_session.commit()

# Create a backup of the exp folder if it exists and the user decides so.
def mkdir_safe(folder_name):
    print("Creating exps folder at {}".format(folder_name))

    if os.path.isdir(folder_name):
        choice = input("The following folder {} already exists, deleting? [y/n]".format(folder_name))
        if choice == 'y':
            shutil.rmtree(folder_name)
        else:
            print("Renaming {} in {} and proceeding.".format(folder_name, folder_name + '_bak'))
            os.rename(folder_name, folder_name + "_bak")

    # Now we create the folder for this experiments
    os.mkdir(folder_name)


if __name__ == "__main__":

    blob_path = sys.argv[1]
    blob_name = os.path.split(blob_path)[1]

    curr_exp_topdir = os.path.join(heapster_exps_folder, blob_name)
    
    if os.path.exists(blob_path) and os.path.isfile(blob_path):
        print("Found binary to analyze at {}".format(blob_path))
        
        ####################################################
        # SANITY CHECKS
        ####################################################
        print("Now checking if we have all the needed file")
        dirname = os.path.dirname(blob_path)
        hb_state_dir = dirname + "/hb_analysis/"

        for file in hb_file:
            if "XXX" in file:
                file = file.replace("XXX", blob_name)
            file_path = hb_state_dir + file
            if os.path.isfile(file_path):
                print("{}...OK".format(file_path))
            else:
                print("Missing {}. Aborting.".format(file_path))
                sys.exit(-1)
        
        # Moving the gen_zoo.py file created by Slimer inside the HeapHopper directory.
        os.remove(heapster_gen_script_path)
        shutil.copyfile(hb_state_dir + "/gen_zoo.py", heapster_gen_script_path)
        
        #answer = input("Are you sure you wanna re-create all experiments folders for {}? [y/N]".format(blob_name))
        answer = "y"
        
        if answer == "y":
            curr_experiments_dir = os.path.join(heapster_exps_folder, blob_name)
            mkdir_safe(curr_experiments_dir)

            # Now we want to test depth from 2 to 6 for every exploit primitive.
            # The goal is to find the lowest number of transactions that can give me 
            # a specific vuln. We don't combine malicious transactions as for now.
            # This will give us the simplest transactions to trigger a vuln.
        
            for exp_primitive_tag in exploit_primitives_active:
                
                exp_primitive_name = exp_primitive_tag.lower()[1:-1]

                for deep_level in range(deep_level_start, deep_level_max):

                    folder_name = os.path.join(curr_experiments_dir, blob_name + "_" + exp_primitive_name + "_" + str(deep_level))
                    mkdir_safe(folder_name)
                    zoo_dir_path = os.path.join(folder_name, "zoo_dir") 
                    mkdir_safe(zoo_dir_path)
                    pocs_dir_path = os.path.join(folder_name, "pocs") 
                    mkdir_safe(pocs_dir_path)
                    # Now fixing the template 
                    with open(heaphopper_base_config_path, "r") as hh_config:
                        hh_config_data = hh_config.read()
                    
                    hh_config_data = hh_config_data.replace("<HB_STATE_PATH>" ,  hb_state_dir + "hb_state.json" )
                    hh_config_data = hh_config_data.replace("<ZOO_DEPTH>"     ,  str(deep_level))
                    hh_config_data = hh_config_data.replace("<BLOB_ZOO_DIR>"  ,  zoo_dir_path)
                    hh_config_data = hh_config_data.replace("<POCS_PATH>"     ,  pocs_dir_path)
                    hh_config_data = hh_config_data.replace("<HB_LOGFILE>"    ,  folder_name + "/hb_log_" + str(deep_level) + ".log")

                    #Now we set to -1 the exploit primitive we want and 0 to the other
                    exp_prim_to_zero = [x for x in exploit_primitives if x != exp_primitive_tag]
                    for e in exp_prim_to_zero:
                        hh_config_data = hh_config_data.replace(e, "0")
        
                    hh_config_data = hh_config_data.replace(exp_primitive_tag, "1")
                    new_config_path = os.path.join(folder_name + "/analysis.yaml") 

                    with open(new_config_path, "w") as new_hh_config:
                        print("Storing config at {}".format(new_config_path))
                        new_hh_config.write(hh_config_data)
                    
                    print("Generating zoo at {}".format(zoo_dir_path))

                    # Now we generate the zoo!
                    try:
                        cmd = heaphopper_gen_zoo.replace("<HH_GLOBAL_CONFIG>", new_config_path)
                        print("> Executing {}".format(cmd))
                        retcode = subprocess.call(cmd, shell=True)
                    except OSError as e:
                        print("Zoo generation failed")
                        sys.exit(-1)
                    
                    print("Compiling zoo at {}".format(zoo_dir_path))

                    # Now we compile every zoo
                    try:
                        cmd = "cd {} && make".format(zoo_dir_path)
                        print("[!] Executing {}".format(cmd))
                        retcode = subprocess.call(cmd, shell=True)
                    except OSError as e:
                        print("Zoo generation failed")
                        sys.exit(-1)

                    hh_analysis_template_path = hb_state_dir + "/hh_analysis_template.yaml"

                    with open(hh_analysis_template_path, "r") as hh_blob_config:
                        hh_blob_config_data_orig = hh_blob_config.read()
                    
                    for vuln in vulns:
                        hh_blob_config_data = hh_blob_config_data_orig.replace("<VULN_LIST>", "[{}]".format(vuln))
                        new_hh_blob_config_path = folder_name + "/analysis_{}.yaml".format(vuln) 
                        print("Storing config at {}".format(new_hh_blob_config_path))
                        with open(new_hh_blob_config_path, "w") as new_hh_blob_config:
                            new_hh_blob_config.write(hh_blob_config_data)
                            
                        # Generate the config for full arbitrary write.
                        if "arb_write" in vuln:
                            hh_blob_config_data = hh_blob_config_data_orig.replace("<VULN_LIST>", "[{}]".format(vuln))
                            hh_blob_config_data = hh_blob_config_data.replace("<ARB_WRITE_TYPE>", "FULL")
                            new_hh_blob_config_path = folder_name + "/analysis_{}_full.yaml".format(vuln) 
                            print("Storing config at {}".format(new_hh_blob_config_path))
                            with open(new_hh_blob_config_path, "w") as new_hh_blob_config:
                                new_hh_blob_config.write(hh_blob_config_data)
                        
            
        #pocs = [] 
        print("Creating DB at for {}".format(blob_name))
        
        db_session = connect_to_db(curr_exp_topdir, blob_name)

        ## Now we want to insert all the POC generated in the database 
        #print("Inserting experiments in the database")
        #for subdir, dirs, files in os.walk(curr_exp_topdir):
        #    for file in files:
        #        #print os.path.join(subdir, file)
        #        filepath = subdir + os.sep + file
        #        
        #        if filepath.endswith(".bin"):
        #            pocs.append(filepath)
        #
        #pocs = sorted(pocs)
        #for poc in pocs:
        #    for config in hh_blob_configs_names:
        #        analysis_config_path = poc.split("zoo_dir")[0] + config
        #        register_experiment(analysis_config_path, poc, db_session)
            
        print("Done")
    else:
        print("[ERROR] Is this a blob? {}".format(blob_path))

