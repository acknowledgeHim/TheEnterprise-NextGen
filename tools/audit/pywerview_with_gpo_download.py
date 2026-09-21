#------------ Used to mount a share to DC and pull back the GPO <GPO PATH>/Machine/Microsoft/Windows NT/SecEdit/GptTmpl.inf file --
import os
import shutil
import subprocess
from glob import glob

def mount(remote_dir, local_dir):
    """Mounts a remote directory and chooses a local file in which to mount the directory against"""
    retcode = subprocess.call(["/sbin/mount", "-t", "smbfs", remote_dir, local_dir])

def unmount(local_dir):
    """Unmounts the local SMB directory"""
    retcode = subprocess.call(["/sbin/umount", local_dir])

def getFileContents(directory):
    """Creates a list of files within a directory"""
    f = []
    for (dirpath, dirnames, filenames) in os.walk(directory):
        f.extend(filenames)
        break
    return f

def printChoices(local_dir):
    """Used to print a list of numbered list of files in a directory"""
    num = 1
    a = getFileContents(local_dir)
    for item in a:
        print(str(num) + ".", item)
        num +=1

def listDirectory(directory):
    return glob(directory)

def selectSingleFile(local_dir, destination):
    '''Used to get the contents of a directory and select a single file to copy to a destination
    --requires printChoices() and getFileContents()
    '''
    a = getFileContents(local_dir)
    printChoices(local_dir)
    b = int(input("please select your choice: "))
    shutil.copy2(local_dir+(a[b-1]), destination)

# ------------------------
import json
import sys
import shlex
import urllib.request
from common import print_text, common
from smb.SMBHandler import SMBHandler

def pywerview_run(command, scope_id, location_id, db_object, log_id, pywerview_args):
    """ pywerview_run """

    try:
        pywerview_values = json.loads(pywerview_args)
        print("54 pwerview_with_gpo_download pywerview_values: " + str(pywerview_values))
        log_info = db_object.view("Log", None, ["id"], [log_id])
        log_source = log_info[0]['source']
        #output_path = log_info[0]['output_filepath']

        domain_controller = log_info[0]['target']

        command = command.replace('"', '')
        output_file_path = log_info[0]['output_filepath']
        target = command[command.find(";")+1:]

        # Output file name
        output_file = output_file_path + "pywerview__" + str(log_id) + "__" + target + ".txt"

        common.create_path(output_file_path)

        cmd = pywerview_values["pythonv2_path"] + " " + pywerview_values["pywerview_path"] + "/pywerview.py " + \
              "get-netgpo -w " + pywerview_values["domain"] + " -u " + pywerview_values["la_da_username"] + " -p " + \
              pywerview_values["la_da_password"] + " -t " + domain_controller
        print("70 pwerview_with_gpo_download cmd: " + str(cmd))
        # Grab list of GPOs using pywerview.py
        with open(output_file, "w") as outfile:
            process = subprocess.Popen(shlex.split(cmd), stderr=subprocess.PIPE, stdout=outfile)

        print("78 pywerview_with_gpo_download output_file: " + str(output_file))
        # Now go through all the GPOs listed and download each one :)
        with open(output_file, 'r') as gpo_listing:
            gpo_listing_string = gpo_listing.read()
            print("81 pywerview_with_gpo_download gpo_listing_string: " + str(gpo_listing_string))
            while "displayname:" in gpo_listing_string:
                display_name_line =  gpo_listing_string[gpo_listing_string.find("displayname:"):]
                display_name_line = display_name_line[:display_name_line.find("\n")]
                display_name = display_name_line[display_name_line.find(" ")+1:].lstrip(" ").lstrip("\t")
                print("86 pywerview_with_gpo_download display_name: " + str(display_name))
                gpo_file_path_line = gpo_listing_string[gpo_listing_string.find("gpcfilesyspath:"):]
                gpo_file_path_line = gpo_file_path_line[:gpo_file_path_line.find("\n")]
                gpo_file_path = gpo_file_path_line[gpo_file_path_line.find("\\\\") + 2:]
                gpo_file_path = gpo_file_path[gpo_file_path.find("\\"):].replace("\\", "/")
                #gpo_file_path = "//" + pywerview_values['la_da_username'] + "@" + gpo_file_path + \
                file_path = "/Machine/Microsoft/Windows NT/SecEdit/GptTmpl.inf"
                print("91 pywerview_with_gpo_download.py gpo_file_path: " + str(gpo_file_path))

                # Connect to SMB share and pull the file
                #conn = SMBConnection(pywerview_values["la_da_username"], pywerview_values["la_da_password"], domain_controller, 'SERVER', use_ntlm_v2=True)
                director = urllib.request.build_opener(SMBHandler)
                file_object = director.open('smb://' + pywerview_values["la_da_username"] + ':' + pywerview_values["la_da_password"] + '@'+ domain_controller + gpo_file_path)
                with open(output_file_path, 'w') as gpo:
                    gpo.write(domain_controller + "\n")
                    gpo.write(display_name + "\n")
                    for line in file_object:
                        gpo.write(line)
                file_object.close()

                # jump past one just did
                gpo_listing_string = gpo_listing_string[gpo_listing_string.find("displayname:") + 12:]

    except Exception as e:
        print_text.print_error("pywerview except: " + str(e) + " Error on line {}".format(sys.exc_info()[-1].tb_lineno))
