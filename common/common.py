import sys
import getpass
import re
import os
import pwd
import grp
import string
import random
import time
import subprocess, shlex
from operator import itemgetter
from threading import Timer
from common import print_text
from enterprise_conf import LINUX_GROUP

def get_tester():
    """Returns the current logged on user"""
    return getpass.getuser()

def get_line_matching_search(search, lines):
    matches = []
    for line in lines:
        if search.lower() in line.lower():
            matches.append(line)
    if len(matches) > 0:
        return matches
    return None

def all_regex_matches(entry, regex):
    """ Find all matching parts and return all matches. """
    if regex != "":
        try:
            matches = re.compile(regex).findall(entry)
            if len(matches) > 0:
                return matches
        except Exception as e:
            print_text.print_error("\tThe regex check is not proper regex.  Coder error!")
    return None

def regex_string_in_line(entry, search_string):
    if search_string != "":
        try:
            match = re.compile(r'^.*(' + search_string + ').*').findall(entry)
            if len(match) > 0:
                return match[0]
        except Exception as e:
            print_text.print_error("\tThe regex search is not proper.  Coder error!")
        return None

def regex_exist_in_entry(entry, regex, return_original=True):
    """
    Used to determine the that user input matches required pattern.
    Returns blank string if failed to find regex pattern in entry.

    Attributes
        entry -- string entry to validate against regular expression
        regex -- regular expression used to verify user input contains required pattern
    """
    try:
        entry = str(entry)
        if regex != "":
            match = re.compile(regex).findall(entry)
            if len(match) > 0:
                return match[0]
        if return_original:
            return entry
    except Exception as e:
        print("common.py 64 except: " + str(e) + " Error on line {}".format(sys.exc_info()[-1].tb_lineno))
        print_text.print_error("\tThe regex check is not proper regex.  Coder error!")
    return ''

def makedirsOLD(path):
    try:
        #os.makedirs(path)
        oldmask = os.umask(000)
        os.makedirs(path, 0o774)
        os.umask(oldmask)
        create_path(path) #sets permissions on last folder
        return True
    except OSError as e:
        print_text.print_error("\tFailed making necessary directory, " + str(path) + ".  Please check permissions.  Error: " + str(e) + " Error on line {}".format(sys.exc_info()[-1].tb_lineno))
        if os.path.isdir(path):
            pass
        else:
            print_text.print_error("\tFailed making necessary directory, " + str(path) + ".  Please check permissions.  Error: " + str(e))
            raise
    except Exception as e:
        print_text.print_error("\t82 common.py Failed making necessary directory, " + str(path) + ".  Please check permissions.  Error: " + str(e) + " Error on line {}".format(sys.exc_info()[-1].tb_lineno))

    return False

def merge_two_lists(list1, list2):
    """ merge 2 lists and remove duplicates. """
    return list(set(list1 + list2))

def merge_two_lists_of_dicts(list1, list2, unique_dictionary_key):
    """ merge 2 lists that are each dictionaries at indices"""
    return sorted(list1 + list2, key=itemgetter(unique_dictionary_key))

def merge_two_dicts(dict1, dict2):
    """
    Given two dicts, merge them into a new dict as a shallow copy.
    Returns the new dictionary.

    Attributes:
        dict1 -- 1st dictionary to merge
        dict2 -- 2nd dictionary to merge w/ 1st
    """
    new_dict = dict1.copy()
    new_dict.update(dict2)
    return new_dict

def assign_permissions(path_to_assign):
    try:
        uid = pwd.getpwnam(get_tester()).pw_uid
        gid = grp.getgrnam(LINUX_GROUP).gr_gid
        #print("113 common get_tester(): " + str(get_tester()))
        #print("114 common path_to_assign: " + str(path_to_assign))
        #print("115 common uid: " + str(uid))
        #print("116 common gid: " + str(gid))
        os.chown(path_to_assign, uid, gid)
    except Exception as e:
        #print_text.print_error("117 common/common Error: " + str(e))
        #print_text.print_error("\tThe 'LINUX_GROUP' value in enterprise_conf.py is not a valid group on your computer.  Please correct this before trying again.")
        pass
    try:
        os.chmod(path_to_assign, 0o774)
        return True
    except Exception as e:
        #print_text.print_error("122 common/common Error: " + str(e))
        #print_text.print_error("\t Failed updating the permissions for the folder path " + path_to_assign +".")
        return False
    return False

def create_path(path_to_create):
    """
    Creates necessary folder structure for client/engagement.
    Returns True if successful, False if not
    """
    try:
        #oldmask = os.umask(000)
        os.makedirs(path_to_create, 0o774)
        #os.umask(oldmask)
        #os.mkdir(path_to_create)
    except Exception as e:
        if "file exists" not in str(e).lower():
            print_text.print_error("\tFailed making the new folder " + path_to_create + ", except: " + str(e))

    if "/output/" in path_to_create:
        output_location = path_to_create.find("/output/") + 8
        output_path = path_to_create[:output_location]
        for root, dirs, files in os.walk(output_path):
            for d in dirs:
                assign_permissions(os.path.join(root,d))
            for f in files:
                file_path = os.path.join(root, f)
                if "/nmap/" not in file_path:
                    assign_permissions(file_path)
    return assign_permissions(path_to_create)


def create_filepath_if_not_exists(filepath):
    """
    Used to make sure the entire directory path is created and permissions properly set.
    :param filepath:
    :return:
    """
    if "media/" not in filepath:
        curr_path = os.path.dirname(os.path.dirname(os.path.abspath(__file__))) + "/media"
    else:
        curr_path = os.path.dirname(os.path.dirname(os.path.abspath(__file__))) + "/"
    dirs = filepath.split("/")
    for dir in dirs :
        curr_path = curr_path + "/" + dir
        if not os.path.isdir(curr_path) and "." not in dir :
            makedirOLD(curr_path)

def makedirOLD(path):
    """
    Creates the directory path that is passed.

    :param path: the directory path to create.
    :return: n/a
    """
    if not os.path.isdir(path):
        ipc_shell('mkdir ' + path)
        ipc_shell('chmod 774 ' + path)


def ipc_shell(shell_command):
    """
    Runs a command as a sub process.

    :param shell_command: the command to run
    :return: the standard output from the command
    """
    try:
        sub_process = subprocess.Popen(shell_command, shell=True, stdout=subprocess.PIPE)
        (std_out, std_err) = sub_process.communicate()
    except OSError as error:
        print_text.print_error("Command Failed:", error, " ", std_err)
    return std_out


def kill_proc(proc, timeout):
    """Kill process that has 'timed-out'"""
    timeout['value'] = True
    proc.kill()


def ipc_shell_timeout(shell_command, timeout_sec):
    """
    Runs command as subprocess with a timeout in seconds specified.
    Returns the subprocess returncode, standard out, standard error, and the timeout value.

    Argruments:
        shell_command -- the command that will be run in the sub process
        timeout_sec -- number of seconds to allow sub process to run before killing it
    """
    sub_process = subprocess.Popen(shlex.split(shell_command),stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    timeout = {"value": False}
    timer = Timer(timeout_sec, kill_proc, [sub_process, timeout])
    timer.start()
    stdout, stderr = sub_process.communicate()
    timer.cancel()
    return sub_process.returncode, stdout.decode("utf-8"), stderr.decode("utf-8"), timeout["value"]

def format_tool(tool):
    """ Format tool name used for filename, etc. """
    if " " in tool:
        tool = tool.replace(" ", "_")
    return tool

def remove_port_from_target(target):
    if target.count(":") > 1:
        target_no_port = target[:target.rfind(":")]
        return format_website(target_no_port)
    return target

def format_target(target):
    """ Format the 'target' string for use in the filename, etc. """
    if "http://" in target:
        target = target.replace("http://", "http_")
    if "https://" in target:
        target = target.replace("https://", "https_")
    if "/" in target:
        target = target.replace("/", "_")
    if ":" in target:
        target = target.replace(":", "-")
    if "," in target:
        target = target.replace(",", "-")
    if " " in target:
        target = target.replace(" ", "-")

    return target

def format_website(website):
    if "http://" in website:
        website = website.replace("http://", "")
    if "https://" in website:
        website = website.replace("https://", "")
    if ":" in website:
        website = website[:website.find(":")]
    if "/" in website:
        website = website[:website.find("/")]
    return website

def string_generator(size=9, chars=string.ascii_uppercase + string.digits + string.ascii_lowercase):
    return ''.join(random.choice(chars) for _ in range(size))

def generate_filename(filename):
    """
    Generates random name for the filename passed.

    :param filename:
    :return: the randomly created filename
    """
    ext = filename.split('.')[-1]
    return string_generator(4) + str(time.time()).replace(".","_") + '.' + ext