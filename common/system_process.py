import re
import subprocess

def is_running(proc):
    s = subprocess.Popen(["ps", "auxww"], stdout=subprocess.PIPE)
    matched_processes = []
    for x in s.stdout:
        if re.search(proc, x.decode("utf-8")):
            matched_processes.append(str(x.decode("utf-8")))
    if len(matched_processes) > 0:
        return (True, matched_processes)

    return (False, None)

def process_with_args_is_running(process_name, search_string):
    """
    Check if string is in the process that was found.
    :param process_name:
    :param search_string:
    :return:
    """
    running, matched_processes = is_running(process_name)
    if running:
        for proc in matched_processes:
            if search_string in proc:
                return True
    return False

def process_with_args_is_running_return_processes(process_name, search_string):
    """
    Check if string is in the process that was found.
    :param process_name:
    :param search_string:
    :return:
    """
    running, matched_processes = is_running(process_name)
    processes = []
    if running:
        for proc in matched_processes:
            if search_string in proc:
                processes.append(proc)
    print("42 system process processes: " + str(processes))
    return processes

def return_pid_of_running_process(proc):
    """ Return pids that matched search, 'proc'"""
    child = subprocess.Popen(['pgrep', '-f', proc], stdout=subprocess.PIPE, shell=False)
    response = child.communicate()[0]
    if response is not None and len(response) > 0:
        return True, [int(pid) for pid in response.split()]
    return False, None
