import sys
import os
import yaml
import json
import shutil
from datetime import datetime
import subprocess
import traceback
import json
import shlex
import importlib
from common import network
from common import print_text, common
from common import send_email
from common.database_object import OurCoolDBObject
import tools
import parsers
from setup import profile
from setup import scope
from flask_files import common_flask

from common.jobs.celery_app import app
from celery import chord, chain
from celery.signals import task_success, task_postrun


@app.task
def on_chord_error(request, exc, traceback):
    print('Task {0!r} raised error: {1!r}'.format(request.id, exc))

@app.task
def run_command_from_chain(hashval, command, db_path, db_key, descriptor, prior=None):
    """ Chain returns parents so must catch that (which is actually then 1st arg so real args shifted over by 1."""
    if prior is not None:
        hashval = command
        command = db_path
        db_path = db_key
        db_key = descriptor
        descriptor = prior
    return run_command(hashval, command, db_path, db_key, descriptor)


@app.task
def run_command(hashval, command, db_path, db_key, descriptor):
    """Run an built-in tool or external tool as a celery task

    :param command: operating system command to run (with arguments)
    :param hashval: hashval pertaining to the Log entry
    :param db_path: path to DB file
    :param key: secret key for decrypting DB
    :param descriptor: if passed built-in function call
    :return: return update to user based on exit code
    """
    current_time = datetime.now()
    print("52 run_command command: " + str(command))

    try:
        celery_info = run_command.request
        celery_dict = {'id': celery_info.id, 'expires': celery_info.expires, 'parent_id': celery_info.parent_id,
                       'group': celery_info.group, 'timelimit': celery_info.timelimit, 'retries': celery_info.retries}

        celery_string = json.dumps(celery_dict)
        db_object = OurCoolDBObject(db_path)

        auto_send_email = db_object.grab_column_from_single_record("Engagement", ["id"], [1], "can_send_auto_notification")
        log_info = db_object.log_record_by_hashval(hashval)
        if log_info is None:
            return None

        tool_name = log_info['source']
        # If previously chose to kill all processes (from job.py then all queued will be marked failed).
        if not log_info['failed']:
            if auto_send_email:
                try:
                    # Now send email
                    send_email.email_notification(db_object, db_key, log_info['source'], log_info['id'], "start")
                except:
                    pass

            # Blacklist check
            comment = ""
            blacklist = False

            if log_info['scope_id'] is not None:
                open_ip, open_port = db_object.scope_known_open(log_info['scope_id'])
            else:
                comment = "No known open IP/Port for associated scope entry so can not do blacklist checks."
                blacklist = None

            if open_ip is None or open_port is None:
                comment = "No known open IP/Port for associated scope entry so can not do blacklist checks."
                blacklist = None

            try:
                if network.valid_ip(open_ip) and int(open_port):
                    if network.check_port(open_ip, open_port):
                        blacklist = False
                    else:
                        blacklist = True
            except Exception as e:
                blacklist = None
                comment = "No known open IP/Port for associated scope entry so can not do blacklist checks."
            if blacklist:
                update_values = dict(comment="Job cancelled because you're already blacklisted. ",
                                     blacklisted=blacklist, running=False, failed=True, queued=False,
                                     start_time=current_time, end_time=current_time)
                db_object.update("Log", update_values, ["hashval"], [hashval])
                return "FAILED"
            else:
                log_info = db_object.log_record_by_hashval(hashval)
                update_values = dict(comment="Job started. " + comment, blacklisted=blacklist,
                                     celery_info=celery_string, running=True, queued=False, finished=False,
                                     run_time=current_time)
                db_object.update("Log", update_values, ["hashval"], [hashval])
                log_info = db_object.log_record_by_hashval(hashval)

            if log_info['source'] != "scope" and log_info['source'] != "manual parser":
                base_output_path = log_info['output_filepath']
                if base_output_path is not None:
                    base_output_path = base_output_path[:base_output_path.find("output/") + 7:]
                else:
                    base_output_path = db_object.engagement_path + "/output/"
                if not os.path.isdir(base_output_path):
                    common.create_path(base_output_path)

                update_permissions = False
                if not os.path.isfile(base_output_path + "tool.log"):
                    update_permissions = True

                with open(base_output_path + "tool.log", "a") as tool_log_file:
                    tool_log_file.write(
                        str(current_time.strftime("%Y-%m-%d %H:%M:%S.%f")) + "\t" + log_info['source'] + "\t" +
                        log_info['target'].replace("\n", " ") + "\t" + "Job started.\n")
                if update_permissions:
                    common.assign_permissions(base_output_path + "tool.log")

            if descriptor is not None and "FUNCTION:" in descriptor:
                func = descriptor.replace("FUNCTION:", "")

                pargs = None
                if ":" in func:
                    pargs = func[func.find(":") + 1:]
                    func = func[:func.find(":")]

                function_path = func[:func.rfind(".")]
                function_name = func[func.rfind(".")+1:]
                function_call = getattr(importlib.import_module(function_path), function_name)

                if pargs is None:
                    status = function_call(command, log_info['scope_id'], "", db_object, log_info['id'])
                else:
                    status = function_call(command, log_info['scope_id'], "", db_object, log_info['id'], pargs)

                # update log if failed
                if status is not None:
                    if( isinstance(status, bool) and not status ) or ( isinstance(status, str) and "Failed. " in status ):
                        update_values = dict(comment=status, running=False, failed=True, queued=False, finished=False,
                                             run_time=current_time)
                        db_object.update("Log", update_values, ["hashval"], [hashval])

                return status
            else:
                command = command.replace('"', '')#.replace("'", "")

                stdout_file = None
                if " > " in command:
                    stdout_file = command[command.find(" > ") + 3:]
                    command = command[:command.find(" > ")]

                if stdout_file is None:
                    process = subprocess.Popen(shlex.split(command), stderr=subprocess.PIPE) #stdout=subprocess.PIPE,
                else:
                    with open(stdout_file, "w") as outfile:
                        process = subprocess.Popen(shlex.split(command), stderr=subprocess.PIPE, stdout=outfile)

                # Update Log record w/ PID
                update_values = dict(hashval=hashval, pid=process.pid)
                db_object.update("Log", update_values, ["hashval"], [hashval])

                stdoutdata, stderrdata = process.communicate()
                stderrdata = stderrdata.decode("utf-8").replace("\n", " ")

                # Blacksheepwall prints to console using stderr so have to catch that
                if ("blacksheepwall" in command and "spreading tasks" in stderrdata.lower()) or ("amass" in command.lower() and "owasp" in stderrdata.lower()):
                    stderrdata = ""

                if "Usage:" in stderrdata:
                    with open(base_output_path + "tool.log", "a") as tool_log_file:
                        tool_log_file.write(
                            str(current_time.strftime("%Y-%m-%d %H:%M:%S.%f")) + "\t" + log_info['source'] + "\t" +
                            log_info['target'].replace("\n", " ") + "\t" + "Failed.  Error: " + str(stderrdata) + "\n")
                    update_values = dict(hashval=hashval, comment="Failed. " + str(stderrdata), end_time=current_time,
                                         running=False, failed=True, finished=False, queued=False)
                    db_object.update("Log", update_values, ["hashval"], [hashval])

                if "incorrect password" in stderrdata.lower():
                    update_values = dict(hashval=hashval, comment="Failed. " + str(stderrdata), end_time=current_time, running=False, failed=True, finished=False, queued=False)
                    db_object.update("Log", update_values, ["hashval"], [hashval])

                    # write to tool.log in output path
                    if log_info['source'] != "scope" and log_info['source'] != "manual parser":
                        base_output_path = log_info['output_filepath']
                        base_output_path = base_output_path[:base_output_path.find("output/") + 7:]
                        if not os.path.isdir(base_output_path):
                            common.create_path(base_output_path)

                        update_permissions = False
                        if not os.path.isfile(base_output_path + "tool.log"):
                            update_permissions = True

                        with open(base_output_path + "tool.log", "a") as tool_log_file:
                            tool_log_file.write(str(current_time.strftime("%Y-%m-%d %H:%M:%S.%f")) + "\t" + log_info['source'] + "\t" + log_info['target'].replace("\n", " ") + "\t" + "Failed.  Error: " + str(stderrdata) + "\n")
                        if update_permissions:
                            common.assign_permissions(base_output_path + "tool.log")

                elif "sorry, try again" not in stderrdata.lower() and stderrdata.strip() != "" and "nmap" not in log_info['source']:
                    update_values = dict(hashval=hashval, comment="Failed. " + str(stderrdata), end_time=current_time,
                                         running=False, failed=True, finished=False, queued=False)
                    db_object.update("Log", update_values, ["hashval"], [hashval])

                    # write to tool.log in output path
                    if log_info['source'] != "scope" and log_info['source'] != "manual parser":
                        base_output_path = log_info['output_filepath']
                        base_output_path = base_output_path[:base_output_path.find("output/") + 7:]
                        if not os.path.isdir(base_output_path):
                            common.create_path(base_output_path)

                        update_permissions = False
                        if not os.path.isfile(base_output_path + "tool.log"):
                            update_permissions = True

                        with open(base_output_path + "tool.log", "a") as tool_log_file:
                            tool_log_file.write(str(current_time.strftime("%Y-%m-%d %H:%M:%S.%f")) + "\t" + log_info['source'] + "\t" + log_info['target'].replace("\n", " ") + "\t" + "Failed.  Error: " + str(stderrdata) + "\n")
                        if update_permissions:
                            common.assign_permissions(base_output_path + "tool.log")

                return process.returncode
    except Exception as e:
        print_text.print_error("tasks except: " + str(e) + " Error on line {}".format(sys.exc_info()[-1].tb_lineno))
        update_values = dict(hashval=hashval, comment="Failed. " + str(e), end_time=current_time, running=False,
                             failed=True, finished=False, queued=False)
        db_object.update("Log", update_values, ["hashval"], [hashval])

        if log_info is not None:
            # write to tool.log in output path
            if log_info['source'] != "scope" and log_info['source'] != "manual parser":
                base_output_path = log_info['output_filepath']
                base_output_path = base_output_path[:base_output_path.find("output/") + 7:]
                if not os.path.isdir(base_output_path):
                    common.create_path(base_output_path)

                update_permissions = False
                if not os.path.isfile(base_output_path + "tool.log"):
                    update_permissions = True

                if update_permissions:
                    common.assign_permissions(base_output_path + "tool.log")

                with open(base_output_path + "tool.log", "a") as tool_log_file:
                    tool_log_file.write(str(current_time.strftime("%Y-%m-%d %H:%M:%S.%f")) + "\t" + log_info['source'] + "\t" + log_info['target'].replace("\n", " ") + "\t" + "Failed.  Error: " + str(e) + "\n")

    return "FAILED"

@app.task
def command_complete(return_value, hashvals, db_path, key, completed_function_path_name):
    """Callback to mark all tasks complete

    A Chord ran as a group will use this function as a callback to
    update the DB and let us know everything has been completed.

    :param hashvals: a list of hashvals for each task
    :param db_path: path to DB file
    :param key: secret key for decrypting DB
    :param descriptor: something to describe the task to use when getting the status
    :param completed_function: path/name of function to call
    """
    current_time = datetime.now()

    try:
        db_object = OurCoolDBObject(db_path)
        end_time = datetime.now()

        # Convert serialized hashvals to list
        if not isinstance(hashvals, list):
            hashvals = json.loads(hashvals)

        if return_value != "FAILED":
            for hashval in hashvals:
                log_info = db_object.log_record_by_hashval(hashval)

                # Still try to parse even if it failed
                if log_info is not None and "sleep_after_for_" not in log_info['target']: #not log_info['failed'] and
                    failed = False
                    finished = True
                    if log_info['failed']:
                        failed = True
                        finished = False
                    update_values = dict(end_time=end_time, allow_rerun=False, running=False,
                                         finished=finished, failed=failed, parsed=False, queued=False)
                    db_object.update("Log", update_values, ["hashval"], [hashval])

                    # make sure file permissions of all files created are set properly
                    for root, dirs, files in os.walk(log_info['output_filepath']):
                        for d in dirs:
                            common.assign_permissions(os.path.join(root,d))
                        for f in files:
                            file_path = os.path.join(root, f)
                            if "/nmap/" not in file_path:
                                common.assign_permissions(file_path)

                    # Grab completed function, parser, from yaml config file
                    completed_function = None
                    yaml_file = log_info['source']
                    if "tools/" in yaml_file:
                        if "(" in yaml_file:
                            yaml_file = yaml_file[:yaml_file.find("(")]
                        if ".yaml" not in yaml_file:
                            yaml_file = yaml_file + ".yaml"
                        config = yaml.load(open(db_object.base_path + "/" + yaml_file), Loader=yaml.SafeLoader)
                        completed_function = config['tool_parser']

                    if completed_function is not None:
                        func_path = completed_function[:completed_function.rfind(".")]
                        func_name = completed_function[completed_function.rfind(".")+1:]

                        completed_function = getattr(importlib.import_module(func_path), func_name)
                        try:
                            success = completed_function(db_path, db_object, key, hashvals)
                        except Exception as e:
                            print_text.print_error("\t Something went wrong with parsing, error: " + str(e) + ".  This log entried had Failed: " + str(log_info['failed']))
        else:
            for hashval in hashvals:
                log_info = db_object.log_record_by_hashval(hashval)
                if log_info is not None:
                    finished = log_info['finished']
                    failed = log_info['failed']
                    current_comment = log_info['comment']
                    allow_rerun = True
                    if finished:
                        allow_rerun = False

                    update_values = dict(hashval=hashval, end_time=end_time, comment="Failed to parse.  " + current_comment, allow_rerun=allow_rerun, running=False, failed=failed, finished=finished, parsed=False, queued=False)
                    db_object.update("Log", update_values, ["hashval"], [hashval])

                    # write to tool.log in output path
                    if log_info['source'] != "scope" and log_info['source'] != "manual parser":
                        base_output_path = log_info['output_filepath']
                        base_output_path = base_output_path[:base_output_path.find("output/") + 7:]
                        if not os.path.isdir(base_output_path):
                            common.create_path(base_output_path)

                        update_permissions = False
                        if not os.path.isfile(base_output_path + "tool.log"):
                            update_permissions = True

                        with open(base_output_path + "tool.log", "a") as tool_log_file:
                            tool_log_file.write(str(current_time.strftime("%Y-%m-%d %H:%M:%S.%f")) + "\t" + log_info['source'] + "\t" + log_info['target'].replace("\n", " ") + "\t" + "Failed to parse." + "\n")
                        if update_permissions:
                            common.assign_permissions(base_output_path + "tool.log")
    except Exception as e:
        print_text.print_error("tasks except: " + str(e) + " Error on line {}".format(sys.exc_info()[-1].tb_lineno))

        for hashval in hashvals:
            log_info = db_object.log_record_by_hashval(hashval)
            if log_info is not None:
                old_comment = log_info['comment']
                if (log_info['end_time'] is None or log_info['end_time'] == ""):
                    if old_comment is not None and old_comment != "":
                        old_comment = old_comment + "\n"
                finished = log_info['finished']
                allow_rerun = True
                if finished:
                    allow_rerun = False
                update_values = dict(hashval=hashval, end_time=end_time, comment=old_comment + "Failed parsing. " + str(e), allow_rerun=allow_rerun, finished=finished, running=False, parsed=False, queued=False)
                db_object.update("Log", update_values, ["hashval"], [hashval])

                # write to tool.log in output path
                if log_info['source']!= "scope" and log_info['source'] != "manual parser":
                    base_output_path = log_info['output_filepath']
                    base_output_path = base_output_path[:base_output_path.find("output/") + 7:]

                    if not os.path.isdir(base_output_path):
                        common.create_path(base_output_path)

                    update_permissions = False
                    if not os.path.isfile(base_output_path + "tool.log"):
                        update_permissions = True

                    with open(base_output_path + "tool.log", "a") as tool_log_file:
                        tool_log_file.write(str(current_time.strftime("%Y-%m-%d %H:%M:%S.%f")) + "\t" + log_info['source'] + "\t" + log_info['target'].replace("\n", " ") + "\t" + "Failed. " + str(e) + "\n")
                    if update_permissions:
                        common.assign_permissions(base_output_path + "tool.log")
    # Check output path to see if empty directory, if so delete the directory
    for hashval in hashvals:
        log_info = db_object.log_record_by_hashval(hashval)
        if log_info is not None:
            output_path = log_info['output_filepath']
            if output_path is not None and os.path.isdir(output_path) and (log_info['finished'] or log_info['failed']):
                all_files = []
                for dirpath, directories, files in os.walk(output_path):
                    if len(files) > 0:
                        all_files = files
                if len(all_files) == 0:
                    shutil.rmtree(output_path)

    # Delete sleep_after Log entries (don't clutter up the Log!)
    for hashval in hashvals:
        target = db_object.grab_column_from_single_record("Log", ['hashval'], [hashval], "target")
        id = db_object.grab_column_from_single_record("Log", ['hashval'], [hashval], "id")
        if target is not None and id is not None and "sleep_after_for_" in target:
            db_object.delete("Log", id)

def run_command_group(commands, db_path, db_key, descriptors, completed_function):
    """Build a chord primitive of run_command tasks

    This will create a Celery chain object to run a group of tasks and then
    move on to the command_complete function to update the DB

    :param commands: dict of hashval:command
    :param db_path: path to DB file
    :param key: secret key for decrypting DB
    :param descriptors: List - passed function to call for built-in
    """
    current_time = datetime.now()

    try:
        full_client_path = common.format_target(db_path[:db_path.rfind("/")])
        db_object = OurCoolDBObject(db_path)
        end_time = datetime.now()
        # Not using chord anymore b/c then if one fails all fail and don't get parsed,
        # instead doing multiple chains where parsing is 2nd job in chain for each chain
        count = 0
        for key, cmd in commands.items():
            chain_commands = []
            chain_commands.append(run_command.si(key, json.dumps(cmd), db_path, db_key, descriptors[count]).set(queue=full_client_path))
            chain_commands.append(command_complete.s([key], db_path, db_key, completed_function).set(queue=full_client_path))
            chain_result = chain(c for c in chain_commands).apply_async(queue=full_client_path, exchange=full_client_path, routing_key=full_client_path)

            # Update Log record celery_info
            update_values = dict(hashval=key, celery_info=chain_result.parent.id)
            db_object.update("Log", update_values, ["hashval"], [key])
            count += 1

    except Exception as e:
        print_text.print_error("tasks except: " + str(e) + " Error on line {}".format(sys.exc_info()[-1].tb_lineno))
        for key, cmd in commands.items():
            log_info = db_object.log_record_by_hashval(key)
            if log_info is not None:
                old_comment = log_info['comment']
                if (log_info['end_time'] is None or log_info['end_time'] == ""):
                    if old_comment is not None and old_comment != "":
                        old_comment = old_comment + "\n"
                    update_values = dict(hashval=key, end_time=end_time, comment=old_comment + "Failed. " + str(e),
                                         running=False, failed=True, finished=False, parsed=False, queued=False)
                    db_object.update("Log", update_values, ["hashval"], [key])

                    # write to tool.log in output path
                    if log_info['source'] != "scope" and log_info['source'] != "manual parser":
                        base_output_path = log_info['output_filepath']
                        base_output_path = base_output_path[:base_output_path.find("output/") + 7:]
                        if not os.path.isdir(base_output_path):
                            common.create_path(base_output_path)

                        update_permissions = False
                        if not os.path.isfile(base_output_path + "tool.log"):
                            update_permissions = True

                        with open(base_output_path + "tool.log", "a") as tool_log_file:
                            tool_log_file.write(str(current_time.strftime("%Y-%m-%d %H:%M:%S.%f")) + "\t" + log_info['source'] + "\t" + log_info['target'].replace("\n", " ") + "\t" + "Failed. " + str(e) + "\n")
                        if update_permissions:
                            common.assign_permissions(base_output_path + "tool.log")
@app.task
def run_chain(chain_commands, db_path):
    full_client_path = common.format_target(db_path[:db_path.rfind("/")])
    return chain(cmd for cmd in chain_commands).apply_async(queue=full_client_path, exchange=full_client_path, routing_key=full_client_path)


def chain_of_command_groups(command_list, db_path, db_key, descriptors, completed_function):
    """Run a group of commands chained together

    This allows us to run a group of tasks, then once complete run then next
    group, and so on. An example use case is for the NMAP Run All

    :param command_list: dictionary where key is Log hashval and value is list [command, scope, location]
    :param db_path: path to DB file
    :param key: secret key for decrypting DB
    :param descriptors: List - of built in functions to call if not external tool
    """
    current_time = datetime.now()

    try:
        full_client_path = common.format_target(db_path[:db_path.rfind("/")])

        db_object = OurCoolDBObject(db_path)
        end_time = datetime.now()

        chain_results = {}
        count = 0
        for key, commands in command_list.items():
            chain_commands = []
            for hashval_cmd in commands:
                # Grab completed function, parser, from yaml config file
                log_info = db_object.log_record_by_hashval(hashval_cmd[0])
                yaml_file = log_info['source']
                if "tools/" in yaml_file:
                    if "(" in yaml_file:
                        yaml_file = yaml_file[:yaml_file.find("(")]
                    if ".yaml" not in yaml_file:
                        yaml_file = yaml_file + ".yaml"
                    config = yaml.safe_load(open(db_object.base_path + "/" + yaml_file))
                    completed_function = config['tool_parser']

                chain_commands.append(run_command.si(hashval_cmd[0], hashval_cmd[1], db_path, db_key, descriptors[count]).set(queue=full_client_path))
                chain_commands.append(command_complete.s([hashval_cmd[0]], db_path, db_key, completed_function).set(queue=full_client_path))

            chain_result = run_chain(chain_commands, db_path)
            count += 1

        #THIS IS CHORD INSIDE CHAIN but we want CHAIN INSIDE OF A CHORD
        #chord_list = []

        #for commands in command_list:
        #    chord_list.append(chord((run_command.si(key, json.dumps(cmd), db_object, db_key, descriptor) for key,cmd in commands.items()),
        #      command_complete.si(json.dumps(list(commands.keys())), db_object, db_key, completed_function)))

        #chain(c for c in chord_list).apply_async()

    except Exception as e:
        print_text.print_error("tasks except: " + str(e) + " Error on line {}".format(sys.exc_info()[-1].tb_lineno))
        for key, commands in command_list.items():
            for hashval_cmd in commands:
                try:
                    log_info = db_object.log_record_by_hashval(hashval_cmd[0])
                    if log_info is not None:
                        old_comment = log_info['comment']
                        if (log_info['end_time'] is None or log_info['end_time'] == ""):
                            if old_comment is not None and old_comment != "":
                                old_comment = old_comment + "\n"
                            update_values = dict(hashval=hashval_cmd[0], end_time=end_time, comment=old_comment + "Failed. " + str(e), running=False, failed=True, parsed=False, finished=False, queued=False)
                            db_object.update("Log", update_values, ["hashval"], [hashval_cmd[0]])

                            # write to tool.log in output path
                            if log_info['source'] != "scope" and log_info['source'] != "manual parser":
                                base_output_path = log_info['output_filepath']
                                base_output_path = base_output_path[:base_output_path.find("output/") + 7:]
                                if not os.path.isdir(base_output_path):
                                    common.create_path(base_output_path)

                                update_permissions = False
                                if not os.path.isfile(base_output_path + "tool.log"):
                                    update_permissions = True

                                with open(base_output_path + "tool.log", "a") as tool_log_file:
                                    tool_log_file.write(str(current_time.strftime("%Y-%m-%d %H:%M:%S.%f")) + "\t" + log_info['source'] + "\t" + log_info['target'].replace("\n", " ") + "\t" + "Failed. " + str(e) + "\n")
                                if update_permissions:
                                    common.assign_permissions(base_output_path + "tool.log")
                except Exception as e2:
                    print_text.print_error("tasks except updating Log failed, except: " + str(e2) + " Error on line {}".format(sys.exc_info()[-1].tb_lineno))


def add_scope_to_celery(db_path, engagement_path, selected_engagement, key, username, fields, allow_unknown):
    fields = json.dumps(fields)
    chain_commands = []
    chain_commands.append(run_add_scope.si(engagement_path, selected_engagement, key, username, fields, allow_unknown).set(queue=engagement_path))
    chain_result = run_chain(chain_commands, db_path)
@app.task
def run_add_scope(engagement_path, selected_engagement, key, username, fields, allow_unknown):
    try:
        fields = json.loads(fields)
        db_object = common_flask.create_db_object(engagement_path, selected_engagement, key, username)
        scope.add_scope(db_object, fields, allow_unknown)
        return "Scope processing in the background..."
    except Exception as e:
        return "Error: " + str(e)

@app.task
def export_to_central_repo(json_data, results, url, key):
    import requests
    results = common.grab_engagement_data()
    # print("results: " + str(results))
    print("len(results): " + str(len(results)))
    # push to Engage
    if len(results) > 0:
        key = 'secret_key'
        url = 'https://url_to_api/all/some/place' + key

        headers = {'Content-type': 'application/json', 'Accept': 'text/plain'}
        r = requests.post(url, data=json.dumps(results), headers=headers)
        print(r.status_code)

    return "Uploading to central repository"

