import datetime
import getpass
import os
import shlex
import shutil
import subprocess
import sys

import pika
import psutil
#from celery.task.control import inspect, revoke #celery4.x way to import
from celery.app.control import Inspect
from celery.worker.control import revoke
from common.jobs.celery_app import app as celery_application

from celeryconfig import RABBITMQ_USER, RABBITMQ_PASS, RABBITMQ_IP, RABBITMQ_Port
from common import print_text, common
from common.jobs.rabbitmq_monitoring import RabbitMQMonitor
from common.manual import Entry
from enterprise_conf import RABBITMQ_HOST, RABBITMQ_PASS, RABBITMQ_PORT, RABBITMQ_USER
from menus.log import JOIN_TABLES
from setup import profile

HEADER_NAMES = [['Row #', 'PID', 'Target', 'Start Time', 'Scope', 'Location', 'Source', 'Queued', 'Running', 'Finished', 'Failed', 'Comment', 'Output File Path', 'Modified By', 'Modified Date']] #'Celery Info',
COLUMN_NAMES = ['id', 'pid', 'target', 'start_time', 'entry', 'name', 'source', 'queued', 'running', 'finished', 'failed', 'comment', 'output_filepath', 'modified_by', 'modified_date'] #'celery_info',

JOB_HEADER = [["Row #", "PID", "Target", "Command", "Start Time", "Source"]]
JOB_COLUMNS = ['id', 'pid', 'target', 'command', 'start_time', 'source']

JOB_HISTORY_HEADER = [["Row #", "Target", "Command", "Source", "Start Time", "End Time", "Finished", "Comment"]]
JOB_HISTORY_COLUMNS = ['id', 'target', 'command', 'source', 'start_time', 'end_time', 'finished', 'failed',
                       'allow_rerun', 'comment']


def retry_url_for_source(source):
    """ Returns the /tool?tool=<yaml> URL to retry the tool that produced this Log row, or None if
    the row isn't a retryable tool job (e.g. a manually-added scope entry or parsed file, not a tool run).
    Mirrors the exact same source -> yaml_file stripping common/jobs/tasks.py's command_complete() uses
    to look up a job's parser, so this stays in sync with how `source` is actually populated. """
    if not source:
        return None
    yaml_file = source
    if "tools/" not in yaml_file:
        return None
    if "(" in yaml_file:
        yaml_file = yaml_file[:yaml_file.find("(")]
    if yaml_file.endswith(".yaml"):
        yaml_file = yaml_file[:-len(".yaml")]
    return "/tool?tool=" + yaml_file

# Implement Pause / Resume Task Functionality
#https://unix.stackexchange.com/questions/2107/how-to-suspend-and-resume-processes

def get_running_jobs(db_object, title, tasks, console_view=True):
    try:
        msg = ""
        valid_ids = []
        valid_information = {}
        results = []
        if tasks is not None:
            for task in tasks.values():
                if len(task) == 0:
                    msg = "\tThere are no " + title + " tasks."
                else:
                    for i, task in enumerate(task):  #
                        if task is not None:
                            # This is the current position of the descriptor parameter
                            #print("44 menus/job task['args']: " + str(task['args']))
                            task_args_list = task['args']#.strip('()')
                            args = task_args_list
                            start_time = str(datetime.datetime.fromtimestamp(int(task['time_start'])).strftime('%Y-%m-%d %H:%M:%S'))

                            # Using hashval, grab real PID and display that as the PID
                            hashval = args[0].replace("'", "").replace('"', '').replace("[", "")
                            match = common.regex_exist_in_entry(hashval, r'[a-zA-Z0-9=\/\+]{40,}')
                            if match != "" and match is not None:
                                record = db_object.log_record_by_hashval(hashval, False)

                                celery_id = task['id']
                                if record is not None:
                                    valid_ids.append(record['id'])
                                    valid_information[str(record['id'])] = celery_id
                                    if console_view:
                                        results.append([print_text.insert_newlines(str(record['id'])),
                                                    print_text.insert_newlines(str(record['pid'])),
                                                    print_text.insert_newlines(str(record['target'])),
                                                    print_text.insert_newlines(str(args[1])),
                                                    print_text.insert_newlines(str(record['start_time'])),
                                                    print_text.insert_newlines(str(record['source']))])
                                    else:
                                        # Flask view (needs list of dictionary)
                                        results.append({'id': str(record['id']), 'pid': str(record['pid']),
                                                'target': str(record['target']), 'command': str(args[1]),
                                                'start_time': str(record['start_time']), 'source': str(record['source']),
                                                'delete': "<img onclick='dialog_html(\"/kill/job?table=Job&ident=" +
                                                          str(record['id']) + "\");' src=/static/images/delete.png height=20>"})
                                else:
                                    msg = msg + "\tAnother client engagement is utilizing celery and has job (" \
                                                         + args[1] + ") running.  You are not allowed to stop other " \
                                                         "peoples jobs.  Killing the celery process will kill " \
                                                         "everyone's current jobs, which might make you enemy #1 with " \
                                                         "whoever's jobs you just terminated in celery."
    except Exception as e:
        print("83 menus/job except: " + str(e) + " Error on line {}".format(sys.exc_info()[-1].tb_lineno))

    return results, valid_ids, valid_information

def view_celery_jobs(db_object, tasks, title):
    """
    Print out active jobs in table view.
    Returns valid_ids that can be used to lookup a PID and delete it by the ID.
    """
    print_text.print_menu("\nRunning " + title + " Jobs:")

    # Supress record get error (b/c most likely another project that has stuff running in celery)
    db_object.print_message = False
    try:
        valid_ids = []
        valid_information = []

        if tasks is not None:
            header_names = JOB_HEADER
            results, valid_ids, valid_information = get_running_jobs(db_object, title, tasks)
            print_text.console_table_view(title + " Tasks", header_names, results)
        else:
            print_text.print_msg("\tNo " + title + " Tasks.")
        return valid_ids, valid_information
    except Exception as e:
        print_text.print_error("jobs except, " + str(e) + " Error on line {}".format(sys.exc_info()[-1].tb_lineno))

def list_rabbitmq_queue(db_object, full_client_engagement_path):
    """ NOT USED MESSED UP"""
    with RabbitMQMonitor(RABBITMQ_HOST, RABBITMQ_PORT , RABBITMQ_USER, RABBITMQ_PASS) as rabbitmq:
        response = rabbitmq.get_queued_messages()

def get_active_tasks(full_client_engagement_path):
    """ Necessary to initialize 2x to make sure it gets the data correctly. """
    engagement_path = common.format_target(full_client_engagement_path.rstrip("/"))

    inspector = Inspect(app=celery_application, destination=['celery@' + engagement_path])
    active_tasks = inspector.active()

    return active_tasks

def list_active_job(db_object, full_client_engagement_path):
    """ View active/running jobs. """
    active_tasks = get_active_tasks(full_client_engagement_path)

    view_celery_jobs(db_object, active_tasks, "Active")

def list_scheduled_job(db_object, full_client_engagement_path):
    #inspector = inspect()
    #tasks = inspector.reserved()

    #view_celery_jobs(db_object, tasks, "Queued")
    #TODO: inspector.scheduled() to show scheduled commands

    try:
        filter_value = [True, False, False]
        db_object.view_results_in_table("Log", COLUMN_NAMES, HEADER_NAMES, JOIN_TABLES, ["queued", "finished", "running"],
                                     filter_value, True)
    except Exception as e:
        print_text.print_error("jobs except, " + str(e) + " Error on line {}".format(sys.exc_info()[-1].tb_lineno))

def list_job_history(db_object, full_client_engagement_path):
    """ View finished/failed job history (console version of the web /view/job/history page). """
    try:
        db_object.view_results_in_table("Log", COLUMN_NAMES, HEADER_NAMES, JOIN_TABLES, ["queued", "running", "finished"],
                                     [False, False, True], True)
        db_object.view_results_in_table("Log", COLUMN_NAMES, HEADER_NAMES, JOIN_TABLES, ["queued", "running", "failed"],
                                     [False, False, True], True)
    except Exception as e:
        print_text.print_error("jobs except, " + str(e) + " Error on line {}".format(sys.exc_info()[-1].tb_lineno))

def kill_active_job(db_object, full_client_engagement_path):
    """ Select process to kill
    :param db_object:
    :param full_client_engagement_path:
    :return:
    """
    try:
        selected_id = 0
        active_tasks = get_active_tasks(full_client_engagement_path)
        valid_ids, valid_information = view_celery_jobs(db_object, active_tasks, "Active")

        while True:
            if len(valid_ids) == 0:
                break
            elif len(valid_ids) > 0:
                selected_id = input("Please enter the Row # of the process to kill: ")
                try:
                    selected_id = int(selected_id)
                except:
                    if selected_id != "":
                        selected_id = None
                if isinstance(selected_id, int):
                    if int(selected_id) in valid_ids:
                        break
                elif selected_id == "":
                    print_text.print_msg("\tExiting back to Job Menu!")
                    break
                print_text.print_error("\tYour selection was not a valid Row #. Please try again.")

        if selected_id > 0:
            kill_job(db_object, selected_id, valid_information)
    except Exception as e:
        print_text.print_error("jobs except, " + str(e) + " Error on line {}".format(sys.exc_info()[-1].tb_lineno))

def kill_all_running(db_object, full_client_engagement_path, console=True):
    """ Kill all running processes. """
    try:
        active_tasks = get_active_tasks(full_client_engagement_path)

        valid_ids, valid_information = view_celery_jobs(db_object, active_tasks, "Active")

        user_verify = None
        if len(valid_ids) > 0:
            if console:
                user_verify = input("Are you sure you want to KILL all these processes, Y|N: ")
            else:
                user_verify = "Y"
            if user_verify == "Y":
                for vid in valid_ids:
                    kill_job(db_object, vid, valid_information)

                # Purge queue
                proc = subprocess.Popen(['sudo', 'rabbitmqctl', 'purge_queue', common.format_target(full_client_engagement_path.rstrip("/"))])
            return user_verify
    except Exception as e:
        print_text.print_error("jobs except, " + str(e) + " Error on line {}".format(sys.exc_info()[-1].tb_lineno))

def kill_all(db_object, full_client_engagement_path):
    """ Kill all running processes and marked queued to not run. """
    try:
        profile_dictionary = profile.grab_profile()
        email_address = profile_dictionary['email']

        user_verify = kill_all_running(db_object, full_client_engagement_path)

        if user_verify is None:
            user_verify = input("Are you sure you want to KILL all queued processes, Y|N: ")

        if user_verify == "Y":
            # Now marked failed for all queued jobs
            queryset = db_object.log_queued()
            if queryset is not None:
                for entry in queryset:
                    if entry is not None:
                        if not entry['finished'] and entry['id'] is not None:
                            current_comment = entry['comment']
                            if current_comment is None:
                                current_comment = ""
                            db_object.update("Log", {'id': entry['id'], 'failed': True,
                                             'comment': 'User killed this process in the queue.\n' + current_comment,
                                             'queued': False})

            # Now clear rabbitmq queue
            channel = pika.BlockingConnection(pika.ConnectionParameters(RABBITMQ_IP, int(RABBITMQ_Port), "/",
                                            credentials = pika.PlainCredentials(RABBITMQ_USER, RABBITMQ_PASS))).channel()
            channel.queue_delete(queue=email_address)

    except Exception as e:
        print_text.print_error("jobs except, " + str(e) + " Error on line {}".format(sys.exc_info()[-1].tb_lineno))


def kill_job(db_object, selected_id, valid_information, passed_pass=None):
    """ Actually does the process killing. """
    try:
        if isinstance(selected_id, int) and selected_id > 0:
            record = db_object.get("Log", ["id"], [int(selected_id)])

            # Kill all children processes first
            if "ScanID" not in record['pid'] and record['pid'].isnumeric():
                terminate_children_process(None, record['pid'])

            # Stop Nessus scan
            if "nessus" in record['source']:
                import yaml
                nessus_config = yaml.load(open('tools/vuln/nessus/nessus.yaml'), Loader=yaml.SafeLoader)
                NESSUS_USERNAME = nessus_config['nessus_username']
                NESSUS_PASSWORD = nessus_config['nessus_password']
                NESSUS_SERVER = nessus_config['nessus_server']
                #from enterprise_conf import NESSUS_SERVER, NESSUS_USERNAME, NESSUS_PASSWORD
                scan_id = record['pid']
                if "ScanID:" in scan_id:
                    scan_id = scan_id.replace("ScanID:", "")
                    MANUAL_FIELDS = []
                    if NESSUS_USERNAME == "":
                        MANUAL_FIELDS.append(["Nessus username", "nessus_username", ''])
                    if NESSUS_PASSWORD == "":
                        MANUAL_FIELDS.append(["Nessus password", "nessus_password", ''])
                    if NESSUS_SERVER == "":
                        MANUAL_FIELDS = (["Nessus URL", "nessus_server", r'^(http://|https://)+[a-zA-Z0-9.-]+'],) + MANUAL_FIELDS
                    with Entry("Result", MANUAL_FIELDS) as me:
                        nessus_values = me.user_input_fields(input_text='Please enter the ')
                    if 'nessus_server' not in nessus_values:
                        nessus_values['nessus_server'] = NESSUS_SERVER
                    if "nessus_username" not in nessus_values:
                        nessus_values['nessus_username'] = NESSUS_USERNAME
                    if "nessus_password" not in nessus_values:
                        nessus_values['nessus_password'] = NESSUS_PASSWORD

                    from tools.vuln.nessus_run import NessusAutomation
                    with NessusAutomation(nessus_values, None, None, None, record['id'], db_object) as nessus_scan:
                        nessus_scan.stop(scan_id, db_object.current_tester)
            elif "zap" in record['source']:
                # Stop ZAP
                scan_id = record['pid']
                if "ScanID:" in scan_id:
                    scan_id = scan_id.replace("ScanID:", "")
                    msg = record['comment']
                    zap_proxy = ""
                    zap_api_key = ""
                    if "ZAP Proxy:" in msg:
                        zap_proxy = msg[msg.find("ZAP Proxy:") + 10:]
                        zap_proxy = zap_proxy[:zap_proxy.find("\n")]
                        if "\\" in zap_proxy:
                            zap_proxy = zap_proxy[:zap_proxy.find("\\")]
                    if "ZAP API KEY:" in msg:
                        zap_api_key = msg[msg.find("ZAP API KEY:") + 12:]
                        if "\n" in zap_api_key:
                            zap_api_key = zap_api_key[:zap_api_key.find("\n")]
                        if "\\" in zap_api_key:
                            zap_api_key = zap_api_key[:zap_api_key.find("\\")]
                        if " " in zap_api_key:
                            zap_api_key = zap_api_key[:zap_api_key.find(" ")]
                    if zap_proxy != "" and zap_api_key != "" and scan_id.isnumeric():
                        xml_file = record['output_filepath'] + "zap__" + str(record['id']) + "__" + common.format_target(
                            record['target']) + ".xml"
                        zap_values = {}
                        zap_values['api_key'] = zap_api_key
                        zap_values['zap_proxy'] = zap_proxy
                        from tools.vuln.web.zap_run import ZAPAutomation
                        with ZAPAutomation(zap_values, "", record['target'], str(record['id']), db_object, False) as zap_scan:
                            zap_scan.stop_scan(scan_id, xml_file)
            elif "nmap" in record['source'] or "responder" in record['source'] or "smbrelay" in record['source']:
                # copy logs/*.txt files and move to output_path
                if "responder" in record['source'] or "smbrelay" in record['source']:
                    from enterprise_user_conf import RESPONDER_PATH
                    log_path = RESPONDER_PATH
                    if "Responder.py" in log_path:
                        log_path = log_path[:log_path.rfind("/")]
                    log_path = log_path + "/logs/"
                    if os.path.isdir(log_path):
                        for f in os.listdir(log_path):
                            if f.endswith(".txt"):
                                shutil.copy2(f, record['output_filepath'])

                if passed_pass is None:
                    print_text.print_msg("Please enter your password as this process must be killed using sudo! ")
                    user_input = getpass.getpass() + "\n"
                else:
                    user_input = passed_pass
                # kill process that spawned nmap
                process = subprocess.Popen(shlex.split("sudo pkill -P " + str(record['pid'])), stdout=subprocess.PIPE,
                                           stdin=subprocess.PIPE, stderr=subprocess.STDOUT)
                stdout = process.communicate(input=user_input.encode("UTF-8"))[0]
                stdout = str(stdout)
                if "not permitted" in stdout or "not allowed" in stdout:
                    print_text.print_error("\t Error while trying to kill nmap process ID, " + str(
                        record['pid']) + ", you must have 'kill' sudo permissions.  Process is stil running!")
            elif record['pid'] is not None and record['pid'] != "":
                if "ScanID" not in record['pid'] and record['pid'].isnumeric():
                    terminate_children_process(None, record['pid'])
                process = subprocess.Popen(shlex.split("kill -9 " + str(record['pid'])), stdout=subprocess.PIPE,
                                           stdin=subprocess.PIPE, stderr=subprocess.STDOUT)
                #terminate_children_process(None, record['pid'])

                #process = subprocess.Popen(shlex.split("pkill -P " + str(record['pid'])), stdout=subprocess.PIPE,
                #                           stdin=subprocess.PIPE, stderr=subprocess.STDOUT)
                print_text.print_msg("Successfully killed process: " + str(record['pid']))

            # Revoke from celery
            revoke(valid_information[str(selected_id)], terminate=True, signal='SIGKILL')

            # Update Log with End Time
            success = db_object.update("Log", {"id": selected_id,
                                               "end_time": datetime.datetime.now(),
                                               "comment": "Process was manually killed before finishing!", "queued": False,
                                               "allow_rerun": True, "failed": True, "running": False, "finished": False})
    except Exception as e:
        print_text.print_error("jobs except, " + str(e) + " Error on line {}".format(sys.exc_info()[-1].tb_lineno))


def terminate_children_process(user_input, parent_id):
    children = get_child_process(str(parent_id))
    if children is not None:
        for child in children:
            child.kill()
            #if user_input is None:
            #    process = subprocess.Popen(shlex.split("kill -9 " + str(child.pid)), stdout=subprocess.PIPE,
            #                               stdin=subprocess.PIPE, stderr=subprocess.STDOUT)
            #else:
            #    process = subprocess.Popen(shlex.split("sudo kill -9 " + str(child.pid)), stdout=subprocess.PIPE,
            #                           stdin=subprocess.PIPE, stderr=subprocess.STDOUT)
            #    stdout = process.communicate(user_input.encode("UTF-8"))[0]

def get_child_process(parent_id):
    try:
        parent = psutil.Process(int(parent_id))
    except:
        print_text.print_error("\t No such process")
        return
    children = parent.children(recursive=True)
    return children

def stop_celery(db_object, full_client_engagement_path):
    """ Stop celery processes for current engagement """
    try:
        profile_dictionary = profile.grab_profile()
        email_address = profile_dictionary['email']

        user_verify = input("Are you sure you want to STOP Celery for this Engagement, Y|N: ")

        if user_verify == "Y":
            client_name = common.format_target(full_client_engagement_path.rstrip("/"))
            subprocess.run(["pkill", "-f", client_name])

    except Exception as e:
        print_text.print_error("jobs except, " + str(e) + " Error on line {}".format(sys.exc_info()[-1].tb_lineno))

