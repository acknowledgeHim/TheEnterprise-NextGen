import logging
import os
import shlex
import subprocess

import yaml
from flask import Blueprint, jsonify, redirect, render_template, request, session

from common import common, print_text, system_process
from common.navigation_menu import NAVIGATION
from flask_files import common_flask
from flask_files.form_class import FormSetup
from flask_files.table_class import TableClass
from menus import job

jobs_bp = Blueprint("jobs", __name__)
logger = logging.getLogger(__name__)


def job_views(active=True):
    try:
        additional = ""
        additional_after = ""
        model = None
        if 'model' in request.args:
            model = request.args['model']

        if model is None:
            db_object = common_flask.create_db_object(session.get('engagement_path'),
                                                      session.get('selected_engagement'), session.get('key'),
                                                      session.get('username'))
        else:
            db_object = common_flask.just_db_object(
                'setup/email_event.db')
        setup_dictionary = common_flask.setup_base_page(session, db_object)
        engagements = setup_dictionary['engagements']
        menu_items = common_flask.loop_through_menu(NAVIGATION)
        engagement_path = session.get('engagement_path')

        url_action = "active"
        if active:
            returned_jobs = job.get_active_tasks(engagement_path)
        else:
            returned_jobs = db_object.view("Log", job.JOB_COLUMNS, ["queued", "finished", "running"],
                                           [True, False, False], True)
        if returned_jobs is None:
            returned_jobs = []

        if len(returned_jobs) > 0:
            additional = "<button class='black_text' onclick='dialog_html(\"/kill/all/running?table=Job\");' name='Kill Running (Active) Job(s)' value='Kill Running (Active) Job(s)'>Kill Running (Active) Job(s)</button>" \
                         "<button class ='black_text' onclick='dialog_html(\"/kill/all/running_queued?table=Job\");' name='Kill Running & Queued Job(s)' value='Kill Running & Queued Job(s)'>Kill Running & Queued Job(s)</button> " \
                         "<button class ='black_text' onclick='dialog_html(\"/kill/job/stop_celery?table=Job\");' name='Terminate Celery Processes' value='Terminate Celery Processes'>Terminate Celery Processes</button>"
        else:
            client_name = common.format_target(engagement_path.rstrip("/"))
            if system_process.process_with_args_is_running('celery', client_name):
                from enterprise_user_conf import AUTO_START_CELERY
                additional_after = "The Celery Processes for this Engagement are not running.  "
                if AUTO_START_CELERY:
                    additional_after = additional_after + "<p>The celery processes will be auto-started when you re-select this engagement."
                else:
                    additional_after = additional_after + "<p>The celery processes must be started manually because the 'AUTO_START_CELERY' option in enterprise_user_conf.py is set to False."

                    additional_after = additional_after + "<p>Jobs will not run for this engagement unless Celery is running for this engagement."

        data = "<table id=datatables_table></table>"
        with TableClass(db_object, "Job") as table_class:
            table_class.all_columns = job.JOB_COLUMNS
            data, datatable_columns = table_class.create_table_header(returned_jobs, {})
    except Exception as e:
        datatable_columns = []
        data = ""
        logger.exception("job_views failed: %s", e)

    celery_cmd = session.get('celery_cmd')
    return render_template('table_view.html', engagements=engagements, menu_items=menu_items,
                           engagement_path="Current Engagement: " + engagement_path, celery_cmd=celery_cmd,
                           current_location="Current Location: " + session.get('current_location_name'),
                           content=additional + data + additional_after, celery='', datatable_columns=datatable_columns)


@jobs_bp.route('/view/job/active', methods=['GET', 'POST'])
def active_job():
    return job_views(True)


@jobs_bp.route('/ajax/job/active', methods=['GET', 'POST'])
def ajax_active_job():
    try:
        model = None
        if 'model' in request.args:
            model = request.args['model']

        if model is None:
            db_object = common_flask.create_db_object(session.get('engagement_path'),
                                  session.get('selected_engagement'), session.get('key'), session.get('username'))
        else:
            db_object = common_flask.just_db_object('setup/email_event.db')

        json_data = request.get_json(force=True)

        engagement_path = session.get('engagement_path')
        tasks = job.get_active_tasks(engagement_path)
        results, valid_ids, valid_information = job.get_running_jobs(db_object, "Active", tasks, False)
        result_dict = {'draw': int(json_data['draw']), 'recordsTotal': len(results), 'recordsFiltered': len(results),
                'data': results}

        return jsonify(result_dict)
    except Exception as e:
        logger.exception("ajax_active_job failed: %s", e)
        return jsonify({'draw': -1, 'recordTotal': -1})


@jobs_bp.route('/view/job/queued', methods=['GET', 'POST'])
def queued_job():
    return job_views(False)


@jobs_bp.route('/ajax/job/queued', methods=['GET', 'POST'])
def ajax_queued_job():
    try:
        model = None
        if 'model' in request.args:
            model = request.args['model']

        if model is None:
            db_object = common_flask.create_db_object(session.get('engagement_path'),
                                  session.get('selected_engagement'), session.get('key'), session.get('username'))
        else:
            db_object = common_flask.just_db_object('setup/email_event.db')

        json_data = request.get_json(force=True)
        results = db_object.view("Log", job.JOB_COLUMNS, ["queued", "finished", "running"],
                                       [True, False, False], True)
        data = []
        if results is not None:
            for result in results:
                result['delete'] = "<img onclick='dialog_html(\"/kill/job?table=Job&ident=" + str(result['id']) + "\");' src=/static/images/delete.png height=20>"
                data.append(result)
        result_dict = {'draw': int(json_data['draw']), 'recordsTotal': len(data),
                       'recordsFiltered': len(data), 'data': data}

        return jsonify(result_dict)
    except Exception as e:
        logger.exception("ajax_queued_job failed: %s", e)
        return jsonify({'draw': -1, 'recordTotal': -1})


@jobs_bp.route('/kill/job', methods=["GET"])
def kill_single_job_confirm():
    """ Kill single passed job by setting up the form for necessary user input then doing the killing. """
    table_name = request.args['table']
    id = request.args['ident']
    model = None
    if 'model' in request.args:
        model = request.args['model']

    if model is None:
        db_object = common_flask.create_db_object(session.get('engagement_path'),
                                                  session.get('selected_engagement'), session.get('key'),
                                                  session.get('username'))
    else:
        db_object = common_flask.just_db_object('setup/email_event.db')

    records = db_object.view("Log", None, ["id"], [id])
    record = records[0]
    source = record['source']

    inputs = [['Are you sure you want to kill the selected job?', 'kill_job', r'^(?:Y|N)$']]
    if "nessus" in source:
        config = yaml.safe_load(open(db_object.base_path + "/tools/vuln/nessus.yaml"))
        NESSUS_SERVER = config['nessus_server']
        NESSUS_USERNAME = config['nessus_username']
        NESSUS_PASSWORD = config['nessus_password']
        if "http" not in NESSUS_SERVER:
            inputs.append(['Nessus server URL', 'nessus_server', ''])
        if NESSUS_USERNAME == "":
            inputs.append(['Nessus Username', 'nessus_username', ''])
        if NESSUS_PASSWORD == "":
            inputs.append(['Nessus Password', 'nessus_password', ''])
    if "sudo" in record['command']:
        inputs.append(['Sudo Password', 'sudo_password', ''])
    if len(inputs) > 0:
        with FormSetup('edit_entry', '/kill/single?table=Job&ident=' + id) as form:
            html_form = form.create_form(inputs, "black_text")

        return "<h1>Kill " + table_name + "</h1>" + html_form


@jobs_bp.route('/kill/single', methods=["GET", "POST"])
def kill_single_job():
    """ This does the actual killing. """
    msg = ""
    try:
        table_name = request.args['table']
        id = request.args['ident']
        want_to_kill_job = request.form['kill_job']
        if want_to_kill_job == "Y":
            model = None
            if 'model' in request.args:
                model = request.args['model']

            if model is None:
                db_object = common_flask.create_db_object(session.get('engagement_path'),
                                                          session.get('selected_engagement'), session.get('key'),
                                                          session.get('username'))
            else:
                db_object = common_flask.just_db_object(
                    'setup/email_event.db')

            records = db_object.view("Log", None, ["id"], [id])
            record = records[0]

            msg = kill_passed_job(request, db_object, record)
        else:
            msg = "Job not killed as you did not confirm that you wanted it killed!"

    except Exception as e:
        logger.exception("kill_single_job failed: %s", e)
        msg = "Failed when killing job!"
    return redirect("/view/job/active?msg=" + msg)


@jobs_bp.route('/kill/all/running')
def job_kill_active_confirm():
    """ Kill all running jobs does the confirmation portion. """
    model = None
    if 'model' in request.args:
        model = request.args['model']

    if model is None:
        db_object = common_flask.create_db_object(session.get('engagement_path'),
                                                  session.get('selected_engagement'), session.get('key'),
                                                  session.get('username'))
    else:
        db_object = common_flask.just_db_object(
            'setup/email_event.db')

    inputs = [['Are you sure you want to kill the selected job?', 'kill_job', r'^(?:Y|N)$']]

    already_added = []
    records = db_object.view("Log", None, ["running"], [True])
    if records is not None:
        for record in records:
            source = record['source']

            if "nessus" in source and source not in already_added:
                already_added.append(source)
                from enterprise_user_conf import NESSUS_SERVER
                if "http" not in NESSUS_SERVER:
                    inputs.append(['Nessus server URL', 'nessus_server', ''])
                inputs.append(['Nessus Username', 'nessus_user', ''])
                inputs.append(['Nessus Password', 'nessus_password', ''])
            if "sudo" in record['command'] and "sudo" not in already_added:
                inputs.append(['Sudo Password', 'sudo_password', ''])
                already_added.append("sudo")

    if len(inputs) > 0:
        with FormSetup('edit_entry', '/kill/all_running?table=Job') as form:
            html_form = form.create_form(inputs, "black_text")

        return "<h1>Kill All Running/Active Jobs</h1>" + html_form
    return ""


@jobs_bp.route('/kill/job/stop_celery')
def stop_celery_confirm():
    """ Kill all running jobs does the confirmation portion. """
    model = None
    if 'model' in request.args:
        model = request.args['model']

    if model is None:
        db_object = common_flask.create_db_object(session.get('engagement_path'),
                                                  session.get('selected_engagement'), session.get('key'),
                                                  session.get('username'))
    else:
        db_object = common_flask.just_db_object(
            'setup/email_event.db')

    inputs = [['Are you sure you want to terminate Celery processes (which kills all running jobs as well)?', 'stop_celery', r'^(?:Y|N)$']]

    already_added = []
    records = db_object.view("Log", None, ["running"], [True])
    if records is not None:
        for record in records:
            source = record['source']

            if "nessus" in source and source not in already_added:
                already_added.append(source)
                NESSUS_SERVER = ""
                with open('tools/vuln/nessus.yaml') as y:
                    yaml_dict = yaml.safe_load(y)
                    if 'nessus_server' in yaml_dict:
                        NESSUS_SERVER = yaml_dict['nessus_server']
                if "http" not in NESSUS_SERVER:
                    inputs.append(['Nessus server URL', 'nessus_server', ''])
                inputs.append(['Nessus Username', 'nessus_user', ''])
                inputs.append(['Nessus Password', 'nessus_password', ''])
            if "sudo" in record['command'] and "sudo" not in already_added:
                inputs.append(['Sudo Password', 'sudo_password', ''])
                already_added.append("sudo")

    if len(inputs) > 0:
        with FormSetup('edit_entry', '/kill/stop_celery?table=Job') as form:
            html_form = form.create_form(inputs, "black_text")

        return "<h1>Stop Celery Processes</h1>" + html_form
    return ""


@jobs_bp.route('/kill/stop_celery', methods=["GET", "POST"])
def stop_celery_processes():
    """ Terminate Celery processes. """
    model = None
    if 'model' in request.args:
        model = request.args['model']

    if model is None:
        db_object = common_flask.create_db_object(session.get('engagement_path'),
                                                  session.get('selected_engagement'), session.get('key'),
                                                  session.get('username'))
    else:
        db_object = common_flask.just_db_object(
            'setup/email_event.db')

    engagement_path = session.get('engagement_path')
    tasks = job.get_active_tasks(engagement_path)
    results, valid_ids, valid_information = job.get_running_jobs(db_object, "active", tasks, False)

    records = []
    for id in valid_ids:
        records.append(db_object.get("Log", ["id"], [id]))
    msg = ""
    if records is not None:
        for record in records:
            msg = msg + kill_passed_job(request, db_object, record, False)
    else:
        msg = "There were no running jobs to kill!  Celery Processes terminated."

    client_name = common.format_target(engagement_path.rstrip("/"))
    subprocess.run(["pkill", "-f", client_name])

    return redirect("/view/job/active?msg=" + msg)


@jobs_bp.route('/kill/all/running_queued', methods=["GET", "POST"])
def kill_all_running_queued_confirm():
    model = None
    if 'model' in request.args:
        model = request.args['model']

    if model is None:
        db_object = common_flask.create_db_object(session.get('engagement_path'),
                                                  session.get('selected_engagement'), session.get('key'),
                                                  session.get('username'))
    else:
        db_object = common_flask.just_db_object(
            'setup/email_event.db')

    inputs = [['Are you sure you want to kill the selected job?', 'kill_job', r'^(?:Y|N)$']]

    already_added = []
    records = db_object.view("Log", None, ["running"], [True])
    if records is not None:
        for record in records:
            source = record['source']

            if "nessus" in source and source not in already_added:
                already_added.append(source)
                config = yaml.safe_load(open(db_object.base_path + "/tools/vuln/nessus.yaml"))
                NESSUS_SERVER = config['nessus_server']
                if "http" not in NESSUS_SERVER:
                    inputs.append(['Nessus server URL', 'nessus_server', ''])
                inputs.append(['Nessus Username', 'nessus_user', ''])
                inputs.append(['Nessus Password', 'nessus_password', ''])
            if "sudo" in record['command'] and "sudo" not in already_added:
                inputs.append(['Sudo Password', 'sudo_password', ''])
                already_added.append("sudo")

    if len(inputs) > 0:
        with FormSetup('edit_entry', '/kill/all_running_queued?table=Job') as form:
            html_form = form.create_form(inputs, "black_text")

        return "<h1>Kill All Running/Active Jobs</h1>" + html_form
    return ""


@jobs_bp.route('/kill/all_running', methods=["GET", "POST"])
def kill_all_active_jobs():
    """ Kill all running jobs. """
    model = None
    if 'model' in request.args:
        model = request.args['model']

    if model is None:
        db_object = common_flask.create_db_object(session.get('engagement_path'),
                                                  session.get('selected_engagement'), session.get('key'),
                                                  session.get('username'))
    else:
        db_object = common_flask.just_db_object(
            'setup/email_event.db')

    engagement_path = session.get('engagement_path')
    tasks = job.get_active_tasks(engagement_path)
    results, valid_ids, valid_information = job.get_running_jobs(db_object, "active", tasks, False)

    records = []
    for id in valid_ids:
        records.append(db_object.get("Log", ["id"], [id]))
    msg = ""
    if records is not None:
        for record in records:
            msg = msg + kill_passed_job(request, db_object, record, False)
    else:
        msg = "There were no running jobs to kill!"

    return redirect("/view/job/active?msg=" + msg)


@jobs_bp.route('/kill/all_running_queued', methods=["GET", "POST"])
def kill_all_running_queued():
    """ Kill all running jobs and queued. """
    model = None
    if 'model' in request.args:
        model = request.args['model']

    if model is None:
        db_object = common_flask.create_db_object(session.get('engagement_path'),
                                                  session.get('selected_engagement'), session.get('key'),
                                                  session.get('username'))
    else:
        db_object = common_flask.just_db_object(
            'setup/email_event.db')

    engagement_path = session.get('engagement_path')
    tasks = job.get_active_tasks(engagement_path)
    results, valid_ids, valid_information = job.get_running_jobs(db_object, "active", tasks, False)

    records = []
    for id in valid_ids:
        records.append(db_object.get("Log", ["id"], [id]))
    msg = ""
    if records is not None:
        for record in records:
            msg = msg + kill_passed_job(request, db_object, record, False)
    else:
        msg = "There were no running jobs to kill.  If anything was queued it is not now too!"

    # Delete Log files of all 'queued' logs
    db_object.delete_where("Log", ["queued", "failed", "finished"], [True, False, False], True, False)

    return redirect("/view/job/active?msg=" + msg)


def kill_passed_job(request, db_object, record, do_redirect=True):
    try:
        msg = ""
        # Kill children processes
        job.terminate_children_process(None, record['pid'])

        source = record['source']
        if "nessus" in source:
                scan_id = record['pid']
                scan_id = scan_id.replace("ScanID:", "")
                from tools.vuln.nessus_run import NessusAutomation
                config = yaml.safe_load(open(db_object.base_path + "/tools/vuln/nessus.yaml"))
                NESSUS_SERVER = config['nessus_server']
                NESSUS_USERNAME = config['nessus_username']
                NESSUS_PASSWORD = config['nessus_password']
                nessus_server = NESSUS_SERVER
                if "nessus_server" in request.form:
                    nessus_server = request.form['nessus_server']
                nessus_username = NESSUS_USERNAME
                if "nessus_username" in request.form:
                    nessus_username = request.form['nessus_username']
                nessus_password = NESSUS_PASSWORD
                if "nessus_password" in request.form:
                    nessus_password = request.form['nessus_password']

                with NessusAutomation({'nessus_username': nessus_username, 'nessus_password': nessus_password,
                                       'nessus_server': nessus_server}, None, None, None, record['id'],
                                      db_object) as nessus_scan:
                    nessus_scan.stop(scan_id, db_object.current_tester)
        elif "zap" in source:
            scan_id = record['pid']
            scan_id = scan_id.replace("ScanID:", "")
            comment = record['comment']
            zap_proxy = ""
            zap_api_key = ""
            if "ZAP Proxy:" in comment:
                zap_proxy = comment[comment.find("ZAP Proxy:") + 10:]
                zap_proxy = zap_proxy[:zap_proxy.find("\n")]
                if "\\" in zap_proxy:
                    zap_proxy = zap_proxy[:zap_proxy.find("\\")]
            if "ZAP API KEY:" in comment:
                zap_api_key = comment[comment.find("ZAP API KEY:") + 12:]
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
                else:
                    msg = "Could not kill ZAP job!"
                    if do_redirect:
                        return redirect("/view/job/active?msg=" + msg)
        elif "sudo" in record['command']:
            # copy logs/*.txt files and move to output_path
            if "responder" in record['source'] or "smbrelay" in record['source']:
                import shutil
                from enterprise_user_conf import RESPONDER_PATH
                log_path = RESPONDER_PATH
                if "Responder.py" in log_path:
                    log_path = log_path[:log_path.rfind("/")]
                log_path = log_path + "/logs/"
                if os.path.isdir(log_path):
                    for f in os.listdir(log_path):
                        if f.endswith(".txt"):
                            shutil.copy2(f, record['output_filepath'])
            # kill process that spawned nmap
            process = subprocess.Popen(shlex.split("sudo pkill -P " + str(record['pid'])),
                                       stdout=subprocess.PIPE,
                                       stdin=subprocess.PIPE, stderr=subprocess.STDOUT)
            stdout = process.communicate(input=request.form['sudo_password'].encode("UTF-8"))[0]
            stdout = str(stdout)
            if "not permitted" in stdout or "not allowed" in stdout:
                msg = "Error while trying to kill nmap process ID, " + str(record['pid']) + ", you must have " \
                                                                                      "'kill' sudo permissions.  Process is stil running!"
                if do_redirect:
                    return redirect("/view/job/active?msg=" + msg)
        else:
            process = subprocess.Popen(shlex.split("kill -9 " + str(record['pid'])), stdout=subprocess.PIPE,
                                       stdin=subprocess.PIPE, stderr=subprocess.STDOUT)

        engagement_path = session.get('engagement_path')
        tasks = job.get_active_tasks(engagement_path)
        results, valid_ids, valid_information = job.get_running_jobs(db_object, "active", tasks)
        # Revoke from celery
        try:
            from celery.worker.control import revoke
            revoke(valid_information[str(record['id'])], terminate=True, signal='SIGKILL')
        except Exception as e:
            print_text.print_error("\t Error but if queued job this is not an error. " + str(e))
            pass # do nothing because probably


        # Update Log with End Time
        import datetime
        success = db_object.update("Log", {"id": record['id'], "end_time": datetime.datetime.now(),
                                           "comment": "Process was manually killed before finishing!",
                                           "queued": False, "allow_rerun": True, "failed": True, "running": False,
                                           "finished": False})

        msg = "Successfully killed job!"
    except Exception as e:
        logger.exception("kill_passed_job failed: %s", e)
        msg = str(e)

    return msg
