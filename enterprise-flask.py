import glob
import json
import os
import re
import shlex
import ssl
import subprocess
import sys

import yaml
from flask import Flask, flash, redirect, render_template, request, session, url_for, jsonify, send_file
from tools.parse_file.file_parser import FileParser

from common import database_object, merge_devices, network
from common import keep_tags, common, system_process, print_text, copy_keys
from common.navigation_menu import NAVIGATION
from enterprise_user_conf import AUTO_START_CELERY, DEVICE_IP, OUTPUT_PATH, FLASK_KEY, FLASK_PORT, MSFRCP_STARTUP, \
    FLASK_FILE_UPLOAD_LIMIT, PENTEST_DIR, ZAP_API_KEY
from enterprise_user_conf import GOLANG_PATH
from flask_files import common_flask
from flask_files import form_views
from flask_files import insert_views
from flask_files.form_class import FormSetup
from flask_files.table_class import TableClass
from menus import job
from tools.tool_config import ToolConfig

context = ssl.SSLContext(ssl.PROTOCOL_TLSv1_2)
context.load_cert_chain('flask_files/flask.crt', 'flask_files/flask.key')

ALLOWED_EXTENSIONS = set(['nessus', 'gnmap', 'xml', 'json', 'txt', 'png', 'jpg', 'jpeg', 'gif']) # For file uploads
app = Flask(__name__)
app.config.from_object(__name__)
app.config['SECRET_KEY'] = FLASK_KEY
app.config['MAX_CONTENT_LENGTH'] = int(FLASK_FILE_UPLOAD_LIMIT) * 1024 * 1024 # file upload limit in MB
app.config['UPLOAD_FOLDER'] = "/usr/local/clients/tmp_file_upload/" #uploaded files should go to specific client (ie. /usr/local/clients/0__Test/0/file_uploads/)

@app.route('/')
def home(msg=""):
    os.system("export PATH=$PATH:/" + GOLANG_PATH + "/bin")

    if not session.get('logged_in'):
        return render_template('login.html')
    else:
        # Copy API keys for theHarvetser & DataSploit
        copy_keys.copy_keys()

        setup_dictionary = common_flask.setup_base_page(session)
        engagements = setup_dictionary['engagements']
        engagement_path = None

        menu_items = common_flask.loop_through_menu(NAVIGATION)
        if session.get('selected_engagement') and session.get('engagement_path'):
            db_object = common_flask.create_db_object(session.get('engagement_path'),
                                      session.get('selected_engagement'), session.get('key'), session.get('username'))
            engagement_path = session.get('engagement_path')

        client_name = common.format_target(engagement_path.rstrip("/"))

        celery_queue = common.format_target(engagement_path.rstrip("/"))
        celery_cmd = "celery --app=common.jobs.celery_app worker -Q " + celery_queue + " -n " + celery_queue
        session['celery_cmd'] = celery_cmd
        celery = "Make sure celery is running for this client by running (inside your python virtual environment):<b><i>" + celery_cmd + "</b></i>"

        if AUTO_START_CELERY and not system_process.process_with_args_is_running("celery", client_name):
            # subprocess.Popen(shlex.split("celery worker -Q " + celery_queue + " -n " + celery_queue + " --app=common.jobs.celery_app --loglevel=CRITICAL"))
            subprocess.Popen(shlex.split("celery --app=common.jobs.celery_app worker -Q " + celery_queue + " -n " + celery_queue))
            celery = "Celery was automatically started in the background for this engagement so you will not see"\
                             " tool output on the console.  To start celery manually, please set AUTO_START_CELERY in "\
                             "enterprise_user_conf.py to False."

        msf_running, msf_processes = system_process.is_running("msfrpcd")
        if not msf_running:
            try:
                celery = celery + "<p>Starting msfrpc ... Metasploit's RPC daemon, allowing you to use Metasploit within "\
                    "TheEnterprise!\nKilling this instance of TheEnterprise will kill the MSFRPCD.  "\
                    "Manually starting this will keep msfprcd running even when this instance of "\
                    "TheEnterprise is exited. \nTo manually start msfrpcd follow these steps:"\
                    "\n\t1. Open new console terminal or screen \n\t2. " + MSFRCP_STARTUP
                subprocess.Popen(shlex.split(MSFRCP_STARTUP), stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            except Exception as e:
                celery = celery + "<p>MSFRPC failed to start and is not running.  Please start it manually before " \
                                  "running metasploit modules by typing (in new console): " + MSFRCP_STARTUP
                print_text.print_error("enterprise except: " + str(e) + " Error on line {}".format(sys.exc_info()[-1].tb_lineno))

        zap_running, zap_processes = system_process.is_running("zap")
        if not zap_running:
            try:
                ZAP_STARTUP = PENTEST_DIR + "/zap/zap.sh -daemon -config api.key=" + ZAP_API_KEY
                print_text.print_msg("Starting ZAP ... OWASP ZAP daemon, allowing you to use ZAP within "
                                     "TheEnterprise!\nKilling this instance of TheEnterprise will kill the ZAP.  "
                                     "Manually starting this will keep zap running even when this instance of "
                                     "TheEnterprise is exited. \nTo manually start zap follow these steps:"
                                     "\n\t1. Open new console terminal or screen \n\t2. " + ZAP_STARTUP)
                subprocess.Popen(shlex.split(ZAP_STARTUP), stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            except Exception as e:
                print_text.print_error(
                    "enterprise except: " + str(e) + " Error on line {}".format(sys.exc_info()[-1].tb_lineno))

        # Make sure Scope Creep is running
        scope_creep_running = network.nc_verify('localhost', '3007')
        if not scope_creep_running:
            try:
                SCOPE_CREEP_STARTUP = "node " + PENTEST_DIR + "/scope_creep/index.js"
                print_text.print_msg("Starting Forrest's Scope Creep on port 3007.  Scope Creep normally runs on port "
                                     "3000 but TE's version runs on port 3007 which is modified in the index.js file.")
                subprocess.Popen(shlex.split(SCOPE_CREEP_STARTUP), stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            except Exception as e:
                print_text.print_error("enterprise-flask except: " + str(e) + " Error on line {}".format(sys.exc_info()[-1].tb_lineno))

        # Make sure pat_config API KEYS are copied to tools/recon/theharvester/API_KEYS (so theHarvester can use them)
        with open("tools/recon/theharvester/API_KEYS.py", "w") as api_keys:
            from enterprise_conf import BING_API_KEY, GOOGLE_CSE_API_KEY, SHODAN_API_KEY
            api_keys.write("BING_API_KEY='" + BING_API_KEY + "'\n")
            api_keys.write("GOOGLE_CSE_API_KEY='" + GOOGLE_CSE_API_KEY + "'\n")
            api_keys.write("SHODAN_API_KEY='" + SHODAN_API_KEY + "'\n")

        curr_location = session.get('current_location_name')
        if curr_location is None:
            curr_location = "main"
            session['current_location_name'] = "main"
            session['current_location'] = 1
        celery_cmd = session.get('celery_cmd')
        return render_template('main.html', engagements=engagements, menu_items=menu_items,
                               engagement_path="Current Engagement: " + engagement_path, celery_cmd=celery_cmd,
                               current_location="Current Working Location: " + curr_location,
                               content="", celery=celery, msg=msg)


@app.route('/engagement')
def engagement():
    """ Engagement main page."""
    if not session.get('logged_in'):
        return render_template('login.html')
    elif 'selected_engagement' in session:
        return home()
    else:
        return select_engagement()


@app.route('/select_engagement')
def select_engagement():
    if not session.get('logged_in'):
        return render_template('login.html')
    elif 'selected_engagement' in request.args:
        session['current_location'] = None
        session['current_location_name'] = None

        selected_engagement = request.args['selected_engagement']
        session['selected_engagement'] = selected_engagement

        if selected_engagement == "Create New Client/Engagement":
            return form_views.create_engagement(session)

        session['engagement_path'] = OUTPUT_PATH + session.get('selected_engagement') + '/'

        db_object = common_flask.create_db_object(session.get('engagement_path'), session.get('selected_engagement'),
                                                  session.get('key'), session.get('username'))

        setup_dictionary = common_flask.setup_base_page(session, db_object)
        new_client_engagements = setup_dictionary['client_engagements']
        selected_engagement_number = new_client_engagements.index(selected_engagement) + 1
        session['selected_engagement_number'] = selected_engagement_number

        # Make sure current location is selected
        locations = db_object.grab_all_locations()
        if locations is not None:
            if len(locations) > 1:
                return select_location()
            elif len(locations) == 1:
                session['current_location'] = locations[0]['id']
                session['current_location_name'] = locations[0]['name']
                current_location_dict = {"current_location": str(locations[0]['id']), 'modified_by': db_object.current_tester}
        else: # add default 'main' location
            add_location_dict = {"name": 'main', 'modified_by': db_object.current_tester}
            record, created = db_object.get_or_create("Location", add_location_dict)
            locations = db_object.grab_all_locations()
            session['current_location'] = locations[0]['id']
            session['current_location_name'] = locations[0]['name']
            current_location_dict = {"current_location": str(locations[0]['id']), 'modified_by': db_object.current_tester}

        record, created = db_object.get_or_create("CurrentLocation", current_location_dict)

        if not created:
            db_object.update("CurrentLocation", current_location_dict, ["modified_by"], [db_object.current_tester])

        return engagement()
    else:
        setup_dictionary = common_flask.setup_base_page(session)
        engagements = setup_dictionary['engagements']

        menu_items = ""

        celery_cmd = session.get('celery_cmd')
        return render_template('select_engagement.html', engagements=engagements, menu_items=menu_items,
                               engagement_path="", celery="", celery_cmd=celery_cmd)


@app.route('/select_location')
def select_location():
    if not session.get('logged_in'):
        return render_template('login.html')
    db_object = common_flask.create_db_object(session.get('engagement_path'), session.get('selected_engagement'),
                                              session.get('key'), session.get('username'))
    if 'selected_location' in request.args:
        session['current_location'] = request.args.get('selected_location')
        if session.get('current_location') == "all_locations":
            session['current_location_name'] = "All Locations"
        else:
            session['current_location_name'] = db_object.grab_column_from_single_record("Location", ["id"],
                                                                [request.args.get('selected_location')], "name")

        current_location_dict = {"current_location": session.get('current_location'), 'modified_by': db_object.current_tester}
        curr_location_info =  db_object.view("CurrentLocation", None, ["modified_by"], [db_object.current_tester], True)
        if curr_location_info is not None:
            current_location_dict['id'] = curr_location_info[0]['id']
            db_object.update("CurrentLocation", current_location_dict, ["modified_by"], [db_object.current_tester])
        else:
            db_object.add("CurrentLocation", current_location_dict)

        return engagement()
    else:
        locations = db_object.grab_all_locations()
        location_str = ""
        for location in locations:
            location_str = location_str + "<a class='list-group-item' href='/select_location?selected_location=" + str(location['id']) + "'>" + location['name'] + "</a>"
        location_str = location_str + "<a class='list-group-item' href='/select_location?selected_location=all_locations'>All locations</a>"

        celery_cmd = session.get('celery_cmd')
        return render_template('select_location.html', locations='Select Current Working Location<br>' + location_str,
                               menu_items="", engagement_path=session.get('engagement_path'), celery="", celery_cmd=celery_cmd)

@app.route('/create_engagement' , methods=['POST'])
def insert_passed_engagement():
    if not session.get('logged_in'):
        return render_template('login.html')
    else:
        flash(insert_views.insert_engagement(session, request))
        return engagement()

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
                os.path.dirname(os.path.realpath(__file__)) + '/setup/email_event.db')
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
        print_text.print_error("enterprise-flask.py except: " + str(e) + " Error on line {}".format(sys.exc_info()[-1].tb_lineno))

    celery_cmd = session.get('celery_cmd')
    return render_template('table_view.html', engagements=engagements, menu_items=menu_items,
                           engagement_path="Current Engagement: " + engagement_path, celery_cmd=celery_cmd,
                           current_location="Current Location: " + session.get('current_location_name'),
                           content=additional + data + additional_after, celery='', datatable_columns=datatable_columns)


@app.route('/view/job/active', methods=['GET', 'POST'])
def active_job():
    if not session.get('logged_in'):
        return render_template('login.html')
    else:
        return job_views(True)

@app.route('/ajax/job/active', methods=['GET', 'POST'])
def ajax_active_job():
    if not session.get('logged_in'):
        return render_template('login.html')
    else:
        try:
            model = None
            if 'model' in request.args:
                model = request.args['model']

            if model is None:
                db_object = common_flask.create_db_object(session.get('engagement_path'),
                                      session.get('selected_engagement'), session.get('key'), session.get('username'))
            else:
                db_object = common_flask.just_db_object(os.path.dirname(os.path.realpath(__file__)) + '/setup/email_event.db')

            json_data = request.get_json(force=True)

            engagement_path = session.get('engagement_path')
            tasks = job.get_active_tasks(engagement_path)
            results, valid_ids, valid_information = job.get_running_jobs(db_object, "Active", tasks, False)
            result_dict = {'draw': int(json_data['draw']), 'recordsTotal': len(results), 'recordsFiltered': len(results),
                    'data': results}

            return jsonify(result_dict)
        except Exception as e:
            print("enterprise-flask.py except: " + str(e) + " Error on line {}".format(sys.exc_info()[-1].tb_lineno))
            return jsonify({'draw': -1, 'recordTotal': -1})

@app.route('/view/job/queued', methods=['GET', 'POST'])
def queued_job():
    if not session.get('logged_in'):
        return render_template('login.html')
    else:
        return job_views(False)

@app.route('/ajax/job/queued', methods=['GET', 'POST'])
def ajax_queued_job():
    if not session.get('logged_in'):
        return render_template('login.html')
    else:
        try:
            model = None
            if 'model' in request.args:
                model = request.args['model']

            if model is None:
                db_object = common_flask.create_db_object(session.get('engagement_path'),
                                      session.get('selected_engagement'), session.get('key'), session.get('username'))
            else:
                db_object = common_flask.just_db_object(os.path.dirname(os.path.realpath(__file__)) + '/setup/email_event.db')

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
            print("enterprise-flask.py except: " + str(e) + " Error on line {}".format(sys.exc_info()[-1].tb_lineno))
            return jsonify({'draw': -1, 'recordTotal': -1})

@app.route('/kill/job', methods=["GET"])
def kill_single_job_confirm():
    """ Kill single passed job by setting up the form for necessary user input then doing the killing. """
    if not session.get('logged_in'):
        return render_template('login.html')
    else:
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
            db_object = common_flask.just_db_object(os.path.dirname(os.path.realpath(__file__)) + '/setup/email_event.db')

        records = db_object.view("Log", None, ["id"], [id])
        record = records[0]
        source = record['source']

        inputs = [['Are you sure you want to kill the selected job?', 'kill_job', r'^(?:Y|N)$']]
        if "nessus" in source:
            #from enterprise_user_conf import NESSUS_SERVER, NESSUS_USERNAME, NESSUS_PASSWORD
            config = yaml.load(open(db_object.base_path + "/tools/vuln/nessus.yaml"), Loader=yaml.SafeLoader)
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


@app.route('/kill/single', methods=["GET", "POST"])
def kill_single_job():
    """ This does the actual killing. """
    if not session.get('logged_in'):
        return render_template('login.html')
    else:
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
                        os.path.dirname(os.path.realpath(__file__)) + '/setup/email_event.db')

                records = db_object.view("Log", None, ["id"], [id])
                record = records[0]

                msg = kill_passed_job(request, db_object, record)
            else:
                msg = "Job not killed as you did not confirm that you wanted it killed!"

        except Exception as e:
            print("enterprise-flask.py except: " + str(e) + " Error on line {}".format(sys.exc_info()[-1].tb_lineno))
            msg = "Failed when killing job!"
        return redirect("/view/job/active?msg=" + msg)

@app.route('/kill/all/running')
def job_kill_active_confirm():
    """ Kill all running jobs does the confirmation portion. """
    if not session.get('logged_in'):
        return render_template('login.html')
    else:
        model = None
        if 'model' in request.args:
            model = request.args['model']

        if model is None:
            db_object = common_flask.create_db_object(session.get('engagement_path'),
                                                      session.get('selected_engagement'), session.get('key'),
                                                      session.get('username'))
        else:
            db_object = common_flask.just_db_object(
                os.path.dirname(os.path.realpath(__file__)) + '/setup/email_event.db')

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

@app.route('/kill/job/stop_celery')
def stop_celery_confirm():
    """ Kill all running jobs does the confirmation portion. """
    if not session.get('logged_in'):
        return render_template('login.html')
    else:
        model = None
        if 'model' in request.args:
            model = request.args['model']

        if model is None:
            db_object = common_flask.create_db_object(session.get('engagement_path'),
                                                      session.get('selected_engagement'), session.get('key'),
                                                      session.get('username'))
        else:
            db_object = common_flask.just_db_object(
                os.path.dirname(os.path.realpath(__file__)) + '/setup/email_event.db')

        inputs = [['Are you sure you want to terminate Celery processes (which kills all running jobs as well)?', 'stop_celery', r'^(?:Y|N)$']]

        already_added = []
        records = db_object.view("Log", None, ["running"], [True])
        if records is not None:
            for record in records:
                source = record['source']

                if "nessus" in source and source not in already_added:
                    already_added.append(source)
                    #from enterprise_user_conf import NESSUS_SERVER
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

@app.route('/kill/stop_celery', methods=["GET", "POST"])
def stop_celery_processes():
    """ Terminate Celery processes. """
    if not session.get('logged_in'):
        return render_template('login.html')
    else:
        model = None
        if 'model' in request.args:
            model = request.args['model']

        if model is None:
            db_object = common_flask.create_db_object(session.get('engagement_path'),
                                                      session.get('selected_engagement'), session.get('key'),
                                                      session.get('username'))
        else:
            db_object = common_flask.just_db_object(
                os.path.dirname(os.path.realpath(__file__)) + '/setup/email_event.db')

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

@app.route('/kill/all/running_queued', methods=["GET", "POST"])
def kill_all_running_queued_confirm():
    if not session.get('logged_in'):
        return render_template('login.html')
    else:
        model = None
        if 'model' in request.args:
            model = request.args['model']

        if model is None:
            db_object = common_flask.create_db_object(session.get('engagement_path'),
                                                      session.get('selected_engagement'), session.get('key'),
                                                      session.get('username'))
        else:
            db_object = common_flask.just_db_object(
                os.path.dirname(os.path.realpath(__file__)) + '/setup/email_event.db')

        inputs = [['Are you sure you want to kill the selected job?', 'kill_job', r'^(?:Y|N)$']]

        already_added = []
        records = db_object.view("Log", None, ["running"], [True])
        if records is not None:
            for record in records:
                source = record['source']

                if "nessus" in source and source not in already_added:
                    already_added.append(source)
                    #from enterprise_user_conf import NESSUS_SERVER
                    config = yaml.load(open(db_object.base_path + "/tools/vuln/nessus.yaml"), Loader=yaml.SafeLoader)
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

@app.route('/kill/all_running', methods=["GET", "POST"])
def kill_all_active_jobs():
    """ Kill all running jobs. """
    if not session.get('logged_in'):
        return render_template('login.html')
    else:
        model = None
        if 'model' in request.args:
            model = request.args['model']

        if model is None:
            db_object = common_flask.create_db_object(session.get('engagement_path'),
                                                      session.get('selected_engagement'), session.get('key'),
                                                      session.get('username'))
        else:
            db_object = common_flask.just_db_object(
                os.path.dirname(os.path.realpath(__file__)) + '/setup/email_event.db')

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

@app.route('/kill/all_running_queued', methods=["GET", "POST"])
def kill_all_running_queued():
    """ Kill all running jobs and queued. """
    if not session.get('logged_in'):
        return render_template('login.html')
    else:
        model = None
        if 'model' in request.args:
            model = request.args['model']

        if model is None:
            db_object = common_flask.create_db_object(session.get('engagement_path'),
                                                      session.get('selected_engagement'), session.get('key'),
                                                      session.get('username'))
        else:
            db_object = common_flask.just_db_object(
                os.path.dirname(os.path.realpath(__file__)) + '/setup/email_event.db')

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
                #from enterprise_user_conf import NESSUS_SERVER, NESSUS_USERNAME, NESSUS_PASSWORD
                config = yaml.load(open(db_object.base_path + "/tools/vuln/nessus.yaml"), Loader=yaml.SafeLoader)
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
            from celery.app.control import Inspect
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
        print("enterprise-flask.py except: " + str(e) + " Error on line {}".format(sys.exc_info()[-1].tb_lineno))
        msg = str(e)

    return msg

@app.route('/ajax', methods=['GET', 'POST'])
def ajaxs():
    if not session.get('logged_in'):
        return render_template('login.html')
    else:
        try:
            model = None
            if 'model' in request.args:
                model = request.args['model']

            if model is None:
                db_object = common_flask.create_db_object(session.get('engagement_path'),
                                      session.get('selected_engagement'), session.get('key'), session.get('username'))
            else:
                db_object = common_flask.just_db_object(os.path.dirname(os.path.realpath(__file__)) + '/setup/email_event.db')

            json_data = request.get_json(force=True)
            with TableClass(db_object, request.args['table'], True, json_data, session.get('username')) as table_class:
                if 'i' in request.args:
                    device = request.args['i']
                    device_info = db_object.get('EngagementDevice', ['target_name'], [device], True)
                    device_id = device_info['id']
                    table_class.global_filters = ["engagementdevice_id"]
                    table_class.global_filter_values = [device_id]

                result_dict = table_class.ajax_view()
                return jsonify(result_dict)
        except Exception as e:
            print("enterprise-flask.py except: " + str(e) + " Error on line {}".format(sys.exc_info()[-1].tb_lineno))

@app.route('/view', methods=['GET', 'POST'])
def views():
    if not session.get('logged_in'):
        return render_template('login.html')
    else:
        try:
            model = None
            if 'model' in request.args:
                model = request.args['model']

            if model is None:
                db_object = common_flask.create_db_object(session.get('engagement_path'),
                                      session.get('selected_engagement'), session.get('key'), session.get('username'))
            else:
                db_object = common_flask.just_db_object(os.path.dirname(os.path.realpath(__file__)) + '/setup/email_event.db')

            setup_dictionary = common_flask.setup_base_page(session, db_object)
            engagements = setup_dictionary['engagements']
            menu_items = common_flask.loop_through_menu(NAVIGATION)
            engagement_path = session.get('engagement_path')

            data = "<table id=datatables_table></table>"
            with TableClass(db_object, request.args['table'], True, None, session.get('username')) as table_class:
                data, datatable_columns = table_class.list_view()

        except Exception as e:
            print("enterprise-flask.py except: " + str(e) + " Error on line {}".format(sys.exc_info()[-1].tb_lineno))
            data = str(e)

        celery_cmd = session.get('celery_cmd')
        return render_template('table_view.html', engagements=engagements, menu_items=menu_items,
                           engagement_path="Current Engagement: " + engagement_path, celery_cmd=celery_cmd,
                           current_location="Current Location: " + session.get('current_location_name'),
                           content=data, celery="", datatable_columns=datatable_columns)

@app.route('/detail', methods=['GET', 'POST'])
def detail():
    if not session.get('logged_in'):
        return render_template('login.html')
    else:
        try:
            model = None
            if 'model' in request.args:
                model = request.args['model']

            if model is None:
                db_object = common_flask.create_db_object(session.get('engagement_path'),
                                      session.get('selected_engagement'), session.get('key'), session.get('username'))
            else:
                db_object = common_flask.just_db_object(os.path.dirname(os.path.realpath(__file__)) + '/setup/email_event.db')

            setup_dictionary = common_flask.setup_base_page(session, db_object)
            engagements = setup_dictionary['engagements']
            menu_items = common_flask.loop_through_menu(NAVIGATION)
            engagement_path = session.get('engagement_path')

            device = request.args['i']
            device_info = db_object.get('EngagementDevice', ['target_name'], [device], True)
            device_id = device_info['id']

            data = "<table id=datatables_table></table>"
            with TableClass(db_object, 'DevicePort', True, None, session.get('username')) as table_class:
                table_class.global_filters = ["engagementdevice_id"]
                table_class.global_filter_values = [device_id]
                data, datatable_columns = table_class.list_view()

        except Exception as e:
            print("enterprise-flask.py except: " + str(e) + " Error on line {}".format(sys.exc_info()[-1].tb_lineno))
            data = str(e)

        celery_cmd = session.get('celery_cmd')
        return render_template('detail_view.html', engagements=engagements, menu_items=menu_items,
                           engagement_path="Current Engagement: " + engagement_path, celery_cmd=celery_cmd,
                           current_location="Current Location: " + session.get('current_location_name'),
                           content=data, celery="", datatable_columns=datatable_columns)

@app.route('/add', methods=['GET'])
def add():
    if not session.get('logged_in'):
        return render_template('login.html')
    else:
        try:
            table_name = request.args['table']
            model = None
            if 'model' in request.args:
                model = request.args['model']

            if model is None:
                db_object = common_flask.create_db_object(session.get('engagement_path'),
                                      session.get('selected_engagement'), session.get('key'), session.get('username'))
            else:
                db_object = common_flask.just_db_object('setup/email_event.db')

            return "<h1>Insert " + table_name + "</h1>" + form_views.edit_form(table_name, None, db_object, model)

        except Exception as e:
            return "Failed.  Error: " + str(e)

@app.route('/insert', methods=['GET', 'POST'])
def insert():
    if not session.get('logged_in'):
        return render_template('login.html')
    else:
        try:
            table_name = request.args['table']

            fields = {}
            for key, value in request.form.items():
                if value.strip() == "":
                    value = None
                fields[key] = value

            model = None
            if 'model' in request.args:
                model = request.args['model']

            if model is None:
                db_object = common_flask.create_db_object(session.get('engagement_path'),
                                      session.get('selected_engagement'), session.get('key'), session.get('username'))
            else:
                db_object = common_flask.just_db_object('setup/email_event.db')

            msg = form_views.insert_entry(db_object, table_name, fields)

        except Exception as e:
            print("enterprise-flask.py except: " + str(e) + " Error on line {}".format(sys.exc_info()[-1].tb_lineno))
            msg = "Failed. " + table_name + " entry was not inserted.  Error: " + str(e)
        if model is not None:
            return redirect(url_for('views', table=table_name, msg=msg, model=model))
        return redirect(url_for('views', table=table_name, msg=msg))

@app.route('/edit', methods=['GET'])
def edit():
    if not session.get('logged_in'):
        return render_template('login.html')
    else:
        try:
            table_name = request.args['table']
            id = request.args['ident']

            model = None
            if 'model' in request.args:
                model = request.args['model']

            if model is None:
                db_object = common_flask.create_db_object(session.get('engagement_path'),
                                      session.get('selected_engagement'), session.get('key'), session.get('username'))
            else:
                db_object = common_flask.just_db_object('setup/email_event.db')

            return "<h1>Edit " + table_name + "</h1>" + form_views.edit_form(table_name, id, db_object, model, "edit")

        except Exception as e:
            return "Failed.  Error: " + str(e)

@app.route('/update', methods=['GET', 'POST'])
def update():
    if not session.get('logged_in'):
        return render_template('login.html')
    else:
        try:
            table_name = request.args['table']
            id = request.args['ident']

            fields = {"id": str(id)}
            for key, value in request.form.items():
                if value.strip() == "":
                    value = None
                fields[key] = value

            model = None
            if 'model' in request.args:
                model = request.args['model']

            if model is None:
                db_object = common_flask.create_db_object(session.get('engagement_path'),
                                      session.get('selected_engagement'), session.get('key'), session.get('username'))
            else:
                db_object = common_flask.just_db_object('setup/email_event.db')

            msg = form_views.update_entry(db_object, table_name, fields)

            if table_name == "CurrentLocation":
                session['current_location'] = fields['current_location']
                field_name = fields['current_location']
                if field_name != "all_locations":
                    field_name = db_object.grab_column_from_single_record("Location", ["id"], [field_name], "name")
                session['current_location_name'] = field_name

        except Exception as e:
            print("enterprise-flask.py except: " + str(e) + " Error on line {}".format(sys.exc_info()[-1].tb_lineno), file=sys.stderr)
            msg = "Failed. " + table_name + " entry was not updated.  Error: " + str(e)

        if model is not None:
            return redirect(url_for('views', table=table_name, msg=msg, model=model))
        return redirect(url_for('views', table=table_name, msg=msg))

@app.route('/delete', methods=['GET'])
def delete():
    if not session.get('logged_in'):
        return render_template('login.html')
    else:
        try:
            table_name = request.args['table']
            model = None
            if 'model' in request.args:
                model = request.args['model']
            id = request.args['ident']

            if model is None:
                db_object = common_flask.create_db_object(session.get('engagement_path'),
                                      session.get('selected_engagement'), session.get('key'), session.get('username'))
            else:
                db_object = common_flask.just_db_object('setup/email_event.db')

            is_running = False
            if table_name == "Log":
                log = db_object.view("Log", ['running'], ['id'], [id], True)
                if log[0]['running']:
                    is_running = True

            if table_name == "Job":
                engagement_path = session.get('engagement_path')
                tasks = job.get_active_tasks(engagement_path)
                results, valid_ids, valid_information = job.get_running_jobs(db_object, 'Active', tasks)
                job.kill_job(db_object, id, valid_information)
                return "Successfully stopped job!"
            elif is_running and table_name == "Log":
                return "You can not delete a Log entry for a running job.  You must first kill the running job."
            else:
                db_object.delete_where(table_name, ["id"], [id], True)
                return "Successfully deleted " + str(table_name) + "."
        except Exception as e:
            return "Failed.  Error: " + str(e)

@app.route('/truncate', methods=['GET'])
def truncate():
    if not session.get('logged_in'):
        return render_template('login.html')
    else:
        try:
            table_name = request.args['table']

            return '<h1>Delete All ' + table_name + ' Records</h1>' + '<form name="truncate" action="/truncate_confirmed?table=' + table_name + '" ' \
                    'method=post enctype="multipart/form-data">' \
                    'This action is not reversable, so only click the confirm button if you know you want to do this!<p>' \
                    '<input type=Submit value="Confirm Delete All"></form>'
        except Exception as e:
            return "Failed.  Error: " + str(e)

@app.route('/truncate_confirmed', methods=['GET', 'POST'])
def truncate_confirmed():

    if not session.get('logged_in'):
        return render_template('login.html')
    else:
        try:
            table_name = request.args['table']

            model = None
            if 'model' in request.args:
                model = request.args['model']

            if model is None:
                db_object = common_flask.create_db_object(session.get('engagement_path'),
                                      session.get('selected_engagement'), session.get('key'), session.get('username'))
            else:
                db_object = common_flask.just_db_object('setup/email_event.db')

            db_object.truncate(table_name)
            msg = 'Successfully deleted all ' + str(table_name) + ' records.'
        except Exception as e:
            msg = "Failed to delete all " + table_name + " records.  Error: " + str(e)
        return redirect(url_for('views', table=table_name, msg=msg))

@app.route('/merge', methods=['GET'])
def merge():
    if not session.get('logged_in'):
        return render_template('login.html')
    else:
        try:
            table_name = request.args['table']
            model = None
            if 'model' in request.args:
                model = request.args['model']

            if model is None:
                db_object = common_flask.create_db_object(session.get('engagement_path'),
                                      session.get('selected_engagement'), session.get('key'), session.get('username'))
            else:
                db_object = common_flask.just_db_object('setup/email_event.db')

            if table_name == "EngagementDevice":
                merge_devices.merge_all_devices(db_object)

            return "Merging " + str(table_name) + " in the background."
        except Exception as e:
            return "Failed.  Error: " + str(e)

@app.route('/tool', methods=['GET'])
def tool():
    """ Tool """

    dropdown_fields = []
    form_html = ""
    fields = []
    answers = {}
    replacements = {}
    global_fields = {}

    try:
        if not session.get('logged_in'):
            return render_template('login.html')

        setup_dictionary = common_flask.setup_base_page(session)
        engagements = setup_dictionary['engagements']

        engagement_path = session.get('engagement_path')
        menu_items = common_flask.loop_through_menu(NAVIGATION)

        db_object = common_flask.create_db_object(session.get('engagement_path'), session.get('selected_engagement'),
                                                  session.get('key'), session.get('username'))

        # grab yaml file from passed yaml_config
        yaml_file = keep_tags.clean_text(request.args['tool'])
        if ".yaml" not in yaml_file:
            yaml_file = yaml_file + ".yaml"
        yaml_config = yaml.safe_load(open(db_object.base_path + "/" + yaml_file))
        tool_config = ToolConfig(db_object, db_object.engagement_path, yaml_file)

        if "callable_yaml" in yaml_config:
            tool_name = ""
            yaml_configs = yaml_config['callable_yaml']
            form_html = ""
            for yaml_c in yaml_configs:
                # Now grab all the yaml files that match in callable_yaml
                # 1st grab all user-input needed
                for f in glob.glob(db_object.base_path + yaml_c + ".yaml"):
                    tmp_fields = []
                    tmp_answers = {}
                    tmp_replacements = []
                    tmp_global_fields = []
                    if ".yaml" in f and f != tool_config.yaml_config_file:
                        current_yaml_config = yaml.safe_load(open(f))

                        #current_yaml_config = ToolConfig(db_object, db_object.engagement_path, yaml_c + ".yaml")
                        if "tool_name" in current_yaml_config:
                            sep = ""
                            if tool_name != "":
                                sep = ", "
                            #tool_name = tool_name + sep + current_yaml_config['tool_name']
                            tool_name = current_yaml_config['tool_name']
                            tool_config.load_config_values(current_yaml_config)
                            if tool_config.questions is not None:
                                tmp_fields, tmp_answers, tmp_replacements, tmp_global_fields = tool_config.manual_entry(True)
                                # find questions that have options to tell it is a dropdown field
                                for question in tool_config.questions:
                                    if "options" in question:
                                        dropdown_fields.append(question['name'])

                            if tool_config.selections is not None:
                                for select in tool_config.selections:
                                    names = ",".join(db_object.dictionary_list_multiple_fields(select['table'],
                                                                    select['display_fields'], None, None, None, " - "))
                                    ids = db_object.dictionary_list(select['table'], 'id')
                                    ids_string = "|".join(str(id) for id in ids)
                                    tmp_fields.append([select['table'], select['table'].lower() + "_id",
                                                  re.compile(ids_string), names])

                            # Append results to full list below - make sure fields not already have tmp_fields
                            for tf in tmp_fields:
                                if tf not in fields:
                                    fields.append(tf)

                            answers.update(tmp_answers)
                            replacements.update(tmp_replacements)
                            global_fields.update(tmp_global_fields)

                            session['answers'] = json.dumps(answers)
                            session['replacements'] = json.dumps(replacements)
                            session['global_fields'] = json.dumps(global_fields)

                            if len(fields) > 0:
                                tmp_form_html = "<h3> User-input to launch " + tool_name + "</h3>" + form_views.tool_form(
                                    yaml_file.replace(".yaml", ""), fields, dropdown_fields)
                                print("1223 enterprise-flask tmp_form_html: " + str(tmp_form_html))
                                if tmp_form_html is not None:
                                    form_html = form_html + tmp_form_html
                            else:
                                return redirect(url_for('run_tool', tool=request.args['tool']))
        else:
            tool_config.load_config_values()
            tool_name = yaml_config['tool_name']

            if tool_config.questions is not None:
                fields, answers, replacements, global_fields = tool_config.manual_entry(True)

                # find questions that have options to tell it is a dropdown field
                for question in yaml_config['questions']:
                    if "options" in question:
                        dropdown_fields.append(question['name'])

            if tool_config.selections is not None:
                current_location = db_object.grab_current_location()
                location_id = None
                if current_location != "all":
                    location_id = current_location
                for select in tool_config.selections:
                    filter_key = None
                    filter_value = None
                    display_fields = select['display_fields']
                    if "filter" in select:
                        if select['filter'] == "CURRENT_LOCATION" and location_id is not None:
                            if select['table'] == "DevicePort":
                                display_fields.append("EngagementDevice.Scope.Location.name")
                            filter_key = ["location_id"]
                            filter_value = [location_id]
                        else:
                            filter_key = []
                            filter_value = []
                            if isinstance(select['filter'], dict):
                                filter_dictionary = select['filter']
                            else:
                                filter_dictionary = json.loads(select['filter'])
                            for key, value in filter_dictionary.items():
                                filter_key.append(key)
                                filter_value.append(value)
                    names = db_object.dictionary_list_multiple_fields(select['table'], display_fields, filter_key,
                                                                           filter_value)
                    names = ",".join(names)
                    return_fields = db_object.dictionary_list(select['table'], select['return_field'], filter_key,
                                                                   filter_value)
                    single_value = None
                    if "," not in names:
                        single_value = names

                    rfields_string = "|".join(str(rfield) for rfield in return_fields)
                    field_name = select['table'].lower() + "_id"
                    if "name" in select:
                        field_name = select['name']
                    fields.append([select['table'], field_name, re.compile(rfields_string), single_value, names])
                    dropdown_fields.append(field_name)

            session['answers'] = json.dumps(answers)
            session['replacements'] = json.dumps(replacements)
            session['global_fields'] = json.dumps(global_fields)

            if len(fields) > 0:
                form_html = "<h1> User-input to launch " + tool_name + "</h1>" + form_views.tool_form(yaml_file.replace(".yaml", ""), fields, dropdown_fields)
            else:
                return redirect(url_for('run_tool', tool=request.args['tool']))
    except Exception as e:
        print_text.print_error("enterprise-flask.py except: " + str(e) + " Error on line {}".format(sys.exc_info()[-1].tb_lineno))

    celery_cmd = session.get('celery_cmd')
    return render_template('form.html', engagements=engagements, menu_items=menu_items,
                                   engagement_path="Current Engagement: " + engagement_path, celery_cmd=celery_cmd,
                                   current_location="Current Working Location: " + session.get('current_location_name'),
                                   content="", celery="", html_form=form_html)

@app.route('/run_tool', methods=['GET', 'POST'])
def run_tool():
    """ Run the Tool."""
    try:
        tool_name = ""
        all_errors = ""
        if not session.get('logged_in'):
            return render_template('login.html')

        setup_dictionary = common_flask.setup_base_page(session)
        engagements = setup_dictionary['engagements']

        engagement_path = session.get('engagement_path')
        menu_items = common_flask.loop_through_menu(NAVIGATION)

        db_object = common_flask.create_db_object(session.get('engagement_path'), session.get('selected_engagement'),
                                                  session.get('key'), session.get('username'))

        # get session objects
        answers = json.loads(session.get('answers'))
        replacements = json.loads(session.get('replacements'))
        global_fields = json.loads(session.get('global_fields'))

        # grab yaml file from passed yaml_config
        yaml_file = keep_tags.clean_text(request.args['tool'])
        if ".yaml" not in yaml_file:
            yaml_file = yaml_file + ".yaml"
        yaml_config = yaml.safe_load(open(db_object.base_path + "/" + yaml_file))
        tool_config = ToolConfig(db_object, db_object.engagement_path, yaml_file)

        if "callable_yaml" in yaml_config:
            tool_config.yaml_configs = tool_config.config['callable_yaml']
            tool_name = ", ".join(tool_config.config['callable_yaml'])
        else:
            tool_config.yaml_configs = [yaml_file]
            tool_name = yaml_config['tool_name']

        all_errors = tool_config.grab_targets_and_generate_commands(request, answers, replacements, global_fields)
        if all_errors is None:
            all_errors = ""
        if tool_config.error is not None:
            all_errors = all_errors + " " + tool_config.error

        all_messages = all_errors + " "  + tool_config.msg

        if all_messages != "":
            return home(all_messages)
            #return redirect(url_for('home', msg=all_errors))
        else:
            return home('Successfully started ' + tool_name)
            #return redirect(url_for('home', msg='Successfully started ' + yaml_config['tool_name']))

    except Exception as e:
        print_text.print_error(
            "enterprise-flask.py except: " + str(e) + " Error on line {}".format(sys.exc_info()[-1].tb_lineno))

@app.route('/file_parse')
def file_parse_setup():
    try:
        if not session.get('logged_in'):
            return render_template('login.html')

        setup_dictionary = common_flask.setup_base_page(session)
        engagements = setup_dictionary['engagements']

        engagement_path = session.get('engagement_path')
        menu_items = common_flask.loop_through_menu(NAVIGATION)

        db_object = common_flask.create_db_object(session.get('engagement_path'), session.get('selected_engagement'),
                                                  session.get('key'), session.get('username'))

        scopes = db_object.dictionary_list("Scope", "id")
        names = ",".join(db_object.dictionary_list("Scope", "entry"))
        scope_string = "|".join(str(scope) for scope in scopes)

        # find all yaml files
        display = []
        default_output_folder = []
        for folder, foldernames, files in os.walk(db_object.base_path):
            for name in files:
                if name.lower().endswith(".yaml"):
                    full_yaml_file_path = os.path.join(folder, name)
                    config = yaml.safe_load(open(full_yaml_file_path))
                    if config is not None and "callable_yaml" not in config and "tool_name" in config:
                        yaml_file = os.path.join(folder, name)
                        yaml_file = yaml_file[yaml_file.find(db_object.base_path) + len(db_object.base_path):]
                        display.append(config['tool_name'] + " (" + yaml_file + ")")
                        default_output_folder.append(config['output_path'])

        with FormSetup('edit_entry', '/file_parser_run') as form:
            inputs = [['full path to file(s) to parse (blank means it will parse files in the default directory)',
                       'path_to_file_to_parse', '']]
            inputs.append(['tool whose output needs parsing', 'tool_yaml_file', sorted(display)])
            inputs.append(['select the scope that the file(s) data belongs to', 'scope_id', re.compile(scope_string), None, names])
            html_form = form.create_form(inputs, "black_text")

        celery_cmd = session.get('celery_cmd')
        return render_template('main.html', engagements=engagements, menu_items=menu_items,
                               engagement_path="Current Engagement: " + engagement_path, celery_cmd=celery_cmd,
                               current_location="Current Working Location: " + session.get('current_location_name'),
                               content='File Parsing (TheEnterprise auto-parses files created when it runs a tool) '
                                       'but here you can parse and add a file\'s contents that was run elsewhere.',
                               celery=html_form, msg="")
    except Exception as e:
        print_text.print_error(
            "enterprise-flask.py except: " + str(e) + " Error on line {}".format(sys.exc_info()[-1].tb_lineno))

@app.route('/file_parser_run', methods=['POST'])
def file_parser_run():
    try:
        if not session.get('logged_in'):
            return render_template('login.html')

        setup_dictionary = common_flask.setup_base_page(session)
        engagements = setup_dictionary['engagements']

        engagement_path = session.get('engagement_path')
        menu_items = common_flask.loop_through_menu(NAVIGATION)

        db_object = common_flask.create_db_object(session.get('engagement_path'), session.get('selected_engagement'),
                                                  session.get('key'), session.get('username'))

        scope_id = request.form['scope_id']
        tool_yaml_file = request.form['tool_yaml_file']
        path_to_file_to_parse = request.form['path_to_file_to_parse']

        tool = tool_yaml_file[:tool_yaml_file.find("(")].strip()
        yaml_file = tool_yaml_file[tool_yaml_file.rfind("(")+1:]
        yaml_file = yaml_file[:yaml_file.find(")")]

        config = yaml.safe_load(open(yaml_file))
        output_path = config['output_path']

        field_values = {'tool': tool, 'yaml_file': yaml_file, 'path_to_file_to_parse': path_to_file_to_parse,
                        'scope_id': scope_id}

        location_id = db_object.grab_column_from_single_record("Scope", ["id"], [scope_id], "location_id")
        if location_id is None:
            return home('You did not select a valid Scope from the repository and therefore the files were not parsed!')

        file_parser = FileParser(db_object, engagement_path)
        file_parser.create_parsing_job(field_values, scope_id, location_id, yaml_file, output_path)

        return home('Successfully added file(s) for parsing.  You can check the Jobs to see it running or when '
                        'it has completed.')
    except Exception as e:
        print_text.print_error(
            "enterprise-flask.py except: " + str(e) + " Error on line {}".format(sys.exc_info()[-1].tb_lineno))

@app.route("/device/lookup_merge", methods=['POST'])
def lookup_merge():
    try:
        if not session.get('logged_in'):
            return render_template('login.html')

        ips = "No matches found, please try searching again!"
        setup_dictionary = common_flask.setup_base_page(session)
        db_object = common_flask.create_db_object(session.get('engagement_path'), session.get('selected_engagement'),
                                                  session.get('key'), session.get('username'))

        search_string = request.form['title']
        div_id = request.form['div_id']

        devices = db_object.join_view("EngagementDevice", ["Scope.Location.name"], None, ["target_name"], [search_string], False)
        if devices is None or len(devices) == 0:
            devices = db_object.join_view("EngagementDevice", ["Scope.Location.name"], None, ["target_ip"], [search_string], False)
        if devices is not None and len(devices) > 0:
            ips = "<ul id='mergeto_selection' class='selection'>"
            for device in devices:
                ips = ips + "<li class='selection_item' onClick='select_item(\"" + div_id + "\", \"" + str(device['id']) + "\", \"" + device['target_name'] + " (" + device['target_ip'] + ") @ " + device['name'] + "\", \"" + str(device['id']) + "\")'>" + device['target_name'] + " (" + device['target_ip'] + ") @ " + device['name'] + "</li>"
            ips = ips + "</ul>"
        return ips

    except Exception as e:
        print_text.print_error(
            "enterprise-flask.py except: " + str(e) + " Error on line {}".format(sys.exc_info()[-1].tb_lineno))

@app.route('/device/lookup_info', methods=['POST'])
def lookup_info():
    try:
        if not session.get('logged_in'):
            return render_template('login.html')

        setup_dictionary = common_flask.setup_base_page(session)
        db_object = common_flask.create_db_object(session.get('engagement_path'), session.get('selected_engagement'),
                                                  session.get('key'), session.get('username'))

        info_id = request.form['info_id']
        div_id = request.form['div_id']
        devices = db_object.join_view("EngagementDevice", ["Scope.entry", "Scope.Location.name"], None, ["id"], [info_id], True)[:1]

        info = "No matches found, please try searching again!"
        for device in devices:
            info = '<center><u><b>' + device['target_name'] + '</b></u>'
            info = info + '<br><b>IP</b>: ' + str(device['target_ip'])
            info = info + '<br><b>Location</b>: ' + str(device['name'])
            info = info + '<br><b>Scope</b>: ' + str(device['entry'])
            info = info + '<br><b>OS</b>: ' + str(device['os'])
            info = info + '<br><b>MAC</b>: ' + str(device['mac'])
            info = info + '<br><b>Info</b>: ' + str(device['info'])
            info = info + '<br><b>Source</b>: ' + device['source']
            info = info + '<br><b>Modified By</b>: ' + device['modified_by']
            info = info + '<br><b>Modified Date</b>: ' + str(device['modified_date'])
            info = info + '</center>'

        return info

    except Exception as e:
        print_text.print_error(
            "enterprise-flask.py except: " + str(e) + " Error on line {}".format(sys.exc_info()[-1].tb_lineno))

def allowed_file(filename):
    return '.' in filename and \
           filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

@app.route('/file_upload', methods=['GET', 'POST'])
def upload_file():
    if not session.get('logged_in'):
        return render_template('login.html')

    table_name = request.args['table']
    engagement_path = session.get('engagement_path')

    db_object = common_flask.create_db_object(session.get('engagement_path'), session.get('selected_engagement'),
                                              session.get('key'), session.get('username'))

    if request.method == 'POST':
        # check if the post request has the file part
        if 'file' not in request.files:
            flash('No file part')
            return redirect(request.url)
        file = request.files['file']

        location_id = request.form['location_id']

        # if user does not select file, browser also
        # submit an empty part without filename
        if file.filename == '':
            flash('No selected file')
            return redirect(request.url)
        msg = "Upload failed :("
        if file and allowed_file(file.filename):
            upload_path = engagement_path + "/uploads/" + table_name.lower() + "/" + file.filename + "/"
            common.create_path(upload_path)
            filename = common.generate_filename(file.filename)
            file.save(os.path.join(upload_path, filename))
            if table_name == "Scope":
                from common.jobs import tasks
                with open(os.path.join(upload_path, filename), 'r') as scope_file:
                    s = scope_file.read()
                    scopes = s.split("\n")
                    for scope in scopes:
                        if scope is not None and scope != "":
                            scope = str(scope).strip()
                            fields = {'entry': scope, 'location_id': location_id}
                            msg = tasks.add_scope_to_celery(db_object.engagement_path, session.get('engagement_path'),
                                                            session.get('selected_engagement'), session.get('key'),
                                                            session.get('username'), fields, False)
                return redirect(url_for('views', table='Scope'))

            return redirect(url_for('home', msg=msg))

    upload_form = "<!doctype html><title>Upload " + table_name + " File</title><h1>Upload " + table_name + "</h1>"\
            "<form method=post enctype=multipart/form-data action='/file_upload?table=" + table_name + "'><input type=file name=file>"

    location_form = ""
    # all locations
    locations = db_object.view("Location", ['id', 'name'])
    # Get current location
    curr_location = db_object.view("CurrentLocation", ['current_location'], ['modified_by'], [session.get('username')])[0]['current_location']

    # auto get location id if possible, otherwise ask for it
    if "all_location" in curr_location and len(locations) > 1:
        location_form = "Location for scope entries: <select name=location_id>"
        for location in locations:
            location_form = location_form + "<option value='" + str(location['id']) + "'>" + location['name'] + "</option>"
        location_form = location_form + "</select><br>"
    elif len(locations) == 1:
        location_id = locations[0]['id']
        location_form = "<input type=hidden name=location_id value=" + str(location_id) + ">"
    else:
        for location in locations:
            if curr_location == location['name'] or str(curr_location) == str(location['id']):
                location_id = location['id']
                location_form = "<input type=hidden name=location_id value=" + str(location_id) + ">"
                break

    upload_form = upload_form + location_form + "<input type=submit value='Upload " + table_name + "'></form>"

    return upload_form


@app.route('/report/excel')
def excel_report():
    try:
        if not session.get('logged_in'):
            return render_template('login.html')

        setup_dictionary = common_flask.setup_base_page(session)
        engagements = setup_dictionary['engagements']

        engagement_path = session.get('engagement_path')
        menu_items = common_flask.loop_through_menu(NAVIGATION)

        db_object = common_flask.create_db_object(session.get('engagement_path'), session.get('selected_engagement'),
                                                  session.get('key'), session.get('username'))
        engagement_info = db_object.view("Engagement")
        client_name = engagement_info[0]['client_name'].replace(" ", "_")
        engagement_number = engagement_info[0]['engagement_number']
        naming_convention = client_name + "__" + engagement_number + "_report.xlsx"

        from export.excel_export import Excel
        excel_report = Excel(db_object, engagement_path)
        excel_report.export(naming_convention)

        if os.path.isfile(engagement_path + naming_convention):
            return send_file(engagement_path + naming_convention)#, as_attachment=True, attachment_filename=naming_convention)
        else:
            return home('Successfully generated the report which can be at: ' + engagement_path + naming_convention)
    except Exception as e:
        print_text.print_error("enterprise-flask.py except: " + str(e) + " Error on line {}".format(sys.exc_info()[-1].tb_lineno))

@app.route('/encrypt/all')
def encrypt_all(msg=''):
    """
    Setup encryption process.
    :return:
    """
    try:
        if not session.get('logged_in'):
            return render_template('login.html')

        setup_dictionary = common_flask.setup_base_page(session)
        engagements = setup_dictionary['engagements']

        engagement_path = session.get('engagement_path')
        menu_items = common_flask.loop_through_menu(NAVIGATION)

        db_object = common_flask.create_db_object(session.get('engagement_path'), session.get('selected_engagement'),
                                                  session.get('key'), session.get('username'))
        with FormSetup('edit_entry', '/encrypt/run') as form:
            inputs = [['Encryption Password', 'encrypt_key_password', ''],
                      ['Confirm Encryption Password', 'confirm_encrypt_key_password', '']]
            html_form = form.create_form(inputs, "black_text")

        celery_cmd = session.get('celery_cmd')
        return render_template('main.html', engagements=engagements, menu_items=menu_items,
                               engagement_path="Current Engagement: " + engagement_path, celery_cmd=celery_cmd,
                               current_location="Current Working Location: " + session.get('current_location_name'),
                               content='Please enter the encryption password you would like to use below. '
                                       'This password will be required to decrypt.', celery=html_form, msg=msg)
    except Exception as e:
        print_text.print_error(
            "enterprise-flask.py except: " + str(e) + " Error on line {}".format(sys.exc_info()[-1].tb_lineno))

@app.route('/download_results/out')
def download_out(msg=''):
    """
    Setup encryption process.
    :return:
    """
    try:
        if not session.get('logged_in'):
            return render_template('login.html')

        setup_dictionary = common_flask.setup_base_page(session)
        engagements = setup_dictionary['engagements']

        engagement_path = session.get('engagement_path').rstrip("/")
        engagement_num = engagement_path[engagement_path.rfind("/")+1:]

        client = engagement_path[engagement_path.find(OUTPUT_PATH)+len(OUTPUT_PATH):].rstrip("/")
        client_folder = client[:client.rfind("/")]
        client_info = client_folder.split("__")
        client_num = client_info[0]

        engagement_path = engagement_path + "/" + client_num + ".out"
        menu_items = common_flask.loop_through_menu(NAVIGATION)
        fname = engagement_path[engagement_path.rfind("/")+1:]
        return send_file(engagement_path, attachment_filename=fname, as_attachment=True)
    except Exception as e:
        print_text.print_error("enterprise-flask.py except: " + str(e) + " Error on line {}".format(sys.exc_info()[-1].tb_lineno))

@app.route('/encrypt/run', methods=['POST'])
def encrypt():
    try:
        if not session.get('logged_in'):
            return render_template('login.html')

        setup_dictionary = common_flask.setup_base_page(session)
        engagements = setup_dictionary['engagements']

        engagement_path = session.get('engagement_path').rstrip("/")
        engagement_number = engagement_path[engagement_path.rfind("/")+1:]
        #client = engagement_path[:engagement_path.find("/"+engagement_number +"/")].rstrip("/")
        client = engagement_path[engagement_path.find(OUTPUT_PATH)+len(OUTPUT_PATH):].rstrip("/")
        client = client[:client.rfind("/")]

        engagement_path = engagement_path + "/"
        menu_items = common_flask.loop_through_menu(NAVIGATION)

        db_object = common_flask.create_db_object(session.get('engagement_path'), session.get('selected_engagement'),
                                                  session.get('key'), session.get('username'))

        encrypt_key = request.form['encrypt_key_password']
        confirm_encrypt_key = request.form['confirm_encrypt_key_password']
        if encrypt_key == confirm_encrypt_key:
            from menus.encrypt_output import EncryptOutput
            with EncryptOutput(db_object, engagement_path) as encrypt_output:
                print("1676 enterprise flask")
                file_location = encrypt_output.all(encrypt_key)
                print("1678 enterprise flask file_location: " + str(file_location))
            return send_file(file_location + client + "__" + engagement_number + ".zip", attachment_filename=client + "__" + engagement_number + ".zip", as_attachment=True)
            #return home('Successfully created 7zip encrypted file for transporting and is located at: ' +
            #            str(file_location))
        else:
            return encrypt_all('Encryption Password and Confirm Encryption Password did not match!  Try again!')
    except Exception as e:
        print_text.print_error(
            "enterprise-flask.py except: " + str(e) + " Error on line {}".format(sys.exc_info()[-1].tb_lineno))
        return home('Error trying to encrypt error: ' + str(e))

@app.route('/login', methods=['POST'])
def do_login():
    """ Login. """
    user = keep_tags.clean_text(request.form['username'])
    passwd = keep_tags.clean_text(request.form['password'])

    correct_key_entered = database_object.verify_key_connect_to_emailevent_db(user, passwd)
    if correct_key_entered:
        session['key'] = passwd
        session['logged_in'] = True
        session['username'] = user
    else:
        flash('Wrong credential, try again!')
    return select_engagement()


@app.route("/logout")
def logout():
    session.clear()
    session['logged_in'] = False
    return home()


if __name__ == "__main__":
    debug_mode = os.environ.get("FLASK_DEBUG", "false").lower() == "true"
    app.run(host=DEVICE_IP, port=FLASK_PORT, debug=debug_mode, ssl_context=context)

