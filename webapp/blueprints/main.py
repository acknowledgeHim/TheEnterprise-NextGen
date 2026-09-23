import os
import shlex
import subprocess
import sys

from flask import Blueprint, redirect, render_template, session

from common import common, copy_keys, network, print_text, system_process
from common.navigation_menu import NAVIGATION
from enterprise_user_conf import AUTO_START_CELERY, GOLANG_PATH, MSFRCP_STARTUP, PENTEST_DIR, ZAP_API_KEY
from flask_files import common_flask

main_bp = Blueprint("main", __name__)


@main_bp.route('/')
def home(msg=""):
    os.system("export PATH=$PATH:/" + GOLANG_PATH + "/bin")

    # Copy API keys for theHarvetser & DataSploit
    copy_keys.copy_keys()

    setup_dictionary = common_flask.setup_base_page(session)
    engagements = setup_dictionary['engagements']
    engagement_path = session.get('engagement_path')

    menu_items = common_flask.loop_through_menu(NAVIGATION)
    if not (session.get('selected_engagement') and engagement_path):
        # Both should always be set together (select_engagement()/insert_engagement() only ever
        # set one without the other on a failure path - which used to leave engagement_path as
        # this function's own `= None` default while 'selected_engagement' was still truthy, so
        # the unconditional use of engagement_path below crashed instead of just going back to
        # the engagement picker, which is the only sane thing to do without a real one selected).
        return redirect("/select_engagement")

    db_object = common_flask.create_db_object(engagement_path,
                              session.get('selected_engagement'), session.get('key'), session.get('username'))

    client_name = common.format_target(engagement_path.rstrip("/"))

    celery_queue = common.format_target(engagement_path.rstrip("/"))
    celery_cmd = "celery --app=common.jobs.celery_app worker -Q " + celery_queue + " -n " + celery_queue
    session['celery_cmd'] = celery_cmd
    # Same path job_output()/celery_console() (webapp/blueprints/jobs.py) resolve from
    # session['engagement_path'] - kept alongside celery_cmd rather than recomputed there, so
    # there's exactly one place this naming lives.
    celery_log_path = engagement_path + "celery_worker.log"
    session['celery_log_path'] = celery_log_path
    celery = "Make sure celery is running for this client by running (inside your python virtual environment):<b><i>" + celery_cmd + "</b></i>"

    if AUTO_START_CELERY and not system_process.process_with_args_is_running("celery", client_name):
        # Un-redirected, this process's stdout/stderr just inherit the Flask app's own -
        # in Docker that means it's mixed into the container's combined log stream with
        # everything else, with no way to view just this engagement's celery activity from the
        # web GUI. Redirecting to a per-engagement file is what makes the Job > Celery Console
        # view (jobs.py's celery_console()/celery_console_output()) possible at all - append
        # mode so restarting celery for this engagement doesn't lose what was already there.
        celery_log_file = open(celery_log_path, "a")
        try:
            subprocess.Popen(shlex.split("celery --app=common.jobs.celery_app worker -Q " + celery_queue + " -n " + celery_queue),
                              stdout=celery_log_file, stderr=subprocess.STDOUT)
        finally:
            # The child inherits its own duplicated copy of this fd from the fork - closing the
            # parent's handle here doesn't affect the child, and not closing it would leak a
            # file descriptor in the Flask process every time this route auto-starts celery.
            celery_log_file.close()
        celery = "Celery was automatically started in the background for this engagement so you will not see"\
                         " tool output on the console.  To start celery manually, please set AUTO_START_CELERY in "\
                         "enterprise_user_conf.py to False.  Its console output is captured under Job > Celery Console."

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
