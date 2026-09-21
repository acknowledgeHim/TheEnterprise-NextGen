import sys
import subprocess
import shlex
from common import print_text
from common import system_process
from enterprise_user_conf import PENTEST_DIR


def scope_creep(command, scope_id, location_id, db_object, log_id):
    """ Scope Creep Recon """
    try:

        scope_creep_running, scope_creep_processes = system_process.is_running("node index.js")
        if scope_creep_running:
            process = scope_creep_processes[0]
        else:
            process = subprocess.Popen(shlex.split(PENTEST_DIR + "/scope_creep/node index.js"), stderr=subprocess.PIPE)

        command = command.replace('"', '')
        domain = command[command.find(";")+1:]

        log_info = db_object.log_record_by_id(log_id)
        output_file_path = log_info['output_filepath']
        output_file = str(output_file_path) + "scope_creep__" + str(log_id) + "__" + str(domain) + ".txt"
        print("13 scope_creep_run output_file: " + str(output_file))

        scope_ips = db_object.scope_ips()



    except Exception as e:
        print_text.print_error("scope_creep_run except: " + str(e) + " Error on line {}".format(sys.exc_info()[-1].tb_lineno))
