import sys
import os
import yaml
import shutil
from enterprise_user_conf import PENTEST_DIR
from common import scope_functions
from parsers.parser import Parser

def responder_parser(db_path, db_object, key, hashvals):
    """
    Loop thru hashvals, verify blacklist status, update Log, send to Parser, then finally email notifications out.
    :param db_path:
    :param db_object:
    :param hashvals:
    :return:
    """
    try:
        # 1st move them from default Responder Log path to correct directory
        try:
            from enterprise_user_conf import RESPONDER_PATH
            responder_path = RESPONDER_PATH
            if "responder.py" in responder_path:
                responder_path = responder_path[:responder_path.rfind("/")+1]
            elif "Responder.py" in responder_path:
                responder_path = responder_path[:responder_path.rfind("/")+1]
        except Exception as e:
            print("responder parser error: " + str(e))

        responder_config = yaml.safe_load(open('tools/attack/responder.yaml'))
        if "responder_path" in responder_config:
            responder_path = responder_config['responder_path']
            if "$PENTEST_DIR$" in responder_path:
                responder_path = responder_path.replace("$PENTEST_DIR$", PENTEST_DIR)

        # Move Responder log files to engagement output path
        source = responder_path + "/logs/"
        for hashval in hashvals:
            output_path = db_object.grab_column_from_single_record("Log", ["hashval"], [hashval], "output_filepath")
            destination = output_path + "/"
            files = os.listdir(source)
            for f in files:
                if ".log" in f:
                    shutil.move(source + f, destination)

        with Parser("responder", db_object, key, hashvals, False) as p:
            p.parse("parsers.attack.responder_parser", "ResponderParser")

    except Exception as e:
        print("responder_parser 24 except: " + str(e) + " Error on line {}".format(sys.exc_info()[-1].tb_lineno))


class ResponderParser():
    """ Parse ResponderParser files. """
    def __init__(self, db_object, location_id, scope_id, file_path_name, ext, just_file_name, target, log_id, output_path, tester_device_list, modified_by, modified_date):

        if "/" in target:
            target = target.replace("/", "_")
        self.db_object = db_object
        self.output_path = output_path
        self.location_id = location_id
        self.scope_id = scope_id
        self.target = target
        self.log_id = log_id
        self.ext = ext
        self.tester_device_list = tester_device_list
        self.file_path = file_path_name
        self.file_name = just_file_name
        self.modified_by = modified_by
        self.modified_date = modified_date
        self.log_info = self.db_object.get("Log", ["id"], [log_id])
        self.tool = self.log_info['source']
        self.start_time = self.log_info["start_time"]
        self.end_time = self.log_info["end_time"]

        # Scope IPs
        self.log_info = db_object.view("Log", ['target', 'command', 'source'], ['id'], [log_id], True)
        self.curr_scope_id = None
        if not os.path.isfile(self.log_info[0]['target']) and not os.path.isdir(self.log_info[0]['target']):
            self.curr_scope_id = self.scope_id
        self.current_location_id = self.db_object.grab_current_location()
        if not isinstance(self.current_location_id, int):
            self.current_location_id = None
        self.scope_ips = scope_functions.scope_ips(db_object, self.current_location_id)
        self.scope_ip_dictionary = scope_functions.scope_dictionary(db_object, 'IP', self.current_location_id)

    def __enter__(self):
        return self

    def __exit__(self, type, value, traceback):
        return self

    def parse(self):
        """ Parse .log files. """

        # Parse the log file!
        pass
