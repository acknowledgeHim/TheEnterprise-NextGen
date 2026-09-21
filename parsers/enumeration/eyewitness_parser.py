import sys
import os
import webbrowser
import time
from parsers. parser import Parser

def eyewitness(db_path, db_object, key, hashvals):
    """
    Loop thru hashvals, verify blacklist status, update Log, send to Parser, then finally email notifications out.
    :param db_path:
    :param db_object:
    :param hashvals:
    :return:
    """
    try:
        with Parser("eyewitness", db_object, key, hashvals, False) as p:
            p.parse("parsers.enumeration.eyewitness_parser", "EyeWitnessParser")

    except Exception as e:
        print("eyewitness parser 19 except: " + str(e) + " Error on line {}".format(sys.exc_info()[-1].tb_lineno))


class EyeWitnessParser():
    """ Parse EyeWitnessParser files. """
    def __init__(self, db_object, location_id, scope_id, file_path_name, ext, just_file_name, target, log_id, output_path, tester_device_list, modified_by, modified_date):

        if "/" in target:
            target = target.replace("/", "_")
        self.db_object = db_object
        self.output_path = output_path
        self.location_id = location_id
        self.scope_id = scope_id
        self.tool = "eyewitness"
        self.target = target
        self.log_id = log_id
        self.ext = ext
        self.tester_device_list = tester_device_list
        self.file_path = file_path_name
        self.file_name = just_file_name
        self.modified_by = modified_by
        self.modified_date = modified_date

    def __enter__(self):
        return self

    def __exit__(self, type, value, traceback):
        return self

    def parse(self):
        """ Open in browser report.html files. """
        try:
            if self.ext == "html" and "report.html" in self.file_path:
                if os.path.isfile(self.file_path):
                    webbrowser.open(self.file_path)
                    time.sleep(30)
                return {}
        except Exception as e:
            print(self.tool + " parser 57 except: " + str(e) + " Error on line {}".format(sys.exc_info()[-1].tb_lineno))
        return {}
