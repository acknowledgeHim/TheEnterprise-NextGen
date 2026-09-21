import sys
import datetime
from common import print_text, keep_tags
from parsers. parser import Parser

def enum4linux(db_path, db_object, key, hashvals):
    """
    Loop thru hashvals, verify blacklist status, update Log, send to Parser, then finally email notifications out.
    :param db_path:
    :param db_object:
    :param hashvals:
    :return:
    """
    try:
        with Parser("enum4linux", db_object, key, hashvals, False) as p:
            p.parse("parsers.enumeration.enum4linux_parser", "Enum4LinuxParser")

    except Exception as e:
        print("enum4linux parser 19 except: " + str(e) + " Error on line {}".format(sys.exc_info()[-1].tb_lineno))


class Enum4LinuxParser():
    """ Parse Enum4LinuxParser files. """
    def __init__(self, db_object, location_id, scope_id, file_path_name, ext, just_file_name, target, log_id, output_path, tester_device_list, modified_by, modified_date):

        if "/" in target:
            target = target.replace("/", "_")
        self.db_object = db_object
        self.output_path = output_path
        self.location_id = location_id
        self.scope_id = scope_id
        self.tool = "enum4linux"
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
        """ Parse .txt files. """
        try:
            if self.ext == "txt":
                engagement_device_list = []
                result_list = []
                with open(self.file_path, 'r') as enum4linux_file:
                    enum = enum4linux_file.read()
                    enum = keep_tags.clean_text(enum)
                    start_time = datetime.datetime.now()
                    if "krbtgt" in enum:
                        result_list.append([self.tool, self.tool + "-Domain_Controller_Null_Enumeration",
                                self.target, start_time, start_time, self.tool + " " + self.target,
                                "Domain Controller allowed Null Enumeration", "", "", "", "high", "", "", "",
                                self.modified_by, self.modified_date])

                output_dictionary = {}
                output_dictionary["devices"] = engagement_device_list
                output_dictionary["devices_fields_to_update"] = [('os', 'c')]
                output_dictionary["results"] = result_list
                output_dictionary["results_fields_to_update"] = [('info', 'as'), ('associated_info', 'as'),
                                                                 ('description', 'as'), ('organization', 'as')]

                return output_dictionary
            else:
                print_text.print_error("Unsupported file for parsing found, skipping it!")
                return {}
        except Exception as e:
            print(self.tool + " parser 75 except: " + str(e) + " Error on line {}".format(sys.exc_info()[-1].tb_lineno))
        return {}
