import sys
import time
import json
from common import print_text, dns_functions
from common import common, network
from parsers.parser import Parser

def hunter_io(db_path, db_object, key, hashvals):
    """
    Loop thru hashvals, verify blacklist status, update Log, send to Parser, then finally email notifications out.
    :param db_path:
    :param db_object:
    :param hashvals:
    :return:
    """
    try:
        with Parser("hunter_io", db_object, key, hashvals, False) as p:
            p.parse("parsers.recon.hunter_io_parser", "HunterIOParser")

    except Exception as e:
        print("hunter-io parser 23 except: " + str(e) + " Error on line {}".format(sys.exc_info()[-1].tb_lineno))

class HunterIOParser():
    """ Parse HunterIOParser files. """

    def __init__(self, db_object, location_id, scope_id, file_path_name, ext, just_file_name, target, log_id,
                 output_path, tester_device_list, modified_by, modified_date):

        if "/" in target:
            target = target.replace("/", "_")
        self.db_object = db_object
        self.output_path = output_path
        self.location_id = location_id
        self.scope_id = scope_id
        self.tool = "hunter_io"
        self.target = target
        self.log_id = log_id
        self.ext = ext
        self.tester_device_list = tester_device_list
        self.file_path = file_path_name
        self.file_name = just_file_name
        self.modified_by = modified_by
        self.modified_date = modified_date

        domain = self.file_path[self.file_path.rfind("__") + 2:]
        self.domain = domain[:domain.rfind(".json")]

    def __enter__(self):
        return self

    def __exit__(self, type, value, traceback):
        return self

    def parse(self):
        """ Parse .json files. """
        try:
            if self.ext == "json":
                recon_list = []
                people_list = []
                with open(self.file_path, 'rb') as json_file:
                    data = json.load(json_file)
                    for key,value in data.items():
                        if value is not None:
                            if key == "domain":
                                recon_list.append([self.scope_id, "DOMAIN", value, "", "", "", "", self.tool + " - " + self.file_name, self.modified_by, self.modified_date])
                            if key == "emails" and isinstance(value, list) and len(value) > 0:
                                for val in value:
                                    if isinstance(val, dict):
                                        email = val['value']
                                        source = val['sources'][0]['uri']
                                        people_list.append([self.location_id, "", email, "", "", "", "", '"', "", '"',
                                                            False, False, self.tool + " - " + self.file_name + " (" + source + ")",
                                                            self.modified_by, self.modified_date])

                output_dictionary = {}
                if len(people_list) > 0:
                    output_dictionary["person"] = people_list
                    output_dictionary["person_fields_to_update"] = [('person_info', 'c'), ('organization', 'c'),
                                                                    ('person_description', 'c'), ('title', 'c'),
                                                                    ('name', 'c'), ('email', 'c'),
                                                                    ('associated_info', 'c')]
                if len(recon_list) > 0:
                    output_dictionary["recon"] = recon_list
                    output_dictionary["recon_fields_to_update"] = [('info', 'as'), ('associated_info', 'as'),
                                                                   ('description', 'as'),
                                                                   ('organization', 'as')]
                return output_dictionary
            else:
                print_text.print_error("Unsupported file for parsing found, skipping it!")
                return {}
        except Exception as e:
            print("hunter-io parser 92 except: " + str(e) + " Error on line {}".format(sys.exc_info()[-1].tb_lineno))
        return {}
