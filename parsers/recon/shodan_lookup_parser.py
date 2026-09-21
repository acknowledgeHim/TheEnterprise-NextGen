import sys
import datetime
from common import print_text
from parsers. parser import Parser

def shodan_parser(db_path, db_object, key, hashvals):
    """
    Loop thru hashvals, verify blacklist status, update Log, send to Parser, then finally email notifications out.
    :param db_path:
    :param db_object:
    :param hashvals:
    :return:
    """
    try:
        with Parser("shodan", db_object, key, hashvals, False) as p:
            p.parse("parsers.recon.shodan_lookup_parser", "ShodanParser")

    except Exception as e:
        print("shodan parser 23 except: " + str(e) + " Error on line {}".format(sys.exc_info()[-1].tb_lineno))


class ShodanParser():
    """ Parse ShodanParser files. """
    def __init__(self, db_object, location_id, scope_id, file_path_name, ext, just_file_name, target, log_id, output_path, tester_device_list, modified_by, modified_date):

        if "/" in target:
            target = target.replace("/", "_")
        self.db_object = db_object
        self.output_path = output_path
        self.location_id = location_id
        self.scope_id = scope_id
        self.tool = "shodan"
        self.target = target
        self.log_id = log_id
        self.ext = ext
        self.tester_device_list = tester_device_list
        self.file_path = file_path_name
        self.file_name = just_file_name
        self.modified_by = modified_by
        self.modified_date = modified_date

        domain = self.file_path[self.file_path.rfind("__") + 2:]
        self.domain = domain[:domain.rfind(".txt")]

    def __enter__(self):
        return self

    def __exit__(self, type, value, traceback):
        return self

    def parse(self):
        """ Parse .txt files. """
        try:
            if self.ext == "txt":
                recon_list = []
                with open(self.file_path, 'r') as domain_file:
                    for record in domain_file:
                        recon_list.append(record.split("\t") + [self.modified_by, self.modified_date])

                output_dictionary = {}
                if len(recon_list) > 0:
                    output_dictionary["recon"] = recon_list
                    output_dictionary["recon_fields_to_update"] = [('info', 'as'), ('associated_info', 'as'),
                                                                   ('description', 'as'), ('organization', 'as')]

                return output_dictionary
            else:
                print_text.print_error("Unsupported file for parsing found, skipping it!")
                return {}
        except Exception as e:
            print("shodan parser 117 except: " + str(e) + " Error on line {}".format(sys.exc_info()[-1].tb_lineno))
        return {}
