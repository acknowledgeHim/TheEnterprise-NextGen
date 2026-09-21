import re
import sys
import datetime
from common import keep_tags, network, print_text
from parsers. parser import Parser

def amass(db_path, db_object, key, hashvals):
    """
    Loop thru hashvals, verify blacklist status, update Log, send to Parser, then finally email notifications out.
    :param db_path:
    :param db_object:
    :param hashvals:
    :return:
    """
    try:
        with Parser("amass_netdomains-whois", db_object, key, hashvals, False) as p:
            p.parse("parsers.recon.amass.netdomains.amass_whois_parser", "AmassParser")

    except Exception as e:
        print("amass_whois_parser 23 except: " + str(e) + " Error on line {}".format(sys.exc_info()[-1].tb_lineno))


class AmassParser():
    """ Parse AmassParser files. """
    def __init__(self, db_object, location_id, scope_id, file_path_name, ext, just_file_name, target, log_id, output_path, tester_device_list, modified_by, modified_date):

        if "/" in target:
            target = target.replace("/", "_")
        self.db_object = db_object
        self.output_path = output_path
        self.location_id = location_id
        self.scope_id = scope_id
        self.tool = "amass_netdomains-whois"
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
                result_list = []
                engagement_device = []
                with open(self.file_path, 'r') as domain_file:
                    for record in domain_file:
                        if '"' in record:
                            record = record.replace('"', '')
                        part = record.split("]")
                        hostname = part[1].strip()
                        ip = ""
                        if "," in hostname:
                            ip = hostname[hostname.find(",")+1:]
                            ip = ip.strip()
                            hostname = hostname[:hostname.find(",")]
                        recon_list.append([self.scope_id, "DNS", hostname, '', ip, '', '', self.tool, self.modified_by,
                                           self.modified_date])

                output_dictionary = {}
                output_dictionary["recon"] = recon_list
                output_dictionary["recon_fields_to_update"] = [('info', 'as'), ('associated_info', 'as'), ('description', 'as'),
                                                               ('organization', 'as')]
                #output_dictionary["devices"] = engagement_device
                #output_dictionary["devices_fields_to_update"] = [('mac', 'c')]
                #output_dictionary["results"] = result_list
                #output_dictionary["results_fields_to_update"] = [('output', 'as'), ('tester_output', 'as')]

                return output_dictionary
            else:
                print_text.print_error("Unsupported file for parsing found, skipping it!")
                return {}
        except Exception as e:
            print("amass lookup parser 90 except: " + str(e) + " Error on line {}".format(sys.exc_info()[-1].tb_lineno))
        return {}
