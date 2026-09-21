import sys
import os
import shutil
from common import dns_functions, common, network, scope_functions
from parsers.parser import Parser

def struts_pwn_parser(db_path, db_object, key, hashvals):
    """
    Loop thru hashvals, verify blacklist status, update Log, send to Parser, then finally email notifications out.
    :param db_path:
    :param db_object:
    :param hashvals:
    :return:
    """
    try:
        with Parser("struts_pwn", db_object, key, hashvals, False) as p:
            p.parse("parsers.attack.struts_pwn_parser-2018-11776", "StrutsPwnParser")

    except Exception as e:
        print("StrutsPwnParser 19 except: " + str(e) + " Error on line {}".format(sys.exc_info()[-1].tb_lineno))


class StrutsPwnParser():
    """ Parse StrutsPwnParser files. """
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
        """ Parse .txt files. """

        try:
            engagement_device_list = []
            result_list = []
            with open(self.file_path, 'r') as result_file:
                result = result_file.read()

                if "Status: Vulnerable!" in result:
                    # Grab just domain from target
                    domain = common.format_website(self.target)
                    # Get domain's IP
                    domain_ip, additional = dns_functions.grab_dns_record(domain, True)

                    # Engagement Device
                    ip = common.format_website(domain_ip)
                    host_name = common.format_website(self.target)

                    curr_scope_id = None
                    if network.valid_ip(ip):
                        for scope_ip in self.scope_ips:
                            if network.check_in_network(scope_ip, ip):
                                curr_scope_id = self.scope_ip_dictionary[scope_ip]
                                break
                    if curr_scope_id is not None:
                        engagement_device_list.append([ip, host_name, domain, "", "", None, None, None, None, None,
                         self.modified_by, self.modified_date, self.tool, curr_scope_id])

                        port = network.return_port(self.target)
                        title = 'Apache Struts RCE Vulnerability (CVE-2018-11776)'
                        # Result
                        result_list.append([self.tool, 'struts_pwn_exploitable', self.target, port, 'tcp', result,
                                        None, self.start_time, self.end_time, self.log_info['command'], title,
                                        title, None, "CVE-2018-11776", "", "",
                                        'https://github.com/mazen160/struts-pwn_CVE-2018-11776', None, self.modified_by])
        except Exception as e:
            print("struts_pwn_parser 227 except: " + str(e) + " Error on line {}".format(sys.exc_info()[-1].tb_lineno))

            if len(result_list) == 0:
                log_info = self.db_object.log_record_by_id(self.log_id)
                current_comment = log_info['comment']
                if current_comment is None:
                    current_comment = ""
                update_values = dict(id=self.log_id,
                                     comment="You probably are being blacklisted.  Here is the error: " + str(e) +
                                             current_comment, parsed=False, failed=True, rerun=True, blacklisted=True)
                self.db_object.update("Log", update_values, ["id"], [self.log_id])

        output_dictionary = {}
        output_dictionary["devices"] = engagement_device_list
        output_dictionary["devices_fields_to_update"] = [('domain', 'ol')]
        output_dictionary["results"] = result_list
        output_dictionary["results_fields_to_update"] = [('output', 'as')]

        return output_dictionary
