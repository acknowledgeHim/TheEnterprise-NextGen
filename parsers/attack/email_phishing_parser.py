import sys
from common import keep_tags, network, print_text, dns_functions
from parsers. parser import Parser

def email_phishing_parser(db_path, db_object, key, hashvals):
    """
    Loop thru hashvals, verify blacklist status, update Log, send to Parser, then finally email notifications out.
    :param db_path:
    :param db_object:
    :param hashvals:
    :return:
    """
    try:
        with Parser("email phishing", db_object, key, hashvals, False) as p:
            p.parse("parsers.attack.email_phishing_parser", "PhishingParser")

    except Exception as e:
        print_text.print_error("\temail_phishing 19 except: " + str(e) + " Error on line {}".format(sys.exc_info()[-1].tb_lineno))


class PhishingParser():
    """ Parse PhishingParser files. """
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

    def __enter__(self):
        return self

    def __exit__(self, type, value, traceback):
        return self

    def parse(self):
        """ Parse .txt files. """
        try:
            return self.parse_phishing_output()

        except Exception as e:
            print_text.print_error("\temail_phishing parser 60 except: " + str(e) + " Error on line {}".format(sys.exc_info()[-1].tb_lineno))
        return {}


    def parse_phishing_output(self):
        """
        Parse.
        :return:
        """
        try:
            engagement_device_list = []
            engagement_device_list_already_added = []
            open_port_list = []
            phishing_list = []
            if self.ext == "txt":
                scenario_id = self.file_path[self.file_path.find("-scenario_id:") + 13:]
                scenario_id = scenario_id[:scenario_id.find("-")]
                with open(self.file_path, 'r') as f:

                    only_text = keep_tags.clean_text(f.read())

                    lines = only_text.split("~~~ENDOFLINE~~~\n")
                    try:
                        for line in lines:
                            fields = line.split("~~~")
                            if len(fields) == 9:
                                associated_ip = fields[1]

                                if not network.valid_ip(associated_ip):
                                    associated_ip = dns_functions.find_dns_records(associated_ip)

                                if network.valid_ip(associated_ip):
                                    if associated_ip + ":" + str(self.scope_id) not in engagement_device_list_already_added:
                                        engagement_device_list.append([associated_ip, fields[1], "", "", "",
                                                                       "", "", "", "", "",
                                                                       self.modified_by, self.modified_date,
                                                                       self.tool, self.scope_id])
                                        engagement_device_list_already_added.append(associated_ip + ":" + str(self.scope_id))

                                        open_port_list.append([associated_ip, fields[2], "tcp", "",
                                            True, self.modified_by, fields[0], "N", fields[0], fields[0], "email phishing"])
                                    phishing_list.append([self.location_id, scenario_id, fields[5], fields[5], "", fields[0], fields[8], self.modified_by])
                            else:
                                pass
                    except Exception as e:
                        print_text.print_error("\temail_phishing parser 100 except: " + str(e) + " Error on line {}".format(sys.exc_info()[-1].tb_lineno))
                        return {}
        except Exception as e:
            print_text.print_error("\temail_phishing parser 104 except: " + str(e) + " Error on line {}".format(sys.exc_info()[-1].tb_lineno))

        output_dictionary = {}
        output_dictionary["devices"] = engagement_device_list
        output_dictionary["devices_fields_to_update"] = [('target_ip', 'as')]
        output_dictionary["ports"] = open_port_list
        output_dictionary["ports_fields_to_update"] = [('output', 'c')]
        output_dictionary['phishing'] = phishing_list
        output_dictionary['phishing_fields_to_update'] = [('data_to', 'as')]
        print("111 email_phishing_parser.py output_dictionary: " + str(output_dictionary))
        return output_dictionary

