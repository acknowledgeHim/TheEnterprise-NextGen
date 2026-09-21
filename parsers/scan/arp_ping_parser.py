import sys, os
from common import scope_functions, network
from parsers. parser import Parser

def arp_ping_parser(db_path, db_object, key, hashvals):
    """
    Loop thru hashvals, verify blacklist status, update Log, send to Parser, then finally email notifications out.
    :param db_path:
    :param db_object:
    :param hashvals:
    :return:
    """
    try:
        with Parser("arp ping", db_object, key, hashvals) as p:
            p.parse("parsers.scan.arp_ping_parser", "ARPPingParser")

    except Exception as e:
        print("arp_ping_parser 73 except: " + str(e) + " Error on line {}".format(sys.exc_info()[-1].tb_lineno))


class ARPPingParser():
    """ Parse ARP files. """
    def __init__(self, db_object, location_id, scope_id, file_path_name, ext, just_file_name, target, log_id, output_path, tester_device_list, modified_by, modified_date):

        if "/" in target:
            target = target.replace("/", "_")
        self.db_object = db_object
        self.output_path = output_path
        self.location_id = location_id
        self.scope_id = scope_id
        self.tool = "arp ping"
        self.target = target
        self.log_id = log_id
        self.ext = ext
        self.tester_device_list = tester_device_list
        self.file_path = file_path_name
        self.file_name = just_file_name
        self.modified_by = modified_by
        self.modified_date = modified_date

        self.already_found_result = []

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
        try:
            if self.ext == "txt":
                return self.parse_file()

        except Exception as e:
            print("arp_ping_parser 93 except: " + str(e) + " Error on line {}".format(sys.exc_info()[-1].tb_lineno))

        return None, None, None, None, None, None

    ed_create_fields_full = ["target_ip", "target_name", "domain", "os", "mac", "accounts", "info",
                             "services", "programs", "av_present", "modified_by",
                             "modified_date", "source", "scope_id"]

    def parse_file(self):
        """ Parse ARP Ping xml files. """
        try:
            engagement_device_list = []
            with open(self.file_path, 'r') as arp_file:
                for line in arp_file:
                    parts = line.split("\t")
                    if self.curr_scope_id is not None:
                        curr_scope_id = self.curr_scope_id
                    if self.curr_scope_id is None:
                        if network.valid_ip(parts[1]):
                            for scope_ip in self.scope_ips:
                                if network.check_in_network(scope_ip, parts[1]):
                                    curr_scope_id = self.scope_ip_dictionary[scope_ip]
                                    break
                    if curr_scope_id is not None:
                        engagement_device_list.append([parts[1], parts[1], None, None, parts[2], None, None, None, None,
                                           None, self.modified_by, self.modified_date, self.tool, self.scope_id])

            output_dictionary = {}
            output_dictionary["devices"] = engagement_device_list
            output_dictionary["devices_fields_to_update"] = [('mac', 'u')]

            return output_dictionary
        except Exception as e:
            print("arp_ping_parser 91 except: " + str(e) + " Error on line {}".format(sys.exc_info()[-1].tb_lineno))
            return {}