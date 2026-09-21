import sys, os
from common import print_text, common, scope_functions, network
from parsers. parser import Parser

def runfinger_parser(db_path, db_object, key, hashvals):
    """
    Loop thru hashvals, verify blacklist status, update Log, send to Parser, then finally email notifications out.
    :param db_path:
    :param db_object:
    :param hashvals:
    :return:
    """
    try:
        with Parser("runfinger", db_object, key, hashvals, False) as p:
            p.parse("parsers.attack.runfinger_parser", "RunFingerParser")

    except Exception as e:
        print("runfinger parser 23 except: " + str(e) + " Error on line {}".format(sys.exc_info()[-1].tb_lineno))


class RunFingerParser():
    """ Parse RunFingerParser files. """
    def __init__(self, db_object, location_id, scope_id, file_path_name, ext, just_file_name, target, log_id, output_path, tester_device_list, modified_by, modified_date):

        if "/" in target:
            target = target.replace("/", "_")
        self.db_object = db_object
        self.output_path = output_path
        self.location_id = location_id
        self.scope_id = scope_id
        self.tool = "runfinger"
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
            if self.ext == "txt":
                engagement_device_list = []
                result_list = []
                devices = []
                with open(self.file_path, 'r') as f:
                    for record in f:
                        parts = record.split(",")

                        domain = parts[2]
                        if "Domain:" in domain:
                            domain = domain[domain.find("Domain:") + 7]
                        domain = domain.replace("'", "")

                        os = parts[1]
                        if "Os:" in os:
                            os = os[os.find("Os:") + 3]
                        os = os.replace("'", "")

                        signing = parts[3]
                        if "Signing:" in signing:
                            signing = signing[signing.find("Signing:") + 8]
                        signing = signing.replace("'", "")

                        if signing == "False":
                            signing = " SMB Signing Disabled "
                        else:
                            signing = ""
                        curr_scope_id = None
                        if network.valid_ip(parts[0]):
                            for scope_ip in self.scope_ips:
                                if network.check_in_network(scope_ip, parts[0]):
                                    curr_scope_id = self.scope_ip_dictionary[scope_ip]
                                    break
                        if curr_scope_id is not None:
                            engagement_device_list.append((parts[0], parts[0], domain, os, None, None, signing,
                                                            None, None, None, self.modified_by, self.modified_date,
                                                            self.tool + " - " + self.file_path, self.scope_id))
                            if signing != "":
                                devices.append(parts[0])

                            result_list.append(["runfinger", "runfinger_smb_signing_disabled", parts[0], "445", 'tcp', record,
                                           "", self.modified_date, self.modified_date,
                                           "responder/tools/runfinger.py -i -g", "SMB Signing Disabled",
                                           "The device did not have SMB signing enabled.",
                                           "Enable SMB signing on all devices.", "0.0", "critical", "configuration",
                                           "", "", self.modified_by])

                output_dictionary = {}
                if len(engagement_device_list) > 0:
                    output_dictionary["devices"] = engagement_device_list
                    output_dictionary["devices_fields_to_update"] = [('info', 'as'), ('os', 'ol'), ('domain', 'c')]

                # write to hosts/unsigned_devices.txt
                if len(devices) > 0:
                    if not os.path.isfile(self.db_object.self.engagement_path + "/hosts/unsigned_devices.txt"):
                        common.create_path(self.db_object.self.engagement_path + "/hosts/")
                    with open(self.db_object.self.engagement_path + "/hosts/unsigned_devices.txt", "w") as ud:
                        ud.write("\n".join(devices))

                if len(result_list) > 0:
                    output_dictionary["results"] = result_list
                    output_dictionary["results_fields_to_update"] = [('output', 'c')]

                return output_dictionary
            else:
                print_text.print_error("Unsupported file for parsing found, skipping it!")
                return {}
        except Exception as e:
            print("runfinger parser 92 except: " + str(e) + " Error on line {}".format(sys.exc_info()[-1].tb_lineno))
        return {}
