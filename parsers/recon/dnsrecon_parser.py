import sys
from common import keep_tags, network, print_text
from parsers. parser import Parser

def dnsrecon(db_path, db_object, key, hashvals):
    """
    Loop thru hashvals, verify blacklist status, update Log, send to Parser, then finally email notifications out.
    :param db_path:
    :param db_object:
    :param hashvals:
    :return:
    """
    try:
        with Parser("dnsrecon", db_object, key, hashvals, False) as p:
            p.parse("parsers.recon.dnsrecon_parser", "DNSReconParser")

    except Exception as e:
        print("dnsrecon_parser 23 except: " + str(e) + " Error on line {}".format(sys.exc_info()[-1].tb_lineno))


class DNSReconParser():
    """ Parse DNSReconParser files. """
    def __init__(self, db_object, location_id, scope_id, file_path_name, ext, just_file_name, target, log_id, output_path, tester_device_list, modified_by, modified_date):

        if "/" in target:
            target = target.replace("/", "_")
        self.db_object = db_object
        self.output_path = output_path
        self.location_id = location_id
        self.scope_id = scope_id
        self.tool = "dnsrecon"
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
                people_list = []
                recon_list = []
                result_list = []
                engagement_device = []
                with open(self.file_path, 'r') as domain_file:
                    text = domain_file.read()
                    name_server_parts = text.split("[*] Trying NS server ")
                    for name_server_part in name_server_parts:
                        lines = name_server_part.split("\n")
                        device = ""
                        port = ""
                        protocol = "tcp"
                        for line in lines:
                            if "\t" in line:
                                line = line.replace("\t", " ")
                            while "  " in line:
                                line = line.replace("  ", " ")

                            if "NS Servers found:" in name_server_part:
                                if "NS " in line:
                                    parts = line.split(" ")
                                    if len(parts) > 3 and network.valid_ip(parts[3]):
                                        engagement_device.append([parts[3], parts[2].lower(), "", "", "", "", "NameServer for " + self.domain, "", "", "",
                                                          self.modified_by, self.modified_date, self.tool, self.scope_id])
                            if "Has port 53" in name_server_part:
                                parts = line.split(" ")
                                if device == "" and "Has port " in line:
                                    device = parts[1]
                                    port = parts[4]
                                    protocol = parts[5]
                                elif "Zone Transfer was successful!!" in line:
                                    result_list.append(["dnsrecon", "dnsrecon-zonetransfer", device.lower(), port, protocol,
                                                        line, "", "", "", "dig -t " + self.domain,
                                                        "NameServer allowed zone transfer", "",
                                                        "", "", "critical", "configuration", "", "", self.modified_by])
                                elif len(parts) > 3 and network.valid_ip(parts[3]):
                                    recon_list.append([self.scope_id, parts[1], parts[2].lower(), None, parts[3], None, None,
                                                       self.tool, self.modified_by, self.modified_date])
                output_dictionary = {}
                output_dictionary["recon"] = recon_list
                output_dictionary["recon_fields_to_update"] = [('info', 'as'), ('associated_info', 'as'), ('description', 'as'),
                                                               ('organization', 'as')]
                output_dictionary["devices"] = engagement_device
                output_dictionary["devices_fields_to_update"] = [('mac', 'c')]
                output_dictionary["results"] = result_list
                output_dictionary["results_fields_to_update"] = [('output', 'as'), ('tester_output', 'as')]

                return output_dictionary
            else:
                print_text.print_error("Unsupported file for parsing found, skipping it!")
                return {}
        except Exception as e:
            print("dnsrecon parser 117 except: " + str(e) + " Error on line {}".format(sys.exc_info()[-1].tb_lineno))
        return {}
