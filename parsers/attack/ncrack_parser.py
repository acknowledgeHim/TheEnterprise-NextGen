import sys, os
import yaml
from common import keep_tags, network, scope_functions
from parsers.parser import Parser

def ncrack_parser(db_path, db_object, key, hashvals):
    """
    Loop thru hashvals, verify blacklist status, update Log, send to Parser, then finally email notifications out.
    :param db_path:
    :param db_object:
    :param hashvals:
    :return:
    """
    try:
        with Parser("ncrack bruteforce", db_object, key, hashvals, False) as p:
            p.parse("parsers.attack.ncrack_parser", "NcrackParser")

    except Exception as e:
        print("ncrack_parser 19 except: " + str(e) + " Error on line {}".format(sys.exc_info()[-1].tb_lineno))


class NcrackParser():
    """ Parse Ncrack files. """
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
        self.command = self.log_info['command']

        yaml_file = self.log_info['source']
        if "(" in yaml_file:
            yaml_file = yaml_file[:yaml_file.find("(")].strip()
        config = yaml.safe_load(open(yaml_file))
        self.tool = config['tool_name']
        if "bruteforce" in self.tool:
            self.service = self.tool[self.tool.find("bruteforce") + 10:].strip()
        else:
            self.service = self.tool

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
            print("54 ncrack_parser self.tool: " + str(self.tool))
            output_dictionary = {}
            if "ncrack bruteforce ftp" in self.tool:
                output_dictionary = self.parse_ftp_bruteforce()
            elif "ncrack bruteforce https" in self.tool:
                output_dictionary = self.parse_https_bruteforce()
            elif "ncrack bruteforce mysql" in self.tool:
                output_dictionary = self.parse_mysql_bruteforce()
            elif "ncrack bruteforce pop3" in self.tool:
                output_dictionary = self.parse_pop3_bruteforce()
            elif "ncrack bruteforce redis" in self.tool:
                output_dictionary = self.parse_redis_bruteforce()
            elif "ncrack bruteforce rdp" in self.tool:
                output_dictionary = self.parse_rdp_bruteforce()
            elif "ncrack bruteforce sip" in self.tool:
                output_dictionary = self.parse_sip_bruteforce()
            elif "ncrack bruteforce smb" in self.tool:
                output_dictionary = self.parse_smb_bruteforce()
            elif "ncrack bruteforce ssh" in self.tool:
                output_dictionary = self.parse_ssh_bruteforce()
            elif "ncrack bruteforce telnet" in self.tool:
                output_dictionary = self.parse_telnet_bruteforce()
            elif "ncrack bruteforce vnc" in self.tool:
                output_dictionary = self.parse_vnc_bruteforce()

            print("68 ncrack_parser output_dictionary: " + str(output_dictionary))
            return output_dictionary
        except Exception as e:
            print("ncrack_parser parser 60 except: " + str(e) + " Error on line {}".format(sys.exc_info()[-1].tb_lineno))
        return {}

    def parse_bruteforce(self, info_text, vuln_text):
        output_dictionary = {}
        if self.ext == "ncrack":
            engagement_device_list = []
            engagement_device_list_already_added = []
            port_list = []
            result_list = []
            credential_list = []
            with open(self.file_path, 'r') as f:
                only_text = keep_tags.clean_text(f.read())

                if "Discovered credentials" in only_text:
                    discovered = only_text[only_text.find("Discovered credentials"):]
                    discovered = discovered[discovered.find("\n")+1:]
                    lines = discovered.split("\n")
                    for line in lines:
                        parts = line.split(" ")
                        if network.valid_ip(parts[0]) and len(parts) > 4:
                            ip = parts[0]
                            port = parts[1]
                            if "/" in port:
                                protocol = port[port.find("/") + 1:]
                                port = port[:port.find("/")]
                            user = parts[3].replace("'", "")
                            passwd = parts[4].replace("'", "")
                            creds = info_text + user + ":" + passwd

                            if ip + str(self.scope_id) not in engagement_device_list_already_added:
                                if self.curr_scope_id is not None:
                                    curr_scope_id = self.curr_scope_id
                                if self.curr_scope_id is None:
                                    if network.valid_ip(ip):
                                        for scope_ip in self.scope_ips:
                                            if network.check_in_network(scope_ip, ip):
                                                curr_scope_id = self.scope_ip_dictionary[scope_ip]
                                                break
                                if curr_scope_id is not None:
                                    engagement_device_list.append([ip, ip, "", "", "", "", "", "", "",
                                                                   "", self.modified_by,
                                                                   self.modified_date, self.tool, curr_scope_id])
                                    engagement_device_list_already_added.append(ip + str(curr_scope_id))

                            result_list.append([self.tool, self.tool, ip, port, protocol, creds, None, self.start_time,
                                                self.end_time, self.command, vuln_text, "", "", "", "", "", "", "",
                                                self.modified_by])

                            credential_list.append(["current", None, user, passwd, False, None, None, None,
                                                    False, None, None, None, None, self.tool, self.modified_by,
                                                    ip, None, None, self.service])

            output_dictionary["devices"] = engagement_device_list
            output_dictionary["devices_fields_to_update"] = [('mac', 'c')]
            output_dictionary["credential"] = credential_list
            output_dictionary["credential_fields_to_update"] = [('passwd', 'c')]
            output_dictionary["results"] = result_list
            output_dictionary["results_fields_to_update"] = [('output', 'as'), ('tester_output', 'as')]

        return output_dictionary

    def parse_ftp_bruteforce(self):
        """Actually does the parsing for FTP bruteforce"""
        return self.parse_bruteforce("Successful FTP login: ", "FTP share had a password that was null or easily guessable")

    def parse_https_bruteforce(self):
        """Actually does the parsing for bruteforce"""
        return self.parse_bruteforce("Successful HTTPS login: ", "HTTPS login had a password that was null or easily guessable")

    def parse_mysql_bruteforce(self):
        """Actually does the parsing for bruteforce"""
        return self.parse_bruteforce("Successful MySQL login: ", "MySQL had a password that was null or easily guessable")

    def parse_pop3_bruteforce(self):
        """Actually does the parsing for bruteforce"""
        return self.parse_bruteforce("Successful POP3 login: ", "POP3 had a password that was null or easily guessable")

    def parse_redis_bruteforce(self):
        """Actually does the parsing for bruteforce """
        return self.parse_bruteforce("Successful Redis login: ", "Redis had a password that was null or easily guessable")

    def parse_rdp_bruteforce(self):
        """Actually does the parsing for bruteforce"""
        return self.parse_bruteforce("Successful RDP login: ", "RDP had a password that was null or easily guessable")

    def parse_sip_bruteforce(self):
        """Actually does the parsing for bruteforce"""
        return self.parse_bruteforce("Successful SIP login: ", "SIP had a password that was null or easily guessable")

    def parse_smb_bruteforce(self):
        """Actually does the parsing for bruteforce"""
        return self.parse_bruteforce("Successful SMB login: ", "SMB had a password that was null or easily guessable")

    def parse_ssh_bruteforce(self):
        """Actually does the parsing for SSH bruteforce (ie ncrack ssh_login)"""
        return self.parse_bruteforce("Successful SSH login: ", "SSH had a password that was null or easily guessable")

    def parse_telnet_bruteforce(self):
        """Actually does the parsing for TELNET bruteforce (ie ncrack telnet_login)"""
        return self.parse_bruteforce("Successful TELNET login: ", "TELNET had a password that was null or easily guessable")

    def parse_vnc_bruteforce(self):
        """Actually does the parsing for VNC bruteforce (ie ncrack vnc_login)"""
        return self.parse_bruteforce("Successful VNC login: ", "VNC had a password that was null or easily guessable")

