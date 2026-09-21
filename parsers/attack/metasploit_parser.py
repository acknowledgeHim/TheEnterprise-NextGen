import sys, os
import yaml
from common import keep_tags, network, print_text, common, scope_functions
from parsers.parser import Parser

def metasploit(db_path, db_object, key, hashvals):
    """
    Loop thru hashvals, verify blacklist status, update Log, send to Parser, then finally email notifications out.
    :param db_path:
    :param db_object:
    :param hashvals:
    :return:
    """
    try:
        with Parser("metasploit bruteforce", db_object, key, hashvals, False) as p:
            p.parse("parsers.attack.metasploit_parser", "MetasploitParser")

    except Exception as e:
        print("metasploit_parser 19 except: " + str(e) + " Error on line {}".format(sys.exc_info()[-1].tb_lineno))


class MetasploitParser():
    """ Parse MetasploitParser files. """
    def __init__(self, db_object, location_id, scope_id, file_path_name, ext, just_file_name, target, log_id,
                 output_path, tester_device_list, modified_by, modified_date):

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
        yaml_file = self.log_info['source']
        if "(" in yaml_file:
            yaml_file = yaml_file[:yaml_file.find("(")].strip()
        config = yaml.safe_load(open(yaml_file))
        self.tool = config['tool_name']
        if "bruteforce" in self.tool:
            self.service = self.tool[self.tool.find("bruteforce") + 10:].strip()
        elif "anonymous" in self.tool:
            self.service = self.tool[self.tool.find("anonymous")+9:].strip()
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
            print("60 metasploit_parser self.tool: " + str(self.tool))
            output_dictionary = {}
            if "metasploit bruteforce esx" in self.tool:
                output_dictionary = self.parse_esx_bruteforce()
            elif "metasploit bruteforce ftp" in self.tool:
                output_dictionary = self.parse_ftp_bruteforce()
            elif "metasploit bruteforce mssql" in self.tool:
                output_dictionary = self.parse_smb_bruteforce()
            elif "metasploit anonymous smb" in self.tool:
                output_dictionary = self.parse_smb_anonymous()
            elif "metasploit bruteforce smb" in self.tool:
                output_dictionary = self.parse_smb_bruteforce()
            elif "metasploit bruteforce ssh" in self.tool:
                output_dictionary = self.parse_ssh_bruteforce()
            elif "metasploit bruteforce telnet" in self.tool:
                output_dictionary = self.parse_telnet_bruteforce()
            elif "metasploit bruteforce snmp" in self.tool:
                output_dictionary = self.parse_snmp_bruteforce()
            elif "metasploit bruteforce vnc" in self.tool:
                output_dictionary = self.parse_vnc_bruteforce()
            elif "metasploit bruteforce wordpress" in self.tool:
                output_dictionary = self.parse_wordpress_bruteforce()
            elif "metasploit extrabacon asa" in self.tool:
                output_dictionary = self.parse_extrabacon_asa_exploit()

            print("68 metasploit_parser output_dictionary: " + str(output_dictionary))
            return output_dictionary
        except Exception as e:
            print("metasploit_parser parser 60 except: " + str(e) + " Error on line {}".format(sys.exc_info()[-1].tb_lineno))
        return {}

    def parse_bruteforce(self, metasploit_cmd, info_text, vuln_text):
        if self.ext == "txt":
            engagement_device_list = []
            engagement_device_list_already_added = []
            port_list = []
            result_list = []
            credential_list = []
            with open(self.file_path, 'r') as msf_file:
                only_text = keep_tags.clean_text(msf_file.read())

                lines = only_text.split("\n")
                try:
                    for line in lines:
                        if "[+]" in line and "LOGIN SUCCESSFUL" in line.upper():
                            columns = line.split(" ")
                            if len(columns) > 1:
                                ip = columns[1]
                                if ":" in ip:
                                    port = ip[ip.find(":") + 1:]
                                    ip = ip[:ip.find(":")]

                                    if network.valid_ip(ip):
                                        if "SUCCESSFUL:" in line:
                                            creds = line[line.find("SUCCESSFUL:") + 11:].strip()
                                        elif "Successful:" in line:
                                            creds = line[line.find("Successful:") + 11:].strip()
                                        if "\n" in creds:
                                            creds = creds[:creds.find("\n")]
                                        creds = creds.strip()
                                        user = creds[:creds.find(":")]
                                        passwd = creds[creds.find(":")+1:]
                                        info = info_text + creds + "\n"
                                        line_no_junk = line.replace("\t", " ") + "\n"

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

                                        result_list.append([self.tool, "AF-" + self.tool, ip, port,
                                             "tcp", info, line_no_junk, self.start_time, self.end_time, metasploit_cmd,
                                             vuln_text, "", "", "", "", "", "", "", self.modified_by])

                                        credential_list.append(["current", None, user, passwd, False, None, None, None,
                                                                False, None, None, None, None, self.tool,
                                                                self.modified_by, ip, None, None, self.service])

                        elif "[+]" in line and "esx" in metasploit_cmd:
                            columns = line.split(" ")
                            if len(columns) > 1:
                                ip = columns[1]
                                if ":" in ip:
                                    port = ip[ip.find(":") + 1:]
                                    ip = ip[:ip.find(":")]
                                    if network.valid_ip(ip):
                                        if self.curr_scope_id is not None:
                                            curr_scope_id = self.curr_scope_id
                                        if self.curr_scope_id is None:
                                            if network.valid_ip(ip):
                                                for scope_ip in self.scope_ips:
                                                    if network.check_in_network(scope_ip, ip):
                                                        curr_scope_id = self.scope_ip_dictionary[scope_ip]
                                                        break
                                        if curr_scope_id is not None:
                                            info = line[line.find("-") + 1].strip()
                                            engagement_device_list.append([ip, self.target, "", "", "", "", "", "", "",
                                                                       "", self.modified_by, self.modified_date,
                                                                       self.tool, curr_scope_id])
                                            port_list.append([ip, port, 'tcp', info, True, self.db_object.current_tester,
                                                          self.modified_date, "N", self.start_time, self.end_time,
                                                          self.tool])
                except Exception as e:
                    print("metasploit parser 101 except: " + str(e) + " Error on line {}".format(sys.exc_info()[-1].tb_lineno))
                    return {}

            output_dictionary = {}
            output_dictionary["devices"] = engagement_device_list
            output_dictionary["devices_fields_to_update"] = [('mac', 'c')]
            output_dictionary["ports"] = port_list
            output_dictionary["ports_fields_to_update"] = [('port_description', 'c')]
            output_dictionary["results"] = result_list
            output_dictionary["results_fields_to_update"] = [('output', 'as'), ('tester_output', 'as')]
            output_dictionary["credential"] = credential_list
            output_dictionary["credential_fields_to_update"] = [('passwd', 'c')]

            return output_dictionary

    def parse_esx_bruteforce(self):
        """Actually does the parsing for TELNET bruteforce (ie metasploit telnet_login)"""
        return self.parse_bruteforce("auxiliary/scanner/vmware/vmware_http_login", "Successful ESX(i) login: ",
                                     "ESX(i) had a password that was null or easily guessable")

    def parse_ftp_bruteforce(self):
        """Actually does the parsing for FTP bruteforce (ie metasploit ftp_login)"""
        return self.parse_bruteforce("auxiliary/scanner/ftp/ftp_login", "Successful FTP login: ",
                                     "FTP share had a password that was null or easily guessable")

    def parse_snmp_bruteforce(self):
        """Actually does the parsing for TELNET bruteforce (ie metasploit telnet_login)"""
        return self.parse_bruteforce("auxiliary/scanner/snmp/snmp_login", "Successful SNMP login: ",
                                     "SNMP had a community string that was null or easily guessable")

    def parse_ssh_bruteforce(self):
        """Actually does the parsing for SSH bruteforce (ie metasploit ssh_login)"""
        return self.parse_bruteforce("auxiliary/scanner/ssh/ssh_login", "Successful SSH login: ",
                                     "SSH had a password that was null or easily guessable")

    def parse_smb_anonymous(self):
        return self.parse_smb_bruteforce()

    def parse_smb_bruteforce(self):
        """
        Parse smb_login.
        :return:
        """
        engagement_device_list = []
        result_list = []
        already_ips = []
        if self.ext == "txt":
            engagement_device_list = []
            engagement_device_list_already_added = []
            result_list = []
            with open(self.file_path, 'r') as msf_file:
                only_text = keep_tags.clean_text(msf_file.read())

                lines = only_text.split("\n")
                try:
                    for line in lines:
                        if "[+]" in line and "success" in line.lower():
                            columns = line.split(" ")
                            if len(columns) > 1:
                                ip = columns[1]
                                if ":" in ip:
                                    port = ip[ip.find(":") + 1:]
                                    ip = ip[:ip.find(":")]

                                    if network.valid_ip(ip):
                                        already_ips.append(ip)
                                        info = None
                                        operating_system = None
                                        if " (" in line:
                                            operating_system = line[line.find(" (") + 2:]
                                            if ") " in operating_system:
                                                operating_system = operating_system[:operating_system.find(") ")]
                                            info = line[line.find(operating_system) + len(operating_system) + 2:]
                                            info = info[:info.find(" [")]
                                        elif "Success:" in line:
                                            info = line[line.find("Success:") + 8:].strip()

                                        if info is not None:
                                            info = "Successful SMB login: " + info + "\n"
                                            line_no_junk = line[line.find(" ") + 1:] + "\n"

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
                                                    engagement_device_list.append([ip, self.target, "", operating_system, "",
                                                                               "", "", "", "", "",
                                                                               self.modified_by, self.modified_date,
                                                                               self.tool, curr_scope_id])
                                                    engagement_device_list_already_added.append(ip + str(curr_scope_id))

                                            result_list.append([self.tool, "AF-" + self.tool, ip, port,
                                                 "tcp", info, line_no_junk, self.start_time, self.end_time,
                                                 "auxiliary/scanner/smb/smb_login",
                                                 "SMB share had a password that was null or easily guessable", "", "",
                                                "", "", "", "", "", self.modified_by])

                                        if operating_system is not None:
                                            if " xp " in operating_system.lower() or " 2003 " in operating_system.lower():
                                                # Result table.
                                                if " xp " in operating_system.lower():
                                                    tool_vulntitle = "Microsoft Windows XP Unsupported Installation Detection"
                                                    result_list.append( [self.tool, "AF-" + self.tool + "-unsupported_XP",
                                                         ip, port, "tcp", info, line_no_junk,
                                                         self.start_time, self.end_time, "auxiliary/scanner/smb/smb_login",
                                                         tool_vulntitle, "", "", "", "", "", "", "", self.modified_by])
                                                elif " 2003 " in operating_system.lower():
                                                    tool_vulntitle = "Microsoft Windows Server 2003 Unsupported Installation Detection"
                                                    result_list.append([self.tool, "AF-" + self.tool + "-unsupported_2003",
                                                         ip, port, "tcp", info, line_no_junk,
                                                         self.start_time, self.end_time, "auxiliary/scanner/smb/smb_login",
                                                         tool_vulntitle, "", "",  "", "", "", "", "", self.modified_by])

                except Exception as e:
                    print("metasploit parser 101 except: " + str(e) + " Error on line {}".format(sys.exc_info()[-1].tb_lineno))
                    return {}

        output_dictionary = {}
        output_dictionary["devices"] = engagement_device_list
        output_dictionary["devices_fields_to_update"] = [('mac', 'c')]
        output_dictionary["results"] = result_list
        output_dictionary["results_fields_to_update"] = [('output', 'as'), ('tester_output', 'as')]

        return output_dictionary


    def parse_telnet_bruteforce(self):
        """Actually does the parsing for TELNET bruteforce (ie metasploit telnet_login)"""
        return self.parse_bruteforce("auxiliary/scanner/telnet/telnet_login", "Successful TELNET login: ",
                                     "TELNET had a password that was null or easily guessable")


    def parse_vnc_bruteforce(self):
        """Actually does the parsing for VNC bruteforce (ie metasploit vnc_login)"""
        return self.parse_bruteforce("auxiliary/scanner/vnc/vnc_login", "Successful VNC login: ",
                                     "VNC had a password that was null or easily guessable")

    def parse_wordpress_bruteforce(self):
        """Actually does the parsing for WordPress bruteforce (ie metasploit wordpress_login)"""
        return self.parse_bruteforce("auxiliary/scanner/http/wordpress_login_enum", "Successful Wordpress login: ",
                                     "Wordpress Login had a password that was null or easily guessable")


    def parse_extrabacon_asa_exploit(self):
        """Actually does the parsing for WordPress bruteforce (ie metasploit wordpress_login)"""
        return self.parse_bruteforce("auxiliary/admin/cisco/cisco_asa_extrabacon", "Successful Cisco ASA SNMP login bypass: ",
                                     "Cisco ASA SNMP had a vulnerability allowing login bypass (EXTRABACON)")
