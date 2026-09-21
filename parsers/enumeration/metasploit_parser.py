import sys, os
import re
import yaml
from common import keep_tags, network, scope_functions
from parsers. parser import Parser

def metasploit(db_path, db_object, key, hashvals):
    """
    Loop thru hashvals, verify blacklist status, update Log, send to Parser, then finally email notifications out.
    :param db_path:
    :param db_object:
    :param hashvals:
    :return:
    """
    try:
        with Parser("metasploit enumeration", db_object, key, hashvals, False) as p:
            p.parse("parsers.enumeration.metasploit_parser", "MetasploitParser")

    except Exception as e:
        print("metasploit parser 19 except: " + str(e) + " Error on line {}".format(sys.exc_info()[-1].tb_lineno))


class MetasploitParser():
    """ Parse Metasploit Enum files. """
    def __init__(self, db_object, location_id, scope_id, file_path_name, ext, just_file_name, target, log_id, output_path, tester_device_list, modified_by, modified_date):
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
            output_dictionary = {}
            if "metasploit enumeration afp_server_info" in self.tool:
                output_dictionary = self.parse_afp()
            elif "metasploit enumeration cold_fusion_version" in self.tool:
                output_dictionary = self.parse_coldfusion()
            elif "metasploit enumeration db2_version" in self.tool:
                output_dictionary = self.parse_db2_version()
                pass
            elif "metasploit enumeration dell_idrac" in self.tool:
                output_dictionary = self.parse_dell_idrac()
                pass
            elif "metasploit enumeration esx_fingerprint" in self.tool:
                output_dictionary = self.parse_esx()
            elif "metasploit enumeration finger_users" in self.tool:
                output_dictionary = self.parse_finger_users()
            elif "metasploit enumeration ftp_anonymous" in self.tool:
                output_dictionary = self.parse_ftp_anon()
            elif "metasploit enumeration ftp_version" in self.tool:
                output_dictionary = self.parse_ftp_enum()
            elif "metasploit enumeration http_put" in self.tool:
                output_dictionary = self.parse_http_put()
            elif "metasploit enumeration http_version" in self.tool:
                output_dictionary = self.parse_http_version()
            elif "metasploit enumeration jboss_vulnscan" in self.tool:
                output_dictionary = self.parse_jboss_vulnscan()
            elif "metasploit enumeration jenkins_enum" in self.tool:
                output_dictionary = self.parse_jenkins_enum()
            elif "metasploit enumeration joomla_version" in self.tool:
                output_dictionary = self.parse_joomla_version()
            elif "metasploit enumeration mssql_version" in self.tool:
                output_dictionary = self.parse_mssql()
            elif "metasploit enumeration mysql_version" in self.tool:
                output_dictionary = self.parse_mysql()
            elif "metasploit enumeration netbios" in self.tool:
                output_dictionary = self.parse_netbios()
            elif "metasploit enumeration nfsmount" in self.tool:
                output_dictionary = self.parse_nfsmount()
            elif "metasploit enumeration oracle version" in self.tool:
                output_dictionary = self.parse_oracle_version()
            elif "metasploit enumeration oracle emc sid" in self.tool:
                output_dictionary = self.parse_oracle_emc_sidl()
            elif "metasploit enumeration oracle sid" in self.tool:
                output_dictionary = self.parse_oracle_sid()
            elif "metasploit enumeration oracle spy sid" in self.tool:
                output_dictionary = self.parse_oracle_spy_sid()
            elif "metasploit enumeration oracle sid bruteforce" in self.tool:
                output_dictionary = self.parse_oracle_sid_bruteforce()
            elif "metasploit enumeration open_x11" in self.tool:
                output_dictionary = self.parse_open_x11()
            elif "metasploit enumeration postgres version" in self.tool:
                output_dictionary = self.parse_postgres_version()
            elif "metasploit enumeration smb_enumusers" in self.tool:
                output_dictionary = self.parse_smb_enumusers()
            elif "metasploit enumeration smb_enumshares" in self.tool:
                output_dictionary = self.parse_smb_enumshares()
            elif "metasploit enumeration smb_enumusers_domain" in self.tool:
                output_dictionary = self.parse_smb_enumusers_domain()
            elif "metasploit enumeration smb_version" in self.tool:
                output_dictionary = self.parse_smb_version()
            elif "metasploit enumeration smtp_version" in self.tool:
                output_dictionary = self.parse_smtp_version()
            elif "metasploit enumeration ssh_version" in self.tool:
                output_dictionary = self.parse_ssh_version()
            elif "metasploit enumeration telnet_version" in self.tool:
                output_dictionary = self.parse_telnet_version()
            elif "metasploit enumeration tomcat_enum" in self.tool:
                output_dictionary = self.parse_tomcat_enum()
            elif "metasploit enumeration vmauthd_version" in self.tool:
                output_dictionary = self.parse_vmauthd_version()
            elif "metasploit enumeration vnc_none_auth" in self.tool:
                output_dictionary = self.parse_vnc_enumeration()
            elif "metasploit enumeration webdav_scanner" in self.tool:
                output_dictionary = self.parse_webdav_scanner()

            return output_dictionary
        except Exception as e:
            print("metasploit_parser enum parser 110 except: " + str(e) + " Error on line {}".format(
                sys.exc_info()[-1].tb_lineno))
        return {}

    def parse_coldfusion(self):
        if self.ext == "txt":
            engagement_device_list = []
            engagement_device_list_already_added = []
            result_list = []
            with open(self.file_path, 'r') as msf_file:
                only_text = keep_tags.clean_text(msf_file.read())

                lines = only_text.split("\n")
                try:
                    for line in lines:
                        if "[+]" in line:
                            columns = line.split(" ")
                            if len(columns) > 1:
                                ip = columns[1]
                                port = ip[ip.find(":") + 1:]
                                ip = ip[:ip.find(":")]

                                if network.valid_ip(ip):
                                    if ip + str(self.scope_id) not in engagement_device_list_already_added:
                                        curr_scope_id = None
                                        if network.valid_ip(ip):
                                            for scope_ip in self.scope_ips:
                                                if network.check_in_network(scope_ip, ip):
                                                    curr_scope_id = self.scope_ip_dictionary[scope_ip]
                                                    break
                                        if curr_scope_id is not None:
                                            engagement_device_list.append([ip, ip, "", None, "",
                                                                           "", "", "", "", "",
                                                                           self.modified_by, self.modified_date,
                                                                           self.tool, curr_scope_id])
                                            engagement_device_list_already_added.append(ip + str(curr_scope_id))

                    output_dictionary = {}
                    output_dictionary["devices"] = engagement_device_list
                    output_dictionary["devices_fields_to_update"] = [('os', 'as')]
                    return output_dictionary
                except Exception as e:
                    print("metasploit enumeration parser 150 except: " + str(e) + " Error on line {}".format(sys.exc_info()[-1].tb_lineno))
        return {}

    def parse_dell_idrac(self):
        if self.ext == "txt":
            engagement_device_list = []
            engagement_device_list_already_added = []
            result_list = []
            with open(self.file_path, 'r') as msf_file:
                only_text = keep_tags.clean_text(msf_file.read())

                lines = only_text.split("\n")
                try:
                    for line in lines:
                        if "[+]" in line:
                            print("\tmetasploit enum dell idrac SUCCESS line: " + str(line))
                            ips = re.findall( r'[0-9]+(?:\.[0-9]+){3}', line )
                            if len(ips) > 0:
                                ip = ips[0]
                                if network.valid_ip(ip):
                                    if ip + str(self.scope_id) not in engagement_device_list_already_added:
                                        curr_scope_id = None
                                        if network.valid_ip(ip):
                                            for scope_ip in self.scope_ips:
                                                if network.check_in_network(scope_ip, ip):
                                                    curr_scope_id = self.scope_ip_dictionary[scope_ip]
                                                    break
                                        if curr_scope_id is not None:
                                            engagement_device_list.append([ip, ip, "", None, "",
                                                                           "", line, "", "", "",
                                                                           self.modified_by, self.modified_date,
                                                                           self.tool, curr_scope_id])
                                            engagement_device_list_already_added.append(ip + str(curr_scope_id))

                    output_dictionary = {}
                    output_dictionary["devices"] = engagement_device_list
                    output_dictionary["devices_fields_to_update"] = [('info', 'as')]
                    return output_dictionary
                except Exception as e:
                    print("metasploit enumeration parser 150 except: " + str(e) + " Error on line {}".format(sys.exc_info()[-1].tb_lineno))
        return {}

    def parse_esx(self):
        if self.ext == "txt":
            engagement_device_list = []
            engagement_device_list_already_added = []
            result_list = []
            with open(self.file_path, 'r') as msf_file:
                only_text = keep_tags.clean_text(msf_file.read())

                lines = only_text.split("\n")
                try:
                    for line in lines:
                        if "[+]" in line and "Identified" in line:
                            columns = line.split(" ")
                            if len(columns) > 1:
                                ip = columns[1]
                                port = ip[ip.find(":") + 1:]
                                ip = ip[:ip.find(":")]

                                if network.valid_ip(ip):
                                    operating_system = line[line.find("Identified ") + 11:]

                                    if ip + str(self.scope_id) not in engagement_device_list_already_added:
                                        curr_scope_id = None
                                        if network.valid_ip(ip):
                                            for scope_ip in self.scope_ips:
                                                if network.check_in_network(scope_ip, ip):
                                                    curr_scope_id = self.scope_ip_dictionary[scope_ip]
                                                    break
                                        if curr_scope_id is not None:
                                            engagement_device_list.append([ip, ip, "", operating_system, "",
                                                                           "", "", "", "", "",
                                                                           self.modified_by, self.modified_date,
                                                                           self.tool, curr_scope_id])
                                            engagement_device_list_already_added.append(ip + str(curr_scope_id))

                    output_dictionary = {}
                    output_dictionary["devices"] = engagement_device_list
                    output_dictionary["devices_fields_to_update"] = [('os', 'as')]
                    return output_dictionary
                except Exception as e:
                    print("metasploit enumeration parser 150 except: " + str(e) + " Error on line {}".format(sys.exc_info()[-1].tb_lineno))
        return {}

    def parse_finger_users(self):
        if self.ext == "txt":
            engagement_device_list = []
            engagement_device_list_already_added = []
            result_list = []
            with open(self.file_path, 'r') as msf_file:
                only_text = keep_tags.clean_text(msf_file.read())

                lines = only_text.split("\n")
                try:
                    for line in lines:
                        if "[+]" in line and "Users found:" in line:
                            columns = line.split(" ")
                            if len(columns) > 1:
                                ip = columns[1]
                                port = ip[ip.find(":") + 1:]
                                ip = ip[:ip.find(":")]

                                if network.valid_ip(ip):
                                    users = line[line.find("Users found: ") + 13:]
                                    users = users.strip()
                                    user_text = ""
                                    if users != "":
                                        user_text = "Users: " + str(user_text)

                                    if ip + str(self.scope_id) not in engagement_device_list_already_added:
                                        curr_scope_id = None
                                        if network.valid_ip(ip):
                                            for scope_ip in self.scope_ips:
                                                if network.check_in_network(scope_ip, ip):
                                                    curr_scope_id = self.scope_ip_dictionary[scope_ip]
                                                    break
                                        if curr_scope_id is not None:
                                            engagement_device_list.append([ip, ip, "", None, "",
                                                                           user_text, "", "", "", "",
                                                                           self.modified_by, self.modified_date,
                                                                           self.tool, curr_scope_id])
                                            engagement_device_list_already_added.append(ip + str(curr_scope_id))

                                            line_no_junk = line[line.find(" ")+1:]

                                            result_list.append(
                                                [self.tool, "AF-" + self.tool, ip, port,
                                                 "tcp", user_text, line_no_junk, self.modified_date, self.modified_date,
                                                 "auxiliary/scanner/finger/finger_users", "Finger Service Enabled", "", "",
                                                 "", "", "", "", "", self.modified_by])

                    output_dictionary = {}
                    output_dictionary["devices"] = engagement_device_list
                    output_dictionary["devices_fields_to_update"] = [('os', 'as')]
                    output_dictionary["results"] = result_list
                    output_dictionary["results_fields_to_update"] = [('output', 'as'), ('tester_output', 'as')]
                    return output_dictionary
                except Exception as e:
                    print("metasploit enumeration parser 150 except: " + str(e) + " Error on line {}".format(sys.exc_info()[-1].tb_lineno))
        return {}

    def parse_ftp_anon(self):
        if self.ext == "txt":
            engagement_device_list = []
            engagement_device_list_already_added = []
            result_list = []
            with open(self.file_path, 'r') as msf_file:
                only_text = keep_tags.clean_text(msf_file.read())

                lines = only_text.split("\n")
                try:
                    for line in lines:
                        if "[+]" in line and "Anonymous" in line:
                            columns = line.split(" ")
                            if len(columns) > 1:
                                ip = columns[1]
                                if ":" in ip:
                                    port = ip[ip.find(":") + 1:]
                                    ip = ip[:ip.find(":")]

                                    if network.valid_ip(ip):
                                        info = line[line.find("Anonymous"):]
                                        if ip + str(self.scope_id) not in engagement_device_list_already_added:
                                            curr_scope_id = None
                                            if network.valid_ip(ip):
                                                for scope_ip in self.scope_ips:
                                                    if network.check_in_network(scope_ip, ip):
                                                        curr_scope_id = self.scope_ip_dictionary[scope_ip]
                                                        break
                                            if curr_scope_id is not None:
                                                engagement_device_list.append([ip, ip, "", None, "",
                                                                               "", info, "", "", "",
                                                                               self.modified_by, self.modified_date,
                                                                               self.tool, curr_scope_id])
                                                engagement_device_list_already_added.append(ip + str(curr_scope_id))

                                                line_no_junk = line[line.find(" ") + 1:] + "\n"

                                                result_list.append(
                                                    [self.tool, "AF-" + self.tool, ip, port,
                                                     "tcp", info, line_no_junk, self.modified_date, self.modified_date,
                                                     "auxiliary/scanner/ftp/anonymous", "Anonymous FTP Enabled", "", "",
                                                     "", "", "", "", "", self.modified_by])

                    output_dictionary = {}
                    output_dictionary["devices"] = engagement_device_list
                    output_dictionary["devices_fields_to_update"] = [('info', 'as')]
                    output_dictionary["results"] = result_list
                    output_dictionary["results_fields_to_update"] = [('output', 'as'), ('tester_output', 'as')]
                    return output_dictionary
                except Exception as e:
                    print("metasploit enumeration parser 150 except: " + str(e) + " Error on line {}".format(sys.exc_info()[-1].tb_lineno))
        return {}

    def parse_ftp_enum(self):
        if self.ext == "txt":
            engagement_device_list = []
            engagement_device_list_already_added = []
            open_port_list = []
            with open(self.file_path, 'r') as msf_file:
                only_text = keep_tags.clean_text(msf_file.read())

                lines = only_text.split("\n")
                try:
                    for line in lines:
                        if "[+]" in line and "FTP Banner" in line:
                            columns = line.split(" ")
                            if len(columns) > 1:
                                ip = columns[1]
                                if ":" in ip:
                                    port = ip[ip.find(":") + 1:]
                                    ip = ip[:ip.find(":")]

                                    if network.valid_ip(ip):
                                        info = line[line.find("FTP Banner"):]
                                        if "\\x" in info:
                                            info = info[:info.find("\\x")]
                                        if ip + str(self.scope_id) not in engagement_device_list_already_added:
                                            curr_scope_id = None
                                            if network.valid_ip(ip):
                                                for scope_ip in self.scope_ips:
                                                    if network.check_in_network(scope_ip, ip):
                                                        curr_scope_id = self.scope_ip_dictionary[scope_ip]
                                                        break
                                            if curr_scope_id is not None:
                                                engagement_device_list.append([ip, ip, "", None, "",
                                                                               "", info, "", "", "",
                                                                               self.modified_by, self.modified_date,
                                                                               self.tool, self.scope_id])
                                                engagement_device_list_already_added.append(ip + str(self.scope_id))
                                                open_port_list.append(
                                                    (ip, port, "tcp", info, True,
                                                     self.modified_by, self.modified_date, False, self.modified_date,
                                                     self.modified_date, 'metasploit enum http_ver - ' + self.file_name))

                    output_dictionary = {}
                    output_dictionary["devices"] = engagement_device_list
                    output_dictionary["devices_fields_to_update"] = [('info', 'as')]
                    output_dictionary["ports"] = open_port_list
                    output_dictionary["ports_fields_to_update"] = [('port_description', 'as')]
                    return output_dictionary
                except Exception as e:
                    print("metasploit enumeration parser 150 except: " + str(e) + " Error on line {}".format(sys.exc_info()[-1].tb_lineno))
        return {}

    def parse_http_put(self):
        if self.ext == "txt":
            engagement_device_list = []
            engagement_device_list_already_added = []
            open_port_list = []
            with open(self.file_path, 'r') as msf_file:
                only_text = keep_tags.clean_text(msf_file.read())

                lines = only_text.split("\n")
                try:
                    for line in lines:
                        if "301-" not in line and "+" in line:
                            columns = line.split(" ")
                            if len(columns) > 1:
                                ip = columns[1]
                                if ":" in ip:
                                    port = ip[ip.find(":") + 1:]
                                    ip = ip[:ip.find(":")]

                                    if network.valid_ip(ip):
                                        info = line[line.find(":" + port) + 1 + len(port):]
                                        info = info.strip()
                                        if info != "":
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
                                                    engagement_device_list.append([ip, ip, "", None, "",
                                                                                   "", info, "", "", "",
                                                                                   self.modified_by, self.modified_date,
                                                                                   self.tool, curr_scope_id])
                                                    engagement_device_list_already_added.append(ip + str(curr_scope_id))

                                                    open_port_list.append(
                                                        (ip, port, "tcp", info, True,
                                                         self.modified_by, self.modified_date, False, self.modified_date,
                                                         self.modified_date, 'metasploit enum http_put - ' + self.file_name))

                    output_dictionary = {}
                    output_dictionary["devices"] = engagement_device_list
                    output_dictionary["devices_fields_to_update"] = [('info', 'as')]
                    output_dictionary["ports"] = open_port_list
                    output_dictionary["ports_fields_to_update"] = [('port_description', 'as')]
                    return output_dictionary
                except Exception as e:
                    print("metasploit enumeration parser 351 except: " + str(e) + " Error on line {}".format(sys.exc_info()[-1].tb_lineno))
        return {}

    def parse_http_version(self):
        if self.ext == "txt":
            engagement_device_list = []
            engagement_device_list_already_added = []
            open_port_list = []
            with open(self.file_path, 'r') as msf_file:
                only_text = keep_tags.clean_text(msf_file.read())

                lines = only_text.split("\n")
                try:
                    for line in lines:
                        if "301-" not in line and "+" in line:
                            columns = line.split(" ")
                            if len(columns) > 1:
                                ip = columns[1]
                                if ":" in ip:
                                    port = ip[ip.find(":") + 1:]
                                    ip = ip[:ip.find(":")]

                                    if network.valid_ip(ip):
                                        info = line[line.find(":" + port) + 1 + len(port):]
                                        info = info.strip()
                                        if info != "":
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
                                                    engagement_device_list.append([ip, ip, "", None, "",
                                                                                   "", info, "", "", "",
                                                                                   self.modified_by, self.modified_date,
                                                                                   self.tool, curr_scope_id])
                                                    engagement_device_list_already_added.append(ip + str(curr_scope_id))

                                                    open_port_list.append(
                                                        (ip, port, "tcp", info, True,
                                                         self.modified_by, self.modified_date, False, self.modified_date,
                                                         self.modified_date, 'metasploit enum http_ver - ' + self.file_name))

                    output_dictionary = {}
                    output_dictionary["devices"] = engagement_device_list
                    output_dictionary["devices_fields_to_update"] = [('info', 'as')]
                    output_dictionary["ports"] = open_port_list
                    output_dictionary["ports_fields_to_update"] = [('port_description', 'as')]

                    return output_dictionary
                except Exception as e:
                    print("metasploit enumeration parser 150 except: " + str(e) + " Error on line {}".format(sys.exc_info()[-1].tb_lineno))
        return {}

    def parse_jboss_vulnscan(self):
        if self.ext == "txt":
            engagement_device_list = []
            engagement_device_list_already_added = []
            result_list = []
            with open(self.file_path, 'r') as msf_file:
                only_text = keep_tags.clean_text(msf_file.read())

                lines = only_text.split("\n")
                try:
                    for line in lines:
                        if "[+]" in line:
                            columns = line.split(" ")
                            if len(columns) > 1:
                                ip = columns[1]
                                if ":" in ip:
                                    port = ip[ip.find(":") + 1:]
                                    ip = ip[:ip.find(":")]

                                    if network.valid_ip(ip):
                                        info = ""
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
                                                engagement_device_list.append([ip, ip, "", None, "",
                                                                               "", info, "", "", "",
                                                                               self.modified_by, self.modified_date,
                                                                               self.tool, curr_scope_id])
                                                engagement_device_list_already_added.append(ip + str(curr_scope_id))
                                                """
                                                line_no_junk = line[line.find(" ") + 1:] + "\n"
                                                output = line[line.find(":" + port) + 1 + len(port):]
                                                result_list.append(
                                                    [self.tool, "AF-" + self.tool, ip, port,
                                                     "tcp", output, line_no_junk, self.modified_date, self.modified_date,
                                                     "auxiliary/scanner/http/jboss_vulnscan",
                                                     "JBoss JMX Console Unrestricted Access", "", "",
                                                     "", "", "", "", "", self.modified_by])
                                                """

                    output_dictionary = {}
                    output_dictionary["devices"] = engagement_device_list
                    output_dictionary["devices_fields_to_update"] = [('info', 'as')]
                    output_dictionary["results"] = result_list
                    output_dictionary["results_fields_to_update"] = [('output', 'as'), ('tester_output', 'as')]
                    return output_dictionary
                except Exception as e:
                    print("metasploit enumeration parser 330 except: " + str(e) + " Error on line {}".format(
                        sys.exc_info()[-1].tb_lineno))
        return {}

    def parse_jenkins_enum(self):
        if self.ext == "txt":
            engagement_device_list = []
            engagement_device_list_already_added = []
            result_list = []
            with open(self.file_path, 'r') as msf_file:
                only_text = keep_tags.clean_text(msf_file.read())

                lines = only_text.split("\n")
                try:
                    for line in lines:
                        if "[+]" in line:
                            columns = line.split(" ")
                            if len(columns) > 1:
                                ip = columns[1]
                                if ":" in ip:
                                    port = ip[ip.find(":") + 1:]
                                    ip = ip[:ip.find(":")]

                                    if network.valid_ip(ip):
                                        info = ""
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
                                                engagement_device_list.append([ip, ip, "", None, "",
                                                                               "", info, "", "", "",
                                                                               self.modified_by, self.modified_date,
                                                                               self.tool, curr_scope_id])
                                                engagement_device_list_already_added.append(ip + str(curr_scope_id))

                                                line_no_junk = line[line.find(" ") + 1:] + "\n"
                                                output = line[line.find(":" + port) + 1 + len(port):]
                                                result_list.append(
                                                    [self.tool, "AF-" + self.tool, ip, port,
                                                     "tcp", output, line_no_junk, self.modified_date, self.modified_date,
                                                     "auxiliary/scanner/http/jenkins_enum",
                                                     "Jenkins Enumeration", "", "",
                                                     "", "", "", "", "", self.modified_by])

                    output_dictionary = {}
                    output_dictionary["devices"] = engagement_device_list
                    output_dictionary["devices_fields_to_update"] = [('info', 'as')]
                    output_dictionary["results"] = result_list
                    output_dictionary["results_fields_to_update"] = [('output', 'as'), ('tester_output', 'as')]
                    return output_dictionary
                except Exception as e:
                    print("metasploit enumeration parser 330 except: " + str(e) + " Error on line {}".format(
                        sys.exc_info()[-1].tb_lineno))
        return {}

    def parse_joomla_version(self):
        if self.ext == "txt":
            engagement_device_list = []
            engagement_device_list_already_added = []
            result_list = []
            with open(self.file_path, 'r') as msf_file:
                only_text = keep_tags.clean_text(msf_file.read())

                lines = only_text.split("\n")
                try:
                    for line in lines:
                        if "[+]" in line:
                            columns = line.split(" ")
                            if len(columns) > 1:
                                ip = columns[1]
                                if ":" in ip:
                                    port = ip[ip.find(":") + 1:]
                                    ip = ip[:ip.find(":")]

                                    if network.valid_ip(ip):
                                        info = ""
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
                                                engagement_device_list.append([ip, ip, "", None, "",
                                                                               "", info, "", "", "",
                                                                               self.modified_by, self.modified_date,
                                                                               self.tool, curr_scope_id])
                                                engagement_device_list_already_added.append(ip + str(curr_scope_id))

                                                line_no_junk = line[line.find(" ") + 1:] + "\n"
                                                output = line[line.find(":" + port) + 1 + len(port):]

                    output_dictionary = {}
                    output_dictionary["devices"] = engagement_device_list
                    output_dictionary["devices_fields_to_update"] = [('info', 'as')]
                    output_dictionary["results"] = result_list
                    output_dictionary["results_fields_to_update"] = [('output', 'as'), ('tester_output', 'as')]
                    return output_dictionary
                except Exception as e:
                    print("metasploit enumeration parser 330 except: " + str(e) + " Error on line {}".format(
                        sys.exc_info()[-1].tb_lineno))
        return {}

    def parse_mssql(self):
        if self.ext == "txt":
            engagement_device_list = []
            engagement_device_list_already_added = []
            result_list = []
            with open(self.file_path, 'r') as msf_file:
                only_text = keep_tags.clean_text(msf_file.read())

                lines = only_text.split("\n")
                try:
                    for line in lines:
                        if "[+]" in line:
                            columns = line.split(" ")
                            if len(columns) > 1:
                                ip = columns[1]
                                if ":" in ip:
                                    port = "1433"
                                    ip = ip[:ip.find(":")]

                                    if network.valid_ip(ip):
                                        info = None
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
                                                engagement_device_list.append([ip, ip, "", None, "",
                                                                               "", info, "", "", "",
                                                                               self.modified_by, self.modified_date,
                                                                               self.tool, curr_scope_id])
                                                engagement_device_list_already_added.append(ip + str(curr_scope_id))
                                                line_no_junk = ""
                                                for l in lines:
                                                    if ip in l and " - " in l:
                                                        line_no_junk = line_no_junk + l + "\n"
                                                result_list.append(
                                                    [self.tool, "AF-" + self.tool, ip, port, "tcp",
                                                     line_no_junk, line_no_junk, self.modified_date, self.modified_date,
                                                     "auxiliary/scanner/mssql/mssql_ping", "MSSQL Browser service enabled",
                                                     "", "", "", "", "", "", "", self.modified_by])

                    output_dictionary = {}
                    output_dictionary["devices"] = engagement_device_list
                    output_dictionary["devices_fields_to_update"] = [('os', 'as')]
                    output_dictionary["results"] = result_list
                    output_dictionary["results_fields_to_update"] = [('output', 'as'), ('tester_output', 'as')]
                    return output_dictionary
                except Exception as e:
                    print("metasploit enumeration parser 330 except: " + str(e) + " Error on line {}".format(
                        sys.exc_info()[-1].tb_lineno))
        return {}

    def parse_mysql(self):
        if self.ext == "txt":
            engagement_device_list = []
            engagement_device_list_already_added = []
            open_port_list = []
            with open(self.file_path, 'r') as msf_file:
                only_text = keep_tags.clean_text(msf_file.read())

                lines = only_text.split("\n")
                try:
                    for line in lines:
                        if "is running" in line:
                            columns = line.split(" ")
                            if len(columns) > 1:
                                ip = columns[1]
                                if ":" in ip:
                                    port = ip[ip.find(":") + 1:]
                                    ip = ip[:ip.find(":")]

                                    if network.valid_ip(ip):
                                        info = line[line.find("is running")+ 10:]
                                        info = info.strip()
                                        if info != "":
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
                                                    engagement_device_list.append([ip, ip, "", None, "",
                                                                                   "", info, "", "", "",
                                                                                   self.modified_by, self.modified_date,
                                                                                   self.tool, curr_scope_id])
                                                    engagement_device_list_already_added.append(ip + str(curr_scope_id))

                                                    open_port_list.append(
                                                        (ip, port, "tcp", info, True,
                                                         self.modified_by, self.modified_date, False, self.modified_date,
                                                         self.modified_date, 'metasploit enum mysql_ver - ' + self.file_name))

                    output_dictionary = {}
                    output_dictionary["devices"] = engagement_device_list
                    output_dictionary["devices_fields_to_update"] = [('info', 'as')]
                    output_dictionary["ports"] = open_port_list
                    output_dictionary["ports_fields_to_update"] = [('port_description', 'as')]
                    return output_dictionary
                except Exception as e:
                    print("metasploit enumeration parser 150 except: " + str(e) + " Error on line {}".format(sys.exc_info()[-1].tb_lineno))
        return {}

    def parse_netbios(self):
        if self.ext == "txt":
            engagement_device_list = []
            engagement_device_list_already_added = []
            result_list = []
            with open(self.file_path, 'r') as msf_file:
                only_text = keep_tags.clean_text(msf_file.read())

                lines = only_text.split("\n")
                for line in lines:
                    try:
                        columns = line.split(" ")
                        if len(columns) > 2:
                            ip = columns[1]
                            port = ""
                            if ":" in ip:
                                port = ip[ip.find(":") + 1:]
                                ip = ip[:ip.find(":")]
                            if network.valid_ip(ip):
                                host_name = columns[2].strip("[").strip("]")
                                domain = None
                                if "(" + host_name + ", " in line:
                                    domain = line[line.find("(" + host_name + ", ") + 2 + len(host_name):]
                                    domain = domain[:domain.find(")")]
                                    if "," in domain:
                                        domain = domain[:domain.find(",")]

                                info = None
                                if "Addresses:(" in line:
                                    info = line[line.find("Addresses:("):]
                                    info = info[:info.find(")") + 1] + "\n"
                                mac = None
                                for col in columns:
                                    if "Mac:" in col:
                                        mac = col[col.find("Mac:") + 4:].strip("\n")
                                        break

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
                                        engagement_device_list.append([ip, ip, domain, None, mac,
                                                                       "", info, "", "", "",
                                                                       self.modified_by, self.modified_date,
                                                                       self.tool, curr_scope_id])
                                        engagement_device_list_already_added.append(ip + str(curr_scope_id))
                                        line_no_junk = ""
                                        for l in lines:
                                            if ip in l and " - " in l:
                                                line_no_junk = line_no_junk + l + "\n"
                                        result_list.append(
                                            [self.tool, "AF-" + self.tool, ip, "137",
                                             "tcp", line_no_junk, line_no_junk, self.modified_date, self.modified_date,
                                             "auxiliary/scanner/netbios/nbname",
                                             "NetBIOS enumeration using null session", "", "",
                                             "", "", "", "", "", self.modified_by])
                    except Exception as e:
                        print("metasploit enumeration parser 491 except: " + str(e) + " Error on line {}".format(
                            sys.exc_info()[-1].tb_lineno))

                output_dictionary = {}
                output_dictionary["devices"] = engagement_device_list
                output_dictionary["devices_fields_to_update"] = [('domain', 'as'), ('mac', 'as'), ('info', 'as')]
                output_dictionary["results"] = result_list
                output_dictionary["results_fields_to_update"] = [('output', 'as'), ('tester_output', 'as')]
                return output_dictionary

        return {}

    def parse_nfsmount(self):
        if self.ext == "txt":
            engagement_device_list = []
            engagement_device_list_already_added = []
            result_list = []
            with open(self.file_path, 'r') as msf_file:
                only_text = keep_tags.clean_text(msf_file.read())

                lines = only_text.split("\n")
                for line in lines:
                    try:
                        columns = line.split(" ")
                        if len(columns) > 2:
                            ip = columns[1]
                            port = ""
                            if ":" in ip:
                                port = ip[ip.find(":") + 1:]
                                ip = ip[:ip.find(":")]
                            if network.valid_ip(ip):
                                info = ""
                                if "NFS Export:" in line:
                                    info = line[line.find("NFS Export:"):]
                                    if "[]" in info:
                                        info = info.replace("[]", "")
                                    if "[ ]" in info:
                                        info = info.replace("[ ]", "")

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
                                        engagement_device_list.append([ip, ip, None, None, None,
                                                                       "", info, "", "", "",
                                                                       self.modified_by, self.modified_date,
                                                                       self.tool, curr_scope_id])
                                        engagement_device_list_already_added.append(ip + str(curr_scope_id))
                                        line_no_junk = ""
                                        for l in lines:
                                            if ip in l and " - " in l:
                                                line_no_junk = line_no_junk + l + "\n"
                                        result_list.append(
                                            [self.tool, "AF-" + self.tool, ip, "137",
                                             "tcp", line_no_junk, line_no_junk, self.modified_date, self.modified_date,
                                             "auxiliary/scanner/nfs/nfsmount",
                                             "Open, unauthenticated NFS mount", "", "",
                                             "", "", "", "", None, self.modified_by])
                    except Exception as e:
                        print("metasploit enumeration parser 491 except: " + str(e) + " Error on line {}".format(
                            sys.exc_info()[-1].tb_lineno))

                output_dictionary = {}
                output_dictionary["devices"] = engagement_device_list
                output_dictionary["devices_fields_to_update"] = [('info', 'c')]
                output_dictionary["results"] = result_list
                output_dictionary["results_fields_to_update"] = [('output', 'as'), ('tester_output', 'as')]
                return output_dictionary

        return {}

    def parse_postgres_version(self):
        if self.ext == "txt":
            engagement_device_list = []
            engagement_device_list_already_added = []
            open_port_list = []
            with open(self.file_path, 'r') as msf_file:
                only_text = keep_tags.clean_text(msf_file.read())

                lines = only_text.split("\n")
                try:
                    for line in lines:
                        if "Postgres " in line:
                            columns = line.split(" ")
                            if len(columns) > 1:
                                ip = columns[1]
                                if ":" in ip:
                                    port = ip[ip.find(":") + 1:]
                                    ip = ip[:ip.find(":")]

                                    if network.valid_ip(ip):
                                        info = line[line.find("Postgres"):]
                                        info = info.strip()
                                        if info != "":
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
                                                    engagement_device_list.append([ip, ip, "", None, "",
                                                                                   "", "", "", "", "",
                                                                                   self.modified_by, self.modified_date,
                                                                                   self.tool, curr_scope_id])
                                                    engagement_device_list_already_added.append(ip + str(curr_scope_id))

                                                    open_port_list.append(
                                                        (ip, port, "tcp", info, True,
                                                         self.modified_by, self.modified_date, False, self.modified_date,
                                                         self.modified_date, 'metasploit enum postgres ver - ' + self.file_name))

                    output_dictionary = {}
                    output_dictionary["devices"] = engagement_device_list
                    output_dictionary["devices_fields_to_update"] = [('info', 'c')]
                    output_dictionary["ports"] = open_port_list
                    output_dictionary["ports_fields_to_update"] = [('port_description', 'as')]
                    return output_dictionary
                except Exception as e:
                    print("metasploit enumeration parser 650 except: " + str(e) + " Error on line {}".format(sys.exc_info()[-1].tb_lineno))
        return {}

    def parse_smb_enumshares(self):
        if self.ext == "txt":
            engagement_device_list = []
            engagement_device_list_already_added = []
            result_list = []
            ips = []
            with open(self.file_path, 'r') as msf_file:
                only_text = keep_tags.clean_text(msf_file.read())

                lines = only_text.split("\n")
                for line in lines:
                    operating_system = ""
                    try:
                        columns = line.split(" ")
                        if len(columns) > 1:
                            ip = columns[1]
                            port = ip[ip.find(":") + 1:]
                            ip = ip[:ip.find(":")]
                            if network.valid_ip(ip) and ip + ":" + port + str(self.scope_id) not in engagement_device_list_already_added and "+" in line:
                                ips.append(ip)

                                shares = ""
                                # find all shares for given IP:port combo
                                for l in lines:
                                    if "+" in l and ip + ":" + port in l:
                                        share = l[l.find("- ") + 2:]
                                        shares = shares + share + "\n"
                                    elif ip + ":" + port in l and "windows" in l:
                                        operating_system = l[l.find("- " ) + 2:]
                                        if "(Unknown)" in operating_system:
                                            operating_system = operating_system.replace("(Unknown)", "")
                                if self.curr_scope_id is not None:
                                    curr_scope_id = self.curr_scope_id
                                if self.curr_scope_id is None:
                                    if network.valid_ip(ip):
                                        for scope_ip in self.scope_ips:
                                            if network.check_in_network(scope_ip, ip):
                                                curr_scope_id = self.scope_ip_dictionary[scope_ip]
                                                break
                                if curr_scope_id is not None:
                                    engagement_device_list.append([ip, ip, None, operating_system, None,
                                                                   "", "Shares: " + shares, "", "", "",
                                                                   self.modified_by, self.modified_date,
                                                                   self.tool, curr_scope_id])
                                    engagement_device_list_already_added.append(ip + str(curr_scope_id))

                                    result_list.append(
                                        [self.tool, "AF-" + self.tool, ip, "445",
                                         "tcp", "Share(s): " + str(shares), None, self.modified_date, self.modified_date,
                                         "auxiliary/scanner/smb/smb_enumshares",
                                         "SMB share had a password that was null or easily guessable", "", "",
                                         "", "", "", "", "", self.modified_by])

                                    if " xp" in operating_system.lower():
                                        result_list.append(
                                            [self.tool, "AF-" + self.tool, ip, "445",
                                             "tcp", operating_system, None, self.modified_date, self.modified_date,
                                             "auxiliary/scanner/smb/smb_enumshares",
                                             "Microsoft Windows XP Unsupported Installation Detection", "", "",
                                             "", "", "", "", "", self.modified_by])
                                    elif " 2003" in operating_system.lower():
                                        result_list.append(
                                            [self.tool, "AF-" + self.tool, ip, "445",
                                             "tcp", operating_system, None, self.modified_date, self.modified_date,
                                             "auxiliary/scanner/smb/smb_enumshares",
                                             "Microsoft Windows Server 2003 Unsupported Installation Detection", "", "",
                                             "", "", "", "", "", self.modified_by])

                    except Exception as e:
                        print("metasploit enumeration parser 565 except: " + str(e) + " Error on line {}".format(
                            sys.exc_info()[-1].tb_lineno))

            output_dictionary = {}
            output_dictionary["devices"] = engagement_device_list
            output_dictionary["devices_fields_to_update"] = [('domain', 'as'), ('mac', 'as'), ('info', 'as')]
            output_dictionary["results"] = result_list
            output_dictionary["results_fields_to_update"] = [('output', 'as'), ('tester_output', 'as')]
            return output_dictionary
        return {}

    def parse_smb_enumusers(self):
        if self.ext == "txt":
            engagement_device_list = []
            engagement_device_list_already_added = []
            result_list = []
            ips = []
            with open(self.file_path, 'r') as msf_file:
                only_text = keep_tags.clean_text(msf_file.read())

                lines = only_text.split("\n")
                for line in lines:
                    password_min = ""
                    lockout_tries = ""
                    users = ""
                    try:
                        columns = line.split(" ")
                        if len(columns) > 1:
                            ip = columns[1]
                            port = ip[ip.find(":") + 1:]
                            ip = ip[:ip.find(":")]
                            if network.valid_ip(ip) and ip + ":" + port + str(self.scope_id) not in engagement_device_list_already_added and "+" in line:
                                ips.append(ip)
                                engagement_device_list_already_added.append(ip + ":" + port + str(self.scope_id))

                                if "[" in line and "]" in line:
                                    users = line[line.find("[")+1:]
                                    users = users[:users.find("]")]
                                    users = users.strip()

                                if "LockoutTries" in line.lower():
                                    lockout_tries = line[line.find("LockoutTries"):]
                                    lockout_tries = lockout_tries[:lockout_tries.find(" ")]

                                if "PasswordMin=" in line.lower():
                                    password_min = line[line.find("PasswordMin="):]
                                    password_min = password_min[:password_min.find(" ")]

                                user_text = ""
                                if users != "":
                                    user_text = "Users: " + str(users)

                                engagement_device_list.append([ip, ip, None, None, None,
                                                               "", user_text, "", "", "",
                                                               self.modified_by, self.modified_date,
                                                               self.tool, self.scope_id])
                                password_min_num = password_min[password_min.find("PasswordMin=") + 12:]
                                password_min_num = password_min_num.strip()
                                if password_min_num.isnumeric():
                                    if int(password_min_num) < 10:
                                        result_list.append(
                                            [self.tool, "AF-" + self.tool, ip, port,
                                             "tcp", password_min, None, self.modified_date, self.modified_date,
                                             "auxiliary/scanner/smb/smb_enumusers",
                                             "Minimum password length is too short", "", "",
                                             "", "", "", "", "", self.modified_by])

                                if lockout_tries == "LockoutTries=0":
                                    result_list.append(
                                        [self.tool, "AF-" + self.tool, ip, port,
                                         "tcp", lockout_tries, None, self.modified_date, self.modified_date,
                                         "auxiliary/scanner/smb/smb_enumusers",
                                         "No lockout policy for invalid password attempts", "", "",
                                         "", "", "", "", "", self.modified_by])
                    except Exception as e:
                        print("metasploit enumeration parser 640 except: " + str(e) + " Error on line {}".format(
                        sys.exc_info()[-1].tb_lineno))

            output_dictionary = {}
            output_dictionary["devices"] = engagement_device_list
            output_dictionary["devices_fields_to_update"] = [('info', 'as')]
            output_dictionary["results"] = result_list
            output_dictionary["results_fields_to_update"] = [('output', 'as')]
            return output_dictionary
        return {}

    def parse_smb_enumusers_domain(self):
        if self.ext == "txt":
            engagement_device_list = []
            engagement_device_list_already_added = []
            result_list = []
            ips = []
            with open(self.file_path, 'r') as msf_file:
                only_text = keep_tags.clean_text(msf_file.read())

                lines = only_text.split("\n")
                for line in lines:
                    password_min = ""
                    lockout_tries = ""
                    users = ""
                    try:
                        columns = line.split(" ")
                        if len(columns) > 1:
                            ip = columns[1]
                            port = ip[ip.find(":") + 1:]
                            ip = ip[:ip.find(":")]
                            if network.valid_ip(ip) and ip + ":" + port + str(self.scope_id) not in engagement_device_list_already_added and "+" in line and "Found user:" in line:
                                ips.append(ip)
                                engagement_device_list_already_added.append(ip + ":" + port + str(self.scope_id))

                                users = line[line.find("Found user:")]

                                engagement_device_list.append([ip, ip, None, None, None, "", "", "", "", "",
                                                               self.modified_by, self.modified_date,
                                                               self.tool, self.scope_id])
                                result_list.append(
                                    [self.tool, "AF-" + self.tool, ip, port,
                                     "tcp", users, None, self.modified_date, self.modified_date,
                                     "auxiliary/scanner/smb/smb_enumusers_domain",
                                     "Anonymous Windows User Enumeration", "", "",
                                     "", "", "", "", "", self.modified_by])
                    except Exception as e:
                        print("metasploit enumeration parser 844 except: " + str(e) + " Error on line {}".format(
                        sys.exc_info()[-1].tb_lineno))

            output_dictionary = {}
            output_dictionary["devices"] = engagement_device_list
            output_dictionary["devices_fields_to_update"] = [('info', 'c')]
            output_dictionary["results"] = result_list
            output_dictionary["results_fields_to_update"] = [('output', 'as')]
            return output_dictionary
        return {}

    def parse_smb_version(self):
        if self.ext == "txt":
            engagement_device_list = []
            engagement_device_list_already_added = []
            result_list = []
            with open(self.file_path, 'r') as msf_file:
                only_text = keep_tags.clean_text(msf_file.read())

                lines = only_text.split("\n")
                for line in lines:
                    try:
                        columns = line.split(" ")
                        if len(columns) > 2:
                            ip = columns[1]
                            port = ""
                            if ":" in ip:
                                port = ip[ip.find(":") + 1:]
                                ip = ip[:ip.find(":")]
                            if network.valid_ip(ip):
                                host_name = line[line.find("(name:") + 6:]
                                host_name = host_name[:host_name.find(")")]
                                domain = None

                                if ip + str(self.scope_id) not in engagement_device_list_already_added and "Host is running" in line:
                                    if "domain:" in line:
                                        domain = line[line.find("domain:") + 7:]
                                        domain = domain[:domain.find(")")]
                                        if "," in domain:
                                            domain = domain[:domain.find(",")]
                                    if "workgroup:" in line:
                                        domain = line[line.find("workgroup:") + 10:]
                                        domain = domain[:domain.find(")")]

                                    os = line[line.find("Host is running ") + 16:]
                                    if "(name:" in os:
                                        os = os[:os.find("(name:")]
                                    elif "(" in os:
                                        os = os[:os.find("(")]

                                    line_no_junk = line[line.find(" ")+1:]
                                    engagement_device_list.append([ip, host_name, domain, os, None,
                                                                   "", line_no_junk, "", "", "",
                                                                   self.modified_by, self.modified_date,
                                                                   self.tool, self.scope_id])
                                    engagement_device_list_already_added.append(ip + str(self.scope_id))

                                    if " xp" in os.lower():
                                        result_list.append(
                                            [self.tool, "AF-" + self.tool, ip, "445",
                                             "tcp", os, None, self.modified_date, self.modified_date,
                                             "auxiliary/scanner/smb/smb_version",
                                             "Microsoft Windows XP Unsupported Installation Detection", "", "",
                                             "", "", "", "", "", self.modified_by])
                                    elif " 2003" in os.lower():
                                        result_list.append(
                                            [self.tool, "AF-" + self.tool, ip, "445",
                                             "tcp", os, None, self.modified_date, self.modified_date,
                                             "auxiliary/scanner/smb/smb_version",
                                             "Microsoft Windows Server 2003 Unsupported Installation Detection", "", "",
                                             "", "", "", "", "", self.modified_by])

                    except Exception as e:
                        print("metasploit enumeration parser 691 except: " + str(e) + " Error on line {}".format(
                            sys.exc_info()[-1].tb_lineno))

                output_dictionary = {}
                output_dictionary["devices"] = engagement_device_list
                output_dictionary["devices_fields_to_update"] = [('target_name', 'u'), ('domain', 'as'), ('os', 'ol'), ('info', 'as')]
                output_dictionary["results"] = result_list
                output_dictionary["results_fields_to_update"] = [('output', 'as'), ('tester_output', 'as')]
                return output_dictionary

        return {}

    def parse_smtp_version(self):
        if self.ext == "txt":
            engagement_device_list = []
            engagement_device_list_already_added = []
            with open(self.file_path, 'r') as msf_file:
                only_text = keep_tags.clean_text(msf_file.read())

                lines = only_text.split("\n")
                for line in lines:
                    try:
                        columns = line.split(" ")
                        if len(columns) > 2:
                            ip = columns[1]
                            port = ""
                            if ":" in ip:
                                port = ip[ip.find(":") + 1:]
                                ip = ip[:ip.find(":")]
                            if network.valid_ip(ip):
                                host_name = ip
                                if "(name:" in line:
                                    host_name = line[line.find("(name:") + 6:]
                                    host_name = host_name[:host_name.find(")")]
                                elif "SMTP 220 " in line:
                                    host_name = line[line.find("SMTP 220 ")+9:]
                                    host_name = host_name[:host_name.find(" ")]

                                domain = ""
                                if "." in host_name:
                                    domain = host_name[host_name.find(".")+1:]
                                    host_name = host_name[:host_name.find(".")]

                                if ip + str(self.scope_id) not in engagement_device_list_already_added and "SMTP 220" in line:
                                    info = line[line.find("SMTP 220") + 8:]
                                    if "\\x" in info:
                                        info = info[:info.find("\\x")]

                                    engagement_device_list.append([ip, host_name, domain, None, None,
                                                                   "", info, "", "", "",
                                                                   self.modified_by, self.modified_date,
                                                                   self.tool, self.scope_id])
                                    engagement_device_list_already_added.append(ip + str(self.scope_id))

                    except Exception as e:
                        print("metasploit enumeration parser 734 except: " + str(e) + " Error on line {}".format(
                            sys.exc_info()[-1].tb_lineno))

                output_dictionary = {}
                output_dictionary["devices"] = engagement_device_list
                output_dictionary["devices_fields_to_update"] = [('info', 'as')]
                return output_dictionary

        return {}


    def parse_ssh_version(self):
        if self.ext == "txt":
            engagement_device_list = []
            engagement_device_list_already_added = []
            open_port_list = []
            with open(self.file_path, 'r') as msf_file:
                only_text = keep_tags.clean_text(msf_file.read())

                lines = only_text.split("\n")
                for line in lines:
                    try:
                        columns = line.split(" ")
                        if len(columns) > 2:
                            ip = columns[1]
                            port = ""
                            if ":" in ip:
                                port = ip[ip.find(":") + 1:]
                                ip = ip[:ip.find(":")]
                            if network.valid_ip(ip):
                                if ip + str(self.scope_id) not in engagement_device_list_already_added and "SMTP 220" in line:
                                    info = line[line.find("SMTP 220") + 8:]
                                    if "\\x" in info:
                                        info = info[:info.find("\\x")]

                                    engagement_device_list.append([ip, ip, None, None, None,
                                                                   "", "", "", "", "",
                                                                   self.modified_by, self.modified_date,
                                                                   self.tool, self.scope_id])
                                    engagement_device_list_already_added.append(ip + str(self.scope_id))

                                    open_port_list.append(
                                        (ip, port, "tcp", info, True,
                                         self.modified_by, self.modified_date, False, self.modified_date,
                                         self.modified_date, 'metasploit enum ssh_ver - ' + self.file_name))

                    except Exception as e:
                        print("metasploit enumeration parser 802 except: " + str(e) + " Error on line {}".format(
                            sys.exc_info()[-1].tb_lineno))

                output_dictionary = {}
                output_dictionary["devices"] = engagement_device_list
                output_dictionary["devices_fields_to_update"] = [('info', 'c')]
                output_dictionary["ports"] = open_port_list
                output_dictionary["ports_fields_to_update"] = [('port_description', 'as')]
                return output_dictionary

        return {}

    def parse_telnet_version(self):
        if self.ext == "txt":
            engagement_device_list = []
            engagement_device_list_already_added = []
            open_port_list = []
            with open(self.file_path, 'r') as msf_file:
                only_text = keep_tags.clean_text(msf_file.read())

                lines = only_text.split("\n")
                for line in lines:
                    try:
                        columns = line.split(" ")
                        if len(columns) > 2:
                            ip = columns[1]
                            port = ""
                            if ":" in ip:
                                port = ip[ip.find(":") + 1:]
                                ip = ip[:ip.find(":")]
                            if network.valid_ip(ip):
                                if ip + str(self.scope_id) not in engagement_device_list_already_added and " TELNET" in line:
                                    info = line[line.find(" TELNET ") + 8:]
                                    if "\\x0a" in info:
                                        info = info.replace("\\x0a", "")
                                    if "\\x1b" in info:
                                        info = info.replace("\\x1b", "")
                                    if "\\x0" in info:
                                        info = info.replace("\\x0", "")

                                    engagement_device_list.append([ip, ip, None, None, None,
                                                                   "", "", "", "", "",
                                                                   self.modified_by, self.modified_date,
                                                                   self.tool, self.scope_id])
                                    engagement_device_list_already_added.append(ip + str(self.scope_id))

                                    open_port_list.append(
                                        (ip, port, "tcp", info, True,
                                         self.modified_by, self.modified_date, False, self.modified_date,
                                         self.modified_date, 'metasploit enum telnet_ver - ' + self.file_name))

                    except Exception as e:
                        print("metasploit enumeration parser 802 except: " + str(e) + " Error on line {}".format(
                            sys.exc_info()[-1].tb_lineno))

                output_dictionary = {}
                output_dictionary["devices"] = engagement_device_list
                output_dictionary["devices_fields_to_update"] = [('info', 'c')]
                output_dictionary["ports"] = open_port_list
                output_dictionary["ports_fields_to_update"] = [('port_description', 'as')]
                return output_dictionary

        return {}

    def parse_tomcat_enum(self):
        if self.ext == "txt":
            engagement_device_list = []
            engagement_device_list_already_added = []
            open_port_list = []
            with open(self.file_path, 'r') as msf_file:
                only_text = keep_tags.clean_text(msf_file.read())

                lines = only_text.split("\n")
                for line in lines:
                    try:
                        columns = line.split(" ")
                        if len(columns) > 2:
                            ip = columns[1]
                            port = ""
                            if ":" in ip:
                                port = ip[ip.find(":") + 1:]
                                ip = ip[:ip.find(":")]
                            if network.valid_ip(ip):
                                if ip + str(self.scope_id) not in engagement_device_list_already_added and "[+]" in line:
                                    info = line[line.find(ip) + 1:]
                                    info = info[info.find(" ") + 1:]

                                    engagement_device_list.append([ip, ip, None, None, None,
                                                                   "", "", "", "", "",
                                                                   self.modified_by, self.modified_date,
                                                                   self.tool, self.scope_id])
                                    engagement_device_list_already_added.append(ip + str(self.scope_id))

                                    open_port_list.append(
                                        (ip, port, "tcp", info, True,
                                         self.modified_by, self.modified_date, False, self.modified_date,
                                         self.modified_date, 'metasploit enum vmauthd_ver - ' + self.file_name))

                    except Exception as e:
                        print("metasploit enumeration parser 1099 except: " + str(e) + " Error on line {}".format(
                            sys.exc_info()[-1].tb_lineno))

                output_dictionary = {}
                output_dictionary["devices"] = engagement_device_list
                output_dictionary["devices_fields_to_update"] = [('info', 'c')]
                output_dictionary["ports"] = open_port_list
                output_dictionary["ports_fields_to_update"] = [('port_description', 'as')]
                return output_dictionary

        return {}

    def parse_vmauthd_version(self):
        if self.ext == "txt":
            engagement_device_list = []
            engagement_device_list_already_added = []
            open_port_list = []
            with open(self.file_path, 'r') as msf_file:
                only_text = keep_tags.clean_text(msf_file.read())

                lines = only_text.split("\n")
                for line in lines:
                    try:
                        columns = line.split(" ")
                        if len(columns) > 2:
                            ip = columns[1]
                            port = ""
                            if ":" in ip:
                                port = ip[ip.find(":") + 1:]
                                ip = ip[:ip.find(":")]
                            if network.valid_ip(ip):
                                if ip + str(self.scope_id) not in engagement_device_list_already_added and "Banner: 220" in line:
                                    info = line[line.find("Banner: 220") + 11:]

                                    engagement_device_list.append([ip, ip, None, None, None,
                                                                   "", "", "", "", "",
                                                                   self.modified_by, self.modified_date,
                                                                   self.tool, self.scope_id])
                                    engagement_device_list_already_added.append(ip + str(self.scope_id))

                                    open_port_list.append(
                                        (ip, port, "tcp", info, True,
                                         self.modified_by, self.modified_date, False, self.modified_date,
                                         self.modified_date, 'metasploit enum vmauthd_ver - ' + self.file_name))

                    except Exception as e:
                        print("metasploit enumeration parser 1099 except: " + str(e) + " Error on line {}".format(
                            sys.exc_info()[-1].tb_lineno))

                output_dictionary = {}
                output_dictionary["devices"] = engagement_device_list
                output_dictionary["devices_fields_to_update"] = [('info', 'c')]
                output_dictionary["ports"] = open_port_list
                output_dictionary["ports_fields_to_update"] = [('port_description', 'as')]
                return output_dictionary

        return {}

    def parse_webdav_scanner(self):
        if self.ext == "txt":
            engagement_device_list = []
            engagement_device_list_already_added = []
            open_port_list = []
            with open(self.file_path, 'r') as msf_file:
                only_text = keep_tags.clean_text(msf_file.read())

                lines = only_text.split("\n")
                for line in lines:
                    try:
                        columns = line.split(" ")
                        if len(columns) > 2:
                            ip = columns[1]
                            port = ""
                            if ":" in ip:
                                port = ip[ip.find(":") + 1:]
                                ip = ip[:ip.find(":")]
                            if network.valid_ip(ip):
                                if ip + str(self.scope_id) not in engagement_device_list_already_added and "+" in line and "webdav enabled" in line.lower():
                                    info = ""
                                    if "(" in line:
                                        info = line[line.find("(")+1:]
                                        info = info[:info.find(")")]

                                    engagement_device_list.append([ip, ip, None, None, None,
                                                                   "", "", "WebDav Enabled", "", "",
                                                                   self.modified_by, self.modified_date,
                                                                   self.tool, self.scope_id])
                                    engagement_device_list_already_added.append(ip + str(self.scope_id))

                                    open_port_list.append(
                                        (ip, port, "tcp", info, True,
                                         self.modified_by, self.modified_date, False, self.modified_date,
                                         self.modified_date, 'metasploit enum webdav_ver - ' + self.file_name))

                    except Exception as e:
                        print("metasploit enumeration parser 1147 except: " + str(e) + " Error on line {}".format(
                            sys.exc_info()[-1].tb_lineno))

                output_dictionary = {}
                output_dictionary["devices"] = engagement_device_list
                output_dictionary["devices_fields_to_update"] = [('services', 'as')]
                output_dictionary["ports"] = open_port_list
                output_dictionary["ports_fields_to_update"] = [('port_description', 'as')]
                return output_dictionary

        return {}