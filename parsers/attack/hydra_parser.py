import sys
import os
import yaml
from common import keep_tags, network
from common import scope_functions
from parsers.parser import Parser

def hydra_parser(db_path, db_object, key, hashvals):
    """
    Loop thru hashvals, verify blacklist status, update Log, send to Parser, then finally email notifications out.
    :param db_path:
    :param db_object:
    :param hashvals:
    :return:
    """
    try:
        with Parser("hydra bruteforce", db_object, key, hashvals, False) as p:
            p.parse("parsers.attack.hydra_parser", "HydraParser")

    except Exception as e:
        print("hydra_parser 19 except: " + str(e) + " Error on line {}".format(sys.exc_info()[-1].tb_lineno))


class HydraParser():
    """ Parse HydraParser files. """
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
            output_dictionary = {}
            if "hydra bruteforce asterix" in self.tool:
                output_dictionary = self.parse_asterix_bruteforce()
            elif "hydra bruteforce cisco aaa" in self.tool:
                output_dictionary = self.parse_cisco_aaa_bruteforce()
            elif "hydra bruteforce cisco enable" in self.tool:
                output_dictionary = self.parse_cisco_enable_bruteforce()
            elif "hydra bruteforce cvs" in self.tool:
                output_dictionary = self.parse_cvs_bruteforce()
            elif "hydra bruteforce firebird" in self.tool:
                output_dictionary = self.parse_firebird_bruteforce()
            elif "hydra bruteforce ftps" in self.tool:
                output_dictionary = self.parse_ftps_bruteforce()
            elif "hydra bruteforce ftp" in self.tool:
                output_dictionary = self.parse_ftp_bruteforce()
            elif "hydra bruteforce https" in self.tool:
                output_dictionary = self.parse_https_bruteforce()
            elif "hydra bruteforce icq" in self.tool:
                output_dictionary = self.parse_icq_bruteforce()
            elif "hydra bruteforce imap" in self.tool:
                output_dictionary = self.parse_imap_bruteforce()
            elif "hydra bruteforce irc" in self.tool:
                output_dictionary = self.parse_irc_bruteforce()
            elif "hydra bruteforce ldap2" in self.tool:
                output_dictionary = self.parse_ldap2_bruteforce()
            elif "hydra bruteforce ldap3" in self.tool:
                output_dictionary = self.parse_ldap3_bruteforce()
            elif "hydra bruteforce mssql" in self.tool:
                output_dictionary = self.parse_mssql_bruteforce()
            elif "hydra bruteforce mysql" in self.tool:
                output_dictionary = self.parse_mysql_bruteforce()
            elif "hydra bruteforce nntp" in self.tool:
                output_dictionary = self.parse_nntp_bruteforce()
            elif "hydra bruteforce oracle listener" in self.tool:
                output_dictionary = self.parse_oracle_listener_bruteforce()
            elif "hydra bruteforce pcanywhere" in self.tool:
                output_dictionary = self.parse_pcanywhere_bruteforce()
            elif "hydra bruteforce pcnfs" in self.tool:
                output_dictionary = self.parse_pcnfs_bruteforce()
            elif "hydra bruteforce pop3" in self.tool:
                output_dictionary = self.parse_pop3_bruteforce()
            elif "hydra bruteforce postgres" in self.tool:
                output_dictionary = self.parse_postgres_bruteforce()
            elif "hydra bruteforce radmin2" in self.tool:
                output_dictionary = self.parse_radmin2_bruteforce()
            elif "hydra bruteforce rexec" in self.tool:
                output_dictionary = self.parse_rexec_bruteforce()
            elif "hydra bruteforce rdp" in self.tool:
                output_dictionary = self.parse_rdp_bruteforce()
            elif "hydra bruteforce rlogin" in self.tool:
                output_dictionary = self.parse_rlogin_bruteforce()
            elif "hydra bruteforce rsh" in self.tool:
                output_dictionary = self.parse_rsh_bruteforce()
            elif "hydra bruteforce sip" in self.tool:
                output_dictionary = self.parse_sip_bruteforce()
            elif "hydra bruteforce smb" in self.tool:
                output_dictionary = self.parse_smb_bruteforce()
            elif "hydra bruteforce smtp" in self.tool:
                output_dictionary = self.parse_smtp_bruteforce()
            elif "hydra bruteforce smtps" in self.tool:
                output_dictionary = self.parse_smtp_bruteforce()
            elif "hydra bruteforce snmp" in self.tool:
                output_dictionary = self.parse_snmp_bruteforce()
            elif "hydra bruteforce socks5" in self.tool:
                output_dictionary = self.parse_socks5_bruteforce()
            elif "hydra bruteforce ssh" in self.tool:
                output_dictionary = self.parse_ssh_bruteforce()
            elif "hydra bruteforce svn" in self.tool:
                output_dictionary = self.parse_svn_bruteforce()
            elif "hydra bruteforce teamspeak" in self.tool:
                output_dictionary = self.parse_teamspeak_bruteforce()
            elif "hydra bruteforce telnet" in self.tool:
                output_dictionary = self.parse_telnet_bruteforce()
            elif "hydra bruteforce vnc" in self.tool:
                output_dictionary = self.parse_vnc_bruteforce()
            elif "hydra bruteforce xmpp" in self.tool:
                output_dictionary = self.parse_xmpp_bruteforce()

            return output_dictionary
        except Exception as e:
            print("hydra_parser parser 60 except: " + str(e) + " Error on line {}".format(sys.exc_info()[-1].tb_lineno))
        return {}

    def parse_bruteforce(self, info_text, vuln_text):
        output_dictionary = {}
        if self.ext == "txt":
            engagement_device_list = []
            engagement_device_list_already_added = []
            result_list = []
            credential_list = []
            with open(self.file_path, 'r') as f:
                only_text = keep_tags.clean_text(f.read())

                if "host:" in only_text:
                    lines = only_text.split("\n")
                    for line in lines:
                        if "][" in line and "host: " in line and "login: " in line and "password: " in line:
                            while "  " in line:
                                line = line.replace("  ", " ")

                            parts = line.split(" ")
                            if network.valid_ip(parts[2]) and len(parts) > 6:
                                ip = parts[2]
                                port = parts[0]
                                port = port[:port.find("]")]
                                port = port.strip("[")
                                protocol = "tcp"

                                user = parts[4].strip()
                                passwd = parts[6].strip()
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

    def parse_asterix_bruteforce(self):
        """Actually does the parsing for bruteforce"""
        return self.parse_bruteforce("Successful Asterix login: ", "Asterix had a password that was null or easily guessable")

    def parse_cisco_aaa_bruteforce(self):
        """Actually does the parsing for bruteforce"""
        return self.parse_bruteforce("Successful Cisco login: ", "Cisco had a password that was null or easily guessable")

    def parse_cisco_enable_bruteforce(self):
        """Actually does the parsing for bruteforce"""
        return self.parse_bruteforce("Successful Cisco Enable login: ", "Cisco Enable had a password that was null or easily guessable")

    def parse_cvs_bruteforce(self):
        """Actually does the parsing for bruteforce"""
        return self.parse_bruteforce("Successful CVS login: ", "CVS had a password that was null or easily guessable")

    def parse_firebird_bruteforce(self):
        """Actually does the parsing for bruteforce"""
        return self.parse_bruteforce("Successful Firebird login: ", "Firebird had a password that was null or easily guessable")

    def parse_ftp_bruteforce(self):
        """Actually does the parsing for FTP bruteforce (ie hydra ftp_login)"""
        return self.parse_bruteforce("Successful FTP login: ", "FTP share had a password that was null or easily guessable")

    def parse_ftps_bruteforce(self):
        """Actually does the parsing for FTP bruteforce (ie hydra ftp_login)"""
        return self.parse_bruteforce("Successful FTPS login: ", "FTPS share had a password that was null or easily guessable")


    def parse_https_bruteforce(self):
        """Actually does the parsing for bruteforce"""
        return self.parse_bruteforce("Successful HTTPS login: ", "HTTPS login had a password that was null or easily guessable")

    def parse_icq_bruteforce(self):
        """Actually does the parsing for bruteforce"""
        return self.parse_bruteforce("Successful ICQ login: ", "ICQ had a password that was null or easily guessable")

    def parse_imap_bruteforce(self):
        """Actually does the parsing for bruteforce"""
        return self.parse_bruteforce("Successful IMAP login: ", "IMAP had a password that was null or easily guessable")

    def parse_irc_bruteforce(self):
        """Actually does the parsing for bruteforce"""
        return self.parse_bruteforce("Successful IRC login: ", "IRC had a password that was null or easily guessable")

    def parse_ldap2_bruteforce(self):
        """Actually does the parsing for bruteforce"""
        return self.parse_bruteforce("Successful LDAP2 login: ", "LDAP2 had a password that was null or easily guessable")

    def parse_ldap3_bruteforce(self):
        """Actually does the parsing for bruteforce"""
        return self.parse_bruteforce("Successful LDAP3 login: ", "LDAP3 had a password that was null or easily guessable")

    def parse_mssql_bruteforce(self):
        """Actually does the parsing for bruteforce"""
        return self.parse_bruteforce("Successful MSSQL login: ", "MSSQL had a password that was null or easily guessable")

    def parse_mysql_bruteforce(self):
        """Actually does the parsing for bruteforce"""
        return self.parse_bruteforce("Successful MySQL login: ", "MySQL had a password that was null or easily guessable")

    def parse_nntp_bruteforce(self):
        """Actually does the parsing for bruteforce"""
        return self.parse_bruteforce("Successful NNTP login: ", "NNTP had a password that was null or easily guessable")

    def parse_oracle_listener_bruteforce(self):
        """Actually does the parsing for bruteforce"""
        return self.parse_bruteforce("Successful Oracle Listener login: ", "Oracle Listener had a password that was null or easily guessable")

    def parse_pcanywhere_bruteforce(self):
        """Actually does the parsing for bruteforce"""
        return self.parse_bruteforce("Successful PCAnywhere login: ", "PCAnywhere had a password that was null or easily guessable")

    def parse_pcnfs_bruteforce(self):
        """Actually does the parsing for bruteforce"""
        return self.parse_bruteforce("Successful PCNFS login: ", "PCNFS had a password that was null or easily guessable")

    def parse_pop3_bruteforce(self):
        """Actually does the parsing for bruteforce"""
        return self.parse_bruteforce("Successful POP3 login: ", "POP3 had a password that was null or easily guessable")

    def parse_postgres_bruteforce(self):
        """Actually does the parsing for bruteforce"""
        return self.parse_bruteforce("Successful Postgres login: ", "Postgres had a password that was null or easily guessable")

    def parse_radmin2_bruteforce(self):
        """Actually does the parsing for bruteforce"""
        return self.parse_bruteforce("Successful RADMIN2 login: ", "RADMIN2 had a password that was null or easily guessable")

    def parse_rexec_bruteforce(self):
        """Actually does the parsing for bruteforce"""
        return self.parse_bruteforce("Successful REXEC login: ", "REXEC had a password that was null or easily guessable")

    def parse_rdp_bruteforce(self):
        """Actually does the parsing for bruteforce"""
        return self.parse_bruteforce("Successful RDP login: ", "RDP had a password that was null or easily guessable")

    def parse_rlogin_bruteforce(self):
        """Actually does the parsing for bruteforce"""
        return self.parse_bruteforce("Successful RLOGIN login: ", "RLOGIN had a password that was null or easily guessable")

    def parse_rsh_bruteforce(self):
        """Actually does the parsing for bruteforce"""
        return self.parse_bruteforce("Successful RSH login: ", "RSH had a password that was null or easily guessable")

    def parse_sip_bruteforce(self):
        """Actually does the parsing for bruteforce"""
        return self.parse_bruteforce("Successful SIP login: ", "SIP had a password that was null or easily guessable")

    def parse_smb_bruteforce(self):
        """Actually does the parsing for bruteforce"""
        return self.parse_bruteforce("Successful SMB login: ", "SMB had a password that was null or easily guessable")

    def parse_smtp_bruteforce(self):
        """Actually does the parsing for bruteforce"""
        return self.parse_bruteforce("Successful SMTP login: ", "SMTP had a password that was null or easily guessable")

    def parse_snmp_bruteforce(self):
        """Actually does the parsing for SNMP bruteforce (ie hydra telnet_login)"""
        return self.parse_bruteforce("Successful SNMP login: ", "SNMP had a community string that was null or easily guessable")

    def parse_socks5_bruteforce(self):
        """Actually does the parsing for bruteforce"""
        return self.parse_bruteforce("Successful SOCKS5 login: ", "SOCKS5 had a password that was null or easily guessable")

    def parse_ssh_bruteforce(self):
        """Actually does the parsing for SSH bruteforce (ie hydra ssh_login)"""
        return self.parse_bruteforce("Successful SSH login: ", "SSH had a password that was null or easily guessable")

    def parse_svn_bruteforce(self):
        """Actually does the parsing for bruteforce"""
        return self.parse_bruteforce("Successful SVN login: ", "SVN had a password that was null or easily guessable")

    def parse_teamspeak_bruteforce(self):
        """Actually does the parsing for bruteforce"""
        return self.parse_bruteforce("Successful TeamSpeak login: ", "TeamSpeak had a password that was null or easily guessable")

    def parse_telnet_bruteforce(self):
        """Actually does the parsing for TELNET bruteforce (ie hydra telnet_login)"""
        return self.parse_bruteforce("Successful TELNET login: ", "TELNET had a password that was null or easily guessable")

    def parse_vnc_bruteforce(self):
        """Actually does the parsing for VNC bruteforce (ie hydra vnc_login)"""
        return self.parse_bruteforce("Successful VNC login: ", "VNC had a password that was null or easily guessable")

    def parse_xmpp_bruteforce(self):
        """Actually does the parsing for bruteforce"""
        return self.parse_bruteforce("Successful XMPP login: ", "XMPP had a password that was null or easily guessable")
