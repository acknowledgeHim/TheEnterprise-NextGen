import sys
import json
from datetime import datetime
from common import print_text, common
from tools.manual_parse.generic_parser_selection import GenericParserSelection
from enterprise_conf import TOOLS_DICT

class ParserSelection(GenericParserSelection):
    """ Manual Parse files"""
    def __init__(self, db_object, full_client_engagement_path):
        self.base_tool = "metasploit enumeration "
        self.output_folder = full_client_engagement_path + TOOLS_DICT["metasploit enumeration netbios"][1]
        try:
            GenericParserSelection.__init__(self, db_object, self.output_folder)
        except Exception as e:
            print_text.print_error("tool parser selection enum except: " + str(e) + " Error on line {}".format(sys.exc_info()[-1].tb_lineno))
        return

    def __enter__(self):
        return self

    def __exit__(self, type, value, traceback):
        return self

    def setup_manual_parser(self):
        try:
            common.makedirs(self.output_folder)

            tool_json = json.dumps({'tool': self.tool})

            targets, commands = self.get_targets(self.tool, self.output_folder)
            self.run_group(targets, commands, "FUNCTION:tools.manual_parse.parse_selection.parse:" + tool_json)
        except Exception as e:
            print_text.print_error("tool parser selection enum except: " + str(e) + " Error on line {}".format(sys.exc_info()[-1].tb_lineno))

    def afp(self):
        """
        All output files.
        """
        self.tool = self.base_tool + "afp_server_info"
        self.setup_manual_parser()

    def cold_fusion(self):
        """
        All output files.
        """
        self.tool = self.base_tool + "cold_fusion_version"
        self.setup_manual_parser()

    def enum_db2(self):
        """
        All output files.
        """
        self.tool = self.base_tool + "db2_version"
        self.setup_manual_parser()

    def dell_idrac(self):
        """
        All output files.
        """
        self.tool = self.base_tool + "dell_idrac"
        self.setup_manual_parser()

    def esx_version(self):
        """
        All output files.
        """
        self.tool = self.base_tool + "esx_fingerprint"
        self.setup_manual_parser()

    def finger(self):
        """
        All output files.
        """
        self.tool = self.base_tool + "finger_users"
        self.setup_manual_parser()

    def ftp_anon(self):
        """
        All output files.
        """
        self.tool = self.base_tool + "ftp_anonymous"
        self.setup_manual_parser()

    def ftp_version(self):
        """
        All output files.
        """
        self.tool = self.base_tool + "ftp_version"
        self.setup_manual_parser()

    def http_put(self):
        """
        All output files.
        """
        self.tool = self.base_tool + "http_put"
        self.setup_manual_parser()

    def http_version(self):
        """
        All output files.
        """
        self.tool = self.base_tool + "http_version"
        self.setup_manual_parser()

    def jboss_vulnscan(self):
        """
        All output files.
        """
        self.tool = self.base_tool + "jboss_vulnscan"
        self.setup_manual_parser()

    def jenkins(self):
        """
        All output files.
        """
        self.tool = self.base_tool + "jenkins_enum"
        self.setup_manual_parser()

    def joomla(self):
        """
        All output files.
        """
        self.tool = self.base_tool + "joomla_version"
        self.setup_manual_parser()

    def mssql(self):
        """
        All output files.
        """
        self.tool = self.base_tool + "mssql_version"
        self.setup_manual_parser()

    def mysql(self):
        """
        All output files.
        """
        self.tool = self.base_tool + "mysql_version"
        self.setup_manual_parser()

    def netbios(self):
        """
        All output files.
        """
        self.tool = self.base_tool + "netbios"
        self.setup_manual_parser()

    def nfsmount(self):
        """
        All output files.
        """
        self.tool = self.base_tool + "nfsmount"
        self.setup_manual_parser()

    def oracle_version(self):
        """
        All output files.
        """
        self.tool = self.base_tool + "oracle version"
        self.setup_manual_parser()

    def oracle_emc_sid(self):
        """
        All output files.
        """
        self.tool = self.base_tool + "oracle emc sid"
        self.setup_manual_parser()

    def oracle_sid(self):
        """
        All output files.
        """
        self.tool = self.base_tool + "oracle sid"
        self.setup_manual_parser()

    def oracle_spy_sid(self):
        """
        All output files.
        """
        self.tool = self.base_tool + "oracle spy sid"
        self.setup_manual_parser()

    def oracle_sid_bruteforce(self):
        """
        All output files.
        """
        self.tool = self.base_tool + "oracle sid bruteforce"
        self.setup_manual_parser()

    def open_x11(self):
        """
        All output files.
        """
        self.tool = self.base_tool + "open_x11"
        self.setup_manual_parser()

    def postgress(self):
        """
        All output files.
        """
        self.tool = self.base_tool + "postgres version"
        self.setup_manual_parser()

    def smb_enumusers(self):
        """
        All output files.
        """
        self.tool = self.base_tool + "smb_enumusers"
        self.setup_manual_parser()

    def smb_enumshares(self):
        """
        All output files.
        """
        self.tool = self.base_tool + "smb_enumshares"
        self.setup_manual_parser()

    def smb_enumusers_domain(self):
        """
        All output files.
        """
        self.tool = self.base_tool + "smb_enumusers_domain"
        self.setup_manual_parser()

    def smb_version(self):
        """
        All output files.
        """
        self.tool = self.base_tool + "smb_version"
        self.setup_manual_parser()

    def smtp_version(self):
        """
        All output files.
        """
        self.tool = self.base_tool + "smtp_version"
        self.setup_manual_parser()

    def ssh_version(self):
        """
        All output files.
        """
        self.tool = self.base_tool + "ssh_version"
        self.setup_manual_parser()

    def telnet_version(self):
        """
        All output files.
        """
        self.tool = self.base_tool + "telnet_version"
        self.setup_manual_parser()

    def tomcat(self):
        """
        All output files.
        """
        self.tool = self.base_tool + "tomcat_enum"
        self.setup_manual_parser()

    def vmauthd(self):
        """
        All output files.
        """
        self.tool = self.base_tool + "vmauthd_version"
        self.setup_manual_parser()

    def vnc_no_auth(self):
        """
        All output files.
        """
        self.tool = self.base_tool + "vnc_none_auth"
        self.setup_manual_parser()

    def webdav(self):
        """
        All output files.
        """
        self.tool = self.base_tool + "webdav_scanner"
        self.setup_manual_parser()

