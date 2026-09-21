import json
import sys

from common import print_text, common
from tools.metasploit.metasploit_class import MetasploitClass

def metasploit_enum_run(command, scope_id, location_id, db_object, log_id, metasploit_args):
    """ Connect to Metasploit RFC and execute """

    try:
        metasploit_values = json.loads(metasploit_args)

        # Grab metasploit module
        log_info = db_object.view("Log", None, ["id"], [log_id])
        log_source = log_info[0]['source']
        module = log_source[log_source.find("(")+1:]
        module = module[module.find("enumeration ") + 12:]
        module = module[:module.find(")")].strip()

        command = command.replace('"', '')
        output_file_path = log_info[0]['output_filepath']
        target = command[command.find(";")+1:]
        rhosts_file = None
        if "--" in target:
            rhosts_file = target[:target.find("--")]
            target = target[target.find("--")+2:]

        target_port = None
        if ":" in target:
            target_port = target[target.find(":")+1:]
            target = target[:target.find(":")]
        if "," in target_port:
            target_port = target_port[:target_port.find(",")]

        # Output file name
        formatted_module = module
        if " " in formatted_module:
            formatted_module = formatted_module.replace(" ", "_")
        output_file = output_file_path + "/metasploit_enumeration_" + formatted_module + "__" + str(log_id) + "__" + target.replace("/", "_")
        if target_port is not None:
            output_file = output_file + "-" + str(target_port)
        output_file = output_file.replace(" ", "")
        output_file = output_file + ".txt"

        # Get client name to be used to name scan + target
        client_name = db_object.grab_column_from_single_record("Engagement", ["id"], [1], "client_name")

        common.create_path(output_file_path)

        with MetasploitAutomation(metasploit_values, output_file, client_name, target, target_port, log_id, db_object, rhosts_file) as metasploit_scan:
            if module == "afp_server_info":
                return metasploit_scan.afp_enumeration()
            elif module == "db2_version":
                return metasploit_scan.db2_enumeration()
            elif module == "cold_fusion_version":
                return metasploit_scan.coldfusion_enumeration()
            elif module == "dell_idrac":
                return metasploit_scan.dell_idrac_enumeration()
            elif module == "esx_fingerprint":
                return metasploit_scan.esx_enumeration()
            elif module == "finger_users":
                return metasploit_scan.finger_enumeration()
            elif module == "ftp_version":
                return metasploit_scan.ftp_anon_enumeration()
            elif module == "ftp_enumeration":
                return metasploit_scan.ftp_enumeration()
            elif module == "jboss_vulnscan":
                return metasploit_scan.jboss_enumeration()
            elif module == "jenkins_enum":
                return metasploit_scan.jenkins_enumeration()
            elif module == "joomla_version":
                return metasploit_scan.joomla_enumeration()
            elif module == "http_version":
                return metasploit_scan.http_enumeration()
            elif module == "http_put":
                return metasploit_scan.http_put_enumeration()
            elif module == "nfsmount":
                return metasploit_scan.nfs_mount_enumeration()
            elif module == "mssql_ping":
                return metasploit_scan.mssql_enumeration()
            elif module == "mysql_version":
                return metasploit_scan.mysql_enumeration()
            elif module == "nbname":
                return metasploit_scan.nbname_enumeration()
            elif module == "oracle_version":
                return metasploit_scan.oracle_enumeration_version()
            elif module == "oracle_emc_sid":
                return metasploit_scan.oracle_enumeration_emc_sid()
            elif module == "oracle_sid_enum":
                return metasploit_scan.oracle_enumeration_sid()
            elif module == "oracle_spy_sid":
                return metasploit_scan.oracle_enumeration_spy_sid()
            elif module == "oracle_sid_bruteforce":
                return metasploit_scan.oracle_enumeration_sid_bruteforce()
            elif module == "postgres_version":
                return metasploit_scan.postgres_enumeration()
            elif module == "smb_version":
                return metasploit_scan.smb_enumeration()
            elif module == "smb_enumusers_domain":
                return metasploit_scan.smb_enumeration_domainusers()
            elif module == "smb_enumshares":
                return metasploit_scan.smb_enumeration_shares()
            elif module == "smb_enumusers":
                return metasploit_scan.smb_enumeration_users()
            elif module == "smtp_version":
                return metasploit_scan.smtp_enumeration()
            elif module == "ssh_version":
                return metasploit_scan.ssh_enumeration()
            elif module == "telnet_version":
                return metasploit_scan.telnet_enumeration()
            elif module == "tomcat_enum":
                return metasploit_scan.tomcat_enumeration()
            elif module == "vmauthd_version":
                return metasploit_scan.vmauth_enumeration()
            elif module == "vnc_none_auth":
                return metasploit_scan.vnc_enumeration()
            elif module == "webdav_scanner":
                return metasploit_scan.webdav_enumeration()
            elif module == "open_x11":
                return metasploit_scan.x11_enumeration()

    except Exception as e:
        print_text.print_error("metasploit_run except: " +  str(e) +  " Error on line {}".format(sys.exc_info()[-1].tb_lineno))


class MetasploitAutomation():
    def __init__(self, metasploit_values, output_file, client_name, target, target_port, log_id, db_object, rhosts_file):
        self.url = metasploit_values['msfrpc_url']
        self.port = metasploit_values['msfrpc_port']
        self.rhosts_file = rhosts_file

        self.output_file = output_file
        print("129 metasploit_enum_run output_file: " + str(output_file))
        self.client_name = client_name
        self.target = target
        self.target_port = int(target_port)
        self.log_id = log_id
        self.db_object = db_object
        self.token = None
        self.user = metasploit_values['msfrpc_user']
        self.passwd = metasploit_values['msfrpc_password']
        self.user_list = metasploit_values['msfrpc_userlist']
        self.word_list = metasploit_values['msfrpc_wordlist']

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        return self

    def enumeration(self, use_statement, set_statements):
        try:
            # replace set RHOSTS with file
            if self.rhosts_file is not None:
                set_statements[0] = "set RHOSTS file:" + self.rhosts_file
            set_statements[1] = "set VERBOSE true"

            with MetasploitClass(self.output_file, self.passwd, self.url, self.user, self.port, uri="/api/") as m_class:
                output = m_class.console_module(use_statement, set_statements)

                if output is not None:
                    with open(self.output_file, 'w') as of:
                        of.write(output)

        except Exception as e:
            print_text.print_error(
                "tool metasploit_run except: " + str(e) + " Error on line {}".format(sys.exc_info()[-1].tb_lineno))

    def afp_enumeration(self):
        use_statement = "use auxiliary/scanner/afp/afp_server_info"
        set_statements = ["set RHOSTS " + self.target, "set THREADS 40", "run"]
        if self.target_port is not None:
            set_statements.insert(1, "set PORT " + str(self.port))
            set_statements.insert(2, "set RPORT " +  str(self.target_port))
        self.enumeration(use_statement, set_statements)

    def db2_enumeration(self):
        use_statement = "use auxiliary/scanner/db2/db2_version"
        set_statements = ["set RHOSTS " + self.target, "set THREADS 40", "run"]
        if self.target_port is not None:
            set_statements.insert(1, "set PORT " + str(self.port))
            set_statements.insert(2, "set RPORT " + str(self.target_port))
        self.enumeration(use_statement, set_statements)

    def coldfusion_enumeration(self):
        use_statement = "use auxiliary/scanner/http/coldfusion_version"
        set_statements = ["set RHOSTS " + self.target, "set THREADS 40", "run"]
        if self.target_port is not None:
            set_statements.insert(1, "set PORT " + str(self.port))
            set_statements.insert(2, "set RPORT " +  str(self.target_port))
        if self.target_port == 443 or self.target_port == 8443:
            set_statements.insert(2, "set ssl true")
        else:
            set_statements.insert(2, "set ssl false")
        self.enumeration(use_statement, set_statements)

    def dell_idrac_enumeration(self):
        use_statement = "use auxiliary/scanner/http/dell_idrac"
        set_statements = ["set RHOSTS " + self.target, "set THREADS 40", "run"]
        if self.target_port is not None:
            set_statements.insert(1, "set PORT " + str(self.port))
            set_statements.insert(2, "set RPORT " + str(self.target_port))
        self.enumeration(use_statement, set_statements)

    def esx_enumeration(self):
        use_statement = "use auxiliary/scanner/vmware/esx_fingerprint"
        set_statements = ["set RHOSTS " + self.target, "set THREADS 40", "run"]
        if self.target_port is not None:
            set_statements.insert(1, "set PORT " + str(self.port))
            set_statements.insert(2, "set RPORT " +  str(self.target_port))

        self.enumeration(use_statement, set_statements)

    def finger_enumeration(self):
        use_statement = "use auxiliary/scanner/finger/finger_users"
        set_statements = ["set RHOSTS " + self.target, "set THREADS 40", "run"]
        if self.target_port is not None:
            set_statements.insert(1, "set PORT " + str(self.port))
            set_statements.insert(2, "set RPORT " + str(self.target_port))

        self.enumeration(use_statement, set_statements)

    def ftp_anon_enumeration(self):
        use_statement = "use auxiliary/scanner/ftp/anonymous"
        set_statements = ["set RHOSTS " + self.target, "set THREADS 40", "run"]
        if self.target_port is not None:
            set_statements.insert(1, "set PORT " + str(self.port))
            set_statements.insert(2, "set RPORT " +  str(self.target_port))

        self.enumeration(use_statement, set_statements)

    def ftp_enumeration(self):
        use_statement = "use auxiliary/scanner/ftp/ftp_version"
        set_statements = ["set RHOSTS " + self.target, "set THREADS 40", "run"]
        if self.target_port is not None:
            set_statements.insert(1, "set PORT " + str(self.port))
            set_statements.insert(2, "set RPORT " +  str(self.target_port))

        self.enumeration(use_statement, set_statements)

    def jboss_enumeration(self):
        use_statement = "use auxiliary/scanner/http/jboss_vulnscan"
        set_statements = ["set RHOSTS " + self.target, "set THREADS 40", "run"]
        if self.target_port is not None:
            set_statements.insert(1, "set PORT " + str(self.port))
            set_statements.insert(2, "set RPORT " +  str(self.target_port))
        if self.target_port == 443 or self.target_port == 8443:
            set_statements.insert(2, "set ssl true")
        else:
            set_statements.insert(2, "set ssl false")
        self.enumeration(use_statement, set_statements)

    def jenkins_enumeration(self):
        use_statement = "use auxiliary/scanner/http/jenkins_enum"
        set_statements = ["set RHOSTS " + self.target, "set THREADS 40", "run"]
        if self.target_port is not None:
            set_statements.insert(1, "set PORT " + str(self.port))
            set_statements.insert(2, "set RPORT " + str(self.target_port))
        if self.target_port == 443 or self.target_port == 8443:
            set_statements.insert(2, "set ssl true")
        else:
            set_statements.insert(2, "set ssl false")
        self.enumeration(use_statement, set_statements)

    def joomla_enumeration(self):
        use_statement = "use auxiliary/scanner/http/joomla_version"
        set_statements = ["set RHOSTS " + self.target, "set THREADS 40", "run"]
        if self.target_port is not None:
            set_statements.insert(1, "set PORT " + str(self.port))
            set_statements.insert(2, "set RPORT " + str(self.target_port))
        if self.target_port == 443 or self.target_port == 8443:
            set_statements.insert(2, "set ssl true")
        else:
            set_statements.insert(2, "set ssl false")
        self.enumeration(use_statement, set_statements)

    def http_enumeration(self):
        use_statement = "use auxiliary/scanner/http/http_version"
        set_statements = ["set RHOSTS " + self.target, "set THREADS 40", "run"]
        if self.target_port is not None:
            set_statements.insert(1, "set PORT " + str(self.port))
            set_statements.insert(2, "set RPORT " + str(self.target_port))
        if self.target_port == 443 or self.target_port == 8443:
            set_statements.insert(2, "set ssl true")
        else:
            set_statements.insert(2, "set ssl false")
        self.enumeration(use_statement, set_statements)

    def http_put_enumeration(self):
        use_statement = "use auxiliary/scanner/http/http_put"
        set_statements = ["set RHOSTS " + self.target, "set THREADS 40", "run"]
        if self.target_port is not None:
            set_statements.insert(1, "set PORT " + str(self.port))
            set_statements.insert(2, "set RPORT " + str(self.target_port))
        if self.target_port == 443 or self.target_port == 8443:
            set_statements.insert(2, "set ssl true")
        else:
            set_statements.insert(2, "set ssl false")
        self.enumeration(use_statement, set_statements)

    def nfs_mount_enumeration(self):
        use_statement = "use auxiliary/scanner/nfs/nfsmount"
        set_statements = ["set RHOSTS " + self.target, "set THREADS 40", "run"]
        if self.target_port is not None:
            set_statements.insert(1, "set PORT " + str(self.port))
            set_statements.insert(2, "set RPORT " + str(self.target_port))
        self.enumeration(use_statement, set_statements)

    def mssql_enumeration(self):
        use_statement = "use auxiliary/scanner/mssql/mssql_ping"
        set_statements = ["set RHOSTS " + self.target, "set THREADS 40", "run"]
        if self.target_port is not None:
            set_statements.insert(1, "set PORT " + str(self.port))
            set_statements.insert(2, "set RPORT " + str(self.target_port))
        self.enumeration(use_statement, set_statements)

    def mysql_enumeration(self):
        use_statement = "use auxiliary/scanner/mysql/mysql_version"
        set_statements = ["set RHOSTS " + self.target, "set THREADS 40", "run"]
        if self.target_port is not None:
            set_statements.insert(1, "set PORT " + str(self.port))
            set_statements.insert(2, "set RPORT " + str(self.target_port))
        self.enumeration(use_statement, set_statements)

    def nbname_enumeration(self):
        use_statement = "use auxiliary/scanner/netbios/nbname"
        set_statements = ["set RHOSTS " + self.target, "set THREADS 40", "run"]
        if self.target_port is not None:
            set_statements.insert(1, "set PORT " + str(self.port))
            set_statements.insert(2, "set RPORT " + str(self.target_port))
        self.enumeration(use_statement, set_statements)

    def oracle_enumeration_version(self):
        use_statement = "use auxiliary/scanner/oracle/tnslsnr_version"
        set_statements = ["set RHOSTS " + self.target, "set THREADS 40", "run"]
        if self.target_port is not None:
            set_statements.insert(1, "set PORT " + str(self.port))
            set_statements.insert(2, "set RPORT " + str(self.target_port))
        self.enumeration(use_statement, set_statements)

    def oracle_enumeration_emc_sid(self):
        use_statement = "use auxiliary/scanner/oracle/emc_sid"
        set_statements = ["set RHOSTS " + self.target, "set THREADS 40", "run"]
        if self.target_port is not None:
            set_statements.insert(1, "set PORT " + str(self.port))
            set_statements.insert(2, "set RPORT " + str(self.target_port))
        self.enumeration(use_statement, set_statements)

    def oracle_enumeration_sid(self):
        use_statement = "use auxiliary/scanner/oracle/sid_enum"
        set_statements = ["set RHOSTS " + self.target, "set THREADS 40", "run"]
        if self.target_port is not None:
            set_statements.insert(1, "set PORT " + str(self.port))
            set_statements.insert(2, "set RPORT " + str(self.target_port))
        self.enumeration(use_statement, set_statements)

    def oracle_enumeration_spy_sid(self):
        use_statement = "use auxiliary/scanner/oracle/spy_sid"
        set_statements = ["set RHOSTS " + self.target, "set THREADS 40", "run"]
        if self.target_port is not None:
            set_statements.insert(1, "set PORT " + str(self.port))
            set_statements.insert(2, "set RPORT " + str(self.target_port))
        self.enumeration(use_statement, set_statements)

    def oracle_enumeration_sid_bruteforce(self):
        use_statement = "use auxiliary/scanner/oracle/sid_brute"
        set_statements = ["set RHOSTS " + self.target, "set THREADS 40", "run"]
        if self.target_port is not None:
            set_statements.insert(1, "set PORT " + str(self.port))
            set_statements.insert(2, "set RPORT " + str(self.target_port))
        self.enumeration(use_statement, set_statements)

    def postgres_enumeration(self):
        use_statement = "use auxiliary/scanner/postgres/postgres_version"
        set_statements = ["set RHOSTS " + self.target, "set THREADS 40", "run"]
        if self.target_port is not None:
            set_statements.insert(1, "set PORT " + str(self.port))
            set_statements.insert(2, "set RPORT " + str(self.target_port))
        self.enumeration(use_statement, set_statements)

    def smb_enumeration(self):
        use_statement = "use auxiliary/scanner/smb/smb_version"
        set_statements = ["set RHOSTS " + self.target, "set THREADS 40", "run"]
        if self.target_port is not None:
            set_statements.insert(1, "set PORT " + str(self.port))
            set_statements.insert(2, "set RPORT " + str(self.target_port))
        self.enumeration(use_statement, set_statements)

    def smb_enumeration_domainusers(self):
        use_statement = "use auxiliary/scanner/smb/smb_enumusers_domain"
        set_statements = ["set RHOSTS " + self.target, "set THREADS 40", "run"]
        if self.target_port is not None:
            set_statements.insert(1, "set PORT " + str(self.port))
        self.enumeration(use_statement, set_statements)

    def smb_enumeration_shares(self):
        use_statement = "use auxiliary/scanner/smb/smb_enumshares"
        set_statements = ["set RHOSTS " + self.target, "set THREADS 40", "run"]
        if self.target_port is not None:
            set_statements.insert(1, "set PORT " + str(self.port))
        self.enumeration(use_statement, set_statements)

    def smb_enumeration_users(self):
        use_statement = "use auxiliary/scanner/smb/smb_enumusers"
        set_statements = ["set RHOSTS " + self.target, "set THREADS 40", "run"]
        if self.target_port is not None:
            set_statements.insert(1, "set PORT " + str(self.port))
        self.enumeration(use_statement, set_statements)

    def smtp_enumeration(self):
        use_statement = "use auxiliary/scanner/smtp/smtp_version"
        set_statements = ["set RHOSTS " + self.target, "set THREADS 40", "run"]
        if self.target_port is not None:
            set_statements.insert(1, "set PORT " + str(self.port))
        self.enumeration(use_statement, set_statements)

    def ssh_enumeration(self):
        use_statement = "use auxiliary/scanner/ssh/ssh_version"
        set_statements = ["set RHOSTS " + self.target, "set THREADS 40", "run"]
        if self.target_port is not None:
            set_statements.insert(1, "set PORT " + str(self.port))
            set_statements.insert(2, "set RPORT " + str(self.target_port))
        self.enumeration(use_statement, set_statements)

    def telnet_enumeration(self):
        use_statement = "use auxiliary/scanner/telnet/telnet_version"
        set_statements = ["set RHOSTS " + self.target, "set THREADS 40", "run"]
        if self.target_port is not None:
            set_statements.insert(1, "set PORT " + str(self.port))
            set_statements.insert(2, "set RPORT " + str(self.target_port))
        self.enumeration(use_statement, set_statements)

    def tomcat_enumeration(self):
        use_statement = "use auxiliary/scanner/http/tomcat_enum"
        set_statements = ["set RHOSTS " + self.target, "set THREADS 40", "run"]
        if self.target_port is not None:
            set_statements.insert(1, "set PORT " + str(self.port))
            set_statements.insert(2, "set RPORT " + str(self.target_port))
        if self.target_port == 443 or self.target_port == 8443:
            set_statements.insert(2, "set ssl true")
        else:
            set_statements.insert(2, "set ssl false")
        self.enumeration(use_statement, set_statements)

    def vmauth_enumeration(self):
        use_statement = "use auxiliary/scanner/vmware/vmauthd_version"
        set_statements = ["set RHOSTS " + self.target, "set THREADS 40", "run"]
        if self.target_port is not None:
            set_statements.insert(1, "set PORT " + str(self.port))
        self.enumeration(use_statement, set_statements)

    def vnc_enumeration(self):
        use_statement = "use auxiliary/scanner/vnc/vnc_none_auth"
        set_statements = ["set RHOSTS " + self.target, "set THREADS 40", "run"]
        if self.target_port is not None:
            set_statements.insert(1, "set PORT " + str(self.port))
        self.enumeration(use_statement, set_statements)

    def webdav_enumeration(self):
        use_statement = "use auxiliary/scanner/http/webdav_scanner"
        set_statements = ["set RHOSTS " + self.target, "set THREADS 40", "run"]
        if self.target_port is not None:
            set_statements.insert(1, "set PORT " + str(self.port))
            set_statements.insert(2, "set RPORT " + str(self.target_port))
        if self.target_port == 443 or self.target_port == 8443:
            set_statements.insert(2, "set ssl true")
        else:
            set_statements.insert(2, "set ssl false")
        self.enumeration(use_statement, set_statements)

    def x11_enumeration(self):
        use_statement = "use auxiliary/scanner/x11/open_x11"
        set_statements = ["set RHOSTS " + self.target, "set THREADS 40", "run"]
        if self.target_port is not None:
            set_statements.insert(1, "set PORT " + str(self.port))
            set_statements.insert(2, "set RPORT " + str(self.target_port))
        self.enumeration(use_statement, set_statements)