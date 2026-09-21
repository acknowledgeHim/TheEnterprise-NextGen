import sys
import time
from tools.metasploit.msfconsole import MsfRpcConsole
from tools.metasploit.msfrpc import Msfrpc
from common import print_text


class MetasploitClass():
    def __init__(self, output_path, password, host='127.0.0.1', username='msf', port=55553, uri="/api/"):
        try:
            self.msf_client = Msfrpc({"port": port, "uri": uri, "host": host, "port": port})

            print_text.print_msg('Logging into the metasploit server.')
            self.msf_client.login(username, password)

            # Get a list of the exploits from the server
            #mod = self.msf_client.call('module.exploits')
            #print("18 metasploit_class exploit modules: " + str(mod))
        except Exception as e:
            print_text.print_error("tool metasploit_class except: " + str(e) + " Error on line {}".format(sys.exc_info()[-1].tb_lineno))
            return "Failed"

        self.output_path = output_path

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        return self

    def console_module(self, use_statement, set_statements):
        """
        Console access to metasploit.
        :param use_statement:
        :param set_statements: list of msf set statements (ex. set RHOSTS 10.0.0.0/24)
        :param spool_name_path: string representing the name of the spool file (ex. msf_ftp-bruteforce_10.0.0.1_24.txt)
        :return:
        """
        try:
            # Create a console
            self.msfconsole = MsfRpcConsole(self.msf_client)
            self.msfconsole.execute(use_statement)
            sts = ""
            for set_statement in set_statements:
                self.msfconsole.execute(set_statement)
                sts += "SET:" + set_statement + "\n"

            #self.msfconsole.execute("run")

            while "(100% complete)" not in str(self.msfconsole.output_txt).lower() \
                    and "[-] unknown command: " not in str(self.msfconsole.output_txt).lower()\
                    and "[-] auxiliary failed:" not in str(self.msfconsole.output_txt).lower():
                print_text.print_msg("MSF Console status: \n" + str(self.msfconsole.output_txt))
                time.sleep(7)
            output = self.msfconsole.output_txt

            self.msfconsole.destroy()

            return "USE:" + use_statement + "\n" + sts + str(output)
        except Exception as e:
            print_text.print_error("tool metasploit class except: " + str(e) + " Error on line {}".format(sys.exc_info()[-1].tb_lineno))

        return

    def module(self, toplevel, module_name, set_statement_dictionary):
        """

        :param toplevel: 'exploit', 'auxillary', etc
        :param module_name: 'unix/ftp/vsftpd_234_backdoor', 'scanner/ftp/ftp_login'
        :pararm set_statement_dictionary: dictionry where key = set Name (ie RHOST) and value = value for set statement
        :return:
        """
        module_object = self.msf_client.modules.use(toplevel, module_name)

        for key, set_statement in set_statement_dictionary.items():
            module_object[key] = set_statement