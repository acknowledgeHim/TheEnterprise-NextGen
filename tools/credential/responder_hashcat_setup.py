import netifaces
import json
import sys
import re
from common import print_text, network
from common.tool import Tool
from common.manual import Entry
from enterprise_conf import PYTHONv2_PATH, YOUR_IP_ADDRESS, RESPONDER_PATH, HASHCAT_PATH, HASHCAT_WORDLIST, TOOLS_DICT

class ResponderHashcat(Tool):

    def __init__(self, db_object, full_client_engagement_path):
        try:

            self.tool = "hashcat cracking"

            self.db_object = db_object
            self.output_folder = full_client_engagement_path
            self.output_folder = self.output_folder + TOOLS_DICT[self.tool][1]

            Tool.__init__(self, db_object, self.output_folder, self.tool)

            self.hashcat_targets = []
            self.hashcat_commands = []
        except Exception as e:
            print_text.print_error("tool responder except: " + str(e) + " Error on line {}".format(sys.exc_info()[-1].tb_lineno))
        return

    def __enter__(self):
        return self

    def __exit__(self, type, value, traceback):
        return self

    def manual_entry(self):
        """
        Asks for necessary manual entry if not hard set in pat_user_config.
        :return:
        """
        try:
            MANUAL_FIELDS = []
            required_fields = []
            if YOUR_IP_ADDRESS == "":
                required_fields.append("your_ip_address")
                ip_addresses = list(map(lambda i:netifaces.ifaddresses(i),netifaces.interfaces()))
                ip_address_string = ""
                sep = ""
                for ip in ip_addresses:
                    if ip_address_string != "":
                        sep = "|"
                    try:
                        ip_address_string = ip_address_string + sep + ip[2][0]['addr']
                    except:
                        pass
                ip_address_regex = re.compile(ip_address_string)
                MANUAL_FIELDS.append(["Your IP address which must be within a Scope Entry (" + ip_address_string + ")", "your_ip_address", ip_address_regex])

            if HASHCAT_PATH == "":
                required_fields.append("hashcat_path")
                MANUAL_FIELDS.append(["the full path to the hashcat executable", "hashcat_path", r'^[a-zA-Z0-9.-_/]+'])
            if HASHCAT_WORDLIST == "":
                required_fields.append("hashcat_wordlist")
                MANUAL_FIELDS.append(["the full path to the wordlist to use for hashcat cracking", "hashcat_wordlist", r'^[a-zA-Z0-9.-_/]+'])

            if len(MANUAL_FIELDS) > 0:
                with Entry("Result", MANUAL_FIELDS, required_fields) as me:
                    hashcat_values = me.user_input_fields(input_text='Please enter ')

            if "hashcat_path" not in self.hashcat_values:
                hashcat_values['hashcat_path'] = HASHCAT_PATH
            if "hashcat_wordlist" not in self.hashcat_values:
                hashcat_values['hashcat_wordlist'] = HASHCAT_WORDLIST

            # get all Scope IP ranges
            scope_ips_dict = self.db_object.scope_ips()
            # find Scope ID that your IP address is within
            for sid in scope_ips_dict:
                if network.check_in_network(sid['entry'], self.hashcat_values['your_ip_address']):
                    hashcat_values['scope_id'] = sid['id']
                    hashcat_values['location_id'] = sid['location_id']
                    break

            if "scope_id" not in hashcat_values:
                print_text.print_error("\tYour IP address is not within any Scope IP entry's range.  Either enter the Scope IP range you are apart of, you can specify 'N' for permission to not perform other testing, or else change your IP address.")
                return

            return hashcat_values

        except Exception as e:
            print_text.print_error("tool responder except: " + str(e) + " Error on line {}".format(sys.exc_info()[-1].tb_lineno))

    def get_targets(self, hashcat_values):
        """ The only entry is

        :param scan_type: type of responder scan ex) tcp-common
        :return: list of scope_ips to scan
        """
        try:
            self.setup_already_done_checks(self.tool)

            responder_base_command = "sudo " + PYTHONv2_PATH + " " + RESPONDER_PATH


            self.hashcat_targets.append(RESPONDER_PATH + "/logs/")
            self.hashcat_commands.append([self.output_folder + ";" + RESPONDER_PATH + "/logs/",
                                          str(hashcat_values['scope_id']), str(hashcat_values['location_id'])])

            if len(self.targets) == 0 and len(self.already_scanned) > 0:
                print_text.print_error("\tYou've already scanned all applicable records and you have specified to not re-run any tools.")

        except Exception as e:
            print_text.print_error("tool responder except: " + str(e) + " Error on line {}".format(sys.exc_info()[-1].tb_lineno))

    def setup(self):
        """
        Function exists for the menu option to target and run the scan
        """
        try:
            hashcat_values = self.manual_entry()

            if self.hashcat_values is not None:
                self.get_targets(hashcat_values)
                self.run_group(self.targets, self.commands, "FUNCTION:tools.credential.responder_hashcat_run.hashcat:" + \
                               json.dumps(self.responder_values))

        except Exception as e:
            print_text.print_error("tool responder except: " + str(e) + " Error on line {}".format(sys.exc_info()[-1].tb_lineno))
