import json
import sys
import re
import time
from common import print_text, network
from common.tool import Tool
from common.manual import Entry
from enterprise_conf import INTERFACE_NAME, YOUR_IP_ADDRESS, PYTHONv2_PATH, TOOLS_DICT

class ScapySetup(Tool):

    def __init__(self, db_object, full_client_engagement_path):
        try:

            self.tool = "scapy email mitm"

            self.db_object = db_object
            self.output_folder = full_client_engagement_path
            self.output_folder = self.output_folder + TOOLS_DICT[self.tool][1]

            Tool.__init__(self, db_object, self.output_folder, self.tool)

        except Exception as e:
            print_text.print_error("tool scapy email mitm except: " + str(e) + " Error on line {}".format(sys.exc_info()[-1].tb_lineno))
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

            # Grab list of interface names
            interface_string, interface_regex, ip_address_string, ip_address_regex = network.grab_interfaces()

            if INTERFACE_NAME == "":
                required_fields.append("interface_name")
                MANUAL_FIELDS.append(["your Network Interface (" + interface_string + ")", "interface_name", interface_regex])
            if YOUR_IP_ADDRESS == "":
                required_fields.append("your_ip_address")
                MANUAL_FIELDS.append(["your IP address (" + ip_address_string + ")", "your_ip_address", ip_address_regex])

            if len(MANUAL_FIELDS) > 0:
                with Entry("Result", MANUAL_FIELDS, required_fields) as me:
                    scapy_values = me.user_input_fields(input_text='Please enter ')

            if "interface_name" not in scapy_values:
                scapy_values['interface_name'] = INTERFACE_NAME
            if "your_ip_address" not in scapy_values:
                scapy_values['your_ip_address'] = YOUR_IP_ADDRESS

            # get all Scope IP ranges
            scope_ips_dict = self.db_object.scope_ips()
            # find Scope ID that your IP address is within
            for sid in scope_ips_dict:
                if network.check_in_network(sid['entry'], scapy_values['your_ip_address']):
                    scapy_values['scope_id'] = sid['id']
                    scapy_values['location_id'] = sid['location_id']
                    break

            if "scope_id" not in scapy_values:
                print_text.print_error("\tYour IP address is not within any Scope IP entry's range.  Either enter the Scope IP range you are apart of, you can specify 'N' for permission to not perform other testing, or else change your IP address.")
                return

            self.entries = scapy_values
            self.entries['ip'] = scapy_values['your_ip_address']
            self.entries['port'] = '25'
            self.entries = [self.entries]

            return scapy_values
            #return json.dumps(self.scapy_values)
        except Exception as e:
            print_text.print_error("tool scapy email mitm except: " + str(e) + " Error on line {}".format(sys.exc_info()[-1].tb_lineno))

    def get_targets(self, scapy_values):
        """
        :return: list of scope_ips to scan
        """
        try:
            self.setup_already_done_checks(self.tool)
            self.timestamp = time.time()

            commands = []
            targets = []
            for entry in self.entries:
                if entry['ip'] + ";" + str(entry['scope_id']) not in self.already_scanned:
                    # add IP to targets
                    targets.append(entry['ip'] + ":" + str(entry['port']))

                    commands.append([responder_base_command + " " + scapy_values['interface_name'] + " -i " +
                                     scapy_values['your_ip_address'] + " -" + scapy_values['responder_switches'],
                                     entry['scope_id'], entry['location_id']])

            if len(targets) == 0 and len(self.already_scanned) > 0:
                print_text.print_error("\tYou've already scanned all applicable records and you have specified to not re-run any tools.")
            print("145 responder setup commands: " +str(commands))
            return targets, commands
        except Exception as e:
            print_text.print_error("tool scapy email mitm except: " + str(e) + " Error on line {}".format(sys.exc_info()[-1].tb_lineno))

    def scapy(self):
        """
        Function exists for the menu option to target and run the scan
        """
        try:
            scapy_values = self.manual_entry()

            if scapy_values is not None:
                targets, commands = self.get_targets(scapy_values)
                self.run_group(targets, commands, "")

        except Exception as e:
            print_text.print_error("tool scapy email mitm except: " + str(e) + " Error on line {}".format(sys.exc_info()[-1].tb_lineno))
