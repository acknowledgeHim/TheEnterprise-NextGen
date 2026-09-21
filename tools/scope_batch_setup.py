import json
import sys
import os
from common import print_text
from setup import scope as sc
from common.tool import Tool
from common.manual import Entry
from common.selection import Selection


class ScopeSetup(Tool):

    def __init__(self, db_object, full_client_engagement_path):
        try:
            tool = "scope"

            self.db_object = db_object
            self.output_folder = full_client_engagement_path

            Tool.__init__(self, db_object, self.output_folder, tool, False)

        except Exception as e:
            print_text.print_error("tool scope except: " + str(e) + " Error on line {}".format(sys.exc_info()[-1].tb_lineno))
        return

    def __enter__(self):
        return self

    def __exit__(self, type, value, traceback):
        return self

    def manual_entry(self):
        """
        Asks for necessary manual entry if not hard set in config.
        :return:
        """
        try:
            locations = self.db_object.dictionary_list("Location", "name")
            count_numbers = self.db_object.dictionary_list("Location", "id")

            if len(locations) == 1:
                location_id = count_numbers[0]
            else:
                with Selection('Select the Location of the scope entry(ies)', locations, None) as selection:
                    location_id = selection.select_option(count_numbers)

            MANUAL_FIELDS = [["the full path for the text file that contains the scope entries or enter a single scope entry here", "entry", ""],
                             ["if you have permission to test this/these entry(ies)", "permission", r'^(?:Y|N)$']]

            scope_values = {}

            if len(MANUAL_FIELDS) > 0:
                with Entry("Scope", MANUAL_FIELDS, ["entry", "permission"]) as me:
                   scope_values = me.user_input_fields(input_text='Please enter ')

                   scope_values['location_id'] = location_id

            if "/" in scope_values['entry']:
                entries = []
                if os.path.isfile(scope_values['entry']):
                    with open(scope_values['entry'], 'r') as f:
                        lines = f.readlines()
                    for line in lines:
                        entries.append(line.replace("\n", ""))
                else:
                    return
            else:
                entries = [scope_values['entry']]

            scope_values['entries'] = entries

            return scope_values

        except Exception as e:
            print_text.print_error("tool scope setup except: " + str(e) + " Error on line {}".format(sys.exc_info()[-1].tb_lineno))

    def get_targets(self, scope_values):
        """Retrieve SE sent_to for scenario selected that have already been sent email

        :param scan_type: type of scope scan ex) tcp-common
        :return: list of scope_ips to scan
        """
        try:
            commands = []
            targets = []
            targets.append(scope_values['entry'])
            commands.append([self.output_folder + ";" + scope_values['entry'], self.scope_id, str(scope_values['location_id']), 'scope_upload', self.output_folder + '/output/'])

            return targets, commands
        except Exception as e:
            print_text.print_error("tool scope setup except: " + str(e) + " Error on line {}".format(sys.exc_info()[-1].tb_lineno))

    def setup(self):
        """
        Function exists for the menu option to target and run the scan
        """
        try:
            self.name = "scope"
            self.tool = self.name

            scope_values = self.manual_entry()
            if scope_values is not None:
                # Add junk scope entry
                field_values = {'location_id': str(scope_values['location_id']), 'entry': scope_values['entry'],
                                'permission': scope_values['permission']}
                try:
                    sc.add_scope(self.db_object, field_values, False)
                except Exception as e:
                    print("scope batch setup Error: " + str(e))
                scope_info = self.db_object.view("Scope", None, ["entry"], [scope_values['entry']])
                print("112 scope batch setup scope_info: " + str(scope_info))
                self.scope_id = scope_info[0]["id"]

                scope_values_json = json.dumps(scope_values)

                targets, commands = self.get_targets(scope_values)
                descriptors = []
                for t in targets:
                    descriptors.append("FUNCTION:tools.scope_batch_run.scope:" + scope_values_json)
                self.run_group(targets, commands, descriptors)

        except Exception as e:
            print_text.print_error("tool scope setup except: " + str(e) + " Error on line {}".format(sys.exc_info()[-1].tb_lineno))

