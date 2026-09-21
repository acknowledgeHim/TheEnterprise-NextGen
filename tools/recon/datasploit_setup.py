import sys
from common import print_text, common
from common.tool import Tool
from common.manual import Entry
from enterprise_conf import TOOLS_DICT
from enterprise_user_conf import DATASPLOIT_PATH, PYTHONv2_PATH

class DatasploitSetup(Tool):
    def __init__(self, db_object, full_client_engagement_path):
        try:
            tool = "datasploit"
            self.output_folder = full_client_engagement_path + TOOLS_DICT[tool][1]

            Tool.__init__(self, db_object, self.output_folder, tool)

            self.repo_entries = self.db_object.all_websites()

        except Exception as e:
            print_text.print_error("tool datasploit except: " + str(e) + " Error on line {}".format(sys.exc_info()[-1].tb_lineno))
        return

    def __enter__(self):
        return self

    def __exit__(self, type, value, traceback):
        return self

    def enter_fields(self):
        """
        Retrieve scope domain entries that haven't been scanned
        """
        try:
            required_manual_fields = ["datasploit_path"]
            MANUAL_FIELDS = []
            if DATASPLOIT_PATH == "":
                MANUAL_FIELDS.append(["Path to Datasploit (ex. /pentest/datasploit)", "datasploit_path", ''])

            if PYTHONv2_PATH == "":
                MANUAL_FIELDS.append(["Path Python2.7", "python2_path", ''])
                required_manual_fields.append("python2_path")

            if len(MANUAL_FIELDS) > 0:
                with Entry("Result", MANUAL_FIELDS, required_manual_fields) as me:
                    values = me.user_input_fields(input_text='Please enter the ')

            datasploit_path = DATASPLOIT_PATH
            if DATASPLOIT_PATH == "":
                datasploit_path = values['datasploit_path']

            python2_path = PYTHONv2_PATH
            if PYTHONv2_PATH == "":
                python2_path = values['python2_path']

            self.datasploit_base_command = python2_path + " " + datasploit_path + " domainOSint.py -d ENTRY"

        except Exception as e:
            print_text.print_error("tool datasploit except: " + str(e) + " Error on line {}".format(sys.exc_info()[-1].tb_lineno))

    def scan(self):
        """
        Main function that Menu calls.
        """
        self.enter_fields()
        targets, commands = self.get_targets_cmd(self.datasploit_base_command)
        self.run_group(targets, commands, "")


