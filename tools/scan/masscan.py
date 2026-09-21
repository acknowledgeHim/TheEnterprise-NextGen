import sys
import datetime
from common import print_text, common
from common.tool import Tool


class MassScan(Tool):
    def __init__(self, db_object, full_client_engagement_path):
        try:
            tool = "masscan"
            self.output_folder = full_client_engagement_path + tool

            Tool.__init__(self, db_object, self.output_folder, tool)

            self.masscan_scan = "masscan SCOPE_ID -p0-65535 -oX " + self.output_folder + "FORMATTED_ENTRY__sSCOPE_ID ENTRY" # --max-rate 10000000

            self.repo_entries = self.db_object.scope_ips()

        except Exception as e:
            print_text.print_error("tool masscan ping except: " + str(e) + " Error on line {}".format(sys.exc_info()[-1].tb_lineno))
        return

    def __enter__(self):
        return self

    def __exit__(self, type, value, traceback):
        return self

    def scan(self):
        """Run one scan type against all targets

        :param scan_type:
        :return:
        """
        try:
            targets, commands = self.get_targets_cmd(self.masscan_scan)
            self.run_group(targets, commands, "")

        except Exception as e:
            print_text.print_error("tool masscan except: " + str(e) + " Error on line {}".format(sys.exc_info()[-1].tb_lineno))
