import sys
from common import print_text, common
from common.tool import Tool
from common.manual import Entry
from enterprise_user_conf import EYEWITNESS_PATH, PYTHONv2_PATH

class CreateHostsFile(Tool):
    def __init__(self, db_object, full_client_engagement_path):
        try:
            tool = "create hosts files"
            self.full_client_engagement_path = full_client_engagement_path
            self.output_folder = full_client_engagement_path + tool

            Tool.__init__(self, db_object, self.output_folder, tool)

            self.web_servers = self.db_object.portscan_websites()
            self.rdp_servers = self.db_object.portscan_rdp()
            self.vnc_servers = self.db_object.portscan_vnc()

        except Exception as e:
            print_text.print_error("tool" + self.tool + " except: " + str(e) + " Error on line {}".format(sys.exc_info()[-1].tb_lineno))
        return

    def __enter__(self):
        return self

    def __exit__(self, type, value, traceback):
        return self

    def setup(self):
        """
        Main function that Menu calls.
        """

        targets = ['hosts_from_open_ports']
        commands = ['hosts_from_open_ports']

        self.run_group(targets, commands, "FUNCTION:tools.scan.create_hosts.create")



def create(command, scope_id, location_id, db_object, log_id):
    """
    Actually create all the hosts files
    :param command:
    :param scope_id:
    :param location_id:
    :param db_object:
    :param log_id:
    :return:
    """

    full_client_engagement_path = db_object.sqlite_file[:db_object.rfind("/") + 1]
    hosts_path = full_client_engagement_path + "hosts/"
    common.makedirs(hosts_path)


