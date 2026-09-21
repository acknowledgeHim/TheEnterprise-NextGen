import sys
import datetime
from common import print_text, common
from common.tool import Tool
from enterprise_conf import TOOLS_DICT


class Nmap(Tool):
    #get all entries from scope
    #loop through entries
    #loop through nmap scan types
    #check Log table to see if already run and completed, still running, etc
    #for still running, make sure PID is still live on machine
    #for ones that have not already completed (unless user wants to redo scan) and not still running, kick off command

    def __init__(self, db_object, full_client_engagement_path):
        try:
            tool = "nmap"
            self.output_folder = full_client_engagement_path + TOOLS_DICT[tool][1]

            Tool.__init__(self, db_object, self.output_folder, tool)

            self.blackbox = ""
            input_sub = input('Stealth / Blackbox Testing, (R)regular - default, (s)stealth, or (e)extreme stealth: ')
            if input_sub.lower() == 's' :
                print_text.print_msg("Please be patient as this will take longer because decoy IPs are used and timing is dropped to T3.")
                self.blackbox = " -T3 -D 122.88.89.12 "
            if input_sub.lower() == 'e' :
                print_text.print_msg("Please be VERY patient as this will take MUCH longer because decoy IPs are used and timing is dropped to T0.")
                self.blackbox = " -T0 -D 122.88.89.12 "

            # Dictionary of scan types (scan : modified scan variables)
            scan_types = {'traditional-internal': '-n -p 21,22,23,25,80,135,139,443,445,902,1158,1433,1521,3306,3389,5432,5800,5900,6000,8080,8443,50000',
                          'tcp-25': '-sS -A --reason --top-ports 25',
                          'tcp-default': '-A -sS',
                          'udp-25': '-sU --top-ports 25',
                          'tcp-all': '-sS -p-',
                          'udp-250': '-sU --top-ports 250'}

            self.NMAP_SCANS = {}
            for scan, modifier in scan_types.items():
                self.NMAP_SCANS[scan] = "sudo nmap {0} -Pn -vv --reason {1} -oA {2}".format(
                    modifier, self.blackbox, self.output_folder)

            self.repo_entries = self.db_object.grab_ips()

        except Exception as e:
            print_text.print_error("tool nmap except: " + str(e) + " Error on line {}".format(sys.exc_info()[-1].tb_lineno))
        return

    def __enter__(self):
        return self

    def __exit__(self, type, value, traceback):
        return self

    def traditional_internal(self):
        self.port_scan("traditional-internal")

    def tcp_25(self):
        self.port_scan("tcp-25")

    def tcp_default(self):
        """Wrapper function to run default tcp scan

        Function exists for the menu option to target and run the scan
        """

        self.port_scan("tcp-default")

    def udp_25(self):
        """Wrapper function to run udp scan against top 25 ports

        Function exists for the menu option to target and run the scan
        """

        self.port_scan("udp-25")

    def udp_250(self):
        """Wrapper function to run udp scan against top 250 ports

        Function exists for the menu option to target and run the scan
        """

        self.port_scan("udp-250")

    def tcp_all(self):
        """Wrapper function to run tcp all scan

        Function exists for the menu option to target and run the scan
        """

        self.port_scan("tcp-all")

    def setup_port_scan(self, scan_type, commands=[], targets=[]):
        """

        :param scan_type:
        :return:
        """
        try:
            #return self.get_targets_cmd(cmd, None, commands, targets)

            targets = []
            commands = []
            if self.repo_entries is not None:
                for count, repo_entry in enumerate(self.repo_entries):
                    sentry = repo_entry['entry']
                    cmd = self.NMAP_SCANS[scan_type] + "nmap_" + scan_type.replace(" ", "_") + "__sSCOPE_ID__FORMATTED_ENTRY ORIGINAL_ENTRY"
                    if "-" in repo_entry['original_entry']:
                        sentry = repo_entry['original_entry']
                        cmd = self.NMAP_SCANS[scan_type] + "nmap_" + scan_type.replace(" ", "_") + "__sSCOPE_ID__FORMATTED_ENTRY ORIGINAL_ENTRY"
                    if sentry not in targets and sentry is not None:
                        location_id = repo_entry['location_id']
                        scope_id = repo_entry['id']
                        if "scope_id" in repo_entry: # ID is actually EngagementDevice ID in this instance
                            scope_id = repo_entry['scope_id']

                        if sentry + ";" + str(scope_id) not in self.already_scanned:
                            targets.append(sentry)

                            # generate necessary folders for output path
                            output_path = None
                            only_yaml_file = yaml_file
                            if "tools/" in only_yaml_file:
                                if "(" in only_yaml_file:
                                    only_yaml_file = only_yaml_file[:only_yaml_file.find("(")]
                                if ".yaml" not in only_yaml_file:
                                    only_yaml_file = only_yaml_file + ".yaml"
                                config = yaml.load(open(self.db_object.base_path + "/" + only_yaml_file), Loader=yaml.SafeLoader)
                                output_path = self.db_object.engagement_path + config['output_path'] + str(datetime.now().timestamp()) + "/"

                                if "manual parser" not in config['tool_name'] and "scope" not in config['tool_name']:
                                    created = common.create_path(output_path) #common.makedirs(output_path)

                            self.output_folder = output_path
                            commands.append(self.generate_command(passed_command, scope_id, sentry, repo_entry, location_id,
                                                                  user_inputs, yaml_file))
            return targets, commands
        except Exception as e:
            print_text.print_error("tool nmap except: " + str(e) + " Error on line {}".format(sys.exc_info()[-1].tb_lineno))


    def port_scan(self, scan_type):
        """Run one scan type against all targets

        :param scan_type:
        :return:
        """
        self.setup_already_done_checks(" " + scan_type)
        targets, commands = self.setup_port_scan(scan_type)
        self.run_group(targets, commands, scan_type)

    def run_all_scans(self):
        """Function to run all nmap scans

        This function is unique to nmap to run all scans sequentially. The code
        builds on the Tool class's run_group function.
        """
        try:
            something_to_scan = False
            list_of_commands = []
            target_command_dictionary = {}
            targets = []
            commands = []
            for scan_type in self.NMAP_SCANS:
                if scan_type != "traditional-internal":
                    new_timestamp = datetime.datetime.now().timestamp()
                    self.output_folder = self.output_folder + "/" + str(self.timestamp) + "/"
                    # replace timestamp section with new timestamp per scan (otherwise you create zip-bombs - crazy zips within zips ...)
                    if "/nmap/" in self.output_folder:
                        self.output_folder = self.output_folder[:self.output_folder.rfind("/nmap/")+ 6]
                    self.output_folder = self.output_folder + str(new_timestamp)
                    common.makedirs(self.output_folder)

                    targets, commands = self.setup_port_scan(scan_type, commands, targets)

            self.run_chain_of_command_groups_setup(targets, commands, "nmap - all scans")

        except Exception as e:
            print_text.print_error("tool nmap except: " + str(e) + " Error on line {}".format(sys.exc_info()[-1].tb_lineno))
