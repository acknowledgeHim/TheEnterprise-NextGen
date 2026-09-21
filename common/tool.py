import sys
import os
import yaml
import errno
import hmac
import hashlib
import base64
from random import randint
from datetime import datetime
from ipaddress import IPv4Network

# Used to add parent path so can reference below stuff
sys.path.append(os.path.join(os.path.dirname(__file__), '..'))

from common import print_text, common, network
from common.jobs import tasks
from enterprise_user_conf import PENTEST_DIR


class Tool:
    def __init__(self, db_object, tool_path, tool, create_folder=True):
        """
        Make sure the tool_path exists, if not create it using os.makedirs() (recursively creates path)
        Grab Log entries by tool which is used to determine if already ran for each scope entry.
        Then grab profile rerun_tool setting, if True then rerun even if already done else don't rerun.
        """
        try:
            self.error = None
            self.already_scanned = None
            self.type = "Tool"
            self.name = tool
            self.background = False

            self.output_folder = tool_path
            self.db_object = db_object
            self.tool = tool
            self.timestamp = datetime.now().timestamp()

            self.tool_name = self.tool

            # Check if target already run / still running for current tool
            if "tool/" in self.tool and self.confg is None:
                yaml_file = self.tool
                if "(" in yaml_file:
                    yaml_file = yaml_file[:yaml_file.find("(")]
                self.config = yaml.load(open(self.db_object.base_path + "/" + yaml_file + ".yaml"), Loader=yaml.SafeLoader)
                self.tool_name = self.config['tool_name']

            # Engagement value specifying if should re-run tools
            self.rerun_tool = self.db_object.rerun_tool()

            # Check location to test setting to possible limit scope entries to just the location specified or all
            self.testing_location = self.db_object.grab_current_location()
            if self.testing_location == "all_locations":
                self.testing_location = None

        except Exception as e:
            print_text.print_error("common.tool except: " + str(e) + " Error on line {}".format(sys.exc_info()[-1].tb_lineno))

        return

    def extract_still_running_targets_for_tool(self):
        """ Gets, from Log, all targets that are still running for current tool.
        :return: list of dictionaries
        """
        still_running_targets = []
        additional_column_filter = ["source"]
        additional_column_value = [self.tool]
        tool_still_running_for_targets = self.db_object.log_not_finished(additional_column_filter, additional_column_value)
        if tool_still_running_for_targets is not None:
            for tsrft in tool_still_running_for_targets:
                still_running_targets.append(tsrft['target'])
        return still_running_targets

    def setup_already_done_checks(self, yaml_file=None):
        # Find log entries for target + tool that have been marked to not re-test
        try:
            # Find all log entries for current tool (mean already ran or still running)
            source = self.tool
            if yaml_file is not None:
                source = yaml_file

            already_run_scope_entries = self.db_object.log_by_source(source)
            self.already_scanned = []
            if not self.rerun_tool:
                for scan in already_run_scope_entries:
                    target = scan['target']
                    if (scan['finished'] and not scan['allow_rerun']) or scan['running'] or scan['queued'] and not scan['failed']:
                        if target + ";" + str(scan['scope_id']) not in self.already_scanned:
                            self.already_scanned.append(target + ";" + str(scan['scope_id']))

        except Exception as e:
            print_text.print_error("common.tool except: " + str(e) + " Error on line {}".format(sys.exc_info()[-1].tb_lineno))

    def run_group(self, targets, commands, descriptors, completed_function=None, output_folders=None):
        """Run command against multiple targets

        Builds all commands and sends it on to Celery to create
        a group primitive.

        :param targets: list of scope_ips
        :param commands: list where [0] is the command to run with <TARGET> for replacements
            [0] = command
            [1] = scope_id
            [2] = location_id
            [3] = source
            [4] = output path
        """
        try:
            if len(targets) == 0:
                msg = "No targets found in your scope (or the ones there have already been run against this tool and you have designated to not rerun tools)!"
                print_text.print_error("\t" + msg)
                return msg

            hashval_commands = {}
            for i, target in enumerate(targets):
                try:
                    source = commands[i][3]
                except:
                    source = "scope upload"
                    #source = self.name
                try:
                    output_path = commands[i][4]
                except:
                    output_path = None

                start_time = datetime.now()

                comment = "Job added to the queue."
                values = dict(target=target, start_time=start_time, source=source, scope_id=commands[i][1],
                              comment=comment, running=False, queued=True, output_filepath=output_path,
                              command=commands[i][0])
                added, hashval = self.db_object.add("Log", values)
                hashval_commands[hashval] = commands[i][0]

                # write to tool.log in output path
                if "output/" in self.output_folder:
                    base_output_path = self.output_folder[:self.output_folder.find("output/") + 7:]
                    common.create_path(base_output_path)

                    update_permissions = False
                    if not os.path.isfile(base_output_path + "tool.log"):
                        update_permissions = True

                    with open(base_output_path + "tool.log", "a") as tool_log_file:
                        tool_log_file.write(start_time.strftime("%Y-%m-%d %H:%M:%S.%f") + "\t" + source + "\t" + str(commands[i][1]) + "\t" + target.replace("\n", " ") + "\t" + comment + "\n")
                    if update_permissions:
                        common.assign_permissions(base_output_path + "tool.log")
            print("147 common/tool.py hashval_commands: " + str(hashval_commands))
            tasks.run_command_group(hashval_commands, self.db_object.sqlite_file, self.db_object.key, descriptors, completed_function)

        except Exception as e:
            print_text.print_error("tool except: " + str(e) + " Error on line {}".format(sys.exc_info()[-1].tb_lineno))

    def run_chain_of_command_groups_setup(self, targets, commands, descriptors, group_by='target'):
        """
        Convert run_group commands which run all at same time to chain of command groups which only 1 runs
        and when finished then next starts.
        """
        try:
            target_command_dictionary = {}
            already_done = []
            for count, target in enumerate(targets):
                tool = self.tool_name
                if commands[count][0] not in already_done:
                    start_time = datetime.now()
                    values = dict(hashval="", target=target, start_time=start_time, source=commands[count][3],
                                  output_filepath=commands[count][4], scope_id=commands[count][1],
                                  comment="Job added to the queue.", running=False, queued=True, command=commands[count][0])
                    success, hashval = self.db_object.add("Log", values)

                    if "(" in str(commands[count][3]) and ")" in str(commands[count][3]):
                        tool = str(commands[count][3])[str(commands[count][3]).find("(")+1:]
                        tool = tool[:tool.find(")")]

                    if success:
                        curr = []
                        # Grab any current entries
                        if group_by == "target" and target in target_command_dictionary:
                                curr = target_command_dictionary[target]
                        elif group_by == "tool" and tool in target_command_dictionary:
                                curr = target_command_dictionary[tool]

                        # add this entry
                        new_list = [hashval, commands[count][0], target]
                        curr.append(new_list)

                        if group_by == "target":
                            target_command_dictionary[target] = curr
                        elif group_by == "tool":
                            target_command_dictionary[tool] = curr

                    already_done.append(commands[count][0])

            if len(target_command_dictionary) > 0:
                print("194 tool.py target_command_dictionary: " + str(target_command_dictionary))
                self.run_chain_of_command_groups(target_command_dictionary, descriptors)
        except Exception as e:
            print_text.print_error("tool.py except: " + str(e) + " Error on line {}".format(sys.exc_info()[-1].tb_lineno))

    def run_chain_of_command_groups(self, command_list, descriptors, completed_function=None):
        """
        Run command against multiple targets but wait for proceeding to finish before continuing with next.
        Not in parrallel but serial.

        Builds all commands and sends it on to Celery to create
        a group primitive.

        :param targets: list of scope_ips
        :param commands: list where [0] is the command to run with <TARGET> for replacements
            [1] is the scope_id
        """
        try:
            if len(command_list) == 0:
                msg = "No targets to found in your scope (or the ones there have already been run against this tool and you have designated to not rerun tools)!"
                print_text.print_error("\t" + msg)
                return msg

            if "tools/" in self.tool and self.config is None:
                yaml_file = self.tool
                only_yaml_file = yaml_file
                if "(" in only_yaml_file:
                    only_yaml_file = only_yaml_file[:only_yaml_file.find("(")]
                if ".yaml" not in only_yaml_file:
                    only_yaml_file = only_yaml_file + ".yaml"
                config = yaml.load(open(self.db_object.base_path + "/" + only_yaml_file), Loader=yaml.SafeLoader)
                completed_function = config['tool_parser']
            if self.config is not None and 'tool_parser' in self.config:
                completed_function = self.config['tool_parser']

            tasks.chain_of_command_groups(command_list, self.db_object.sqlite_file, self.db_object.key, descriptors, completed_function) #self.completion_function)
        except Exception as e:
            print_text.print_error("tool except: " + str(e) + " Error on line {}".format(sys.exc_info()[-1].tb_lineno))

    def generate_command(self, passed_command, scope_id, sentry, repo_entry, location_id, user_inputs=None, yaml_file=None):
        # Replace PLACEHOLDER text with appropriate  values
        try:
            if passed_command is not None:
                # Global replacements
                c = passed_command

                port = "0"
                if "port" in repo_entry:
                    port = str(repo_entry['port'])
                if "http://" in sentry:
                    port = "80"
                if "https://" in sentry:
                    port = "443"
                if ("https://" in sentry or "http://" in sentry) and sentry.count(":") > 1:
                    port = sentry[sentry.rfind(":") + 1:]
                    if "/" in port:
                        port = port[:port.find("/")]
                # Host file being passed as entry
                host_file = sentry
                if "/" in sentry and ".txt" in sentry and "__s" in sentry:
                    port = sentry[sentry.rfind("/") + 1:]
                    port = port[:port.find("__")]
                    sentry = sentry[sentry.rfind("/") + 1:]
                    if "." in sentry:
                        sentry = sentry.replace(".", "")
                scope_info = self.db_object.view('Scope', ['original_entry'], ['id'], [scope_id])
                print("261 tool.py scope_id: " + str(scope_id))
                print("262 tool.py scope_info: " + str(scope_info))
                original_entry = scope_info[0]['original_entry']
                if "CLIENT_NAME" in c:
                    client_name = self.db_object.grab_column_from_single_record("Engagement", ['id'], [1], "client_name")
                    if "CLIENT_NAME_FORMATTED" in c:
                        c = c.replace("CLIENT_NAME_FORMATTED", client_name.replace(" ", "ZZZZZ"))
                    if "CLIENT_NAME" in c:
                        c = c.replace("CLIENT_NAME", client_name)
                if "SCOPE_ID" in c:
                    c = c.replace("SCOPE_ID", str(scope_id))
                if "FORMATTED_ENTRY" in c:
                    c = c.replace("FORMATTED_ENTRY", common.format_target(sentry))
                if "ORIGINAL_ENTRY" in c:
                    c = c.replace("ORIGINAL_ENTRY", original_entry)
                    print("279 common/tool.py c: " + str(c))
                if "CHECK_ENTRY" in c:
                    if "-" in repo_entry['original_entry']:
                        sentry = network.return_range_of_ips_from_cidr(repo_entry['entry'], True)
                        c = c.replace("CHECK_ENTRY", sentry)
                if "ENTRY_IP" in c:
                    just_ip = sentry
                    if "/" in just_ip:
                        just_ip = just_ip[:just_ip.find("/")]
                    if network.valid_ip(just_ip):
                        c = c.replace("ENTRY_IP", just_ip)
                if "ENTRY_IP_MASK" in c and "/" in sentry:
                    mask = str(IPv4Network(sentry).netmask)
                    c = c.replace("ENTRY_IP_MASK", mask)
                if "ENTRY" in c:
                    c = c.replace("ENTRY", sentry)
                if "PORT" in c:
                    c = c.replace("PORT", port)
                if "OUTPUT_FOLDER" in c:
                    c = c.replace("OUTPUT_FOLDER", self.output_folder)
                if "FORMATTED_WEBSITE" in c:
                    c = c.replace("FORMATTED_WEBSITE", common.format_website(sentry))
                if "ENGAGEMENT_PATH" in c:
                    c = c.replace("ENGAGEMENT_PATH", self.db_object.engagement_path)
                if "PROTOCOL" in c:
                    protocol = 'http'
                    if "https://" in sentry:
                        protocol = "https"
                    c = c.replace("PROTOCOL", protocol)
                if "SSL" in c:
                    ssl = ""
                    if "https://" in sentry:
                        ssl = "-ssl"
                    c = c.replace("SSL", ssl)
                if "CODE_BASE_PATH" in c:
                    basepath = os.path.dirname(os.path.realpath(__file__))
                    basepath = basepath[:basepath.rfind("enterprise/") + 11]
                    c = c.replace("CODE_BASE_PATH",  basepath)
                if "RDP_HOST_FILE" in c:
                    c = c.replace("RDP_HOST_FILE", self.db_object.engagement_path + "/hosts/" + str(port).strip() + "__s" + str(scope_id) + ".txt")
                if "VNC_HOST_FILE" in c:
                    c = c.replace("VNC_HOST_FILE", self.db_object.engagement_path + "/hosts/" + str(port).strip() + "__s" + str(scope_id) + ".txt")
                if "WEB_HOST_FILE" in c:
                    c = c.replace("WEB_HOST_FILE", self.db_object.engagement_path + "/hosts/" + str(port).strip() + "__s" + str(scope_id) + ".txt")
                if "SMB_SIGNING_DISABLED_FILE" in c:
                    c = c.replace("SMB_SIGNING_DISABLED_FILE", self.db_object.engagement_path + "/hosts/devices_smb_signing_disabled" + "__s" + str(scope_id) + ".txt")
                if "HOST_FILE" in c:
                    c = c.replace("HOST_FILE", host_file)
                if "$PENTEST_DIR$" in c:
                    c = c.replace("$PENTEST_DIR$", PENTEST_DIR)

                # User inputted replacements
                if user_inputs is not None:
                    for key, user_input in user_inputs.items():
                        if "<" + key + ">" in c:
                            c = c.replace("<" + key +">", str(user_input))
            else:
                c = self.output_folder + ";" + sentry

            return[c, scope_id, location_id, yaml_file, self.output_folder]
        except Exception as e:
            print_text.print_error("tool.py except: " + str(e) + " Error on line {}".format(sys.exc_info()[-1].tb_lineno))

    def get_targets_cmd(self, passed_command=None, insert_sleep=False, targets=[], commands=[], check_already_done=True, user_inputs=None, yaml_file=None):
        """
        Create the
        :param passed_command:
        :return:
        """
        try:
            if self.already_scanned is None:
                self.already_scanned = []

            if check_already_done:
                self.setup_already_done_checks(yaml_file)

            if self.repo_entries is not None:
                for count, repo_entry in enumerate(self.repo_entries):
                    sentry = repo_entry['entry']
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
                                output_path = self.db_object.engagement_path + config['output_path'] + str(
                                    datetime.now().timestamp()) + "/"

                                if "manual parser" not in config['tool_name'] and "scope" not in config['tool_name']:
                                    created = common.create_path(output_path) #common.makedirs(output_path)

                            self.output_folder = output_path
                            commands.append(self.generate_command(passed_command, scope_id, sentry, repo_entry, location_id,
                                                                  user_inputs, yaml_file))

                            if insert_sleep and count + 1 < len(self.repo_entries):
                                # If must do a 'sleep' call between each lookup so that we don't get blocked
                                random_number = randint(300, 1150)
                                # If a lot of entries then need to increase the sleep time
                                if count > 4:
                                    random_number = random_number * count * randint(1, 3)
                                commands.append(["sleep " + str(random_number) + "s", repo_entry['id'], repo_entry['location_id'], yaml_file, None])
                                targets.append("sleep_after_for_" + sentry)
                                self.field_values_list.append({})

            if len(targets) == 0 and len(self.already_scanned) > 0:
                self.error = "You've already scanned all IPs in the scope and you have specified to not re-run any tools."
                print_text.print_error("\t" + self.error)

            return targets, commands
        except Exception as e:
            self.error = str(e)
            print_text.print_error("tool.py except: " + str(e) + " Error on line {}".format(sys.exc_info()[-1].tb_lineno))

    def reformat_entries(self, passed_entries):
        """
        Loops thru entries and puts in dictionary where key is scope_id + ":" + port and value is list of entries
        :param entries:
        :return:
        """
        try:
            for entry in passed_entries:
                cur_location = entry['location_id']
                port = str(entry['port']).strip()
                scope_id = str(entry['scope_id'])
                ip = entry['ip']
                if (self.testing_location is None or str(self.testing_location) == str(cur_location)) and \
                                                        ip + port + ":" + scope_id not in self.already_scanned:
                    self.already_done.append(ip + ":" + port + ":" + scope_id)
                    entry['id'] = scope_id
                    entry['entry'] = ip

                    if scope_id + ":" + port in self.entries:
                        self.entries[scope_id + ":" + port] = self.entries[scope_id + ":" + port] + [entry]
                    else:
                        self.entries[scope_id + ":" + port] = [entry]
        except Exception as e:
            self.error = str(e)
            print_text.print_error("tool.py except: " + str(e) + " Error on line {}".format(sys.exc_info()[-1].tb_lineno))

    def setup_grouped_targets_by_scope_and_port(self, regex_description, regex_port, protocol, passed_entries=None,
                                                yaml_file=None):
        """
        Combines device ports based on scope_id and port so that they are run as one entry;
        Commands are self.output_folder;hosts/PORT_sSCOPE_ID.txt (ex. /usr/local/clients/0_I/0/output/;hosts/80__s3.txt)
        :param regex_description:
        :param regex_port:
        :param protocol:
        :return:
        """
        try:
            # grab running, queued or completed logs from this tool to make sure not duplicating targets
            if self.check_already_run:
                self.setup_already_done_checks()

            self.format_port_entries(passed_entries, regex_description, regex_port, protocol)

            base_file_path = self.create_host_path()

            # now come up with the targets / commands
            commands = []
            targets = []
            already_added = []
            for key, entries in self.entries.items():
                scope_id = key[:key.find(":")]
                target_string, host_filename = self.create_host_file(base_file_path, key, already_added, entries)
                port = str(entries[0]['port']).strip()

                # add IP to targets
                if target_string != "":
                    # generate necessary folders for output path
                    output_path = None
                    only_yaml_file = yaml_file
                    if "tools/" in only_yaml_file:
                        if "(" in only_yaml_file:
                            only_yaml_file = only_yaml_file[:only_yaml_file.find("(")]
                        if ".yaml" not in only_yaml_file:
                            only_yaml_file = only_yaml_file + ".yaml"
                        config = yaml.load(open(self.db_object.base_path + "/" + only_yaml_file), Loader=yaml.SafeLoader)
                        output_path = self.db_object.engagement_path + config['output_path'] + str(
                            datetime.now().timestamp()) + "/"
                        if "manual parser" not in config['tool_name'] and "scope" not in config['tool_name']:
                            created = common.create_path(output_path) #common.makedirs(output_path)

                    location_id = str(self.db_object.grab_column_from_single_record("Scope", ["id"], [scope_id], "location_id"))

                    targets.append(host_filename)
                    commands.append([self.output_folder + ";" + base_file_path.strip() + port + "__s" + scope_id + ".txt--" + target_string, scope_id, str(location_id), yaml_file, output_path])

            if len(targets) == 0 and len(self.already_scanned) > 0:
                self.error = "You've already scanned all applicable records and you have specified to not re-run any tools."
                print_text.print_error("\t" + self.error)

            return targets, commands
        except Exception as e:
            self.error = str(e)
            print_text.print_error("tool.py except: " + str(e) + " Error on line {}".format(sys.exc_info()[-1].tb_lineno))

    def format_port_entries(self, passed_entries, regex_description, regex_port, protocol):
        # get all found servers (from DevicePort table) and setup self.entries
        description_entries = None
        port_entries = None
        if regex_description is not None and protocol is not None:
            if protocol == "both":
                tcp_entries = self.db_object.portscan_filter_by_description(regex_description, "tcp")
                udp_entries = self.db_object.portscan_filter_by_description(regex_description, "udp")
                description_entries = {}
                description_entries.append(tcp_entries)
                description_entries.append(udp_entries)
            else:
                description_entries = self.db_object.portscan_filter_by_description(regex_description, protocol)
        if regex_port is not None and protocol is not None:
            if protocol == "both":
                tcp_entries = self.db_object.portscan_filter_by_port(regex_port, "tcp")
                udp_entries = self.db_object.portscan_filter_by_port(regex_port, "udp")
                port_entries = {}
                port_entries.append(tcp_entries)
                port_entries.append(udp_entries)
            else:
                port_entries = self.db_object.portscan_filter_by_port(regex_port, protocol)

        # put entries into self.entries dictionary where key is the scope_id + : + port
        self.already_done = []
        self.entries = {}
        if description_entries is not None:
            self.reformat_entries(description_entries)

        if port_entries is not None:
            self.reformat_entries(port_entries)

        if passed_entries is not None:
            self.reformat_entries(passed_entries)

    def create_host_path(self):
        # Calculate path and create directory for all host files to be stored
        base_file_path = self.db_object.sqlite_file
        if ".out" in base_file_path:
            base_file_path = base_file_path[:base_file_path.rfind("/") + 1] + "hosts/"
        base_file_path = base_file_path.rstrip(" ").rstrip("'").lstrip("'")
        if not os.path.isdir(base_file_path):
            created = common.create_path(base_file_path)
            #common.makedirs(base_file_path)

        return base_file_path.strip()

    def create_host_file(self, base_file_path, key, already_added, entries, special_file_name=None):
        """ Write the hosts file. """
        try:
            scope_id = str(key)
            if ":" in scope_id:
                scope_id = scope_id[:scope_id.find(":")]
            target_string = ""
            targets_newline = ""
            port = ""
            for entry in entries:
                port = str(entry['port'])
                port = port.replace(" ", "")
                if target_string == "":
                    sep = ""
                    line_sep = ""
                else:
                    sep = ","
                    line_sep = "\n"

                if 'ip' in entry:
                    ip = entry['ip']
                elif 'entry' in entry:
                    ip = entry['entry']

                found = False
                if not self.rerun_tool:
                    for already in self.already_scanned:
                        if ip + ":" + port in already and scope_id in already:
                            found = True
                if not found and ip + ":" + port not in already_added:
                    already_added.append(ip + ":" + port)
                    target_string = target_string + sep + ip + ":" + port
                    targets_newline = targets_newline + line_sep + ip

            # add IP to targets
            host_file_name = None
            if target_string != "":
                # First generate hosts file for this set of port + scope_id
                host_file_name = base_file_path + port + "__s" + str(scope_id) + ".txt"
                if special_file_name is not None:
                    host_file_name = base_file_path + special_file_name + "__s" + str(scope_id) + ".txt"
                with open(host_file_name, "w") as target_file:
                    target_file.write(targets_newline)

            return target_string, host_file_name
        except Exception as e:
            print_text.print_error("tool.py except: " + str(e) + " Error on line {}".format(sys.exc_info()[-1].tb_lineno))

