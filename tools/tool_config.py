import sys
import os
import json
import re
import glob
import yaml
import importlib
from common import print_text, keep_tags, common
import enterprise_user_conf
from common.tool import Tool
from common.manual import Entry
from common.selection import Selection

class ToolConfig(Tool):
    #loop through domain entries from scope
    #loop through nmap scan types
    #check Log table to see if already run and completed, still running, etc
    #for ones that have not already completed (unless user wants to redo scan) and not still running, kick off command

    def __init__(self, db_object, full_client_engagement_path, yaml_file):
        try:
            self.msg = ""
            self.error = ""

            self.full_client_engagement_path = full_client_engagement_path
            self.db_object = db_object
            self.already_gotten_field_values = {}

            self.field_values_list = []

            if ".yaml" not in yaml_file:
                yaml_file = yaml_file + ".yaml"
            self.yaml_file = yaml_file
            self.repo_entries = None
            self.regex_port = None
            self.regex_description = None
            self.protocol = "tcp"
            self.base_command = None
            self.function_to_call = ""
            self.questions = None
            self.selections = None
            self.create_folder = True
            self.check_already_run = True
            self.simultaneous = True
            self.parser = "manual"
            self.sleep_between_targets = False
            self.answers = None
            self.replacements = None
            self.global_fields = None

            self.location_id = self.db_object.grab_current_location()
            if self.location_id == "all":
                self.location_id = None

            # Load Yaml Config
            self.already_asked_for_input = {}
            self.yaml_config_file = db_object.base_path + "/" + yaml_file
            self.config = yaml.load(open(self.yaml_config_file), Loader=yaml.SafeLoader)
            self.yaml_configs = None
            self.callable = False
            if "callable_yaml" in self.config:
                self.callable = True

        except Exception as e:
            print_text.print_error("tool config except: " + str(e) + " Error on line {}".format(sys.exc_info()[-1].tb_lineno))
        return

    def __enter__(self):
        return self

    def __exit__(self, type, value, traceback):
        return self

    def load_config_values(self, config=None):
        try:
            if config is None:
                config = self.config
            self.tool = config['tool_name']
            self.output_path = config['output_path']
            if "create_data_folder" in config and config['create_data_folder'] is not None:
                create_folder = self.db_object.engagement_path + self.output_path+ "/" + self.config['create_data_folder']
                common.create_path(create_folder)
                common.assign_permissions(create_folder)
            if "simultaneous" in config:
                self.simultaneous = config['simultaneous']
            if "function_to_call" in config:
                self.function_to_call = config['function_to_call']
            elif "command" in config:
                self.base_command = config['command']
            if "questions" in config:
                self.questions = config['questions']
            if "selections" in config:
                self.selections = config['selections']
            if "check_already_run" in config:
                self.check_already_run = config['check_already_run']
            if "create_folder" in config:
                self.create_folder = config['create_folder']
            if "tool_parser" in config:
                self.parser = config['tool_parser']
            if "sleep_between_targets" in config:
                self.sleep_between_targets = config['sleep_between_targets']
            self.target_by_host_file = False
            if "target_by_host_file" in config:
                self.target_by_host_file = config['target_by_host_file']

            self.special_to_replace = None

            self.output_folder = self.full_client_engagement_path + self.output_path

            Tool.__init__(self, self.db_object, self.output_folder, self.yaml_file + "(" + self.tool + ")")

            # Get targets from YAML
            targets = config['targets']
            self.use_original_scope_entry = False
            if 'use_original_scope_entry' in targets:
                self.use_original_scope_entry = targets['use_original_scope_entry']
            if "target" in targets and targets['target'] != "":
                pass
                # individual target passed, need to find its scope, and location
            if "scope" in targets and targets['scope'] != "":
                target = targets['scope']
                if target == "SCOPE_IPS":
                    self.repo_entries = self.db_object.grab_ips()   #self.db_object.scope_ips()
                elif target == "FORCE_SCOPE_IPS": # not allow live hosts results instead
                    self.repo_entries = self.db_object.scope_ips()
                elif target == "SINGLE_SCOPE_IP":
                    te = self.db_object.scope_ips()
                    if len(te) > 0:
                        self.repo_entries = [te[0]]
                elif target == "ALL_DOMAINS":
                    scope_domains = self.db_object.scope_domains()
                    recon_domains = self.db_object.recon_domains()
                    if scope_domains is not None and recon_domains is not None:
                        self.repo_entries =  scope_domains + recon_domains
                    elif scope_domains is not None:
                        self.repo_entries = scope_domains
                    elif recon_domains is not None:
                        self.repo_entries = recon_domains
                    else:
                        self.repo_entries = None
                elif target == "SCOPE_DOMAINS":
                    self.repo_entries = self.db_object.scope_domains()
                elif target == "SINGLE_SCOPE_DOMAIN": #just grabs 1st domain pulled back
                    te = self.db_object.scope_domains()
                    if len(te) > 0:
                        self.repo_entries = [te[0]]
                elif target == "SCOPE_WEBSITES":
                    self.repo_entries = self.db_object.scope_websites()
                elif target == "ALL_WEBSITES":
                    self.repo_entries = self.db_object.all_websites()
                elif target == "SCOPE_IPS+SCOPE_WEBSITES":
                    self.repo_entries = self.db_object.grab_ips() + self.db_object.scope_websites()
                elif target =="SCOPE_IPS+SCOPE_WEBSITES_AS_DOMAIN": #for nessus
                    websites = self.db_object.scope_websites()
                    domains = []
                    for w in websites:
                        print("150 tool_config w: " + str(w))
                        #domains.append()
                    self.repo_entries = self.db_object.grab_ips() + domains
                elif target == "SCOPE_IPS+SCOPE_DOMAINS":
                    self.repo_entries = self.db_object.grab_ips() + self.db_object.scope_domains()
                elif target == "ASN":
                    self.repo_entries = self.db_object.asn_records()
                elif target == "CLIENTNAME":
                    entry = self.db_object.view("Engagement", ['client_name'])
                    te = self.db_object.scope_domains()
                    if len(te) > 0:
                        te[0]['entry'] = entry[0]['client_name']
                        self.repo_entries = [te[0]]
                elif target == "ALL":
                    self.repo_entries = self.db_object.scope_all()
            elif "special" in targets:
                special = targets['special']
                if "<" in special and ">" in special:
                    special = special.replace("<", "").replace(">", "")
                    self.special_to_replace = special
                else:
                    special_function = getattr(self.db_object, targets['special'])
                    self.repo_entries = special_function()
            if "port_numbers" in targets and targets['port_numbers'] != "":
                if "," in targets['port_numbers']:
                    self.regex_port = str(targets['port_numbers']).replace(",", "|")
                else:
                    self.regex_port = str(targets['port_numbers'])
                self.protocol = "tcp"
                if "protocol" in targets:
                    self.protocol = targets['protocol']
            if "port_descriptions" in targets and targets['port_descriptions'] != "":
                if "," in targets['port_descriptions']:
                    self.regex_description = re.compile(targets['port_descriptions'].replace(",", "|"))
                else:
                    self.regex_description = re.compile(targets['port_descriptions'])
                self.protocol = "tcp"
                if "protocol" in targets:
                    self.protocol = targets['protocol']
        except Exception as e:
            print_text.print_error("tool_config.py except: " + str(e) + " Error on line {}".format(sys.exc_info()[-1].tb_lineno))

    def replace_placeholders(self, c):
        """ Place holders in question not user-inputted answer. """
        if "CLIENT_NAME" in c:
            client_name = self.db_object.grab_column_from_single_record("Engagement", ['id'], [1], "client_name")
            if "CLIENT_NAME_FORMATTED" in c:
                c = c.replace("CLIENT_NAME_FORMATTED", client_name.replace(" ", "ZZZZZ"))
            if "CLIENT_NAME" in c:
                c = c.replace("CLIENT_NAME", client_name)
        return c

    def manual_selection(self):
        """ Selections that need user input. """
        returns = {}
        try:
            for sel in self.selections:
                if sel['table'].lower() + "_" + sel['return_field'] not in self.already_gotten_field_values:
                    if "table" in sel and "display_fields" in sel and "return_field" in sel:
                        filter_key = None
                        filter_value = None
                        display_fields = sel['display_fields']
                        if "filter" in sel:
                            if sel['filter'] == "CURRENT_LOCATION" and self.location_id is not None:
                                if sel['table'] == "DevicePort":
                                    display_fields.append("EngagementDevice.Scope.Location.name")
                                filter_key = ["location_id"]
                                filter_value = [self.location_id]
                            else:
                                filter_key = []
                                filter_value = []
                                print_text.print_error("157 tool_config sel['filter']: " + str(sel['filter']))
                                filter_dictionary = sel['filter']
                                if not isinstance(filter_dictionary, dict):
                                    filter_dictionary = json.loads(sel['filter'])
                                for key, value in filter_dictionary.items():
                                    filter_key.append(key)
                                    filter_value.append(value)
                        names = self.db_object.dictionary_list_multiple_fields(sel['table'], display_fields, filter_key, filter_value)
                        return_values = self.db_object.dictionary_list(sel['table'], sel['return_field'], filter_key, filter_value)
                        count_numbers = list(range(1, len(return_values)+1))

                        name = sel['table'].lower() + "_" + sel['return_field']
                        if "name" in sel:
                            name = sel['name']

                        if len(names) > 0:
                            if len(names) == 1:
                                returns[name] = (return_values[0])
                                print_text.print_msg("Only 1 " + sel['table'] + ", " + names[0] + ", in the Repo so it was auto selected.")
                            else:
                                with Selection('Select the ' + sel['table'], names, None) as selection:
                                    selected_index = selection.select_option(count_numbers)
                                    returns[name] = return_values[selected_index-1]
                        else:
                            print_text.print_error("\tNo " + sel['table'] + " selected!")
        except Exception as e:
            print_text.print_error("tool_config.py except: " + str(e) + " Error on line {}".format(sys.exc_info()[-1].tb_lineno))
        return returns

    def manual_entry(self, webform=False):
        """ Questions need user input. """
        try:
            required_fields = []
            fields = []
            answers = {}
            replacements = {}
            field_values = None
            global_fields = {}
            for question in self.questions:
                additional_text = ""
                if "question" in question and "name" in question:
                    q = self.replace_placeholders(question['question'])

                    # Check if global variable part of yaml config (in enterprise_user_conf.py)
                    global_var = ""
                    if "global" in question and question["global"]:
                        if question['name'].lower() in self.config:
                            global_var = self.config[question['name'].lower()]
                            if "$PENTEST_DIR$" in str(global_var):
                                global_var = global_var.replace("$PENTEST_DIR$", enterprise_user_conf.PENTEST_DIR)
                            if "$DEFAULT_WORDLIST$" in str(global_var):
                                global_var = global_var.replace("$DEFAULT_WORDLIST$", enterprise_user_conf.DEFAULT_WORDLIST)
                        if global_var is None:
                            global_var = ""
                        if global_var == "":
                            try:
                                global_var = getattr(importlib.import_module('enterprise_user_conf'), question['name'].upper())
                            except Exception as e:
                                #print_text.print_error("tool config except: " + str(e) + " Error on line {}".format(sys.exc_info()[-1].tb_lineno))
                                pass

                    if global_var == "":
                        regex = ""
                        if "regex" in question and question['regex'] is not None:
                            regex = question['regex']
                            if "options" in question:
                                from common import network
                                interface_string, interface_regex, ip_address_string, ip_address_regex = network.grab_interfaces()
                                if question['options'] == "NETWORK_INTERFACE_NAME":
                                    regex = interface_regex
                                    additional_text = " (" +  interface_string + ")"
                                elif question['options'] == "NETWORK_IP_ADDRESS":
                                    regex = ip_address_regex
                                    additional_text = " (" + ip_address_string + ")"
                                regex = re.compile(regex)
                        elif "options" in question and question['options'] is not None:
                            from common import network
                            interface_string, interface_regex, ip_address_string, ip_address_regex = network.grab_interfaces()
                            if question['options'] == "NETWORK_INTERFACE_NAME":
                                regex = interface_regex
                                additional_text = " (" + interface_string + ")"
                            elif question['options'] == "NETWORK_IP_ADDRESS":
                                regex = ip_address_regex
                                additional_text = " (" + ip_address_string + ")"

                            regex = re.compile(regex)

                        # if not nullable make it required for user to enter
                        if "nullable" in question and not question['nullable']:
                            required_fields.append(question['name'])
                        elif "nullable" in question and question['nullable'] and webform:
                            # For Flask if can be nullable don't force regex javascript
                            regex = ""

                        # Add the user input question to list of questions to ask user
                        if question["name"] not in self.already_gotten_field_values:
                            fields.append([q + additional_text, question['name'], regex])
                    else:
                        global_fields[question['name']] = global_var

                    # Setup mapping to answer from user input
                    if "answers" in question:
                        answers[question['name']] = question['answers']

                    if "replacements" in question:
                        question_replacements = question['replacements']
                        # Used to replace user_inputted text not based on an answer
                        for key, value in question_replacements.items():
                            current_question = question['name']
                            if value is None:
                                value = ""
                            if key == "space":
                                real_key = " "
                            else:
                                real_key = key
                            if current_question in replacements:
                                replacements[current_question].append({real_key: value})
                            else:
                                replacements[current_question] = {real_key: value}
            print("344 tool_config global_fields: " + str(global_fields))
            print("345 tool_config replacements: " + str(replacements))
            print("346 tool_config question: " + str(question))
            # User input
            if not webform:
                with Entry("File Search", fields, required_fields) as me:
                    field_values = me.user_input_fields(input_text='Please enter')

                self.answers = answers
                self.replacements = replacements
                self.global_fields = global_fields
                return field_values

            return fields, answers, replacements, global_fields
        except Exception as e:
            print_text.print_error("tool config except: " + str(e) + " Error on line {}".format(sys.exc_info()[-1].tb_lineno))

    def replace_user_inputs(self, field_values, answers, replacements, global_fields):
        """
        Used to do replacements and necessary formatting after user inputted values.
        :param field_values:
        :param answers:
        :param replacements:
        :param global_fields:
        :return:
        """

        try:
            # Now add already_entered field_values
            if self.questions is not None:
                for question in self.questions:
                    if self.already_gotten_field_values is not None and question["name"] in self.already_gotten_field_values:
                        field_values[question['name']] = self.already_gotten_field_values[question["name"]]

            # Go through answers to convert user responses to what tool really needs
            if answers is not None and len(answers) > 0:
                for field_key, answer_dict in answers.items():
                    prepend = ""
                    append = ""
                    if "prepend_to_all" in answer_dict:
                        prepend = answer_dict['prepend_to_all']
                    if "append_to_all" in answer_dict:
                        append = answer_dict['append_to_all']

                    # each answer is a dictionary where key is the characters to replace and value is characters to replace with
                    if field_key in field_values:
                        field_value = field_values[field_key]
                        if field_value is None:
                            field_value = ""
                        if field_value in answer_dict:
                            answer_value = answer_dict[field_value]
                            if answer_value is None:
                                answer_value = ""
                                prepend = ""
                                append = ""
                            field_values[field_key] = prepend + str(answer_value) + append
                        if field_value == "" and "blank" in answer_dict:
                            blank = answer_dict['blank']
                            if blank is None:
                                blank = ""
                                prepend = ""
                                append = ""
                            field_values[field_key] = str(prepend) + str(blank) + str(append)
                        elif field_value == "" and "default" in answer_dict:
                            if answer_dict['default'] is None:
                                prepend = ""
                                append = ""
                            field_values[field_key] = prepend + str(answer_dict['default']) + append
                        elif field_values[field_key] != "":
                            pass
                        else:
                            field_values[field_key] = ""

            # Go through replacements to make any necessary changes
            if replacements is not None and len(replacements) > 0:
                # Go thru all replacements (outer dictionary where key is field name)
                for field_key, replacement_dict in replacements.items():
                    # each replacement is a dictionary where key is the characters to replace and value is characters to replace with
                    if field_key in field_values:
                        # Now loop through all possible replacements for that field value
                        field_value = field_values[field_key]
                        if field_value is not None:
                            for replacement_key, replacement_value in replacement_dict.items():
                                # Make sure that the replacement character is in the field_value
                                if replacement_key is not None and replacement_key in field_value:
                                    field_values[field_key] = field_value.replace(replacement_key, replacement_value)

            # concat global_fields with user inputted fields
            if global_fields is not None and len(global_fields) > 0:
                for key, value in global_fields.items():
                    prepend = ""
                    append = ""
                    if answers is not None and key in answers:
                        if "prepend_to_all" in answers[key]:
                            prepend = answers[key]['prepend_to_all']
                        if "append_to_all" in answers[key]:
                            append = answers[key]['append_to_all']
                    field_values[key] = prepend + str(value) + append

            if field_values is not None:
                # concats field_values to already_gotten_field_values
                self.already_gotten_field_values.update(field_values)

                # if target is actually an answer from user make that change here
                if self.special_to_replace is not None and self.special_to_replace in field_values:
                    scope_id = None
                    if "scope_entry" in field_values:
                        scope_id = field_values['scope_entry']
                    elif "scope_id" in field_values:
                        scope_id = field_values['scope_id']
                    if scope_id is not None: # make scope ID required
                        location_id = self.db_object.grab_column_from_single_record("Scope", ["id"], [scope_id], "location_id")
                        self.repo_entries = [{'id': scope_id, 'entry': field_values[self.special_to_replace], 'port': '0', 'scope_id': scope_id, 'location_id': location_id}]

            return field_values
        except Exception as e:
            print_text.print_error("tool config except: " + str(e) + " Error on line {}".format(sys.exc_info()[-1].tb_lineno))

    def setup(self):
        """
        Main function that Menu calls.  sets up
        """
        try:
            if self.callable:
                self.yaml_configs = self.config['callable_yaml']
                for yaml_config in self.yaml_configs:
                    # Now grab all the yaml files that match in callable_yaml
                    # 1st grab all user-input needed
                    for f in glob.glob(self.db_object.base_path + yaml_config + ".yaml"):
                        if ".yaml" in f and f != self.yaml_config_file:
                            self.config = yaml.load(open(f), Loader=yaml.SafeLoader)
                            if "tool_name" in self.config:
                                self.load_config_values()
                                self.need_user_input(self.config['tool_name'])
            else:
                self.load_config_values()
                self.need_user_input(self.config['tool_name'])

            msg = self.grab_targets_and_generate_commands()
            return msg

        except Exception as e:
            print_text.print_error("tool config except: " + str(e) + " Error on line {}".format(sys.exc_info()[-1].tb_lineno))

    def grab_targets_and_generate_commands(self, request=False, answers=None, replacements=None, global_fields=None):
        """
         Does actual pulling out info from yaml file to generate targets, commands, and descriptors
        """
        try:
            if self.callable:
                targets = []
                commands = []
                descriptors = []

                # First create self.field_values if flask passed data
                if request:
                    for yaml_config in self.yaml_configs:
                        for f in glob.glob(self.db_object.base_path + yaml_config + ".yaml"):
                            field_values = {}
                            if ".yaml" in f and f != self.yaml_config_file:
                                self.config = yaml.load(open(f), Loader=yaml.SafeLoader)
                                self.setup_field_values(request, field_values, answers, replacements, global_fields)
                count = 0
                for yaml_config in self.yaml_configs:
                    # now go through again to run with all user input now gather
                    for f in glob.glob(self.db_object.base_path + yaml_config + ".yaml"):
                        if ".yaml" in f and f != self.yaml_config_file:
                            self.config = yaml.load(open(f), Loader=yaml.SafeLoader)
                            if "tool_name" in self.config:
                                self.load_config_values()
                                function_to_call = None
                                if 'function_to_call' in self.config:
                                    function_to_call = self.config['function_to_call']
                                yaml_file = f
                                if yaml_file.find("tools/") > 0:
                                    yaml_file = yaml_file[yaml_file.find("tools/"):]

                                tmp_targets, tmp_commands, tmp_descriptors = self.run_tool(function_to_call, yaml_file + "(" + self.config['tool_name'] + ")", count)

                                targets = targets + tmp_targets
                                commands = commands + tmp_commands
                                descriptors = descriptors + tmp_descriptors
                        count += 1
            else:
                if request:
                    field_values = {}
                    self.setup_field_values(request, field_values, answers, replacements, global_fields)
                function_to_call = None
                if 'function_to_call' in self.config:
                    function_to_call = self.config['function_to_call']

                self.load_config_values()
                targets, commands, descriptors = self.run_tool(function_to_call, self.tool)

            # Now call the tool.py function to kick off the task
            if self.simultaneous:
                msg = self.run_group(targets, commands, descriptors, self.parser)
                if msg is None:
                    msg = ""
            else:
                if "group_by" in self.config:
                    msg = self.run_chain_of_command_groups_setup(targets, commands, descriptors, self.config['group_by'])
                else:
                    msg = self.run_chain_of_command_groups_setup(targets, commands, descriptors)
                if msg is None:
                    msg = ""
        except Exception as e:
            print_text.print_error("tool config except: " + str(e) + " Error on line {}".format(sys.exc_info()[-1].tb_lineno))
            return str(e)
        return msg

    def setup_field_values(self, request, field_values, answers, replacements, global_fields):
        """ Used by Flask version. """
        if "tool_name" in self.config:
            self.load_config_values()
            if self.questions is not None:
                for question in self.questions:
                    try:
                        current_value = keep_tags.clean_text(request.form[question['name']])
                        if current_value is not None:
                            current_value = current_value.strip()
                        if current_value.upper() == "N":
                            current_value = False
                        elif current_value.upper() == "Y":
                            current_value = True
                    except:
                        current_value = ''
                    field_values[question['name']] = current_value

            if self.selections is not None:
                for select in self.selections:
                    name = select['table'].lower() + "_id"
                    if "name" in select:
                        name = select['name']
                    try:
                        current_value = keep_tags.clean_text(
                            request.form[name])
                    except:
                        current_value = ''
                    field_values[name] = current_value

        if len(field_values) < 1:
            field_values = None
            self.field_values_list.append(field_values)
        else:
            self.field_values_list.append(self.replace_user_inputs(field_values, answers, replacements, global_fields))

    def need_user_input(self, tool_name):
        """ Get user input. Console version. """
        try:
            field_values = None
            if self.questions is not None or self.selections is not None:
                print_text.print_msg("Input(s) needed for " + str(tool_name))

            if self.questions is not None:
                field_values = self.manual_entry()

            selected_fields = None
            if self.selections is not None:
                selected_fields = self.manual_selection()

                # Now add already selected field_values
                for sel in self.selections:
                    if sel['table'].lower() + "_" + sel['return_field'] in self.already_gotten_field_values:
                        field_values[sel['table'].lower() + "_" + sel['return_field']] = self.already_gotten_field_values[sel['table'].lower() + "_" + sel['return_field']]

            if field_values is not None and selected_fields is not None:
                for key, value in selected_fields.items():
                    field_values[key] = value

            # do any replacements necessary here
            field_values = self.replace_user_inputs(field_values, self.answers, self.replacements, self.global_fields)

            self.field_values_list.append(field_values)
        except Exception as e:
            print_text.print_error("tool_config.py except: " + str(e) + " Error on line {}".format(sys.exc_info()[-1].tb_lineno))

    def run_tool(self, function_to_call, current_tool, count=0):
        """ Setup tool and push to the queue for celery. """
        try:
            targets = []
            commands = []
            descriptors = []

            # Make sure there was user input otherwise don't pass it
            field_values = None
            if len(self.field_values_list) > count:
                field_values = self.field_values_list[count]
            #print("627 tool_config field_values: " + str(field_values))

            # built-in feature
            if function_to_call is not None and "FUNCTION:" in function_to_call:
                if "function_pass_json" in self.config and self.config['function_pass_json'] and field_values is not None:
                    function_to_call = function_to_call + ":" + json.dumps(field_values)

                if self.regex_port is not None or self.regex_description is not None:
                    targets, commands = self.setup_grouped_targets_by_scope_and_port(self.regex_description,
                                                                     self.regex_port, self.protocol, None, current_tool)
                if self.repo_entries is not None:
                    targets, commands = self.get_targets_cmd(None, self.sleep_between_targets, targets,
                                         commands, self.check_already_run, field_values, current_tool)
            else:
                # external tool
                if self.regex_port is not None or self.regex_description is not None:
                    self.already_scanned = []
                    self.format_port_entries(None, self.regex_description, self.regex_port, self.protocol)
                    if isinstance(self.entries, dict) and len(self.entries) > 0:
                        # Create hosts path
                        base_file_path = self.create_host_path()
                        # create hosts files
                        already_added = []
                        if self.target_by_host_file:
                            if self.repo_entries is None:
                                self.repo_entries = []
                            for key, entries in self.entries.items():
                                target_string, host_filename = self.create_host_file(base_file_path, key, already_added, entries)
                                self.repo_entries.append({'id': entries[0]['scope_id'], 'entry': host_filename,
                                                          'scope_id': entries[0]['scope_id'],
                                                          'location_id': entries[0]['location_id']})
                        else:
                            if self.repo_entries is None:
                                self.repo_entries = []
                            for key, value in self.entries.items():
                                for v in value:
                                    self.repo_entries.append(v)
                    else:
                        no_targs_msg = "No targets to try or you've already run against all of them."
                        print_text.print_error("\t " + no_targs_msg)
                        if self.error is None:
                            self.error = ""
                        self.error = self.error + "<br>" + no_targs_msg
                        return targets, commands, descriptors
                elif self.target_by_host_file and self.repo_entries is not None and len(self.repo_entries) > 0:
                    # Create hosts path
                    base_file_path = self.create_host_path()

                    # setup filename if not entry__scope_id
                    special_file_name = None
                    if "special" in self.config['targets'] and "<" not in self.config['targets']['special']:
                        special_file_name = self.config['targets']['special']

                    # Group hosts by scope_id
                    already_added = []
                    entries_by_scope = {}
                    for entry in self.repo_entries:
                        if entry["scope_id"] in entries_by_scope:
                            tmp_list = entries_by_scope[entry["scope_id"]]
                            if tmp_list is not None:
                                entries_by_scope[entry["scope_id"]] = tmp_list.append(entry)
                        else:
                            entries_by_scope[entry["scope_id"]] = [entry]

                    # create hosts files
                    if self.repo_entries is None:
                        self.repo_entries = []
                    for scope_id, entries in entries_by_scope.items():
                        target_string, host_filename = self.create_host_file(base_file_path, str(scope_id), already_added, entries, special_file_name)
                        self.repo_entries.append({'id': entries[0]['scope_id'], 'entry': host_filename,
                                                  'scope_id': entries[0]['scope_id'],
                                                  'location_id': entries[0]['location_id']})

                        tmp_targets, tmp_commands = self.get_targets_cmd(self.base_command, self.sleep_between_targets,
                                                 targets, commands, self.check_already_run, field_values, current_tool)
                        if tmp_targets is not None:
                            targets = tmp_targets
                        if tmp_commands is not None:
                            commands = tmp_commands

                if len(targets) == 0 and self.repo_entries is not None and len(self.repo_entries) > 0:
                    targets, commands = self.get_targets_cmd(self.base_command, self.sleep_between_targets, targets,
                                         commands, self.check_already_run, field_values, current_tool)

            for t in targets:
                descriptors.append(function_to_call)

            # Reset repo_entries b/c otherwise compounds
            self.repo_entries = []

        except Exception as e:
            self.error = str(e)
            print_text.print_error("tool_config.py except: " + str(e) + " Error on line {}".format(sys.exc_info()[-1].tb_lineno))

        self.msg = self.msg + "<br>" + "Targets found and added for " + self.tool_name
        return targets, commands, descriptors