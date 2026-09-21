import html
import yaml
import datetime
import sys
import os
import json
import requests
import fnmatch
import importlib
from common import sqlalchemy_model
from common import send_email
from common import dns_functions
from common import common_merge
from common import scope_functions
from parsers import models_to_dictionary
from common import common, keep_tags, network, print_text, encryption

class Parser():
    """
    Setup up parsing.
    STILL NEED successful msf-bruteforce: ESX, Tomcat, POSTGRES, MySQL so can parse
    """

    def __init__(self, tool, db_object, key, hashvals, blacklist_check=True):
        try:
            self.tags = '' #html tags allowed
            self.modified_by = common.get_tester()
            self.modified_date = datetime.datetime.now()
            self.db_object = db_object
            self.key = key
            self.tool = db_object.grab_column_from_single_record("Log", ["hashval"], [hashvals[0]], "source")
            if "(" in self.tool:
                self.tool = self.tool[self.tool.rfind("(")+1:]
                self.tool = self.tool.replace(")", "").strip()
            self.location_id = None
            self.scope_id = None
            self.blacklist_check = blacklist_check

            self.output_dictionary = {}
            self.output_dictionary_list = [] #list of self.output_dictionary

            self.success = "Failed to upload and add results to repo."

            # grab value if allowed to auto send notifications
            self.auto_send_email = self.db_object.grab_column_from_single_record("Engagement", ["id"], [1],
                                                                       "can_send_auto_notification")
            self.files_for_parsing = self.parser_setup(hashvals)

        except Exception as e:
            print_text.print_error("\tparser except: " + str(e) + " Error on line {}".format(sys.exc_info()[-1].tb_lineno))

    def __enter__(self):
        return self

    def __exit__(self, type, value, traceback):
        self.parser_teardown()
        return self

    def parser_setup(self, hashvals):
        """
        Used to setup the parsing process.  Find the output files, etc.
        Output files should be in format output/tool/target__locationID
        :param db_object:
        :param hashvals:
        :param tool:
        :return:
        """
        try:
            files_for_parsing = []
            already_done_log_ids = []

            for hashval in hashvals:
                target_isa_file = False
                not_regular_output_path = False
                log_info = self.db_object.get("Log", ["hashval"], [hashval])

                if log_info is not None:
                    target = log_info['target']
                    full_target = target

                    target = common.format_target(target)

                    command = log_info['command']

                    output_path = log_info['output_filepath']
                    if output_path is not None:
                        yaml_file = log_info['source']

                        tool = yaml_file
                        if "tools/" in yaml_file:
                            if "(" in yaml_file:
                                yaml_file = yaml_file[:yaml_file.find("(")]
                            if ".yaml" not in yaml_file:
                                yaml_file = yaml_file + ".yaml"
                            config = yaml.safe_load(open(self.db_object.base_path + "/" + yaml_file))
                            tool = config['tool_name']

                        self.tool_no_space = common.format_tool(tool)
                        if ":" in self.tool_no_space:
                            self.tool_no_space = self.tool_no_space[:self.tool_no_space.find(":")]

                        if ";" in target:
                            target = target[target.find(";")+1:]
                            full_target = full_target.replace(";", "")

                        if os.path.isfile(output_path + target):
                            target_isa_file = True
                        elif os.path.isfile(full_target):
                            target_isa_file = True
                            not_regular_output_path = True

                        command_isa_file = False
                        if os.path.isfile(command):
                            command_isa_file = True

                        # Verify that this is a new to parse log entry (should be!)
                        if log_info is not None and log_info['id'] not in already_done_log_ids and output_path is not None and not log_info['failed']:
                            already_done_log_ids.append(log_info['id'])

                            if self.blacklist_check:
                                # Blacklist checking
                                scope_info = self.db_object.get("Scope", ["id"], [log_info['scope_id']])
                                open_ip = scope_info['open_ip']
                                open_port = scope_info['open_port']
                                comment = "Starting to parse " + self.tool + " results."
                                if open_ip is not None and open_ip != "" and open_port is not None and open_port != "":
                                    blacklisted = False
                                    print_text.print_msg("Blacklist checking ...")
                                    is_open = network.nc_verify(open_ip, open_port)
                                    if not is_open:
                                        blacklisted = True
                                        comment = "Staring to parse " + self.tool + " results, but these results are most likely not complete since it appears we've been blacklisted!"
                                else:
                                    blacklisted = None
                                    comment = "No blacklist check performed as that scope entry did not have a known open IP:Port. " + comment

                                update_values = dict(id=log_info['id'], blacklisted=blacklisted, comment=comment)
                                self.db_object.update("Log", update_values)

                            already_added_file = []
                            if not target_isa_file:
                                # Loop through all files in output_path that start with tool then scope_id then target
                                for root, dirs, files in os.walk(output_path):
                                    for filename in fnmatch.filter(files, "*__s" + str(log_info['scope_id']) + "__" + target + "*"):
                                        if ".7z" not in filename:
                                            if filename not in already_added_file:
                                                already_added_file.append(filename)
                                                files_for_parsing.append({'filename': root + filename, 'target': full_target,
                                                                          'log_id': log_info['id'], 'output_path': output_path,
                                                                          'scope_id': log_info['scope_id'], 'tool_name': True})
                                # Loop through all files in output_path that start with tool then log_id then target
                                if len(files_for_parsing) == 0:
                                    for root, dirs, files in os.walk(output_path):
                                        for filename in fnmatch.filter(files, "*__" + str(log_info['id']) + "__" + target + "*"):
                                            if ".7z" not in filename:
                                                if filename not in already_added_file:
                                                    already_added_file.append(filename)
                                                    files_for_parsing.append({'filename': root + filename, 'target': full_target,
                                                                          'log_id': log_info['id'], 'output_path': output_path,
                                                                          'scope_id': log_info['scope_id'], 'tool_name': True})
                                if len(files_for_parsing) == 0:
                                    # Loop through all files in output_path that start with tool then target
                                    for root, dirs, files in os.walk(output_path):
                                        for filename in fnmatch.filter(files, "*__" + target + "*"):
                                            if ".7z" not in filename:
                                                if filename not in already_added_file:
                                                    already_added_file.append(filename)
                                                    files_for_parsing.append(
                                                        {'filename': root + filename, 'target': full_target,
                                                         'log_id': log_info['id'], 'output_path': output_path,
                                                         'scope_id': log_info['scope_id'], 'tool_name': True})
                                if len(files_for_parsing) == 0:
                                    # Loop through all the files in the output_path that have LOG_ID in it
                                    for root, dirs, files in os.walk(output_path):
                                        for filename in fnmatch.filter(files, "*__" + str(log_info['id']) + "*"):
                                            if ".7z" not in filename:
                                                if filename not in already_added_file:
                                                    already_added_file.append(filename)
                                                    files_for_parsing.append(
                                                        {'filename': root + filename, 'target': full_target,
                                                         'log_id': log_info['id'], 'output_path': output_path,
                                                         'scope_id': log_info['scope_id'], 'tool_name': False})
                                if len(files_for_parsing) == 0:
                                    # Loop through all the files in the output_path that have sSCOPE_ID in it
                                    for root, dirs, files in os.walk(output_path):
                                        for filename in fnmatch.filter(files, "*__s" + str(log_info['scope_id']) + "*"):
                                            if ".7z" not in filename:
                                                if filename not in already_added_file:
                                                    already_added_file.append(filename)
                                                    files_for_parsing.append(
                                                        {'filename': root + filename, 'target': full_target,
                                                         'log_id': log_info['id'], 'output_path': output_path,
                                                         'scope_id': log_info['scope_id'], 'tool_name': False})
                                if len(files_for_parsing) == 0:
                                    # Loop through all the files in the output_path that start with the target
                                    for root, dirs, files in os.walk(output_path):
                                        for filename in fnmatch.filter(files, target + "*"):
                                            if ".7z" not in filename:
                                                if filename not in already_added_file:
                                                    already_added_file.append(filename)
                                                    files_for_parsing.append(
                                                        {'filename': root + filename, 'target': full_target,
                                                         'log_id': log_info['id'], 'output_path': output_path,
                                                         'scope_id': log_info['scope_id'], 'tool_name': False})
                                # As default just try all files in output_path
                                # Should not reach this point with proper naming convention
                                if len(files_for_parsing) == 0:
                                    for root, dirs, files in os.walk(output_path):
                                        for filename in files:
                                            if ".7z" not in filename:
                                                if filename not in already_added_file:
                                                    already_added_file.append(filename)
                                                    files_for_parsing.append({'filename': root + filename, 'target': full_target,
                                                                              'log_id': log_info['id'], 'output_path': output_path,
                                                                              'scope_id': log_info['scope_id'], 'tool_name': True})
                            elif target_isa_file and not command_isa_file:
                                # Default for tools where target is a host_file (list of targets)
                                for root, dirs, files in os.walk(output_path):
                                    for filename in fnmatch.filter(files, "*" + "__s" + str(log_info['scope_id'])):
                                        if ".7z" not in filename:
                                            if filename not in already_added_file:
                                                already_added_file.append(filename)
                                                files_for_parsing.append(
                                                    {'filename': root + filename, 'target': full_target,
                                                     'log_id': log_info['id'], 'output_path': output_path,
                                                     'scope_id': log_info['scope_id'], 'tool_name': False})
                                # As a backup grab all files in the output path
                                if len(files_for_parsing) == 0:
                                    for root, dirs, files in os.walk(output_path):
                                        for filename in files:
                                            if ".7z" not in filename:
                                                if filename not in already_added_file:
                                                    already_added_file.append(filename)
                                                    files_for_parsing.append(
                                                        {'filename': root + filename, 'target': full_target,
                                                         'log_id': log_info['id'], 'output_path': output_path,
                                                         'scope_id': log_info['scope_id'], 'tool_name': False})
                            else:
                                uncompressed_file = output_path + target
                                if not_regular_output_path:
                                    uncompressed_file = full_target
                                if ";" in target:
                                    uncompressed_file = target[target.find(";")+1:]
                                t_target = log_info['target']
                                if ":" in log_info['target']:
                                    t_target = t_target[:t_target.find(":")]
                                files_for_parsing.append({'filename': uncompressed_file, 'target': t_target,
                                                          'log_id': log_info['id'], 'output_path': output_path,
                                                          'scope_id': log_info['scope_id'],
                                                          'tool_name': None})

            return files_for_parsing
        except Exception as e:
            print_text.print_error("\tparser 103 except: " + str(e) + " Error on line {}".format(sys.exc_info()[-1].tb_lineno))

    def parse(self, class_path, class_name):
        """ Calls class necessary for parsing. Main function call! """
        try:
            for ffp in self.files_for_parsing:
                filename = ffp['filename']

                self.location_id = self.db_object.grab_column_from_single_record("Scope", ["id"], [ffp['scope_id']], "location_id")
                target = ffp['target']
                log_id = ffp['log_id']
                self.scope_id = ffp['scope_id']
                output_path = ffp['output_path']

                # Get all IPS of devices used during testing, to make sure not included in results
                self.list_of_tester_devices = self.db_object.tester_device_list(self.location_id)

                ext = filename[filename.rfind(".")+1:]
                just_filename = filename[filename.rfind("/")+1:]

                ParserClass = getattr(importlib.import_module(class_path), class_name)
                with ParserClass(self.db_object, self.location_id, self.scope_id, filename, ext, just_filename, target, log_id, output_path, self.list_of_tester_devices, self.modified_by, self.modified_date) as parser_class:
                    self.output_dictionary = parser_class.parse()

                if self.output_dictionary is not None:
                    self.output_dictionary_list.append(self.output_dictionary)

                    # Potentially New Scope Items (virtual websites)
                    if "scopes" in self.output_dictionary and self.output_dictionary["scopes"] is not None:
                        self.insert_scope(self.output_dictionary["scopes"], self.output_dictionary["scopes_fields_to_update"])

                    # Engagement Devices
                    if "devices" in self.output_dictionary and self.output_dictionary["devices"] is not None:
                        self.insert_engagementdevice_full(self.output_dictionary["devices"], self.output_dictionary["devices_fields_to_update"])

                        # Open Ports
                        if "ports" in self.output_dictionary and self.output_dictionary["ports"] is not None:
                            self.insert_deviceport(self.output_dictionary["ports"], self.output_dictionary["ports_fields_to_update"])

                        # Result
                        if "results" in self.output_dictionary and self.output_dictionary["results"] is not None:
                            self.insert_findingresults(self.output_dictionary["results"], self.output_dictionary["results_fields_to_update"])

                        # Credential
                        if "credential" in self.output_dictionary and self.output_dictionary['credential'] is not None:
                            self.insert_credential(self.output_dictionary['credential'], self.output_dictionary['credential_fields_to_update'])

                    # Recon
                    if "recon" in self.output_dictionary and self.output_dictionary["recon"] is not None:
                        self.insert_recon(self.output_dictionary["recon"], self.output_dictionary["recon_fields_to_update"])

                    # Person
                    if "person" in self.output_dictionary and self.output_dictionary["person"] is not None:
                        self.insert_person(self.output_dictionary["person"], self.output_dictionary["person_fields_to_update"])

                    # Phishing
                    if "phishing" in self.output_dictionary and self.output_dictionary['phishing'] is not None:
                        self.insert_phishing(self.output_dictionary['phishing'], self.output_dictionary['phishing_fields_to_update'])

                update_values = dict(id=log_id, comment="Finished parsing results and added to the repo.", parsed=True)
                self.db_object.update("Log", update_values)

        except Exception as e:
            print("parser 150 except: " + str(e) + " Error on line {}".format(sys.exc_info()[-1].tb_lineno))

    def parser_teardown(self):
        """
        Zip encrypt parsed files and remove unencrypted ones!
        :param files_for_parsing:
        :return:
        """
        try:
            # Create string of all filenames to zip-encrypt
            filenames = []
            for ffp in self.files_for_parsing:
                filenames.append(ffp['filename'])

            if len(self.files_for_parsing) > 0:
                output_path = self.files_for_parsing[0]['output_path']
                target = self.files_for_parsing[0]['target']
                target = common.format_target(target)
                tool_name = self.files_for_parsing[0]['tool_name']
                log_id = self.files_for_parsing[0]['log_id']
                original_filename = self.files_for_parsing[0]['target']

                if ";" in original_filename:
                    target = original_filename[original_filename.find(";") + 1:]
                    original_filename = original_filename[:original_filename.find(";")]

                if "7z__" not in original_filename and ".7z" not in original_filename:
                    original_filename = "7z__" + self.tool_no_space + "__" + str(log_id) + "__" + target + ".7z"
                    if tool_name is None:
                        original_filename = "7z__" +  target + ".7z"

                if "/" in original_filename:
                    original_filename = original_filename[original_filename.rfind("/") + 1:]

                # 7zip is SLOW and brings whole system to an almost standstill, so not doing that at this time!
                # Maybe just Option to 7z encrypt all output?
                # THIS IS WHERE WE ZIP-ENCRYPT the files
                #call = ['7z', 'u', '-p' + self.key, '-y', output_path + original_filename, output_path] + filenames
                #subprocess.check_output(call)

                # Validate the 7z file is not corrupt
                #validate = ['7z', 't', output_path + original_filename, '-p' + self.key, output_path] + filenames
                #subprocess.Popen(validate)

                #if self.tool == "email filter":
                #    call = ['7z', 'u', '-p' + self.key, '-y', output_path + "individual_emails/individual_emails.7z", output_path + 'individual_emails/*']
                #    subprocess.check_output(call)

                self.end_time = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S.%f")
                comment = 'Finished parsing output files.  '
                for ffp in self.files_for_parsing:
                    log_info = self.db_object.log_record_by_id(log_id)
                    current_comment = log_info['comment']
                    if current_comment is None:
                        current_comment = ""
                    update_values = dict(id=log_id, comment=comment + current_comment, parsed=True)
                    self.db_object.update("Log", update_values, ["id"], [log_id])

                    log_info = self.db_object.log_record_by_id(log_id)
                    # write to tool.log in output path
                    base_output_path = log_info['output_filepath']
                    base_output_path = base_output_path[:base_output_path.find("output/") + 7:]
                    common.create_path(base_output_path)
                    with open(base_output_path + "tool.log", "a") as tool_log_file:
                        tool_log_file.write(self.end_time + "\t" + log_info['source'] + "\t\t" + log_info['target'].replace("\n", " ") + "\t" + "Finished parsing." + "\n")

                    # Because no longer 7zip encrypting - TOO SLOW!!!
                    #filename = ffp['filename']
                    #try:
                    #    os.remove(filename)
                    #except Exception as e:
                    #    print_text.print_error("\t Failed to delete file: " + str(filename) + " after it was archived!")

                # Now send email
                if self.auto_send_email:
                    send_email.email_notification(self.db_object, self.key, self.tool, log_id, "end")

                # Not doing this for now as auto pushing takes resources from the-enterprise and would rather push later
                # to enable make this > 0
                if len(self.output_dictionary_list) == -1:
                    try:
                        # Push to Engage
                        # Push as JSON object to Engage the self.output_dictionary_list
                        engagement_number = self.db_object.grab_engagement_number()
                        engage_url = "https://10.0.10.198/engagement/sync_external_zanimat_data/" + str(engagement_number) + "/"
                        print("325 parser engage_url: " + str(engage_url))
                        data = {"data": self.output_dictionary_list}
                        print("326 parser data: " + str(data))
                        r = requests.post(engage_url, json=data, verify=False)
                        print(r.status_code)
                        print(r.json())
                    except Exception as e:
                        print_text.print_error("parser except: " + str(e) + " Error on line {}".format(sys.exc_info()[-1].tb_lineno))

                # write to tool.log in output path
                log_info = self.db_object.get("Log", ["id"], [log_id])
                output_filepath = log_info['output_filepath']
                base_output_path = output_filepath[:output_filepath.find("output/") + 7:]
                with open(base_output_path + "tool.log", "a") as tool_log_file:
                    tool_log_file.write(self.end_time + "\t" + log_info['source'] + "\t" + str(log_info['scope_id']) + "\t" +
                                    target.replace("\n", " ") + "\t" + comment.replace("\n", " ") + "\n")

            # Delete any log files for current tool that were "sleep_after_" commands
            self.db_object.delete_where("Log", ["source", "target"], [self.tool, "sleep_after_"], False)

        except Exception as e:
            print_text.print_error("parser except: " + str(e) + " Error on line {}".format(sys.exc_info()[-1].tb_lineno))
            print_text.print_error("Your output files at: " + str(output_path) + " might not have been zip encrypted and/or deleted the unencrypted files.  Please verify!")

    def remove_extra_spaces(self, text):
        """
        Used to remove extra spaces and tabs.
        :param text:
        :return:
        """
        if "\t" in text:
            text = text.replace("\t", " ")
        while "  " in text:
            text = text.replace("  ", " ")
        return text

    def get_xml_tag_text(self, elements, tag):
        """ Used to extract tag from current xml element. """
        tag_text = None
        try:
            tags = list(elements.iter(tag))
            for tg in tags:
                tag_text = tg.text
                if tag_text is not None and tag_text != "":
                    tag_text = keep_tags.keeptags_repeat(tag_text, self.tags)
                    break
        except Exception as e:
            print_text.print_error("Parser.py 401 except: " + str(e) + " Error on line {}".format(sys.exc_info()[-1].tb_lineno))
        return tag_text

    def remove_tagtext_junk(self, tag_text):
        """ Used to remove burp junk. """
        try:
            if tag_text is not None:
                tag_text = tag_text.replace("<![CDATA[", "").replace("]]>", "")
                tag_text = html.unescape(tag_text)
        except Exception as e:
            print_text.print_error("Parser.py 411 except: " + str(e) + " Error on line {}".format(sys.exc_info()[-1].tb_lineno))
        return tag_text

    def convert_list_to_field_values(self, db_table_name, fields_to_update, header_fields, result_list):
        """
        Converts list of data into necessary list of dictionaries.
        Returns a list of dictionaries.
        :param header_fields: list of the field names
        :param result_list: 2d list of the results
        :return:
        """
        success = ""
        try:
            hash_fields = sqlalchemy_model.retrieve_hash_fields(db_table_name)
            self.db_object.print_message = True

            for result in result_list:
                try:
                    tmp_dict = {}
                    for count,field in enumerate(header_fields):
                        field_value = result[count]
                        if isinstance(field_value, str):
                            field_value = field_value.rstrip("\n")
                        tmp_dict[field] = field_value
                    tmp_field_values = encryption.get_hash_string(hash_fields, tmp_dict)
                    tmp_dict['hashval'] = tmp_field_values['hashval']

                    # check ip + scope_id if already exists for EngagementDevice
                    record = None
                    created = False
                    if db_table_name == "EngagementDevice" and "target_ip" in tmp_field_values and \
                        tmp_field_values['target_ip'] is not None and network.valid_ip(tmp_field_values['target_ip']):
                        ip_field_values = encryption.get_hash_string(["target_ip", "scope_id"], tmp_dict)
                        # if already exists
                        engagementdevice = self.db_object.view(db_table_name, ['id'], ['hashval'], [ip_field_values['hashval']])
                        if engagementdevice is not None and len(engagementdevice) > 0:
                            record = engagementdevice[0] # will update current record not add new (duplicate one)
                    else:
                        record_val = self.db_object.view(db_table_name, ['id'], ['hashval'], [tmp_field_values['hashval']])
                        if record_val is not None and len(record_val) > 0:
                            record = record_val[0]

                    if record is None:
                        record, created = self.db_object.get_or_create(db_table_name, tmp_dict)
                        success = db_table_name + " added!"

                        # Try updating if was already there
                        if not created and record is not None:
                            record_dict = self.db_object.get(db_table_name, ["id"], [record['id']])
                            success = self.update_fields(db_table_name, self.db_object, tmp_field_values, fields_to_update, record_dict)
                    else:
                        record_dict = self.db_object.get(db_table_name, ["id"], [record['id']])
                        success = self.update_fields(db_table_name, self.db_object, tmp_field_values, fields_to_update,
                                                     record_dict)

                except Exception as e:
                    print_text.print_error("\tparser 444 except: "  +str(e) + " Error on line {}".format(sys.exc_info()[-1].tb_lineno))

            return success
        except Exception as e:
            print_text.print_error("Parser.py 448 except: " + str(e) + " Error on line {}".format(sys.exc_info()[-1].tb_lineno))
            success = "parser error: " + str(e)

        return success

    def update_fields(self, db_table_name, interaction, field_values, fields_to_update, db_field_values):
        """

        :param interaction:
        :param field_values:
        :param db_field_values:
        :param unique_fields:
        :return:
        """
        try:
            update_entry = {}
            for update_field in fields_to_update:
                update_field_name = update_field[0]
                update_action = update_field[1]
                if field_values is not None and update_field_name in field_values and db_field_values is not None and update_field_name in db_field_values:
                    new_field = field_values[update_field_name]
                    if new_field is None:
                        new_field = ""
                    current_field = db_field_values[update_field_name]
                    if current_field is None:
                        current_field = ""
                        sep = ""
                    else:
                        sep = "\n"

                    if update_action == "a":
                        update_entry[update_field_name] = current_field + sep + new_field
                    elif update_action == "u" and new_field != "":
                        update_entry[update_field_name] = new_field
                    elif update_action == "c" and current_field == "":
                        update_entry[update_field_name] = new_field
                    elif update_action == "as" and new_field.lower() not in current_field.lower():
                        update_entry[update_field_name] = current_field + sep + new_field
                    elif update_action == "ol" and len(new_field) > len(current_field):
                        update_entry[update_field_name] = new_field

            if len(update_entry) > 0:
                update_entry['id'] = db_field_values['id']
                success = interaction.update(db_table_name, update_entry)
            #else:
            #print_text.print_msg("\tDidn't update because the record already contains all the information that was going to be updated!")
        except Exception as e:
            success = "Failed. " + str(e)
            print_text.print_error("Parser 494 except: " + str(e) + " Error on line {}".format(sys.exc_info()[-1].tb_lineno))

    def delete_tester_device(self, table_name):
        """
        Delete tester devices from EngagementDevices
        :param table_name:
        :return:
        """
        for tdl in self.list_of_tester_devices:
            self.db_object.delete_where(table_name, ["target_ip", "scope_id"], [tdl, self.scope_id])

    def find_engagement_device(self, table, passed_record, ignore_scope=False):
        """
        First lookup engagement device by name then by ip
        :param table: table name
        :param passed_record: value to lookup engagementdevice
        :return:
        """
        try:
            if ignore_scope:
                edevices, edevices_ip = models_to_dictionary.engagementdevice_to_dict(self.db_object)
            else:
                edevices, edevices_ip = models_to_dictionary.engagementdevice_to_dict(self.db_object, self.scope_id)

            if " -> " in passed_record:
                passed_record = passed_record[passed_record.find(" -> ")+4:].strip()

            engagement_device = None
            ip = passed_record.lower()
            if ip in edevices:
                engagement_device = edevices[ip]
            elif ip in edevices_ip:
                engagement_device = edevices_ip[ip]
            elif "://" in ip:
                tmp_ip = ip[ip.find("://") + 3:]
                if ":" in tmp_ip:
                    tmp_ip = tmp_ip[:tmp_ip.find(":")]
                    if tmp_ip in edevices:
                        engagement_device = edevices[tmp_ip]
                    elif tmp_ip in edevices_ip:
                        engagement_device = edevices_ip[tmp_ip]
            else:
                print_text.print_error("\t Associated engagement device not found for target: " + ip + " so " + table + " not added!")

            return engagement_device
        except Exception as e:
            pass
            #print_text.print_error("Parser 600 except: " + str(e) + " Error on line {}".format(sys.exc_info()[-1].tb_lineno))
        return None

    def insert_scope(self, records, fields_to_update):
        """ Insert Scope records.  (Mostly a virtual web server addition.)"""
        success = "Success. Scope records added."

        try:
            description = ""
            updated_records = []
            for record in records:
                domain = record[1]
                ip = record[1]
                if "(" in record[1]:
                    ip = ip[ip.find("(")+1:]
                    ip = ip[:ip.find(")")]
                    domain = domain[:domain.find("(")]
                    domain = domain.strip()

                additional = ""
                if not network.valid_ip(domain):
                    additional, registrar, domain_valid_date_range, nameservers = dns_functions.grab_whois_domain(domain)
                information = ""
                if network.valid_ip(ip) and not network.private_ip(ip):
                    information = dns_functions.grab_whois_ip(ip)
                    sep = ""
                    if additional != "":
                        sep = "; "
                    additional = additional + sep + dns_functions.get_formated_geo_data(ip)
                updated_records.append(record + [information, description, additional])

            create_fields = ["location_id", "original_entry", "entry", "permission", "type", "open_ip", "open_port",
                               "validate", "modified_by", "modified_date", "information","description", "additional"]
            field_values = self.convert_list_to_field_values("Scope", fields_to_update, create_fields, updated_records)
        except Exception as e:
            success = "Failed. " + str(e)
            print_text.print_error("Parser 528 except: " + str(e) + " Error on line {}".format(sys.exc_info()[-1].tb_lineno))

    def insert_recon(self, recon_records, recon_fields_to_update):
        """ Insert Recon records. """
        success = "Success. Recon records added."

        try:
            recon_create_fields = ["scope_id", "recon_type", "record", "info", "associated_info", "recon_description", "organization",
                                   "source", "modified_by", "modified_date"]
            field_values = self.convert_list_to_field_values("Recon", recon_fields_to_update, recon_create_fields, recon_records)
        except Exception as e:
            success = "Failed. " + str(e)
            print_text.print_error("Parser 540 except: " + str(e) + " Error on line {}".format(sys.exc_info()[-1].tb_lineno))

    def insert_person(self, records, fields_to_update):
        """ Insert Person records. """
        success = "Success. Person records added."
        try:
            create_fields = ["location_id", "full_name", "email", "person_info", "associated_info", "person_description",
                             "organization", "title", "phone", "full_address", "vendor", "client", "source",
                             "modified_by", "modified_date"]
            field_values = self.convert_list_to_field_values("Person", fields_to_update, create_fields, records)
        except Exception as e:
            success = "Failed. " + str(e)
            print_text.print_error("Parser 540 except: " + str(e) + " Error on line {}".format(sys.exc_info()[-1].tb_lineno))

    def insert_engagementdevice_full(self, engagement_device_list, fields_to_update):
        """
        Insert EngagementDevice using list of tuples, engagement_device_list. Most common EngagementDevice info.
        For duplicates, append info, services, programs, and accounts.
        :param - fields_to_update - list of tuples ie. [('field_name', 'a'), 'field_name', 'c', field_name', 'u')]
            where 'a' means append to existing data in the field and 'c' means over write if field data is currently Null,
            'u' means update (over write) existing field data, 'as' means to append if data to append is not already in
            field, and 'ol' means to over write if longer character count than what is currently in field
        """
        try:
            db_table_name = "EngagementDevice"
            ed_create_fields_full = ["target_ip", "target_name", "domain", "os", "mac", "accounts", "info",
                                     "services", "programs", "av_present", "modified_by",
                                     "modified_date", "source", "scope_id"]

            # Get current list of Devices
            devices_dictionary = models_to_dictionary.same_ip_scope(self.db_object, self.scope_id)

            # Make sure not duplicating engagement devices (filter out if already have device)
            updated_engagement_device_list = []
            devices, devices_ips = models_to_dictionary.engagementdevice_to_dict(self.db_object, self.scope_id)
            scope_ips = scope_functions.scope_ips(self.db_object)
            scope_websites_ips = scope_functions.scope_website_ips(self.db_object)

            for device in engagement_device_list:
                in_scope = True
                ip = None
                if device[0] is not None and device[0] != "" and network.valid_ip(device[0]):
                    ip = device[0]
                elif network.valid_ip(device[1]):
                    ip = device[1]

                if ip is not None:
                    in_scope = False
                    for scope_ip in scope_ips:
                        if network.check_in_network(scope_ip, ip):
                            in_scope = True
                            break
                if not in_scope and len(scope_websites_ips) > 0:
                    for website_ip in scope_websites_ips:
                        if network.check_in_network(website_ip, ip):
                            in_scope = True
                            break

                if in_scope: #make sure in scope if IP address must be w/ scope ip range
                    # target doesn't exist
                    if device[1].lower() not in devices:
                        # target name is not IP then update current engagement device with target name
                        tmp_fields_to_update = fields_to_update
                        if device[0] != device[1] and device[0] in devices_ips:
                            # Check if current device name is different than one adding (could be virtual if so)
                            ed = self.db_object.view(db_table_name, None, ["id"], [devices_ips[device[0]]])
                            current_engagement_device = ed[0]
                            if current_engagement_device['target_ip'] != current_engagement_device['target_name']:
                                updated_engagement_device_list.append(device) # probably a virtual device since names are different but IPs are the same
                            else: # means current engagement device has IP as as target name so update target name using this newly parsed one
                                scope_id = device[13]
                                tmp_dict = {"target_ip": device[0], "target_name": device[1], "domain": device[2],
                                            "os": device[3], "mac": device[4], "accounts": device[5], "info": device[6],
                                            "services": device[7], "programs": device[8], "av_present": device[9],
                                            "modified_by": device[10], "modified_date": device[11], "source": device[12],
                                            "scope_id": scope_id}
                                if "target_name" not in tmp_fields_to_update and device[0] != device[1]:
                                    tmp_fields_to_update.append(("target_name", "u"))
                                    device_dict = self.db_object.get(db_table_name, ["id"], [devices_ips[device[0]]])
                                success = self.update_fields(db_table_name, self.db_object, tmp_dict, tmp_fields_to_update, device_dict)
                        else:
                            updated_engagement_device_list.append(device)
                    else: # target_name already found
                        updated_engagement_device_list.append(device)

            field_values = self.convert_list_to_field_values(db_table_name, fields_to_update, ed_create_fields_full, updated_engagement_device_list)

            # Make sure to your tester devices are not in the results!
            self.delete_tester_device(db_table_name)

            # Now merge any EngagementDevices that have same IP in same Scope
            engagement_devices = self.db_object.view("EngagementDevice", None, None, None, True, [('scope_id','asc'), ('target_ip', 'asc')], None)

            current_scope_id = None
            current_ip = None
            similar_devices = []
            if engagement_devices is not None:
                for device in engagement_devices:
                    scope_id = device['scope_id']
                    ip = device['target_ip']
                    if current_scope_id is not None and scope_id != current_scope_id and current_ip is not None and current_ip != ip:
                        if similar_devices is not None and len(similar_devices) > 1:
                            # merge engagement devices
                            common_merge.merge_devices(self.db_object, similar_devices)
                        similar_devices = []
                    elif scope_id == current_scope_id and current_ip == ip:
                        # add device since it is similar
                        similar_devices.append(device)
                    current_scope_id = scope_id
                    current_ip = ip

        except Exception as e:
            print_text.print_error("Parser 533 except: " + str(e) + " Error on line {}".format(sys.exc_info()[-1].tb_lineno))

    def insert_deviceport(self, dp_results, fields_to_update):
        """ Insert DevicePorts using List of tuples, dp_results. """
        try:
            # scope_id doesn't matter in this case (helpful when parsing based on manual that actually has targets from multiple scopes)
            if len(self.db_object.grab_all_locations()) < 2:
                self.scope_id = None

            self.edevices, self.edevices_ip = models_to_dictionary.engagementdevice_to_dict(self.db_object, self.scope_id)

            open_port_list = []
            for result in dp_results:
                if result[7] == "":
                    result[7] = None
                if result[9] == "":
                    result[9] = None
                if result[10] == "":
                   result[10] = None
                try:
                    edevice_id = str(self.edevices[result[0]])
                except Exception as e:
                    try:
                        edevice_id = str(self.edevices_ip[result[0]])
                    except:
                        try:
                            if "http" in result[0]:
                                tmp = result[0]
                                tmp = tmp[tmp.find("://")+2:]
                                tmp = tmp.strip("/")
                            else:
                                http = "http://"
                                if result[1] == "443":
                                    http = "https://"
                                tmp = http + result[0] + ":" + str(result[1]) + "/"

                            edevice_id = str(self.edevices[tmp])
                        except:
                            print_text.print_error("Parser 804 except: " + str(e) + " Error on line {}".format(sys.exc_info()[-1].tb_lineno))
                            edevice_id = None
                            if tmp in self.edevices_ip:
                                edevice_id = self.edevices_ip[tmp]
                if edevice_id is not None:
                    if isinstance(result, tuple):
                        open_port_list.append(result + (edevice_id, ))
                    elif isinstance(result, list):
                        open_port_list.append(result + [edevice_id])

            dp_table_fields = ['ip', 'port', 'protocol', 'port_description', 'validated',
                                'modified_by', 'modified_date', 'stealth', 'start_time', 'end_time',
                                'source', 'engagementdevice_id']
            db_table_name = "DevicePort"
            if dp_results is not None:
                field_values = self.convert_list_to_field_values(db_table_name, fields_to_update, dp_table_fields, open_port_list)
                return True
            else:
                return False
        except Exception as e:
            print_text.print_error("Parser 258 except: " + str(e) + " Error on line {}".format(sys.exc_info()[-1].tb_lineno))
            return False

    def insert_findingresults(self, r_results, fields_to_update):
        """
        Now that vulndef and engagement devices added can grab those values, then add finding result.
        r_results is list of dictionary in following format:
            result[0] = tool
            result[1] = tool_plugin_id
            result[2] = target
            result[3] = port
            result[4] = protocol
            result[5] = output
            result[6] = tester_output
            result[7] = start_time
            result[8] = end_time
            result[9] = command
            result[10] = finding title
            result[11] = finding_description
            result[12] = finding_remediation
            result[13] = finding_cvss
            result[14] = finding_severity
            result[15] = finding_classification
            result[16] = finding_exploits_available
            result[17] = finding_patch_publication_date
            result[18] = modified_by
        """
        try:
            if len(r_results) > 0:
                if len(r_results[0]) != 19:
                    message = "Failed.  A result must be have 19 fields. You only have " + str(len(r_results[0])) +"!"
                    print_text.print_error(message)
                    return message

                # scope_id doesn't matter in this case (helpful when parsing based on manual that actually has targets from multiple scopes)
                if len(self.db_object.grab_all_locations()) < 2:
                    self.scope_id = None

                updated_results = []
                for result in r_results:
                    try:
                        if result[17] == "":
                            result[17] = None
                        if result[7] == "":
                            result[7] = None
                        if result[8] == "":
                            result[8] = None
                        engagement_device = self.find_engagement_device("result", result[2])
                        if engagement_device is not None:
                            updated_results.append(result + [engagement_device])
                    except Exception as e:
                        print("821 parser.py Could not determine engagement_device: " + str(e))

                result_create_fields = ['tool', 'tool_plugin_id', 'target', 'port', 'protocol', 'output',
                                        'tester_output', 'start_time', 'end_time', 'command', 'finding_title',
                                        'finding_description', 'finding_remediation', 'finding_cvss', 'finding_severity',
                                        'finding_classification', 'finding_exploits_available',
                                        'finding_patch_publication_date', 'modified_by', 'engagementdevice_id']

                db_table_name = "Result"
                field_values = self.convert_list_to_field_values(db_table_name, fields_to_update, result_create_fields,
                                                                 updated_results)
        except Exception as e:
            print_text.print_error("Parser 621 except: " + str(e) + " Error on line {}".format(sys.exc_info()[-1].tb_lineno))

    def insert_phishing(self, phishing_list, fields_to_update):
        """
        Insert Phishing using list of tuples, phishing_list.
        :param - fields_to_update - list of tuples ie. [('field_name', 'a'), 'field_name', 'c', field_name', 'u')]
            where 'a' means append to existing data in the field and 'c' means over write if field data is currently Null,
            'u' means update (over write) existing field data, 'as' means to append if data to append is not already in
            field, and 'ol' means to over write if longer character count than what is currently in field
        """
        try:
            db_table_name = "Phishing"
            create_fields = ["location_id", "scenario_id", "sent_to", "smtp_to", "data_to", "modified_date",
                             "received_response", "modified_by"]

            field_values = self.convert_list_to_field_values(db_table_name, fields_to_update, create_fields, phishing_list)
        except Exception as e:
            print_text.print_error("Parser 645 except: " + str(e) + " Error on line {}".format(sys.exc_info()[-1].tb_lineno))

    def insert_credential(self, records, fields_to_update):
        """ Insert Credential records. """
        success = "Success. Credential records added."

        try:
            updated_records = []
            for result in records:
                engagement_device = self.find_engagement_device("", result[15])
                if result[15] is not None:
                    engagement_device = self.find_engagement_device("credential", result[15])

                if engagement_device is not None:
                    result[15] = engagement_device
                    updated_records.append(result)

            create_fields = ["status", "domain", "username", "passwd", "salted_hash", "hash_value", "hash_type",
                            "amount_of_time_to_crack", "disabled", "pwdlastset", "pwdnotexpire", "da", "la",
                            "credential_source", "modified_by", "engagementdevice_id", "comment", "additional",
                             "service"]

            if len(updated_records) > 0:
                field_values = self.convert_list_to_field_values("Credential", fields_to_update, create_fields, updated_records)
        except Exception as e:
            success = "Failed. " + str(e)
            print_text.print_error("Parser 742 except: " + str(e) + " Error on line {}".format(sys.exc_info()[-1].tb_lineno))


