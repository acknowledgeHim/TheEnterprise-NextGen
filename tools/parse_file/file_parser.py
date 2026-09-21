import sys
import os
import json
import yaml
from common import print_text, common
from common.tool import Tool
from common.manual import Entry
from common.selection import Selection

class FileParser(Tool):

    def __init__(self, db_object, full_client_engagement_path):
        try:
            self.full_client_engagement_path = full_client_engagement_path
            self.db_object = db_object

            self.output_folder = full_client_engagement_path + "/output/"
            Tool.__init__(self, self.db_object, self.output_folder, "file parser", False)

        except Exception as e:
            print_text.print_error("file_parser except: " + str(e) + " Error on line {}".format(sys.exc_info()[-1].tb_lineno))
        return

    def __enter__(self):
        return self

    def __exit__(self, type, value, traceback):
        return self

    def setup(self):
        """
        Main function that Menu calls.  sets up
        """
        try:

            required_fields = []
            fields = [['full path to file(s) to parse (blank means it will parse files in the default directory)',
                       'path_to_file_to_parse', ''],
                        ['the tool name or part of a tool name to filter the tools, otherwise you\'ll get a LARGE list',
                         'filter_tools', '']]

            with Entry("File Search", fields, required_fields) as me:
                field_values = me.user_input_fields(input_text='Please enter')

            filter_tools = field_values['filter_tools']
            if isinstance(filter_tools, bool):
                if filter_tools:
                    filter_tools = "y"
                else:
                    filter_tools = "n"

            # find all yaml files
            count = 1
            count_numbers = [0]
            display = ['ALL output (only works for files in the correct tools output_path - not a possible specified path above)']
            default_output_folder = []
            for folder, foldernames, files in os.walk(self.db_object.base_path):
                for name in files:
                    if name.lower().endswith(".yaml"):
                        full_yaml_file_path = os.path.join(folder, name)
                        config = yaml.safe_load(open(full_yaml_file_path))
                        if config is not None and "callable_yaml" not in config and "tool_name" in config:
                            if filter_tools == "" or filter_tools in full_yaml_file_path:
                                yaml_file = os.path.join(folder, name)
                                yaml_file = yaml_file[yaml_file.find(self.db_object.base_path) + len(self.db_object.base_path):]
                                display.append(config['tool_name'] + " (" + yaml_file + ")")
                                default_output_folder.append(config['output_path'])
                                count_numbers.append(count)
                                count += 1

            if len(display) > 0:
                with Selection('Select the tool whose output needs parsing', display, None) as selection:
                    selected_index = selection.select_option(count_numbers)

                selected_tool = display[selected_index]
                yaml_file = selected_tool[selected_tool.find("(") + 1:]
                yaml_file = yaml_file[:yaml_file.find(")")]
                output_path = default_output_folder[selected_index - 1]

                # Must select scope id of file(s) that will be parsed
                scopes = self.db_object.dictionary_list("Scope", "entry")
                scopes_count_numbers = self.db_object.dictionary_list("Scope", "id")
                with Selection('Select the scope the data in the files is part of', scopes, None) as selection:
                    scope_id = selection.select_option(scopes_count_numbers)

                # get location id
                location_id = self.db_object.grab_column_from_single_record("Scope", ["id"], [scope_id], "location_id")

                field_values['yaml_file'] = yaml_file
                field_values['tool'] = selected_tool

                self.create_parsing_job(field_values, scope_id, location_id, yaml_file, output_path)
            else:
                print_text.print_error("\tLooks like you tried to filter the tools and your filter term did not match any tools.")

        except Exception as e:
            print_text.print_error("file_parser except: " + str(e) + " Error on line {}".format(sys.exc_info()[-1].tb_lineno))

    def create_parsing_job(self, field_values, scope_id, location_id, yaml_file, output_path):
        try:
            if "path_to_file_to_parse" not in field_values or field_values['path_to_file_to_parse'] == "" or field_values['path_to_file_to_parse'] is None:
                field_values['path_to_file_to_parse'] = self.db_object.engagement_path + output_path

            targets = []
            commands = []
            print("106 file_parser field_values['path_to_file_to_parse']: "  + str(field_values['path_to_file_to_parse']))
            if os.path.isfile(field_values['path_to_file_to_parse']):
                folder_where_file_is_found = field_values['path_to_file_to_parse']
                folder_where_file_is_found = folder_where_file_is_found[:folder_where_file_is_found.rfind("/") + 1]
                #tmp_scope_id, tmp_location_id = self.try_to_determine_scope(folder_where_file_is_found)
                targets.append(field_values['path_to_file_to_parse'])
                commands.append(
                    [field_values['path_to_file_to_parse'], scope_id, location_id, yaml_file, folder_where_file_is_found])
            elif os.path.isdir(field_values['path_to_file_to_parse']):
                if output_path in field_values['path_to_file_to_parse']:
                    for folder, foldernames, files in os.walk(field_values['path_to_file_to_parse']):
                        for f in files:
                            target = os.path.join(folder, f)
                            tmp_scope_id, tmp_location_id = self.try_to_determine_scope(target)
                            if tmp_location_id is None:
                                tmp_scope_id = scope_id
                                tmp_location_id = location_id
                            targets.append(target)
                            commands.append([target, tmp_scope_id, tmp_location_id, yaml_file, field_values['path_to_file_to_parse']])
                else:
                    field_values['path_to_file_to_parse'] = field_values['path_to_file_to_parse'] + "/"
                    #targets = [f for f in os.listdir(field_values['path_to_file_to_parse']) if os.path.isfile(os.path.join(field_values['path_to_file_to_parse']+"/", f))]
                    targets = []
                    for folder, foldernames, files in os.walk(field_values['path_to_file_to_parse']):
                        for f in files:
                            targets.append(os.path.join(folder, f))
                    for target in targets:
                        tmp_scope_id, tmp_location_id = self.try_to_determine_scope(target)
                        if tmp_location_id is None:
                            tmp_scope_id = scope_id
                            tmp_location_id = location_id
                        commands.append([target, tmp_scope_id, tmp_location_id, yaml_file, field_values['path_to_file_to_parse']])

            descriptors = []
            for t in targets:
                descriptors.append("FUNCTION:tools.parse_file.file_parser_run.parse_file")
            print("143 file_parser targets: " + str(targets))
            print("144 file parser commands: " + str(commands))
            self.run_group(targets, commands, descriptors)
        except Exception as e:
            print_text.print_error("file_parser except: " + str(e) + " Error on line {}".format(sys.exc_info()[-1].tb_lineno))

    def try_to_determine_scope(self, file_name):
        """ Given a filename, see if scope_id or log_id is part of that filename. """
        location_id = None
        scope_id = common.regex_exist_in_entry(file_name, r'[_]{2}[s]{1}[\d]+')
        if "__s" in scope_id:
            scope_id = scope_id.replace("__s", "")
            scope_info = self.db_object.get("Scope", ["id"], [scope_id])
            if scope_info is not None:
                location_id = scope_info['location_id']
        if scope_id is None or scope_id == "":
            log_id = common.regex_exist_in_entry(file_name, r'[_]{2}[\d]+[_]{2}')
            if "__" in log_id:
                log_id = log_id.replace("__", "")
            if log_id != "":
                # look up scope_id by log_id
                log_info = self.db_object.log_record_by_id(log_id)
                if log_info is not None:
                    scope_id = log_info['scope_id']
                    location_id = log_info['location_id']
        else:
            scope_info = self.db_object.get("Scope", ["id"], [scope_id])
            if scope_info is not None:
                location_id = scope_info['location_id']

        return scope_id, location_id

