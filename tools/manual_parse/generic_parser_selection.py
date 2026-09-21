import sys
import os
import subprocess
import shlex
from common import print_text
from common import common
from common.tool import Tool
from common.entry_db_middle_man import Entry
from common.selection import Selection

class GenericParserSelection(Tool):
    """ Manual Parse files"""
    def __init__(self, db_object, full_client_engagement_path):
        try:
            self.output_folder = full_client_engagement_path

            self.key = db_object.key

            Tool.__init__(self, db_object, self.output_folder, "manual parser")

        except Exception as e:
            print_text.print_error("tool generic parser selection except: " + str(e) + " Error on line {}".format(sys.exc_info()[-1].tb_lineno))
        return

    def __enter__(self):
        return self

    def __exit__(self, type, value, traceback):
        return self

    def select_scope(self, scopes, scopes_count_numbers):
        with Selection('Select the Scope of this file', scopes, None) as selection:
            scope_id = selection.select_option(scopes_count_numbers)
            scope_info = self.db_object.get("Scope", ["id"], [scope_id])
            location_id = scope_info['location_id']
        return scope_id, location_id

    def get_targets(self, tool, default_path):
        """
        targets - list of files to parse
        commands - tool source + target file
                tool source so can lookup the parsing function from pat_config.py TOOLS_DICT
        """
        try:
            targets = []
            commands = []

            scopes = self.db_object.dictionary_list("Scope", "entry")
            scopes_count_numbers = self.db_object.dictionary_list("Scope", "id")

            PATH_MANUAL_ENTRY = (["the directory for multiple files or the directory/file_name for a single file to parse or leave blank to parse files already in the output path of this client", "path", ''], )
            pathway = "ask"
            with Entry(None, PATH_MANUAL_ENTRY) as me:
                while not os.path.isdir(pathway) and pathway != "" and not os.path.isfile(pathway):
                    if pathway != "ask":
                        print_text.print_error("\t The pathway you entered was not valid, either enter a valid pathway or leave it blank to use the parsers default output path.")
                    field_values = me.user_input_fields(input_text='Please enter ')

                    pathway = field_values['path']

            use_default_path = False
            if pathway == "":
                pathway = default_path
                if "." in pathway:
                    pathway = pathway.rstrip("/")
                    pathway = pathway[:pathway.rfind("/")]
                use_default_path = True

            if os.path.isfile(pathway):
                files = [pathway[pathway.rfind("/")+1:]]
                pathway = pathway[:pathway.rfind("/")+1]
                self.generic_tool_path = pathway
            else:
                # Now loop through to get all files in that pathway
                if not use_default_path:
                    files = [f for f in os.listdir(pathway) if os.path.isfile(os.path.join(pathway, f))]
                    self.generic_tool_path = pathway
                else:
                    self.generic_tool_path = pathway
                    files = []
                    for root, dirs, fls in os.walk(pathway):
                        for filename in fls:
                            local_path = ""
                            if "." in root:
                                local_path = root[root.find(pathway) + len(pathway):] + "/"
                            files.append(local_path + filename)

            # remove hidden system files that might have gotten pulled (anything starting with '.')
            good_files = []
            for f in files:
                if "/." not in f:
                    good_files.append(f)

            do_once = True
            for count, f in enumerate(good_files):
                possible_scope = []
                scope_id = None
                location_id = None
                if f[0] != ".":
                    if tool == "nmap":
                        scope_dictionary_list = self.db_object.view("Scope", ['entry', 'id', 'location_id'], ['type'], ['IP'], True)
                        for scope in scope_dictionary_list:
                            scope_entry = scope['entry']
                            if scope_entry.replace("/", "_") in f:
                                possible_scope.append(scope) # list of possible scope items that match
                        if len(possible_scope) > 1:
                            tmp_count_numbers = []
                            for ps in possible_scope:
                                tmp_count_numbers.append(ps['id'])
                            with Selection('Select the Scope of this file', possible_scope, None) as selection:
                                scope_id = selection.select_option(tmp_count_numbers)
                                scope_info = self.db_object.get("Scope", ["id"], [scope_id])
                                location_id = scope_info['location_id']
                        elif len(possible_scope) == 1:
                            scope_id = possible_scope[0]["id"]
                            location_id = possible_scope[0]["location_id"]
                        else:
                            print_text.print_msg("File, " + f + ", found to parse. Please select the scope this files applies to.")
                            scope_id, location_id = self.select_scope(scopes, scopes_count_numbers)
                    else:
                        scope_id = common.regex_exist_in_entry(f, r'[_]{2}[s]{1}[\d]+')
                        if "__s" in scope_id:
                            scope_id = scope_id.replace("__s", "")
                            scope_info = self.db_object.get("Scope", ["id"], [scope_id])
                            if scope_info is None:
                                print_text.print_msg("File, " + f + ", found to parse. Please select the scope this files applies to.")
                                scope_id, location_id = self.select_scope(scopes, scopes_count_numbers)
                        if scope_id is None or scope_id == "":
                            log_id = common.regex_exist_in_entry(f, r'[_]{2}[\d]+[_]{2}')
                            if "__" in log_id:
                                log_id = log_id.replace("__", "")
                            if log_id != "":
                                # look up scope_id by log_id
                                log_info = self.db_object.log_record_by_id(log_id)
                                if log_info is None:
                                    print_text.print_msg("File, " + f + ", found to parse. Please select the scope this files applies to.")
                                    scope_id, location_id = self.select_scope(scopes, scopes_count_numbers)
                                else:
                                    scope_id = log_info['scope_id']
                                    location_id = log_info['location_id']
                            else:
                                print_text.print_msg("File, " + f + ", found to parse. Please select the scope this files applies to.")
                                scope_id, location_id = self.select_scope(scopes, scopes_count_numbers)
                        else:
                            scope_info = self.db_object.get("Scope", ["id"], [scope_id])
                            if scope_info is None:
                                print_text.print_msg("File, " + f + ", found to parse. Please select the scope this files applies to.")
                                scope_id, location_id = self.select_scope(scopes, scopes_count_numbers)
                            else:
                                location_id = scope_info['location_id']

                    if scope_id is None:
                        if len(scopes) == 1:
                            scope_id = scopes_count_numbers[0]
                        elif scope_id == "" or scope_id is None:
                            print_text.print_msg("File, " + f + ", found to parse. Please select the scope this files applies to.")
                            scope_id, location_id = self.select_scope(scopes, scopes_count_numbers)

                    # un 7z if it is one
                    if ".7z" in f:
                        stdoutdata = subprocess.check_output(shlex.split("7z l " + self.generic_tool_path + f))
                        stdoutdata = stdoutdata.decode("utf-8")

                        # now must pull out real file name(s) that will be extracted loop through those and add those to targets and commands
                        output = stdoutdata[stdoutdata.find("-------\n")+8:]
                        output = output[:output.find("-------\n")]
                        output = output[:output.rfind("\n")]

                        lines = output.split("\n")
                        for line in lines:
                            real_file = common.regex_exist_in_entry(line, r'[0-9a-zA-Z-_\.]+$')
                            if real_file != "" and "------" not in real_file:
                                if real_file[0] != ".":
                                    commands.append([pathway + ";" + real_file, scope_id, location_id])
                                    targets.append(f + ";" + real_file)
                                    if do_once:
                                        print_text.print_msg("Uncompressed file, " + real_file + ", added to be parsed.")
                                        print_text.print_msg("\tRemaining messages regarding files uncompressed are being suppressed.")
                                        do_once = False

                        stdoutdata = subprocess.check_output(['7z', 'x', self.generic_tool_path + f, '-p' + self.key, '-o'+pathway, '-y'])
                    else:
                        commands.append([pathway + ";" + f, scope_id, location_id])
                        targets.append(pathway + ";" + f)

        except Exception as e:
            print_text.print_error("tool generic parser selection except: " + str(e) + " Error on line {}".format(
                sys.exc_info()[-1].tb_lineno))

        return targets, commands
