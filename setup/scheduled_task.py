import sys, os, yaml
from common import print_text, network
from common.manual import Entry
from common.entry_db_middle_man import MiddleMan
from common.selection import Selection


DB_TABLE_NAME = "ScheduledTask"
MANUAL_FIELDS = [["Earliest Start Date/Time (YYYY-MM-DD HH:MM:SS)", "earliest_start_time", ''],
                 ["Stop Running (will kill process) Date/Time (YYYY-MM-DD HH:MM:SS)", "stop_running_by_time", ''],
                 ["Longest Time (in mins) Allowed to Run", "longest_run_time", ''],
                 ["Minimum Time (in mins) Necessary to Run (won't start if Stop Running Date/Time is sooner than current time + this minimum time)", "minimum_time_necessary_to_run", '']]

HEADER_NAMES = [['Row #', 'Tool Config', 'Earliest Start DateTime', 'Stop By DateTime', 'Longest Time to Run', 'Min. Time to Run', 'PID', 'Finished', 'Failed', 'Modified By', 'Modified Date']]
COLUMN_NAMES = ['id', 'tool_config', 'earliest_start_time', 'stop_running_by_time', 'longest_run_time', 'minimum_time_to_allow_to_run', 'pid', 'finished', 'failed', 'modified_by', 'modified_date']
JOIN_TABLES = ["Log.pid", "Log.failed", "Log.finished"]

class ScheduledTask(MiddleMan):
    """
    Add or remove ScheduledTask entries.
    """
    def __init__(self, db_object, full_client_engagement_path):
        MiddleMan.__init__(self, db_object, full_client_engagement_path, DB_TABLE_NAME, MANUAL_FIELDS, COLUMN_NAMES, HEADER_NAMES)
        self.db_object = db_object
        return

    def __enter__(self):
        return self

    def __exit__(self, type, value, traceback):
        return self

    def add(self):
        """
        Add entry to SqlCipher DB
        Overrides db.Interaction.add
        Returns number of entries added or 0 if failed.
        """
        try:
            required_fields = []
            fields = MANUAL_FIELDS

            with Entry("Search for Tool to Schedule", fields, required_fields) as me:
                field_values = me.user_input_fields(input_text='Please enter')

            # find all yaml files
            count = 1
            count_numbers = [0]
            display = ['Select the Tool to Schedule (tool will only run if all required fields have either a default value or Global Var in the YaML config file)']
            default_output_folder = []
            for folder, foldernames, files in os.walk(self.db_object.base_path):
                for name in files:
                    if name.lower().endswith(".yaml"):
                        full_yaml_file_path = os.path.join(folder, name)
                        config = yaml.safe_load(open(full_yaml_file_path))
                        yaml_file = os.path.join(folder, name)
                        yaml_file = yaml_file[yaml_file.find(self.db_object.base_path) + len(self.db_object.base_path):]
                        display.append(config['tool_name'] + " (" + yaml_file + ")")
                        default_output_folder.append(config['output_path'])
                        count_numbers.append(count)
                        count += 1

            field_values['yaml_file'] = yaml_file

            if len(display) > 0:
                with Selection('Select the tool whose output needs parsing', display, None) as selection:
                    selected_index = selection.select_option(count_numbers)

                selected_tool = display[selected_index - 1]
                yaml_file = selected_tool[selected_tool.find("(") + 1:]
                yaml_file = yaml_file[:yaml_file.find(")")]
                output_path = default_output_folder[selected_index - 1]

                # Now need to figure out how to "schedule these" by pushing to special celery task maybe?

                #self.create_parsing_job(field_values, scope_id, location_id, yaml_file, output_path)
        except Exception as e:
            print_text.print_error("\tLooks like you tried to filter the tools and your filter term did not match any tools.")

    def join_view(self):
        """ Overwrite join_view in entry_db_middleman.py """
        return MiddleMan.join_view(self, JOIN_TABLES)


    def delete(self):
        """ Overwrite delete in entry_db_middleman.py. """
        return MiddleMan.delete(self, JOIN_TABLES)