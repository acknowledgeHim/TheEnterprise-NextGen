import sys
import datetime
from common.entry_db_middle_man import MiddleMan
from result.result_class import GenericResult
from common.manual import Entry
from common.selection import Selection

DB_TABLE_NAME = "Log"
ADD_MANUAL_FIELDS = [["Source", "source", r'[a-z\- ]+'], ["Blacklisted, Y|N", "blacklisted", r'^(?:Y|N)$'],
                     ["Target (blank sets it the same as the scope)", "target", ''],
                     ["comment / status", "comment", ''],
                     ["Allow Rerun for this target by source, Y|N", "allow_rerun", r'^(?:Y|N)$']]
ADD_REQUIRED = ['source', 'comment']
MANUAL_FIELDS = (#["PID", "pid", r'^(?:[\d]+)$'],
                 #["Target", "target", r'^(?:[a-zA-Z0-9._%+-\:/]+)$'],
                 #["Start Time (YYYY-MM-DD HH:MM:SS.MILSEC)", "start_time", r'^(?:[\d]{4}-[\d]{2}-[\d]{2} [\d]{2}:[\d]{2}:[\d]{2}.[\d]{6})$'],
                 #["End Time (YYYY-MM-DD HH:MM:SS.MILSEC)", "end_time", r'^(?:[\d]{4}-[\d]{2}-[\d]{2} [\d]{2}:[\d]{2}:[\d]{2}.[\d]{6})$'],
                 #["Source", "source", r'[a-z\- ]+'],
                 ["Blacklisted, Y|N", "blacklisted", r'^(?:N|Y)$'], ["Prepend a Comment", "comment", ''], ["Allow Rerun for this target by source, Y|N", "allow_rerun", r'^(?:N|Y)$'])
HEADER_NAMES = [['Row #', 'PID', 'Target', 'Queued-Up Time', 'Started Running Time', 'End Time', 'Scope', 'Location', 'Source', 'Blacklisted', 'Allow Rerun', 'Queued', 'Running', 'Finished', 'Parsed', 'Failed', 'Comment', 'Output File Path', 'Modified By', 'Modified Date']] #'Celery Info',
COLUMN_NAMES = ['id', 'pid', 'target', 'start_time', 'run_time', 'end_time', 'entry', 'name', 'source', 'blacklisted', 'allow_rerun', 'queued', 'running', 'finished', 'parsed', 'failed', 'comment', 'output_filepath', 'modified_by', 'modified_date'] #'celery_info',
JOIN_TABLES = ["Scope.entry", "Scope.Location.name"]


class LogEntry(MiddleMan):
    """
    View, add or remove Logs. Adding/removing only for testing purposes.
    """
    def __init__(self, db_object, full_client_engagement_path):
        MiddleMan.__init__(self, db_object, full_client_engagement_path, DB_TABLE_NAME, MANUAL_FIELDS, COLUMN_NAMES, HEADER_NAMES)
        GenericResult.__init__(self, db_object, full_client_engagement_path, DB_TABLE_NAME, MANUAL_FIELDS, COLUMN_NAMES, HEADER_NAMES, JOIN_TABLES)
        return

    def __enter__(self):
        return self

    def __exit__(self, type, value, traceback):
        return self

    def join_view(self):
        """ Overwrite join_view in entry_db_middleman.py """
        return MiddleMan.join_view(self, JOIN_TABLES)

    def join_view_filter(self):
        """ Overwrite join_view in entry_db_middleman.py """
        return GenericResult.join_view_filter(self)

    def update(self):
        """ Overwrite update in entry_db_middleman.py. """
        return MiddleMan.update(self, JOIN_TABLES)

    def delete(self):
        """ Overwrite delete in entry_db_middleman.py. """
        return MiddleMan.delete(self, JOIN_TABLES)

    def add(self):
        """ Overwrite add in entry_db_middleman.py """

        try:
            scopes = self.db_object.dictionary_list("Scope", "entry")
            scopes_count_numbers = self.db_object.dictionary_list("Scope", "id")

            if len(scopes) == 1:
                scope_id = scopes_count_numbers[0]
            else:
                with Selection('Select the Scope of this entry', scopes, None) as selection:
                    scope_id = selection.select_option(scopes_count_numbers)

            scope_info = self.db_object.get("Scope", None, ["id"], [scope_id], True)
            scope_entry = scope_info["entry"]
            location_id = scope_info["location_id"]

            with Entry(self.DB_TABLE_NAME, ADD_MANUAL_FIELDS, ADD_REQUIRED) as me:
                field_values = me.user_input_fields(input_text='Please enter the ')

            if field_values['target'].strip() == "":
                field_values['target'] = scope_entry
            field_values['start_time'] = str(datetime.datetime.now())
            field_values['end_time'] = field_values['start_time']
            field_values['scope'] = scope_id
            field_values['location_id'] = location_id

            number_rows_added = self.db_object.add(self.DB_TABLE_NAME, field_values)
            return number_rows_added
        except Exception as e:
            print("except: " + str(e) + " Error on line {}".format(sys.exc_info()[-1].tb_lineno))

        return -1