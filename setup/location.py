from common.entry_db_middle_man import MiddleMan
from common.selection import Selection
from common.manual import Entry

DB_TABLE_NAME = "Location"
MANUAL_FIELDS = [["Name", "name", r'^(?:[a-zA-Z_0-9\. -]+)$']]
HEADER_NAMES = [['Row #', 'Name', 'Modified By', 'Modified Date']]
COLUMN_NAMES = ['id', 'name', 'modified_by', 'modified_date']


class Location(MiddleMan):
    """
    Add or remove Location. For all engagements there
	should be at least one Client Contact, namely the 'tester'.
	These contacts then have the option to receive email updates during testing.
    """
    def __init__(self, db_object, full_client_engagement_path):
        MiddleMan.__init__(self, db_object, full_client_engagement_path, DB_TABLE_NAME, MANUAL_FIELDS, COLUMN_NAMES, HEADER_NAMES)
        return

    def __enter__(self):
        return self

    def __exit__(self, type, value, traceback):
        return self


    def delete(self, join_tables=None):
        """ Override normal delete. """

        number_entries = self.db_object.count_records(self.DB_TABLE_NAME)

        if number_entries > 200:
            with Selection('There are more than 200 records in this table, select the column to filter the records on',
                           self.HEADER_NAMES[0], None) as selection:
                column_id = selection.select_option()

            manual_fields = [
                ['the search string for column ' + self.HEADER_NAMES[0][int(column_id) - 1] + ' to filter the records',
                 self.COLUMN_NAMES[int(column_id) - 1], ''],
                [
                    'Y - that records must match exactly your string or N - your string can be contained within a records ' +
                    self.COLUMN_NAMES[int(column_id) - 1] + " column", 'equal', r'^(?:Y|N)$']]
            with Entry(self.DB_TABLE_NAME, manual_fields) as me:
                field_values = me.user_input_fields(input_text='Please enter ')

            equal = field_values['equal']

            selected_record, selected_record_num = self.db_object.select_to_edit_or_delete(self.DB_TABLE_NAME,
                                                            self.COLUMN_NAMES, self.HEADER_NAMES, "delete", join_tables,
                                                            self.COLUMN_NAMES[int(column_id) - 1],
                                                            field_values[self.COLUMN_NAMES[int(column_id) - 1]], equal)
        else:
            selected_record, selected_record_num = self.db_object.select_to_edit_or_delete(self.DB_TABLE_NAME,
                                                            self.COLUMN_NAMES, self.HEADER_NAMES, "delete", join_tables)

        # Update CurrentLocation(TestingLocation) where matches to be 'all_locations
        self.db_object.update("CurrentLocation", {'current_location': 'all_locations'}, ["current_location"], [str(selected_record_num)], True)

        # Now actually delete Location
        self.db_object.delete(self.DB_TABLE_NAME, selected_record_num)