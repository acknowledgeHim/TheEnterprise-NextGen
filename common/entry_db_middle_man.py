import sys
from common import print_text
from common.manual import Entry
from common.selection import Selection

class MiddleMan():
    """
    Setup View/Add/Update/Delete menu.
    View data when View selected from menu.
    Add data when Add selected from menu.
    Update data when Update selected from menu.
    Delete data when Delete selected from menu.

    Attributes:
        db_object -- SqlCipher object
        full_client_engagement -- full client/engagement output path (and where sqlcipher db is)
        DB_TABLE_NAME -- SqlCipher Table name
        MANUAL_FIELDS -- fields that user will be prompted to enter data for, if it can be false, and regex expression that must match
        COLUMN_NAMES -- fields that represent actual DB column name (used in conjunction with HEADER_NAME to diplay DB records)
        HEADER_NAME -- used to print out results in Table Form, these are the table Column names
    """

    def __init__(self, db_object, full_client_engagement_path, DB_TABLE_NAME, MANUAL_FIELDS, COLUMN_NAMES, HEADER_NAMES, REQUIRED_FIELDS=None):
        self.db_object = db_object
        self.full_client_engagement_path = full_client_engagement_path
        self.DB_TABLE_NAME = DB_TABLE_NAME
        self.MANUAL_FIELDS = MANUAL_FIELDS
        self.COLUMN_NAMES = COLUMN_NAMES
        self.HEADER_NAMES = HEADER_NAMES
        self.REQUIRED_FIELDS = REQUIRED_FIELDS
        return

    def __enter__(self):
        return self

    def __exit__(self, type, value, traceback):
        return self

    def view(self):
        """
        Calls Interaction.view to display all database entries.
        """
        self.db_object.view_results_in_table(self.DB_TABLE_NAME, self.COLUMN_NAMES, self.HEADER_NAMES, None)

    def view_filter(self, filter_column=None, filter_value=None, equal=False):
        number_entries = self.db_object.count_records(self.DB_TABLE_NAME)

        if filter_column is None or filter_value is None:
            with Selection('Select the column to filter the records on',
                           self.HEADER_NAMES[0], None) as selection:
                column_id = selection.select_option()

            manual_fields = [
                ['the search string for column ' + self.HEADER_NAMES[0][int(column_id) - 1] + ' to filter the records', self.COLUMN_NAMES[int(column_id) - 1], ''],
                ['Y - that records must match exactly your string or N - your string can be contained within a records ' + self.COLUMN_NAMES[int(column_id) - 1] + " column", 'equal', r'^(?:Y|N)$']]
            with Entry(self.DB_TABLE_NAME, manual_fields) as me:
                field_values = me.user_input_fields(input_text='Please enter ')

            filter_columns = [self.COLUMN_NAMES[int(column_id) - 1]]
            filter_values = [field_values[self.COLUMN_NAMES[int(column_id) - 1]]]
            equal = field_values['equal']

            table_columns = self.db_object.table_column_names(self.DB_TABLE_NAME)

            join_tables = None

            # Filter by current testing location
            current_location = self.db_object.grab_current_location()
            if "location_id" in table_columns:
                if current_location != "all_locations":
                    filter_columns.append("location_id")
                    filter_values.append(int(current_location))
            elif "scope_id" in table_columns:
                join_tables = ["Scope.entry"]
                if current_location != "all_locations":
                    filter_columns.append("Scope.location_id")
                    filter_values.append(int(current_location))
            elif "engagementdevice_id" in table_columns:
                join_tables = ["Scope.entry", "Location.name"]
                if current_location != "all_locations":
                    filter_columns.append("EngagementDevice.Scope.location_id")
                    filter_values.append(int(current_location))

        self.db_object.view_results_in_table(self.DB_TABLE_NAME, self.COLUMN_NAMES, self.HEADER_NAMES, join_tables, filter_columns, filter_values, equal)

    def join_view(self, join_tables):
        """
        Calls Interaction.join_view to display all database entries.
        """
        try:
            number_entries = self.db_object.count_records(self.DB_TABLE_NAME)

            filter_columns = []
            filter_values = []
            equal = "Y"
            table_columns = self.db_object.table_column_names(self.DB_TABLE_NAME)

            # Filter by current testing location
            current_location = self.db_object.grab_current_location()
            if "location_id" in table_columns:
                if current_location != "all_locations":
                    filter_columns.append("location_id")
                    filter_values.append(int(current_location))
            elif "scope_id" in table_columns:
                if current_location != "all_locations":
                    filter_columns.append("Scope.location_id")
                    filter_values.append(int(current_location))
            elif "engagementdevice_id" in table_columns:
                if current_location != "all_locations":
                    filter_columns.append("EngagementDevice.Scope.location_id")
                    filter_values.append(int(current_location))

            if number_entries > 200:
                with Selection('There are more than 200 records in this table, select the column to filter the records on', self.HEADER_NAMES[0], None) as selection:
                    column_id = selection.select_option()

                manual_fields = [['the search string for column ' + self.HEADER_NAMES[0][int(column_id)-1] + ' to filter the records', self.COLUMN_NAMES[int(column_id) - 1], ''],
                                 ['Y - that records must match exactly your string or N - your string can be contained within a records ' + self.COLUMN_NAMES[int(column_id) - 1] + " column", 'equal', r'^(?:Y|N)$']]
                with Entry(self.DB_TABLE_NAME, manual_fields) as me:
                    field_values = me.user_input_fields(input_text='Please enter ')

                equal = field_values['equal']
                filter_columns.append(self.COLUMN_NAMES[int(column_id)-1])
                filter_values.append(field_values[self.COLUMN_NAMES[int(column_id)-1]])

            if len(filter_columns) > 0 and len(filter_values) > 0:
                self.db_object.view_results_in_table(self.DB_TABLE_NAME, self.COLUMN_NAMES, self.HEADER_NAMES, join_tables, filter_columns, filter_values, equal)
            else:
                self.db_object.view_results_in_table(self.DB_TABLE_NAME, self.COLUMN_NAMES, self.HEADER_NAMES, join_tables)

            print_text.print_msg("Total of " + str(number_entries) + " records in the repository.")
        except Exception as e:
            print("entry db middle man 68 except: " + str(e) + " Error on line {}".format(sys.exc_info()[-1].tb_lineno))

    def join_view_filter(self, join_tables):
        """
        Calls Interaction.join_view to display all database entries.
        """
        try:
            number_entries = self.db_object.count_records(self.DB_TABLE_NAME)

            with Selection('Select the column to filter the records on', self.HEADER_NAMES[0], None) as selection:
                column_id = selection.select_option()

            manual_fields = [['the search string for column ' + self.HEADER_NAMES[0][int(column_id)-1] + ' to filter the records', self.COLUMN_NAMES[int(column_id) - 1], ''],
                             ['Y - that records must match exactly your string or N - your string can be contained within a records ' + self.COLUMN_NAMES[int(column_id) - 1] + " column", 'equal', r'^(?:Y|N)$']]
            with Entry(self.DB_TABLE_NAME, manual_fields) as me:
                field_values = me.user_input_fields(input_text='Please enter ')

            equal = field_values['equal']

            filter_columns = [self.COLUMN_NAMES[int(column_id)-1]]
            filter_values = [field_values[self.COLUMN_NAMES[int(column_id)-1]]]

            table_columns = self.db_object.table_column_names(self.DB_TABLE_NAME)

            # Filter by current testing location
            current_location = self.db_object.grab_current_location()
            if "location_id" in table_columns:
                if current_location != "all_locations":
                    filter_columns.append("location_id")
                    filter_values.append(int(current_location))
            elif "scope_id" in table_columns:
                if "Scope.entry" not in join_tables:
                    join_tables.append("Scope.entry")
                if current_location != "all_locations":
                    filter_columns.append("Scope.location_id")
                    filter_values.append(int(current_location))
            elif "engagementdevice_id" in table_columns:
                if "Scope.entry" not in join_tables:
                    join_tables.append("Scope.entry")
                if "Scope.Location.name" not in join_tables:
                    join_tables.append("Scope.Location.name")
                if current_location != "all_locations":
                    filter_columns.append("EngagementDevice.Scope.location_id")
                    filter_values.append(int(current_location))

            self.db_object.view_results_in_table(self.DB_TABLE_NAME, self.COLUMN_NAMES, self.HEADER_NAMES, join_tables, filter_columns, filter_values, equal)

            print_text.print_msg("Total of " + str(number_entries) + " records in the repository.")
        except Exception as e:
            print("entry db middle man 68 except: " + str(e) + " Error on line {}".format(sys.exc_info()[-1].tb_lineno))


    def add(self):
        """
        Uses manual.Entry to grab user input for fields to insert.
        Then passes user data to Interaction.add to insert into DB.
        Returns the number of rows added.
        """
        with Entry(self.DB_TABLE_NAME, self.MANUAL_FIELDS, self.REQUIRED_FIELDS) as me:
            field_values = me.user_input_fields(input_text='Please enter the ')
        number_rows_added = self.db_object.add(self.DB_TABLE_NAME, field_values)
        return number_rows_added

    def update(self, join_tables=None):
        """
        Grabs all records from DB to display so user can select which record to edit.
        Users selects record.
        Uses manual.Entry to ask for updated values for each field.
        Saves changes to DB using Interaction.update
        """
        try:
            number_entries = 0
            number_entries = self.db_object.count_records(self.DB_TABLE_NAME)

            if number_entries > 200:
                with Selection('There are more than 200 records in this table, select the column to filter the records on',
                        self.HEADER_NAMES[0], None) as selection:
                    column_id = selection.select_option()

                manual_fields = [['the search string for column ' + self.HEADER_NAMES[0][int(column_id) - 1] + ' to filter the records', self.COLUMN_NAMES[int(column_id) - 1], ''],
                    ['Y - that records must match exactly your string or N - your string can be contained within a records ' + self.COLUMN_NAMES[int(column_id) - 1] + " column", 'equal', r'^(?:Y|N)$']]
                with Entry(self.DB_TABLE_NAME, manual_fields) as me:
                    field_values = me.user_input_fields(input_text='Please enter ')

                equal = field_values['equal']

                update_fields, row_num = self.db_object.select_to_edit_or_delete(self.DB_TABLE_NAME,
                                                           self.COLUMN_NAMES, self.HEADER_NAMES, "delete", join_tables,
                                                           self.COLUMN_NAMES[int(column_id) - 1],
                                                           field_values[self.COLUMN_NAMES[int(column_id) - 1]], equal)
            else:
                update_fields, row_num = self.db_object.select_to_edit_or_delete(self.DB_TABLE_NAME,
                                                           self.COLUMN_NAMES, self.HEADER_NAMES, "modify", join_tables)

            with Entry(self.DB_TABLE_NAME, self.MANUAL_FIELDS) as me:
                field_values = me.user_input_fields(update_fields, input_text='Please enter the')

            self.db_object.update(self.DB_TABLE_NAME, field_values)
        except Exception as e:
            print("entry db middle man 81 except: " + str(e) + " Error on line {}".format(sys.exc_info()[-1].tb_lineno))

    def update_where(self, passed_table_name):
        try:
            number_entries = self.db_object.count_records(self.DB_TABLE_NAME)

            with Selection('Please select the field/column you want to use to filter the items to update',
                    self.HEADER_NAMES[0], None) as selection:
                column_id = selection.select_option()

            manual_fields = [
                ['the value for ' + self.HEADER_NAMES[0][int(column_id) - 1] + ' entries must match to be updated', self.COLUMN_NAMES[int(column_id) - 1], ''],
                ['either equal: match supplied value, notequal: match everything but supplied value, or like: match any that the supplied value is found in ' +
                    self.COLUMN_NAMES[int(column_id) - 1] + " column", 'equal', r'^(?:equal|notequal|like)$'],
                ['the string to update the selected records with', 'update_string', '']]
            required_fields = [self.COLUMN_NAMES[int(column_id) - 1], 'equal', 'update_string']
            with Entry(self.DB_TABLE_NAME, manual_fields, required_fields) as me:
                field_values = me.user_input_fields(input_text='Please enter ')

            with Selection('Please select the field/column you want to update', self.HEADER_NAMES[0], None) as selection:
                update_column_id = selection.select_option()

            equal = field_values['equal']
            if equal == "equal":
                equal = True
            elif equal == "notequal":
                equal = None
            elif equal == "like":
                equal = False
            else:
                print_text.print_msg("You didn't select a proper action to perform.  Try again.")
                return

            if passed_table_name is None:
                passed_table_name = self.DB_TABLE_NAME

            # Print off how many records will be deleted and ask, are you sure?
            records = self.db_object.view(passed_table_name, None, [self.COLUMN_NAMES[int(column_id) - 1]],
                                         [field_values[self.COLUMN_NAMES[int(column_id) - 1]]], equal)

            # make them validate that they want to do this
            with Entry(self.DB_TABLE_NAME, (["Y if you are sure you want to update the " + str(len(entries)) + " matching records in " + self.DB_TABLE_NAME, "validate", r'^(?:Y|N)$'],)) as me:
                validate_field_values = me.user_input_fields(input_text='Please enter ')

            if validate_field_values["validate"] is True:
                for record in records:
                    record[self.COLUMN_NAMES[int(update_column_id) - 1]] = field_values['update_string']
                    self.db_object.update(self.DB_TABLE_NAME, record)
        except Exception as e:
            print("entry db middle man except: " + str(e) + " Error on line {}".format(sys.exc_info()[-1].tb_lineno))

    def delete_where(self, join_tables=None):
        """
        Displays current entries.
        Deletes user selected entry.
        """
        try:
            number_entries = self.db_object.count_records(self.DB_TABLE_NAME)

            with Selection('Please select the field/column you want to use to filter the items to delete \n(Ex. to delete all Scope permissions that = "N" select the permissions field)',
                           self.HEADER_NAMES[0], None) as selection:
                column_id = selection.select_option()

            manual_fields = [
                ['the value for ' + self.HEADER_NAMES[0][int(column_id) - 1] + ' entries must match to be deleted',
                 self.COLUMN_NAMES[int(column_id) - 1], ''],
                ['either equal: match supplied value, notequal: match everything but supplied value, or like: match any that the supplied value is found in ' +
                    self.COLUMN_NAMES[int(column_id) - 1] + " column", 'equal', r'^(?:equal|notequal|like)$']]
            with Entry(self.DB_TABLE_NAME, manual_fields) as me:
                field_values = me.user_input_fields(input_text='Please enter ')

            equal = field_values['equal']
            if equal == "equal":
                equal = True
            elif equal == "notequal":
                equal = None
            elif equal == "like":
                equal = False
            else:
                print_text.print_msg("You didn't select a proper action to perform.  Try again.")
                return

            # Print off how many records will be deleted and ask, are you sure?
            entries = self.db_object.view(self.DB_TABLE_NAME, None, [self.COLUMN_NAMES[int(column_id) - 1]],
                                         [field_values[self.COLUMN_NAMES[int(column_id) - 1]]], equal)

            # make them validate that they want to do this
            if entries is not None and len(entries) > 0:
                with Entry(self.DB_TABLE_NAME, (["Y if you are sure you want to delete the " + str(len(entries)) + " matching records in " + self.DB_TABLE_NAME, "validate", r'^(?:Y|N)$'],)) as me:
                    validate_field_values = me.user_input_fields(input_text='Please enter ')

                if validate_field_values["validate"] == True:
                    # Get list of all IDs to delete
                    ids = self.db_object.dictionary_list(self.DB_TABLE_NAME, "id", [self.COLUMN_NAMES[int(column_id) - 1]], [field_values[self.COLUMN_NAMES[int(column_id) - 1]]], equal)
                    # delete each record by ID (otherwise locks up when doing multiple delete with foreign key check deleting)
                    for id in ids:
                        self.db_object.delete(self.DB_TABLE_NAME, id)
            else:
                print_text.print_msg("Your search did not match any records so none were deleted.")
        except Exception as e:
            print("entry db middle 283 except: " + str(e) + " Error on line {}".format(sys.exc_info()[-1].tb_lineno))

    def delete(self, join_tables=None):
        """
        Displays current entries.
        Deletes user selected entry.
        """
        number_entries = self.db_object.count_records(self.DB_TABLE_NAME)

        if number_entries > 200:
            with Selection('There are more than 200 records in this table, select the column to filter the records on',
                           self.HEADER_NAMES[0], None) as selection:
                column_id = selection.select_option()

            manual_fields = [
                ['the search string for column ' + self.HEADER_NAMES[0][int(column_id) - 1] + ' to filter the records',
                 self.COLUMN_NAMES[int(column_id) - 1], ''],
                ['Y - that records must match exactly your string or N - your string can be contained within a records ' +
                    self.COLUMN_NAMES[int(column_id) - 1] + " column", 'equal', r'^(?:Y|N)$']]
            with Entry(self.DB_TABLE_NAME, manual_fields) as me:
                field_values = me.user_input_fields(input_text='Please enter ')

            equal = field_values['equal']

            filter_columns = [self.COLUMN_NAMES[int(column_id) - 1]]
            filter_values = [field_values[self.COLUMN_NAMES[int(column_id) - 1]]]

            table_columns = self.db_object.table_column_names(self.DB_TABLE_NAME)
            # Filter by current testing location
            current_location = self.db_object.grab_current_location()
            if "location_id" in table_columns:
                if current_location != "all_locations":
                    filter_columns.append("location_id")
                    filter_values.append(int(current_location))
            elif "scope_id" in table_columns:
                if "Scope.entry" not in join_tables:
                    join_tables.append("Scope.entry")
                if current_location != "all_locations":
                    filter_columns.append("Scope.location_id")
                    filter_values.append(int(current_location))
            elif "engagementdevice_id" in table_columns:
                if "Scope.entry" not in join_tables:
                    join_tables.append("Scope.entry")
                if "Scope.Location.name" not in join_tables:
                    join_tables.append("Scope.Location.name")
                if current_location != "all_locations":
                    filter_columns.append("EngagementDevice.Scope.location_id")
                    filter_values.append(int(current_location))

            if len(filter_columns) == 0:
                filter_columns = None
                filter_values = None

            selected_record, selected_record_num = self.db_object.select_to_edit_or_delete(self.DB_TABLE_NAME,
                                                       self.COLUMN_NAMES, self.HEADER_NAMES, "delete", join_tables,
                                                       filter_columns, filter_values, equal)
        else:
            filter_columns = []
            filter_values = []
            table_columns = self.db_object.table_column_names(self.DB_TABLE_NAME)
            # Filter by current testing location
            current_location = self.db_object.grab_current_location()
            if "location_id" in table_columns:
                if current_location != "all_locations":
                    filter_columns.append("location_id")
                    filter_values.append(int(current_location))
            elif "scope_id" in table_columns:
                if "Scope.entry" not in join_tables:
                    join_tables.append("Scope.entry")
                if current_location != "all_locations":
                    filter_columns.append("Scope.location_id")
                    filter_values.append(int(current_location))
            elif "engagementdevice_id" in table_columns:
                if "Scope.entry" not in join_tables:
                    join_tables.append("Scope.entry")
                if "Scope.Location.name" not in join_tables:
                    join_tables.append("Scope.Location.name")
                if current_location != "all_locations":
                    filter_columns.append("EngagementDevice.Scope.location_id")
                    filter_values.append(int(current_location))
            if len(filter_columns) == 0:
                filter_columns = None
                filter_values = None

            selected_record, selected_record_num = self.db_object.select_to_edit_or_delete(self.DB_TABLE_NAME,
                                                           self.COLUMN_NAMES, self.HEADER_NAMES, "delete", join_tables,
                                                           filter_columns, filter_values)

        self.db_object.delete(self.DB_TABLE_NAME, selected_record_num)

    def truncate(self):
        """ Delete all records in table. """

        # make them validate that they want to do this
        with Entry(self.DB_TABLE_NAME, (["Y if you are sure you want to delete all records in " + self.DB_TABLE_NAME, "validate", r'^(?:Y|N)$'],)) as me:
            field_values = me.user_input_fields(input_text='Please enter ')

        if field_values["validate"] == True:
            self.db_object.truncate(self.DB_TABLE_NAME)
        else:
            print_text.print_msg("\t Records not deleted as you did not validate that you wanted them all deleted.")
