import os, sys
from common.entry_db_middle_man import MiddleMan
from common.manual import Entry
from common.selection import Selection
from common.database_object import OurCoolDBObject
from common import encryption

DB_TABLE_NAME = "FlaskUser"
MANUAL_FIELDS = [["Username", "username", ""],
                 ["Passphrase (must be at least 20 characters long)", "passwd", r'.{20,}']]

HEADER_NAMES = [['Row #', 'Username', 'Modified By', 'Modified Date']]
COLUMN_NAMES = ['id', 'username', 'modified_by', 'modified_date']


class FlaskUser(MiddleMan):
    """
    View, add or remove Flask Users. Adding/removing only for testing purposes.
    """

    def __init__(self, db_object, full_client_engagement_path):
        db_object = OurCoolDBObject(os.path.dirname(os.path.realpath(__file__)) + '/email_event.db', 'common.email_db_model')
        MiddleMan.__init__(self, db_object, full_client_engagement_path, DB_TABLE_NAME, MANUAL_FIELDS,
                           COLUMN_NAMES, HEADER_NAMES)
        return

    def __enter__(self):
        return self

    def __exit__(self, type, value, traceback):
        return self

    def add(self):
        """
        Uses manual.Entry to grab user input for fields to insert.
        Then passes user data to Interaction.add to insert into DB.
        Returns the number of rows added.
        """
        with Entry(self.DB_TABLE_NAME, self.MANUAL_FIELDS) as me:
            field_values = me.user_input_fields(input_text='Please enter the ')
        field_values['passwd'] = encryption.hash_string(field_values['passwd'])
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
            update_fields, row_num = self.db_object.select_to_edit_or_delete(self.DB_TABLE_NAME,
                                                           self.COLUMN_NAMES, self.HEADER_NAMES, "modify", join_tables)

            with Entry(self.DB_TABLE_NAME, self.MANUAL_FIELDS) as me:
                field_values = me.user_input_fields(update_fields, input_text='Please enter the')
            field_values['passwd'] = encryption.hash_string(field_values['passwd'])
            self.db_object.update(self.DB_TABLE_NAME, field_values)
        except Exception as e:
            print("flaskuser.py except: " + str(e) + " Error on line {}".format(sys.exc_info()[-1].tb_lineno))