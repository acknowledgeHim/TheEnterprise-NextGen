import sys
from common import print_text, network
from common.manual import Entry
from common.entry_db_middle_man import MiddleMan
from common.selection import Selection


DB_TABLE_NAME = "TesterDevice"
MANUAL_FIELDS = [["IP", "tester_ip", '']] #(((25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9])\.){3,3}(25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9]))|'
                              #r'((([0-9a-fA-F]{1,4}:){7,7}[0-9a-fA-F]{1,4}|([0-9a-fA-F]{1,4}:){1,7}:|'
                              #r'([0-9a-fA-F]{1,4}:){1,6}:[0-9a-fA-F]{1,4}|([0-9a-fA-F]{1,4}:){1,5}(:[0-9a-fA-F]{1,4}){1,2}|'
                              #r'([0-9a-fA-F]{1,4}:){1,4}(:[0-9a-fA-F]{1,4}){1,3}|([0-9a-fA-F]{1,4}:){1,3}(:[0-9a-fA-F]{1,4}){1,4}|'
                              #r'([0-9a-fA-F]{1,4}:){1,2}(:[0-9a-fA-F]{1,4}){1,5}|[0-9a-fA-F]{1,4}:((:[0-9a-fA-F]{1,4}){1,6})|'
                              #r':((:[0-9a-fA-F]{1,4}){1,7}|:)|fe80:(:[0-9a-fA-F]{0,4}){0,4}%[0-9a-zA-Z]{1,}|'
                              #r'::(ffff(:0{1,4}){0,1}:){0,1}((25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9])\.){3,3}(25[0-5]|(2[0-4]|'
                              #r'1{0,1}[0-9]){0,1}[0-9])|([0-9a-fA-F]{1,4}:){1,4}:((25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9])\.){3,3}(25[0-5]|'
                              #r'(2[0-4]|1{0,1}[0-9]){0,1}[0-9])))']

HEADER_NAMES = [['Row #', 'Location', 'IP', 'Modified By', 'Modified Date']]
COLUMN_NAMES = ['id', 'name', 'tester_ip', 'modified_by', 'modified_date']
JOIN_TABLES = ["Location.name"]

class TesterDevice(MiddleMan):
    """
    Add or remove Tester Device entries.
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
            testing_location = self.db_object.grab_current_location()
            if testing_location == "all_locations":
                locations = self.db_object.dictionary_list("Location", "name")
                count_numbers = self.db_object.dictionary_list("Location", "id")
            else:
                locations = self.db_object.dictionary_list("Location", "name", ['id'], [testing_location])
                count_numbers = self.db_object.dictionary_list("Location", "id", ['id'], [testing_location])

            if len(locations) > 0:
                number_rows_added = 0
                while True:
                    with Entry(self.DB_TABLE_NAME, self.MANUAL_FIELDS) as me:
                        field_values = me.user_input_fields(input_text='Please enter the')
                    if network.valid_ip(field_values['tester_ip']):
                        break
                    else:
                        print_text.print_error("\tYou did not enter a valid IP, try again!")
                if len(locations) == 1:
                    location_id = count_numbers[0]
                else:
                    with Selection('Select the Location of the Tester Device', locations, None) as selection:
                        location_id = selection.select_option(count_numbers)

                field_values['location_id'] = location_id
                number_rows_added = self.db_object.add(DB_TABLE_NAME, field_values)

                return number_rows_added
        except Exception as e:
            print_text.print_error("\tFailed to add Scope entry to database except: " + str(e) + " Error on line {}".format(sys.exc_info()[-1].tb_lineno))


    def join_view(self):
        """ Overwrite join_view in entry_db_middleman.py """
        return MiddleMan.join_view(self, JOIN_TABLES)


    def delete(self):
        """ Overwrite delete in entry_db_middleman.py. """
        return MiddleMan.delete(self, JOIN_TABLES)