import sys
from common import print_text, common
from setup import current_location
from common.entry_db_middle_man import MiddleMan

DB_TABLE_NAME = "CurrentLocation"
MANUAL_FIELDS = [None]
HEADER_NAMES = [['Row #', 'Current Location to Test', 'User']]
COLUMN_NAMES = ['id', 'current_location', 'modified_by']
JOIN_TABLES = ["Location.name"]

class TestingLocation(MiddleMan):
    """
    View current location to test and/or change it.
    """
    def __init__(self, db_object, full_client_engagement_path):
        MiddleMan.__init__(self, db_object, full_client_engagement_path, DB_TABLE_NAME, MANUAL_FIELDS, COLUMN_NAMES, HEADER_NAMES)
        self.db_object = db_object
        return

    def __enter__(self):
        return self

    def __exit__(self, type, value, traceback):
        return self

    def join_view(self):
        """ Overwrite join_view in entry_db_middleman.py """
        return MiddleMan.join_view(self, JOIN_TABLES)

    def custom_view(self):
        try:
            info = self.db_object.get(DB_TABLE_NAME, ["modified_by"], [common.get_tester()])
            current_location = info["current_location"]
            modified_by = info["modified_by"]

            if current_location != "all_locations":
                current_location = self.db_object.grab_column_from_single_record("Location", ["id"], [int(current_location)], "name")

            results = [[1, current_location, modified_by]]
            print_text.console_table_view(DB_TABLE_NAME, HEADER_NAMES, results)

        except Exception as e:
            print("testing location 58 except: " + str(e) + " Error on line {}".format(sys.exc_info()[-1].tb_lineno))

    def switch(self):
        current_location.reset_current_testing_location(self.db_object)
