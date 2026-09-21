from common.entry_db_middle_man import MiddleMan

DB_TABLE_NAME = "ClientContact"
MANUAL_FIELDS = [["Name", "contact_name", r'^(?:[a-zA-Z_ -]+)$'],
                 ["Email", "contact_email", r'^[a-zA-Z0-9._%+-]+@(?:[a-zA-Z0-9-]+\.)+[a-zA-Z]{2,}$'],
                 ["Title", "title", ''],
                 ["Email Notification, Y|N", "real_time_notification", r'^(?:Y|N)$']]
HEADER_NAMES = [['Row #', 'Title', 'Name', 'Email', 'Email Notification', 'Modified By', 'Modified Date']]
COLUMN_NAMES = ['id', 'title', 'contact_name', 'contact_email', 'real_time_notification', 'modified_by', 'modified_date']

class ClientContact(MiddleMan):
    """
    Add or remove Client contacts. For all engagements there
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
