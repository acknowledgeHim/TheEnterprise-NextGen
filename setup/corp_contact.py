from common.entry_db_middle_man import MiddleMan

DB_TABLE_NAME = "CorpContact"
MANUAL_FIELDS = [["Email", "email", r'^[a-zA-Z0-9._%+-]+@(?:[a-zA-Z0-9-]+\.)+[a-zA-Z]{2,}$'],
                      ["Email Notification, Y|N", "real_time_notification", r'^(?:Y|N)$'],
                      ["Client Relation - partner, principal, manager, or tester", "client_relation", r'^(?:partner|principal|manager|tester)$']]
COLUMN_NAMES = ['id', 'email', 'modified_by', 'real_time_notification', 'client_relation']
HEADER_NAMES = [['Row #', 'Email', 'Modified By', 'Email Notification', 'Relation']]


class CorpContact(MiddleMan):
    """
    Add or remove Corp contacts. For all engagements there
	should be at least one Corp Contact, namely the 'tester'.
	These contacts then have the option to receive email updates during testing.
    """
    def __init__(self, db_object, full_client_engagement_path):
        MiddleMan.__init__(self, db_object, full_client_engagement_path, DB_TABLE_NAME, MANUAL_FIELDS, COLUMN_NAMES, HEADER_NAMES)
        return

    def __enter__(self):
        return self

    def __exit__(self, type, value, traceback):
        return self
