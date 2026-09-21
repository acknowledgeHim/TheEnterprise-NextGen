from result.result_class import GenericResult

DB_TABLE_NAME = "Person"
MANUAL_FIELDS = [["Organization", "organization", ''], ["Full Name", "full_name", ''], ["Email", "email", ''],
                 ["Info", "person_info", ''], ["Associated Info", "associated_info", ''],
                 ["Description", "person_description", ''], ['Title', 'title', ''], ['Phone', 'phone', ''],
                 ['Address', 'full_address', ''], ['Vendor', 'vendor', r'^(?:Y|N)$'],
                 ['Client', 'client', r'^(?:Y|N)$'], ['Source', 'source', '']]
HEADER_NAMES = [['Row #', 'Location', 'Organization', 'Name', 'Email', 'Info', 'Associated Info', 'Description', 'Title', 'Vendor',
                 'Client', 'Address', 'Phone', 'Source', 'Modified By', 'Modified Date']]
COLUMN_NAMES = ['id', 'name', 'organization', 'full_name', 'email', 'person_info', 'associated_info', 'person_description', 'title',
                'vendor', 'client', 'full_address', 'phone', 'source', 'modified_by', 'modified_date']
JOIN_TABLES = ["Location.name"]

class Person(GenericResult):
    def __init__(self, db_object, full_client_engagement_path):
        GenericResult.__init__(self, db_object, full_client_engagement_path, DB_TABLE_NAME, MANUAL_FIELDS, COLUMN_NAMES, HEADER_NAMES, JOIN_TABLES)

    def __enter__(self):
        return self

    def __exit__(self, type, value, traceback):
        return self

    def join_view(self):
        return GenericResult.join_view(self)

    def join_view_filter(self):
        """ Overwrite join_view in entry_db_middleman.py """
        return GenericResult.join_view_filter(self)

    def add(self):
        return GenericResult.add(self, True)

    def update(self):
        return GenericResult.update(self, True)

    def delete(self):
        return GenericResult.delete(self)

