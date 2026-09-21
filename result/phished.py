from result.result_class import GenericResult

DB_TABLE_NAME = "Phishing"
MANUAL_FIELDS = [["SMTP To", "smtp_to", ''], ["Data To", "data_to", ''], ["Received Response", "received_response", '']]
HEADER_NAMES = [['Row #', 'Location', 'Scenario', 'SMTP To', 'Data To', 'Received Response', 'Modified By', 'Modified Date']]
COLUMN_NAMES = ['id', 'name', 'scenario', 'smtp_to', 'data_to', 'received_response', 'modified_by', 'modified_date']
JOIN_TABLES = ["Location.name", "PhishingScenario.scenario"]


class PhishingResult(GenericResult):
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
        return GenericResult.add(self, False)

    def update(self):
        return GenericResult.update(self, True)

    def delete(self):
        return GenericResult.delete(self)

