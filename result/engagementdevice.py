from result.result_class import GenericResult

DB_TABLE_NAME = "EngagementDevice"
MANUAL_FIELDS = [["Target", "target_name", r'[a-zA-Z_0-9\-\/\:\.]+'],
                 ["IP", "target_ip", ''],
                 ["Domain", "domain", ''],
                 ["MAC", "mac", ''],
                 ["Information", "info", ''],
                 ["Anti-Virus", "av_present", ''],
                 ["Services", "services", ''],
                 ["Programs", "programs", ''],
                 ["Accounts", "accounts", ''],
                 ["Source", "source", r'[a-zA-Z_0-9\-\/\:\.]+']]
HEADER_NAMES = [['Row #', 'Scope', 'Location', 'Target', 'IP', 'Domain', 'OS', 'MAC', 'Info', 'AV', 'Services', 'Programs', 'Accounts', 'Source', 'Modified By', 'Modified Date']]
COLUMN_NAMES = ['id', 'entry', 'name', 'target_name', 'target_ip', 'domain', 'os', 'mac', 'info', 'av_present', 'services', 'programs', 'accounts', 'source', 'modified_by', 'modified_date']
JOIN_TABLES = ["Scope.Location.name", "Scope.entry"]


class EngagementDevice(GenericResult):
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
        return GenericResult.add(self)

    def update(self):
        return GenericResult.update(self)

    def delete(self):
        return GenericResult.delete(self)

