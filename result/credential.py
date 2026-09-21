from result.result_class import GenericResult

DB_TABLE_NAME = "Credential"
MANUAL_FIELDS = [["Status", "status", r'^(?:current|history)$'], ["Domain", "domain", ''], ["Username", "username", r'[a-zA-Z_0-9\-\/\:\.]+'],
                 ["Password", "passwd", ''], ["Salted Hash", "salted_hash", ''], ["Hash value", "hash_value", ''],
                 ["Hash type", "hash_type", ''], ["Amount of Time to crack", "amount_of_time_to_crack", ''],
                 ["Disabled", "disabled", r'^(?:Y|N)$'], ["Password last set", "pwdlastset", ''],
                 ["Password not expire", "pwdnotexpire", r'^(?:Y|N)$'],
                 ["Comment", "comment", ''], ["Additional", "additional", ''], ["Local Admin", "la", r'^(?:Y|N)$'],
                 ["Domain Admin", "da", r'^(?:Y|N)$'], ["Source", "credential_source", r'[a-zA-Z_0-9\-\/\:\.]+'],
                 ["Validated", "validated_credential", r'^(?:Y|N)$'], ["Service", "service", '']]
HEADER_NAMES = [['Row #', 'EngagementDevice', 'Status', 'Service', 'Domain', 'Username', 'Password', 'Salted Hash', 'Disabled', 'Pwd Last Set', 'DA', 'la', 'Modified By', 'Modified Date', 'Source']]
COLUMN_NAMES = ['id', 'target_name', 'status', 'service', 'domain', 'username', 'passwd', 'salted_hash', 'disabled', 'pwdlastset', 'da', 'la', 'modified_by', 'modified_date', 'credential_source']
JOIN_TABLES = ["EngagementDevice.target_name"]


class Credential(GenericResult):
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

