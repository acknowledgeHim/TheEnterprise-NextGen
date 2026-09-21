from result.result_class import GenericResult

DB_TABLE_NAME = "Result"
MANUAL_FIELDS = [["Title", "finding_title", ''], ["Description", "finding_description", ''],
                 ["Remediaton", "finding_remediation", ''], ["CVSS", "finding_cvss", ''], ["severity", "finding_severity", ''],
                 ["classification", "finding_classification", ''], ["Target", "target", ''], ["Port", "port", r'[\d]'],
                 ["Protocol (tcp|udp)", "protocol", r'^(?:tcp|udp)$'], ["Output", "output", ''], ["Tool", "tool", ''],
                 ["Exploits available", "finding_exploits_available", ""],
                 ["Patch Publication Date (YYYY-MM-DD)", "finding_patch_publication_date", ""],
                 ['Tester Output', 'tester_output', ''], ['Command', 'command', '']]
HEADER_NAMES = [['Row #', 'Scope', 'Location', 'Finding', 'Target', 'Port', 'Protocol', 'Output', 'Tester Output', 'Modified By', 'Modified Date', 'Source']]
COLUMN_NAMES = ['id', 'entry', 'name', 'finding_title', 'target', 'port', 'protocol', 'output', 'tester_output', 'modified_by', 'modified_date', 'tool']
JOIN_TABLES = ["EngagementDevice.Scope.entry", "EngagementDevice.Scope.Location.name"]


class Result(GenericResult):
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

