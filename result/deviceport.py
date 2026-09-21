from enterprise_conf import IP_REGEX
from result.result_class import GenericResult

DB_TABLE_NAME = "DevicePort"
MANUAL_FIELDS = [["IP", "ip", r'[0-9a-zA-Z\.\:]{7,}'],
                 ["Port", "port", r'^(?:[\d]+)$'],
                 ["Protocol (tcp/udp)", "protocol", r'^(?:tcp|udp)$'],
                 ["Description", "port_description", ''],
                 ["Stealth (Y|N)", "stealth", r'^(?:Y|N)$'],
                 ["Source", "source", r'^(?:[a-zA-Z_0-9\-\/\:\. ]+)$'],
                 ["Validated (Y|N)", "validated", r'^(?:Y|N)$']]
HEADER_NAMES = [['Row #', 'Scope', 'Location', 'Engagement Device', 'IP', 'Port', 'Protocol', 'Description', 'Start Time', 'End Time', 'Stealth', 'Source', 'Validated', 'Modified By', 'Modified Date']]
COLUMN_NAMES = ['id', 'entry', 'name', 'target_name', 'ip', 'port', 'protocol', 'port_description', 'start_time', 'end_time', 'stealth', 'source', 'validated', 'modified_by', 'modified_date']
JOIN_TABLES = ["EngagementDevice.Scope.Location.name", "EngagementDevice.Scope.entry", "EngagementDevice.target_name"]


class DevicePort(GenericResult):
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

