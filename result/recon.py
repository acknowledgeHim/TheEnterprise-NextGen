from result.result_class import GenericResult

DB_TABLE_NAME = "Recon"
MANUAL_FIELDS = [["Record", "record", ''], ["Type (A|CNAME|DNS|NS|MX|SPF|TXT|DMARC|DKIM|SOA)", "recon_type", r'^(?:CNAME|DNS|NS|MX|A|SPF|TXT|DMARC|DKIM|SOA)$'], ["Source", "source", ''],
                 ["Info", "info", ''], ["Associated Info", "associated_info", ''], ["Description", "recon_description", '']]
HEADER_NAMES = [['Row #', 'Scope', 'Type', 'Record', 'Info', 'Associated Info', 'Description', 'Organization', 'Source', 'Modified By', 'Modified Date']]
COLUMN_NAMES = ['id', 'entry', 'recon_type', 'record', 'info', 'associated_info', 'recon_description', 'organization', 'source', 'modified_by', 'modified_date']
JOIN_TABLES = ["Scope.entry"]


class Recon(GenericResult):
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

