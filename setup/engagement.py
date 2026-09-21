import sys
from common import common
from setup import current_location
from common.manual import Entry
from common.entry_db_middle_man import MiddleMan


DB_TABLE_NAME = "Engagement"
MANUAL_FIELDS = [["Start Date, YYYY-MM-DD", "start_date",  r'^(?:[\d]{4}-[\d]{2}-[\d]{2})$'],
                      ["Expected Completion Date, YYYY-MM-DD", "expected_completion_date", r'^(?:[\d]{4}-[\d]{2}-[\d]{2})$'],
                      ["External IPs only, Y|N", 'external_only', r'^(?:N|Y)$'],
                      ["if you, the tester, should be emailed, Y|N", 'email_tester', r'^(?:N|Y)$'],
                      ["if Corporate Contacts should be emailed, Y|N", 'email_company_contact', r'^(?:N|Y)$'],
                      ["if Client Contacts should be emailed, Y|N", 'email_client_contact', r'^(?:N|Y)$'],
                      ["if tool already ran per scope item should be re-run, Y|N", 'rerun_tool', r'^(?:N|Y)$'],
                      ["if should automatically email notifications (must be able to hit your email server you setup in"
                            " enterprise_user_conf.py), Y|N", 'can_send_auto_notification', r'^(?:N|Y)$'],
                      ["if should create finding for open ports that are internet accessible and should not be (only "
                            "time you would not want this is if they use external IP ranges as internal ones), Y|N",
                            "create_finding_for_internet_openport", r'^(?:N|Y)$'],
                      ["External Identification", 'identification', ''],
                 ]
MORE_MANUAL_FIELDS = [["if tools should only base targets off live hosts (must do Scan/Ping 1st if so)", "base_results_off_live_hosts_ping", r'^(?:N|Y)$']]
HEADER_NAMES = [['Row #','Number','Name','Start Date','Expected Completion Date','Corp Email Notification','Client Email Notification','Rerun Tool', 'External Only', 'Tools use IPs only from LiveHosts', 'Open Port Findings']]
COLUMN_NAMES = ['id','client_number','client_name','start_date','expected_completion_date','email_company_contact','email_client_contact', 'rerun_tool', 'external_only', 'base_results_off_live_hosts_ping', 'create_finding_for_internet_openport']

#REQUIRED_FIELDS = ['start_date', 'expected_completion_date', 'external_only', 'email_tester', 'email_company_contact',
#                   'email_client_contact', 'rerun_tool', 'can_send_auto_notification',
#                   'create_finding_for_internet_openport']

REQUIRED_FIELDS = ['start_date', 'external_only', 'email_tester',
                   'rerun_tool', 'can_send_auto_notification',
                   'create_finding_for_internet_openport']

class Engagement(MiddleMan):
    """
    Add/Update/View Client/Engagement.
    """
    def __init__(self, db_object, full_client_engagement_path):
        MiddleMan.__init__(self, db_object, full_client_engagement_path, DB_TABLE_NAME, MANUAL_FIELDS, COLUMN_NAMES, HEADER_NAMES)
        self.db_object = db_object
        return

    def __enter__(self):
        return self

    def __exit__(self, type, value, traceback):
        return self

    def add(self, field_values_passed):
        """
        Override MiddleMan.add
        Must also create Information table info.
        """
        with Entry(DB_TABLE_NAME, MANUAL_FIELDS, REQUIRED_FIELDS) as me:
            field_values = me.user_input_fields(input_text='Please enter ')
            if field_values_passed != None:
                field_values = common.merge_two_dicts(field_values,field_values_passed)
        if field_values['external_only']:
            field_values['base_results_off_live_hosts_ping'] = False
        else:
            with Entry(DB_TABLE_NAME, MORE_MANUAL_FIELDS) as me:
                more_field_values = me.user_input_fields(input_text='Please enter ')
            field_values['base_results_off_live_hosts_ping'] = False
            if more_field_values['base_results_off_live_hosts_ping']:
                field_values['base_results_off_live_hosts_ping'] = True

        number_rows_added, hashval = self.db_object.add(DB_TABLE_NAME, field_values)

        # Current TheEnterprise Version (necessary in case tables, etc change in future releases)
        version_added, hashval = self.db_object.add("Information", {'version': '1.0'})

        # Add default 'main' location
        success, hashval = self.db_object.add("Location", {'name': 'main'})

        # Now assign current location as default 'main' location
        current_location.reset_current_testing_location(self.db_object)

        return number_rows_added

    def update(self):
        """
        Override MiddleMan.update
        Must also add client_name, client_number, id keys to field_values dict.
        """
        try:
            selected_record, selected_record_num = self.db_object.select_to_edit_or_delete(DB_TABLE_NAME, COLUMN_NAMES,
                                                                               HEADER_NAMES, "modify")
            ALL_MANUAL_FIELDS = MANUAL_FIELDS + MORE_MANUAL_FIELDS
            with Entry(DB_TABLE_NAME, ALL_MANUAL_FIELDS) as me:
                field_values = me.user_input_fields(selected_record, input_text='Please enter the')

            field_values['id'] = selected_record['id']
            field_values['client_name'] = selected_record['client_name']
            field_values['client_number'] = selected_record['client_number']
            self.db_object.update(DB_TABLE_NAME, field_values)
        except Exception as e:
            print("setup engagement 90 except: " + str(e) + " Error on line {}".format(sys.exc_info()[-1].tb_lineno))
        return
