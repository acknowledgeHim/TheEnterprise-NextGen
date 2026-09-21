from common.entry_db_middle_man import MiddleMan
from tools.attack.email_phish_setup import EmailPhishingSetup

SCENARIO_DB_TABLE_NAME = "PhishingScenario"
SCENARIO_COLUMN_NAMES = ['id', 'scenario_file', 'scenario', 'email_server', 'email_filter_tests_used', 'subject', 'phish_url', 'delay_between_emails', 'smtp_from', 'data_from', 'modified_by']
SCENARIO_HEADER_NAMES = [['Row #', 'File', 'Scenario', 'Email Server', 'Email Tests To Use', 'Subject', 'Phishing URL', 'Delay Between Emails', 'SMTP FROM', 'DATA FROM', 'Modified By']]

DB_TABLE_NAME = "Phishing"
MANUAL_FIELDS = [["email server", "email_server", ""]]
COLUMN_NAMES = ['id', 'name', 'scenario', 'sent_to', 'smtp_to', 'data_to', 'modified_by']
HEADER_NAMES = [['Row #', 'Location', 'Scenario', 'Sent To', 'SMTP To', 'Data To', 'Modified By']]
JOIN_TABLES = ["Location.name", "PhishingScenario.scenario"]


class GoPhish(MiddleMan):
    """
    Add or remove Email Phishing Scenarios.
    """
    def __init__(self, db_object, full_client_engagement_path):
        self.db_object = db_object
        self.full_client_engagement_path = full_client_engagement_path
        MiddleMan.__init__(self, db_object, full_client_engagement_path, DB_TABLE_NAME, MANUAL_FIELDS, COLUMN_NAMES, HEADER_NAMES)
        return

    def __enter__(self):
        return self

    def __exit__(self, type, value, traceback):
        return self


    def view(self):
        """ Override view, allowing to select scenario and only view those phished for selected scenario."""
        # select setup scenario
        selected_record, selected_scenario_id = self.db_object.select_to_edit_or_delete(SCENARIO_DB_TABLE_NAME,
                                                    SCENARIO_COLUMN_NAMES, SCENARIO_HEADER_NAMES, "view emails phished")

        self.db_object.view_results_in_table(self.DB_TABLE_NAME, self.COLUMN_NAMES, self.HEADER_NAMES, JOIN_TABLES,
                                     "scenario_id", selected_scenario_id, True)

    def phishing(self):
        """ Go Phishing! """
        # select setup scenario
        selected_record, selected_scenario_id = self.db_object.select_to_edit_or_delete(SCENARIO_DB_TABLE_NAME,
                                                    SCENARIO_COLUMN_NAMES, SCENARIO_HEADER_NAMES, "use for phishing")

        if selected_scenario_id is not None:
            with EmailPhishingSetup(self.db_object, self.full_client_engagement_path) as phishing_setup:
                phishing_setup.phish(selected_scenario_id)