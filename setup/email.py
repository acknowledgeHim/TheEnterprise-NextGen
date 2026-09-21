import re
import os
from common import print_text
from common.entry_db_middle_man import MiddleMan
from common.database_object import OurCoolDBObject

from enterprise_conf import EMAIL_EVENT_DB

# Need to get all YAML files in recon/scan/...
tools = []

TOOLS_STRING = '|'.join(tools)
TOOLS_STRING_REGEX = r'^(?:' + TOOLS_STRING + ')$'
INSTALLED_TOOLS_REGEX = re.compile(TOOLS_STRING)

DB_TABLE_NAME = "EmailEvent"
MANUAL_FIELDS = (["event, " + TOOLS_STRING, "event", TOOLS_STRING_REGEX],
                 ["email subject", "subject", r'^(?:[a-zA-Z0-9._%+-\:/ ()]+)$'],
                 ["tester message (enter '\\n' for a new line)", "tester_msg", r'^(?:[a-zA-Z0-9._%+-\:/ ()]+)$'],
                 ["corporate (your company) contact message (enter '\\n' for a new line)", "corp_msg", r'^(?:[a-zA-Z0-9._%+-\:/ ()]+)$'],
                 ["client contact message (enter '\\n' for a new line)", "client_msg", r'^(?:[a-zA-Z0-9._%+-\:/ ()]+)$'],
                 ["when to send the notification (when a tool is started or after it has finished/ended), start|end",
                  "start_or_end", r'^(?:start|end)$'])
MANUAL_FIELDS2 = [["tool", "event", TOOLS_STRING_REGEX],
                 ["email subject", "subject", r'^(?:[a-zA-Z0-9._%+-\:/ ()]+)$'],
                 ["tester message (enter '\\n' for a new line)", "tester_msg", r'^(?:[a-zA-Z0-9._%+-\:/ ()]+)$'],
                 ["corporate (your company) contact message (enter '\\n' for a new line)", "corp_msg", r'^(?:[a-zA-Z0-9._%+-\:/ ()]+)$'],
                 ["client contact message (enter '\\n' for a new line)", "client_msg", r'^(?:[a-zA-Z0-9._%+-\:/ ()]+)$'],
                 ["when to send the notification (when a tool is started or after it has finished/ended), start|end",
                  "start_or_end", r'^(?:start|end)$']]
HEADER_NAMES = [
    ['Row #', 'When to Send', 'Event', 'Email Subject', 'Tester MSG', 'Corp MSG', 'Client MSG', 'Modified By', 'Modified Date']]
COLUMN_NAMES = ['id', 'start_or_end', 'event', 'subject', 'tester_msg', 'corp_msg', 'client_msg', 'modified_by', 'modified_date']


class EmailEventEntry(MiddleMan):
    """
    View, add or remove Emails. Adding/removing only for testing purposes.
    """

    def __init__(self, db_object, full_client_engagement_path):
        db_object = OurCoolDBObject(os.path.dirname(os.path.realpath(__file__)) + '/email_event.db')
        print_text.print_msg(
            "This represents the email message that will be sent to each possible receipent: the tester, Corp contacts, and Client contacts. "
            "\n Keywords that will be replaced with appropriate variables are: "
            "\n\tCLIENTNAME - placeholder to put the current client's name"
            "\n\tDOMAINNAME - placeholder to put the domain name entry being used (pulled from the Scope)"
            "\n\tEMAIL_ADDRESS - placeholder to put your email address (pulled from your profile)"
            "\n\tEMAIL_MSG_WHERE_TO_FORWARD_BACK_TO - placeholder to put the email address where they should forward test emails back to (pulled from enterprise_user_conf.py)"
            "\n\tENGAGEMENT - placeholder to put the engagement number"
            "\n\tSCENARIONAME - placeholder to put the email phishing scenario being used"
            "\n\tSERVICE - placeholder to put the service being targeted, such as SNMP, HTTP, etc"
            "\n\tSTART_DATE - placeholder to put the engagement start date"
            "\n\tTARGET - placeholder to put the current scope entry (or device) being used"
            "\n\tTOOLNAME - placeholder to put the tool used")
        print_text.print_bold("\n\nIf you leave the Client or Corp contact message blank then that contact type will not receive an email for that particular event.")
        MiddleMan.__init__(self, db_object, full_client_engagement_path, DB_TABLE_NAME, MANUAL_FIELDS,
                           COLUMN_NAMES, HEADER_NAMES)
        return

    def __enter__(self):
        return self

    def __exit__(self, type, value, traceback):
        return self
