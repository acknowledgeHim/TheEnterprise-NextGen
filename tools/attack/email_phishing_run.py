import json
import sys
import time
from common import print_text, common
from tools.attack import generate_phishing_email
from enterprise_user_conf import EMAIL_RELAY_SERVERS_TO_BOUNCE_EMAILS_FROM

def phish(command, scope_id, location_id, db_object, log_id, phishing_args):
    """ Email Filter / Relay Tests. """
    try:
        phishing_values = json.loads(phishing_args)

        command = command.replace('"', '')
        output_file_path = command[:command.find(";")]
        common.create_path(output_file_path)

        scenario_id = phishing_values['scenario_id']
        scenario = db_object.get("PhishingScenario", ["id"], [scenario_id], False)

        email_server = scenario.email_server
        eserver_parts = email_server.split(":")
        email_port = eserver_parts[1]
        email_server = eserver_parts[0]

        target = email_server

        delay_between_emails = scenario.delay_between_emails
        smtp_from = scenario.smtp_from
        data_from = scenario.data_from
        data_to = scenario.data_to
        read_receipt_to = scenario.read_receipt_to
        scenario_name = scenario.scenario
        email_addresses = phishing_values['email_addresses']
        print("31 email_phishing_run output_file_path: " + output_file_path + "email_phishing__" + str(log_id) + "__" + scenario_name.replace(" ", "_") +
                          "-scenario_id:" + str(scenario_id) + "-" + email_server + "-" + ".txt")
        with open(output_file_path + "email_phishing__" + str(log_id) + "__" + scenario_name.replace(" ", "_") +
                          "-scenario_id:" + str(scenario_id) + "-" + email_server + "-" + ".txt", "a") as phishing_output:

            for email in email_addresses:
                msg_root, message_for_log = generate_phishing_email.generate(email, scenario, db_object)
                generate_phishing_email.sending_email(email_server, email_port, smtp_from, [email], msg_root, message_for_log, phishing_output, data_from, data_to, scenario_name, read_receipt_to, target)

                time.sleep(int(delay_between_emails))

    except Exception as e:
        print_text.print_error("email phishing run except: " + str(e) + " Error on line {}".format(sys.exc_info()[-1].tb_lineno))
