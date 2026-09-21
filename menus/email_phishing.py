import os
import sys
import fnmatch
from common import common, encryption, print_text, network
from common.manual import Entry
from common.selection import Selection
from common.entry_db_middle_man import MiddleMan
from common.sqlalchemy_model import retrieve_hash_fields

DB_TABLE_NAME = "PhishingScenario"
ADD_MANUAL_FIELDS = [["delay (in seconds) between each phishing email or leave blank for no delay", "delay_between_emails", r'[\d]+'],
                     ["Y to send the phishing email to people already marked as phished, or N to skip already phished email addresses", "send_to_already_phished", r'^(?:Y|N)$'],
                     ["the SMTP FROM email address to use or leave blank to use the default one in the scenario (if you selected a test # to use then the domain portion will be adjusted accordingly)", "smtp_from", ""],
                     ["the DATA FROM email address to use or leave blank to use the default one in the scenario (if you selected a test # to use then the domain portion will be adjusted accordingly)", "data_from", ""],
                     ["the On Behalf Of email address to use (if you selected a test # this might be done automatically, depending upon the test # selected) (optional)", "on_behalf_of", ""],
                     ["the By Way Of email address to use (if you selected a test # this might be done automatically, depending upon the test # selected) (optional)", "by_way_of", ""],
                     #["the DATA TO email address to use or leave blank to not spoof the DATA TO field", "data_to", ""],
                     ["the Read Receipt To email address or leave blank to not send with a Read Receipt (optional)", "read_receipt_to", ""],
                     ["the email signature (if different than the default in the scenario txt file), use a modified Markdown syntax (not HTML - review TheEnterprise User Guide)", "signature", ""],
                     ["Y to send the email as a High priority or N to send as normal priority (optional)", "priority", r'^(?:Y|N)$'],
                     ["email server username if necessary (ex. sending through godaddy's email server from a one-off domain)", "login_username_for_email_server", ""],
                     ["email server password if necessary (ex. sending through godaddy's email server from a one-off domain)", "login_password_for_email_server", ""],
                     ["the full path to any attachment(s) where multiple are separated by a ',' (ex. /tmp/bad.exe,/tmp/reallybad.zip)", "attachment", ""],
                     ["the full path (directory) where inline images are located, where multiple are separated by a ',' (ex. /usr/local/,/tmp/)", "inline_image_path", ""]]

MANUAL_FIELDS = [["email server", "email_server", ""], ['email filter tests to use (separate multiple tests with a comma)', 'email_filter_tests_used', ''],
                 ["delay (in seconds) between each phishing email or leave blank for no delay", "delay_between_emails", r'[\d]+'],
                 ["Y to send the phishing email to people already marked as phished, or N to skip already phished email addresses", "send_to_already_phished", r'^(?:Y|N)$'],
                 ["the SMTP FROM email address to use or leave blank to use the default one in the scenario (if you selected a test # to use then the domain portion will be adjusted accordingly)", "smtp_from", ""],
                 ["the DATA FROM email address to use or leave blank to use the default one in the scenario (if you selected a test # to use then the domain portion will be adjusted accordingly)", "data_from", ""],
                 ["the On Behalf Of email address to use (if you selected a test # this might be done automatically, depending upon the test # selected) (optional)", "on_behalf_of", ""],
                 ["the By Way Of email address to use (if you selected a test # this might be done automatically, depending upon the test # selected) (optional)", "by_way_of", ""],
                 #["the DATA TO email address to use or leave blank to not spoof the DATA TO field", "data_to", ""],
                 ["the Read Receipt To email address or leave blank to not send with a Read Receipt (optional)", "read_receipt_to", ""],
                 ["Y to send the email as a High priority or N to send as normal priority (optional)", "priority", r'^(?:Y|N)$'],
                 ["email server username if necessary (ex. sending through godaddy's email server from a one-off domain)", "login_username_for_email_server", ""],
                 ["email server password if necessary (ex. sending through godaddy's email server from a one-off domain)", "login_password_for_email_server", ""],
                 ["the full path to any attachments where multiple are separated by a ','", "attachment", ""],
                 ["the full path (directory) where inline images are located, where multiple are separated by a ',' (ex. /usr/local/,/tmp/)", "inline_image_path", ""],
                 ["phishing url", "phish_url", ''], ["email phishing subject", "subject", '']]

COLUMN_NAMES = ['id', 'scenario_file', 'scenario', 'email_server', 'email_filter_tests_used', 'subject', 'phish_url',
                'delay_between_emails', 'smtp_from', 'data_from', 'on_behalf_of', 'by_way_of', 'priority',
                'spam_score', 'signature', 'modified_by']
HEADER_NAMES = [['Row #', 'File', 'Scenario', 'Email Server', 'Email Tests To Use', 'Subject', 'Phishing URL',
                 'Delay Between Emails', 'SMTP FROM', 'DATA FROM', 'On Behalf Of', 'By Way Of', 'Priority Flag',
                 'SPAM Score', 'Signature', 'Modified By']]


class PhishingScenarioMenu(MiddleMan):
    """
    Add or remove Email Phishing Scenarios.
    """
    def __init__(self, db_object, full_client_engagement_path):
        self.db_object = db_object
        MiddleMan.__init__(self, db_object, full_client_engagement_path, DB_TABLE_NAME, MANUAL_FIELDS, COLUMN_NAMES, HEADER_NAMES)
        return

    def __enter__(self):
        return self

    def __exit__(self, type, value, traceback):
        return self


    def add(self):
        # override
        # Find which email filter / relay tests passed
        try:
            # Grab scenarios
            scenarios, scenario_names = grab_scenarios()

            with Selection('Select the Phishing Scenario to use', scenario_names, None) as selection:
                scenario_num = selection.select_option()
            scenario = scenarios[int(scenario_num)-1]

            # Print out email filter tests that might have been successful
            email_servers, email_tests_by_email_server = possible_filter_tests()

            email_phishing_values = {}

            if len(email_servers) > 0:
                ADD_MANUAL_FIELDS.insert(0, ["Using the table above enter the email server (and optionally any test #) to use (ex 2:6,10,19 where 2 is the column # for the email server)", "email_server", ""])
            else:
                ADD_MANUAL_FIELDS.insert(0, ["Enter the email server to use (if it is not on port 25 then append ':port#' at the end - ex: mail.example.com:465)", "typed_email_server", ""])

            body = scenario['body']

            if "PHISHING_URL" in body:
                ADD_MANUAL_FIELDS.insert(1, ["do URL spoofing (might increase chances of the phishing email getting caught), Y|N",
                    "url_spoofing", r'^(?:Y|N)$'])
                ADD_MANUAL_FIELDS.insert(2, ["the PHISHING_URL (leave blank to use the default 'PHISHING_URL' for the scenario)", "phish_url", ""])

            if len(ADD_MANUAL_FIELDS) > 0:
                with Entry("Result", ADD_MANUAL_FIELDS, ["email_server", "delay_between_emails"]) as me:
                    email_phishing_values = me.user_input_fields(input_text='Please enter ')

            body = scenario['body']

            email_phishing_values = generate_email_from_based_on_tests(scenario, email_phishing_values, email_servers, email_tests_by_email_server)()

            email_phishing_values['body'] = body.replace("\t", "     ")

            ADDITIONAL_MANUAL_FIELDS = []
            required_fields = []
            if scenario['smtp_from'].strip() == "" and email_phishing_values['smtp_from'].strip() == "":
                ADDITIONAL_MANUAL_FIELDS.append([" the SMTP FROM (who the email will be 'coming from')", "smtp_from", ""])
                required_fields.append("smtp_from")
            if scenario['data_from'].strip() == "" and email_phishing_values['data_from'].strip() == "":
                ADDITIONAL_MANUAL_FIELDS.append([" the DATA FROM (who the email will be 'coming from')", "data_from", ""])
                required_fields.append("data_from")

            if len(ADDITIONAL_MANUAL_FIELDS) > 0:
                with Entry("Result", ADDITIONAL_MANUAL_FIELDS, required_fields) as me:
                    email_phishing_values_additional = me.user_input_fields(input_text='Please enter ')

                if "smtp_from" in email_phishing_values_additional:
                    email_phishing_values['smtp_from'] = email_phishing_values_additional['smtp_from']
                if "data_from" in email_phishing_values_additional:
                    email_phishing_values['data_from'] = email_phishing_values_additional['data_from']

            print("294 email_phishing email_phishing_values: " + str(email_phishing_values))

            email_phishing_hash_values = retrieve_hash_fields("PhishingScenario")
            if isinstance(email_phishing_values, dict):
                email_phishing_values = encryption.get_hash_string(email_phishing_hash_values, email_phishing_values)
            elif isinstance(email_phishing_values, list):
                new_email_phishing_values = []
                for fval in email_phishing_values:
                    fval = encryption.get_hash_string(email_phishing_hash_values, fval)
                    new_email_phishing_values.append(fval)
                email_phishing_values = new_email_phishing_values

            if isinstance(email_phishing_values, str):
                print_text.print_error("\tError: " + email_phishing_values)
            elif len(email_phishing_values) > 0:
                number_rows_added = self.db_object.add(DB_TABLE_NAME, email_phishing_values)
        except Exception as e:
            print_text.print_error("email_phishing except: " + str(e) + " Error on line {}".format(sys.exc_info()[-1].tb_lineno))

    def php_script(self):
        # 1st get all Public IP ranges
        scope_ips = self.db_object.scope_ips()
        ips = ""
        for entry in scope_ips:
            ip = entry['entry']
            ip = ip[:ip.find("/")]
            if not network.is_private(ip):
                sep = ""
                if ips != "":
                    sep = ", "
                ips = ips + sep + "'" + entry['entry'] + "'"

        if ips != "":
            php_script = "<?php\n"
            php_script = php_script + "$ip_ranges = array(" + ips + ");\n"
            php_script = php_script + "$client = $_SERVER['HTTP_CLIENT_IP'];\n $forward = $_SERVER['HTTP_X_FORWARDED_FOR'];" \
                                      "\n $remote = $_SERVER['REMOTE_ADDR'];\n"
            php_script = php_script + "function ip_in_range($ip, $range) {\n\t if(strpos($range, '/') == false) {\n\t\t " \
                                      "$range .= '/32';}\n\tlist($range, $netmask) = explode('/', $range, 2);\n\t" \
                                      "$range_decimal = ip2long($range);\n\t $ip_decimal = ip2long($ip);\n\t " \
                                      "$wildcard_decimal = pow(2, (32 - $netmask ) ) - 1;\n\t " \
                                      "$netmask_decimal = $wildcard_decimal;\n\t" \
                                      "return ( ($ip_decimal & $netmask_decimal) == ($range_decimal & $netmask_decimal) );\n}\n"
            php_script = php_script + "$is_from_client = false;\n"
            php_script = php_script + "for($i=0; $i < count($ip_ranges); $i++) {\n\tif(ip_in_range($client, $ip_ranges[$i]) " \
                                      "or ip_in_range($forward, $ip_ranges[$i]) or " \
                                      "ip_in_range($remote, $ip_ranges[$i]) ){\n\t\t$is_from_client = true;\n\tbreak;}}\n"
            php_script = php_script + "if($is_from_client) { \n\n\n } else { \n\n\n }\n"
            php_script = php_script + "?>\n"

            #write it to engagement_path + /output/phishing
            phishing_path = self.full_client_engagement_path + "/phishing/"
            common.makedirs(phishing_path)
            with open(phishing_path + "php_script.txt", "w") as script:
                script.write(php_script)
            print_text.print_msg("PHP script written to " + self.full_client_engagement_path + "/phishing/php_script.txt.  "
                                       "Copy and paste its contents at the beginning of you index.php page.")
        else:
            print_text.print_error("\tNo public, external IP addresses are in the repository for this engagement.")

    def grab_scenarios(self):
        """ Grab all Scenario .txt files and pull necessary info."""
        scenarios = []
        scenario_names = []
        for root, dirs, files in os.walk(os.getcwd() + "/tools/attack/phishing_scenarios/"):
            for filename in fnmatch.filter(files, "*.txt"):
                subject = ""
                smtp_from = ""
                read_receipt = False
                data_from = ""
                signature = ""
                phish_url = ""
                real_url = ""

                with open(root + "/" + filename, "r") as f:
                    f_content = f.read()
                    lines = f_content.split("\n")
                    if "SUBJECT=" in f_content:
                        tmp = common.get_line_matching_search("SUBJECT=", lines)
                        if tmp is not None:
                            tmp = tmp[0]
                            subject = tmp.replace("SUBJECT=", "").replace("\n", "").replace("\r", "").strip()
                    if "SMTP_FROM=" in f_content:
                        tmp = common.get_line_matching_search("SMTP_FROM=", lines)
                        if tmp is not None:
                            tmp = tmp[0]
                            smtp_from = tmp.replace("SMTP_FROM=", "").replace("\n", "").replace("\r", "").strip()
                    if "DATA_FROM=" in f_content:
                        tmp = common.get_line_matching_search("DATA_FROM=", lines)
                        if tmp is not None:
                            tmp = tmp[0]
                            data_from = tmp.replace("DATA_FROM=", "").replace("\n", "").replace("\r", "").strip()
                    if "READ_RECEIPT=" in f_content:
                        tmp = common.get_line_matching_search("READ_RECEIPT=", lines)
                        if tmp is not None:
                            tmp = tmp[0]
                            read_receipt = tmp.replace("READ_RECEIPT=", "").replace("\n", "").replace("\r", "").strip()
                            if read_receipt.lower() == "yes":
                                read_receipt = True
                    if "SIGNATURE=" in f_content:
                        tmp = common.get_line_matching_search("SIGNATURE=", lines)
                        if tmp is not None:
                            tmp = tmp[0]
                            signature = tmp.replace("SIGNATURE=", "").replace("\n", "").replace("\r", "").strip()
                    if "PHISHING_URL=" in f_content:
                        tmp = common.get_line_matching_search("PHISHING_URL=", lines)
                        if tmp is not None:
                            tmp = tmp[0]
                            phish_url = tmp.replace("PHISHING_URL=", "").replace("\n", "").replace("\r", "").strip()
                    if "REAL_URL=" in f_content:
                        tmp = common.get_line_matching_search("REAL_URL=", lines)
                        if tmp is not None:
                            tmp = tmp[0]
                            real_url = tmp.replace("REAL_URL=", "").replace("\n", "").replace("\r", "").strip()

                    body = f_content[f_content.find("BODY=") + 5:]
                    if body.strip() != "":
                        scenarios.append({"filename": filename, "subject": subject, "smtp_from": smtp_from,
                                          "data_from": data_from, "read_receipt": read_receipt, "signature": signature,
                                          "phishing_url": phish_url, "real_url": real_url, "body": body})
                        scenario_names.append(filename + " - " + subject)
        return scenarios, scenario_names


    def possible_filter_tests(self):
        """ Email Filter tests."""
        try:
            columns_to_return = ['output', 'tester_output', 'target', 'port', 'id', 'command']
            failed_results = self.db_object.dictionary_list("Result", "id", ['output', 'tool'], ['Failed', 'email filter'],
                                                            False)

            email_tests = []
            if failed_results is not None:
                tmp_email_tests = self.db_object.view("Result", columns_to_return, ['tool'], ['email filter'], True)
                if tmp_email_tests is not None:
                    for et in tmp_email_tests:
                        if et['id'] not in failed_results:
                            email_tests.append(et)
            else:
                email_tests = self.db_object.view("Result", columns_to_return, 'id', failed_results, ["tool"],
                                                  ["email filter"])

            if email_tests is not None and len(email_tests) > 0:
                email_servers = []  # pull out the email servers that had a possible successful test
                email_tests_by_email_server = {}
                results_dict = {}
                for et in email_tests:
                    test_num = et['command']
                    test_num = test_num[test_num.find("#") + 1:]
                    test_num = test_num.replace(" ", "")
                    if test_num != "0":
                        if et['target'] + ":" + et['port'] not in email_servers:
                            email_servers.append(et['target'] + ":" + et['port'])
                            results_dict[et['target'] + ":" + et['port']] = test_num
                        else:
                            sep = ", "
                            tmp_result = results_dict[et['target'] + ":" + et['port']]
                            if "\n" not in tmp_result:
                                if len(tmp_result) > 20:
                                    tmp_result = tmp_result + ",\n"
                                    sep = ""
                            else:
                                junk_result = tmp_result[tmp_result.rfind("\n") + 2:]
                                if len(junk_result) > 20:
                                    tmp_result = tmp_result + ",\n"
                                    sep = ""
                            results_dict[et['target'] + ":" + et['port']] = tmp_result + sep + test_num
                        email_tests_by_email_server[et['target'] + ":" + et['port'] + test_num] = et['output']

                # Format for printing in table view
                tmp_results = []
                for es in email_servers:
                    tmp_results.append(results_dict[es])

                if len(email_servers) > 0:
                    print_text.print_msg("Validate the client actually received each one correctly before selecting it for use."
                                         "\n\tTo select the mail server and test number(s) to use, enter the "
                                         "Column # then ':' followed by each test # to use separated by a ',' (ex: 2:3,10,19)")
                    print_text.console_table_view("Possible Successful Email Filter Tests", [email_servers], [tmp_results])
                else:
                    print_text.print_msg("No email filter tests in the repo.")

                return email_servers, email_tests_by_email_server
        except Exception as e:
            print_text.print_error(
                "email_phishing except: " + str(e) + " Error on line {}".format(sys.exc_info()[-1].tb_lineno))
        print_text.print_error("\tEither no email filter tests are in the repository or all of them failed "
                               "(if all failed you probably got blacklisted).")
        return None, None


def generate_email_from_based_on_tests(scenario, email_phishing_values, email_servers, email_tests_by_email_server):
    """ Subsitutes SMTP FROM, etc based on selected tests"""
    domain_smtp_from = ""
    domain_data_from = ""
    resent_from = None
    sender = None
    tests = []
    if "email_server" in email_phishing_values:
        email_server = email_phishing_values['email_server']
        if ":" in email_server:
            tests = email_server[email_server.find(":") + 1:]
            email_phishing_values['email_filter_tests_used'] = tests
            email_server = email_server[:email_server.find(":")]

            email_server_name = email_servers[int(email_server) - 1]
            test_list = tests.replace(" ", "").split(",")
            for test in test_list:
                tester_output_of_test_num_selected = email_tests_by_email_server[email_server_name + test]
                tmp_domain_smtp_from = tester_output_of_test_num_selected[
                                       tester_output_of_test_num_selected.find("SMTP_FROM: ") + 11:]
                tmp_domain_smtp_from = tmp_domain_smtp_from[:tmp_domain_smtp_from.find(" ")]
                if (test == "5" or test == "7" or test == "8") and domain_smtp_from == "":
                    domain_smtp_from = tmp_domain_smtp_from
                    domain_data_from = domain_smtp_from
                elif test == "3" or test == "4":
                    domain_smtp_from = tmp_domain_smtp_from
                    domain_data_from = domain_smtp_from
                elif test == "11" or test == "28":
                    domain_smtp_from = tmp_domain_smtp_from
                    domain_data_from = tester_output_of_test_num_selected[
                                       tester_output_of_test_num_selected.find("DATA_FROM: ") + 11:]
                    domain_data_from = domain_data_from[:domain_data_from.find(" ")]
                elif test == "46" or test == "47":
                    resent_from = tester_output_of_test_num_selected[
                                  tester_output_of_test_num_selected.find("BY WAY OF: ") + 11:]
                    resent_from = resent_from[:resent_from.find(" ")]
                elif test == "48" or test == "49":
                    sender = tester_output_of_test_num_selected[
                             tester_output_of_test_num_selected.find("On Behalf Of: ") + 14:]
                    sender = sender[:sender.find(" ")]
    elif "typed_email_server" in email_phishing_values:
        email_server_name = email_phishing_values['typed_email_server']
        if ":" not in email_server_name:
            email_server_name = email_server_name + ":25"

    # modify domain portion of SMTP_FROM and/or DATA_FROM according to selected test
    if domain_smtp_from != "":
        smtp_from = email_phishing_values['smtp_from']
        if smtp_from == "":
            email_phishing_values['smtp_from'] = domain_smtp_from
        else:
            smtp_from = smtp_from[:smtp_from.find("@")]
            email_phishing_values['smtp_from'] = smtp_from + "@" + domain_smtp_from[
                                                                   domain_smtp_from.find("@") + 1:]
    if domain_data_from != "":
        data_from = email_phishing_values['data_from']
        if data_from == "":
            email_phishing_values['data_from'] = domain_data_from
        else:
            data_from = data_from[:data_from.find("@")]
            email_phishing_values['data_from'] = data_from + "@" + domain_data_from[
                                                                   domain_data_from.find("@") + 1:]

    email_phishing_values['email_server'] = email_server_name

    # Setup resent-from and sender values
    if resent_from is not None and email_phishing_values['resent_from'].strip() == "":
        email_phishing_values['resent_from'] = resent_from
    if sender is not None and email_phishing_values['sender'].strip() == "":
        email_phishing_values['sender'] = sender

    # generate phishing URL based on what was selected
    phish_url = scenario['phishing_url']
    if 'phish_url' in email_phishing_values and email_phishing_values['phish_url'] != "":
        phish_url = email_phishing_values['phish_url']
    if "10" in tests or "20" in tests:
        email_phishing_values['phish_url'] = "<a href='" + phish_url + "'>" + scenario['real_url'] + "</a>"
    elif email_phishing_values["url_spoofing"]:
        email_phishing_values['phish_url'] = "<a href='" + phish_url + "'>" + scenario['real_url'] + "</a>"
    else:
        email_phishing_values['phish_url'] = "<a href='" + phish_url + "'>" + phish_url + "</a>"

    if "signature" not in email_phishing_values or email_phishing_values['signature'] == "":
        email_phishing_values['signature'] = scenario['signature']

    # use SMTP FROM & DATA FROM from scenario as default
    if email_phishing_values['smtp_from'].strip() == "":
        email_phishing_values['smtp_from'] = scenario['smtp_from']
    if email_phishing_values['data_from'].strip() == "":
        email_phishing_values['data_from'] = scenario['data_from']

    # No PHISH_URL entered so use one from scenario as default
    if 'phish_url' in email_phishing_values and email_phishing_values['phish_url'] == "":
        email_phishing_values['phish_url'] = scenario['phish_url']

    email_phishing_values['scenario_file'] = scenario['filename']
    email_phishing_values['subject'] = scenario['subject']
    email_phishing_values['scenario'] = email_phishing_values['subject']

    return email_phishing_values

