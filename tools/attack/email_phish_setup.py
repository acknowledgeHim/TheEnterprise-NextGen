import json
import sys
import spamcheck
from common import print_text
from tools.attack import generate_phishing_email
from common.tool import Tool
from common.manual import Entry
from common.selection import Selection
from enterprise_conf import TOOLS_DICT


class EmailPhishingSetup(Tool):

    def __init__(self, db_object, full_client_engagement_path):
        try:

            self.tool = "email phishing"

            self.db_object = db_object
            self.output_folder = full_client_engagement_path + TOOLS_DICT[self.tool][1]

            Tool.__init__(self, db_object, self.output_folder, self.tool)

            self.scopes = None

        except Exception as e:
            print_text.print_error("tool email phishing except: " + str(e) + " Error on line {}".format(sys.exc_info()[-1].tb_lineno))
        return

    def __enter__(self):
        return self

    def __exit__(self, type, value, traceback):
        return self

    def manual_entry(self, scenario_id):
        """
        Asks for necessary manual entry if not hard set in config.
        :return:
        """
        try:
            locations = self.db_object.dictionary_list("Location", "name")
            count_numbers = self.db_object.dictionary_list("Location", "id")

            if len(locations) == 1:
                location_id = count_numbers[0]
            else:
                with Selection('Select the Location of the people you are going to be sending the email phishing to', locations, None) as selection:
                    location_id = selection.select_option(count_numbers)

            self.scopes = self.db_object.dictionary_list("Scope", "entry", ["type"], ["DOMAIN"], True)
            scope_count_numbers = self.db_object.dictionary_list("Scope", "id")
            if len(self.scopes) < 1:
                print_text.print_error("\tYou must add at least 1 domain as a Scope entry to do phishing!")
                return
            elif len(self.scopes) == 1:
                scope_id = scope_count_numbers[0]
            else:
                with Selection('Select the domain scope this phishing applies to', self.scopes, None) as selection:
                    scope_id = selection.select_option(scope_count_numbers)

            MANUAL_FIELDS = [["the full path for the text file that contains the email addresses, enter a single TEST email address (which will also do a SPAM score) or leave blank to use emails found through reconnaissance", "phishing_emails", ""]]

            email_phishing_values = {}

            if len(MANUAL_FIELDS) > 0:
                with Entry("Result", MANUAL_FIELDS, ["phishing_emails"]) as me:
                    email_phishing_values = me.user_input_fields(input_text='Please enter ')

            email_phishing_values['scope_id'] = scope_id
            email_phishing_values['location_id'] = location_id
            email_phishing_values['scenario_id'] = scenario_id

            return email_phishing_values

        except Exception as e:
            print_text.print_error("tool email phishing setup except: " + str(e) + " Error on line {}".format(sys.exc_info()[-1].tb_lineno))


    def already_sent_phishing_email_to_for_current_scenario(self, scenario_id):
        """
        Grab all sent_to (email addresses) for current scenario b/c already been sent this phishing email
        :param scenario_id: id of current scenario
        :return: list of email addresses already phished for this scenario
        """
        return self.db_object.dictionary_list("Phishing", "sent_to", ['scenario_id'], [scenario_id], True)

    def format_email_address(self, names, domains, separater, first_or_last=None, flipped=None):
        """ Remove middle name & do some formatting for email naming convention. """
        emails = []
        for name in names:
            name = name.strip()
            if name.count(" ") > 1:
                email_begin = name[:name.find(" ")]
                email_end = name[name.rfind(" ") + 1:]
                if first_or_last is not None:
                    if first_or_last == "first":
                        email_begin = email_begin[0]
                    elif first_or_last == "last":
                        email_end = email_end[0]
                name = email_begin + " " + email_end
                if flipped is True:
                    name = email_end + " " + email_begin

            name = name.replace(" ", separater)
            for domain in domains:
                emails.append(name + "@" + domain)
        return emails

    def convert_name_to_email_format1(self, names, domains):
        """ Convert name to email using format 1. """
        return self.format_email_address(names, domains, ".")

    def convert_name_to_email_format2(self, names, domains):
        """ Convert name to email using format 2. """
        return self.format_email_address(names, domains, "", "first")

    def convert_name_to_email_format3(self, names, domains):
        """ Convert name to email using format 3. """
        return self.format_email_address(names, domains, "", "last")

    def convert_name_to_email_format4(self, names, domains):
        """ Convert name to email using format 4. """
        return self.format_email_address(names, domains, "")

    def convert_name_to_email_format5(self, names, domains):
        """ Convert name to email using format 5. """
        return self.format_email_address(names, domains, "", None, True)

    def convert_name_to_email_format6(self, names, domains):
        """ Convert name to email using format 6. """
        return self.format_email_address(names, domains, "", "first", True)

    def convert_name_to_email_format7(self, names, domains):
        """ Convert name to email using format 7. """
        return self.format_email_address(names, domains, "", "last", True)

    def get_targets(self, email_phishing_values):
        """Retrieve SE sent_to for scenario selected that have already been sent email

        :param scan_type: type of email phishing scan ex) tcp-common
        :return: list of scope_ips to scan
        """
        try:
            scenario = self.db_object.get("PhishingScenario", ["id"], [email_phishing_values['scenario_id']], True)

            scenario_filename = scenario.scenario_file
            already_sent_emails = self.already_sent_phishing_email_to_for_current_scenario(scenario.id)
            email_addresses = []
            if email_phishing_values['phishing_emails'] == "":
                # Client contact
                client_contacts_email = self.db_object.grab_client_contacts_to_send_notification()

                domains = []
                for cce in client_contacts_email:
                    domain = cce[cce.find("@") + 1:]
                    if domain not in domains:
                        domains.append(domain)

                # Grab all email addresses from Recon Table
                recon_emails = self.db_object.dictionary_list("Recon", 'record', ['recon_type'], ['email'], True)

                MANUAL_FIELDS = [["(Optional) the domain(s) to append to names found if different than the client contact's and domain is not in the Scope (separate multiple domains with ',')", 'domains', '']]
                with Entry("Result", MANUAL_FIELDS, ['email_convention']) as me:
                    email_phishing_values_more = me.user_input_fields(input_text='Please enter ')

                if email_phishing_values_more['domain'].strip() != "":
                    domain = email_phishing_values_more['domains']
                    domains = domains + domain.split(",")

                for sdomain in self.scopes:
                    domains = self.scopes + domains

                # Remove duplicate domains
                s = set(domains)
                domains = list(s)

                # Grab all person entries from Recon Table (and use format specified)
                recon_people = self.db_object.dictionary_list("Recon", 'record', ['recon_type'], ['person'], True)
                email_formats = ['first.last@', 'flast@', 'firstl@', 'firstlast@', 'last.first@', 'lastf@', 'lfirst@']
                with Selection('Select the Email Format Convention to use', email_formats, None) as selection:
                    email_format = selection.select_option()

                if email_format == 1:
                    converted_emails = self.convert_name_to_email_format1(recon_people, domains)
                elif email_format == 2:
                    converted_emails = self.convert_name_to_email_format2(recon_people, domains)
                elif email_format == 3:
                    converted_emails = self.convert_name_to_email_format3(recon_people, domains)
                elif email_format == 4:
                    converted_emails = self.convert_name_to_email_format4(recon_people, domains)
                elif email_format == 5:
                    converted_emails = self.convert_name_to_email_format5(recon_people, domains)
                elif email_format == 6:
                    converted_emails = self.convert_name_to_email_format6(recon_people, domains)
                elif email_format == 7:
                    converted_emails = self.convert_name_to_email_format7(recon_people, domains)

                email_addresses = recon_emails + converted_emails

            elif "@" in email_phishing_values['phishing_emails']:
                # send a TEST phishing email to adress listed and do a SPAM score (if not already done)
                email_addresses = [email_phishing_values['phishing_emails']]

                # check if SPAM score already done for Scenario
                if scenario.spam_score == "" or scenario.spam_score is None:
                    msg_root, message_for_log = generate_phishing_email.generate(email_phishing_values['phishing_emails'], scenario, self.db_object)
                    result = spamcheck.check(msg_root, report=True)
                    print_text.print_msg("SPAM Score: " + str(result))
                    if "score" in result and "report" in result:
                        update_value = {'id': scenario.id, 'scenario': scenario.scenario,
                                        'smtp_from': scenario.smtp_from, 'data_from': scenario.data_from,
                                        'spam_score': "Score: " + str(result['score']) + "\nReport: " + str(result['report'])}
                        self.db_object.update("PhishingScenario", update_value)
            else:
                with open(email_phishing_values['phishing_emails'], 'r') as provided_emails:
                    email_addresses = provided_emails.readlines()

            # remove duplicate email addresses
            s = set(email_addresses)
            email_addresses = list(s)

            email_phishing_values['email_addresses'] = email_addresses

            commands = []
            targets = []
            scenario_name = scenario.scenario
            targets.append(scenario_name.replace(" ", "_"))
            commands.append([self.output_folder + ";" + scenario_filename, str(email_phishing_values['scope_id'])])

            return targets, commands, email_phishing_values
        except Exception as e:
            print_text.print_error("tool email phishing setup except: " + str(e) + " Error on line {}".format(sys.exc_info()[-1].tb_lineno))

    def phish(self, selected_scenario_id):
        """
        Function exists for the menu option to target and run the scan
        """
        try:
            email_phishing_values = self.manual_entry(selected_scenario_id)
            if email_phishing_values is not None:
                targets, commands, email_phishing_values = self.get_targets(email_phishing_values)
                email_phishing_json = json.dumps(email_phishing_values)
                self.run_group(targets, commands, "FUNCTION:tools.attack.email_phishing_run.phish:" + email_phishing_json)

        except Exception as e:
            print_text.print_error("tool email phishing setup except: " + str(e) + " Error on line {}".format(sys.exc_info()[-1].tb_lineno))

