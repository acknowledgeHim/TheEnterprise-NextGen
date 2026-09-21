import sys
import json
import time
import random
from datetime import datetime
from common import print_text, common
from tools.vuln.email_filter_class import EmailFilter

def email_filter_run(command, scope_id, location_id, db_object, log_id, email_filter_args):
    """ Email Filter / Relay Tests. """
    try:
        email_filter_values = json.loads(email_filter_args)

        command = command.replace('"', '')
        output_file_path = command[:command.find(";")]
        email_server = command[command.find(";")+1:]
        if ":" in email_server:
            email_server_parts = email_server.split(":")
            email_server = email_server_parts[0]
            port = email_server_parts[1]
        else:
            port = 25

        common.create_path(output_file_path)
        username = None
        if "username" in email_filter_values and email_filter_values['username'] is not None and email_filter_values['username'] != "":
            username = email_filter_values['username']
            del email_filter_values['username']
        passwd = None
        if "passwd" in email_filter_values and email_filter_values['passwd'] is not None and email_filter_values['passwd'] != "":
            passwd = email_filter_values['passwd']
            del email_filter_values['passwd']

        send_email_filter_tests(output_file_path, log_id, email_server, port, db_object, scope_id, email_filter_values)

        # Check if email_relay_servers_to_bounce_emails_from has been sent to, if not send to them as well
        if "email_relay_servers_to_bounce_emails_from" in email_filter_values:
            port = '25'
            if username is not None:
                email_filter_values['username'] = username
            if passwd is not None:
                email_filter_values['passwd'] = passwd
            if username is not None and passwd is not None:
                port = '456'
            email_relay_servers_to_bounce_emails_from = [email_filter_values['email_relay_servers_to_bounce_emails_from']]
            if ";" in email_filter_values['email_relay_servers_to_bounce_emails_from']:
              email_relay_servers_to_bounce_emails_from = email_filter_values['email_relay_servers_to_bounce_emails_from'].split(";")
            for email_relay_server in email_relay_servers_to_bounce_emails_from:
                if email_relay_server is not None and email_relay_server != "":
                    time.sleep(682)  # wait about 10 mins before starting to send through
                    list_of_columns_to_return = ["id", "target", "scope_id", "location_id", "entry"]
                    log_info = db_object.join_view("Log", ["Scope.entry", "Scope.Location.name"], list_of_columns_to_return, ["target"],
                                      [email_relay_server], True)
                    send_email_filter_tests(output_file_path, log_id, email_relay_server, port, db_object, scope_id, email_filter_values)
    except Exception as e:
        print_text.print_error("email filter run except: " +  str(e) +  " Error on line {}".format(sys.exc_info()[-1].tb_lineno))

def send_email_filter_tests(output_file_path, log_id, email_server, port, db_object, scope_id, email_filter_values):
    try:
        engagement = db_object.view('Engagement', ['identification'], ['id'], [1], True)
        identification = engagement[0]['identification']
        if identification is None or identification.strip() == '':
            identification = 'Not Specified'

        email_filter_values['identification_code'] = identification

        # With Read Receipt
        #with EmailFilter(output_file_path + "email_filter__" + str(log_id) + "__" + email_server + "-" + str(port) + ".txt",
        #                 db_object, log_id, email_server, port, scope_id, email_filter_values) as email_filter:
        #    email_filter.mail_relay()

        # Without Priority
        # email_filter_values.pop("priority", None)
        # with EmailFilter(output_file_path + "email_filter__" + str(log_id) + "__" + email_server + "-" + str(port) + ".txt",
        #                 db_object, log_id, email_server, port, scope_id, email_filter_values) as email_filter:
        #    email_filter.mail_relay()
        print("39 email_filter_run")
        # Without Read Receipt
        email_filter_values.pop("send_read_receipt_to", None)
        email_filter_values.pop("test_additional_msg", None)
        with EmailFilter(output_file_path + "email_filter__" + str(log_id) + "__" + email_server + "-" + str(port) + ".txt",
                         db_object, log_id, email_server, port, scope_id, email_filter_values) as email_filter:
            email_filter.mail_relay()

        # Without Subscribe & without Read Receipt
        # email_filter_values.pop('unsubscribe', None)
        # with EmailFilter(output_file_path + "email_filter__" + str(log_id) + "__" + email_server + "-" + str(port) + ".txt",
        #                 db_object, log_id, email_server, port, scope_id, email_filter_values) as email_filter:
        #    email_filter.mail_relay()
    except Exception as e:
        print_text.print_error("email filter run except: " + str(e) + " Error on line {}".format(sys.exc_info()[-1].tb_lineno))