import tempfile
import smtplib
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from email.mime.image import MIMEImage
from email.mime.base import MIMEBase
from email.utils import COMMASPACE, formatdate, make_msgid
from email import encoders
import dns.resolver
import datetime
import time
import sys
import os
import string
import random
import socket
import hmac
import hashlib
import base64
from common import network, common, print_text, dns_functions, keep_tags
from enterprise_conf import HASH_KEY

# /opt/zimbra/store/0/27/msg/0/*.msg - mailstore for user: notification@issgs.net
# need to parse *.msg according to From: clientname@clientdomain & have Subject: Testing Mail Relay
# write python script that is running in cron every 5min to look for all new messages to notification@issgs.net on email server
# 2nd python script that this script kicks off (but doesn't wait to finish) that waits for .unprocessed file to appear in client_path and then updates DB

# add email that tests exfil - <img src='http://issgs.net:53', etc
# add to each email <img src='http://issgs.net/test.gif?self.encrypted_server_info' so that log of webserver will show if user received email or not

class EmailFilter():
    def __init__(self, output_file_path, db_object, log_id, email_server, port, scope_id, email_filter_values):
        try:
            self.output_folder = output_file_path
            self.db_object = db_object
            self.log_id = log_id
            self.email_server = email_server
            self.port = str(port)
            self.scope_id = str(scope_id)
            scope_info = db_object.join_view('Scope', ['Location.name'], ['entry', 'name'], ['id'], [self.scope_id], True)
            self.scope_entry = scope_info[0]['entry']
            self.location_name = scope_info[0]['name']
            self.hashkey = HASH_KEY
            self.attachment_path = "tools/vuln/email_attachments/"

            self.email_filter_values = email_filter_values

            self.send_read_receipt_to = None #if set, adds read receipt to this email
            self.test_additional_msg = ""
            self.test_additional_body_txt = ""
            self.test_num_prefix = 0
            self.bad_receipient = False

            if 'send_read_receipt_to' in email_filter_values:
                self.send_read_receipt_to = keep_tags.clean_text(email_filter_values['send_read_receipt_to'])
                self.test_num_prefix = 1000
            if 'test_additional_msg' in email_filter_values:
                self.test_additional_msg = keep_tags.clean_text(email_filter_values['test_additional_msg'])
            if 'unsubscribe' in email_filter_values:
                self.test_num_prefix = 2000
                self.test_additional_msg = "  Email contains a hidden unsubscribe link to decrease SPAM scoring."
                self.test_additional_body_txt = "<p><p><font color=white size=1><a href='http://yourdomain.com/unsubscribe' style='color:white;'>Unsubscribe</a></font>"

            self.smtp_username = None
            if 'username' in email_filter_values:
                self.smtp_username = email_filter_values['username']
            self.smtp_passwd = None
            if 'passwd' in email_filter_values:
                self.smtp_passwd = email_filter_values['passwd']
            if 'testers_domain' in email_filter_values:
                self.testers_domain = keep_tags.clean_text(email_filter_values['testers_domain'])
            if 'public_ip' in email_filter_values:
                self.your_public_ip = keep_tags.clean_text(email_filter_values['public_ip'])
            if 'your_ip_address' in email_filter_values:
                self.your_ip_address = keep_tags.clean_text(email_filter_values['your_ip_address'])
            self.private_ip = self.your_ip_address
            if not network.valid_ip(self.your_ip_address):
                self.private_ip = "192.168.0.12"
            if 'smtp_ehlo_server' in email_filter_values:
                self.smtp_ehlo_server = keep_tags.clean_text(email_filter_values['smtp_ehlo_server'])
            if 'email_relay_servers_to_bounce_emails_from' in email_filter_values:
                self.email_relay_servers_to_bounce_emails_from = keep_tags.clean_text(email_filter_values['email_relay_servers_to_bounce_emails_from'])
            if 'invalid_user_name' in email_filter_values:
                self.invalid_user_name = email_filter_values['invalid_user_name']
            if 'spoof_domain_no_spf_dmarc_dkim' in email_filter_values:
                spoof_domain_no_spf_dmarc_dkim = keep_tags.clean_text(email_filter_values['spoof_domain_no_spf_dmarc_dkim'])
                self.spoof_domains_no_spf_dmarc_dkim = [spoof_domain_no_spf_dmarc_dkim]
                if ";" in spoof_domain_no_spf_dmarc_dkim:
                    self.spoof_domains_no_spf_dmarc_dkim = spoof_domain_no_spf_dmarc_dkim.split(";")
            if 'spoof_domain_with_spf_hardfail' in email_filter_values:
                self.spoof_domain_with_spf_hardfail = keep_tags.clean_text(email_filter_values['spoof_domain_with_spf_hardfail'])
            if 'spoof_domain_with_spf_softfail' in email_filter_values:
                self.spoof_domain_with_spf_softfail = keep_tags.clean_text(email_filter_values['spoof_domain_with_spf_softfail'])
            if "email_msg_where_to_forward_back_to" in email_filter_values:
                self.forward_email_to = keep_tags.clean_text(email_filter_values['email_msg_where_to_forward_back_to'])

            self.repeat = 3
            if "num_invalid_domains_to_try" in email_filter_values:
                self.repeat = int(keep_tags.clean_text(email_filter_values['num_invalid_domains_to_try']))
            self.identification_code = ''.join(random.choices(string.ascii_uppercase + string.digits, k=938))
            if "identification_code" in email_filter_values:
                self.identification_code = keep_tags.clean_text(email_filter_values['identification_code'])

            if "email_msg_where_to_forward_back_to" in email_filter_values:
                self.forward_email_to = keep_tags.clean_text(email_filter_values['email_msg_where_to_forward_back_to'])

            self.client_email = keep_tags.clean_text(email_filter_values['email_to'])
            if "\\" in self.client_email:
                self.client_email = self.client_email.replace("\\", "")

            self.client_username = self.client_email[:self.client_email.find("@")]
            self.domain = self.client_email[self.client_email.find("@") + 1:]#email_filter_values['client_domain']
            self.pause_time = float(keep_tags.clean_text(email_filter_values['emailfilter_pause_time']))

            if self.email_relay_servers_to_bounce_emails_from is None:
                self.email_relay_servers_to_bounce_emails_from = []

            # Find IP for client domain
            self.email_public_ip = self.email_server
            if self.email_server not in self.email_relay_servers_to_bounce_emails_from:
                if not network.valid_ip(self.email_public_ip):
                    # check if in Recon as mx record
                    self.email_public_ip = self.db_object.grab_column_from_single_record("Recon", ["record", "recon_type"],
                                                                                    [self.email_server, "mx"], "associated_info")
                    if self.email_public_ip is None or not network.valid_ip(self.email_public_ip):
                        # check if in Recon as dns record
                        self.email_public_ip = self.db_object.grab_column_from_single_record("Recon", ["record", "recon_type"],
                                                                                        [self.email_server, "dns"], "associated_info")
                        if self.email_public_ip is None or not network.valid_ip(self.email_public_ip):
                            # check in scope domain
                            self.email_public_ip = self.db_object.grab_column_from_single_record("Scope", ["entry", "type"],
                                                                                            [self.email_server, "DOMAIN"], "open_ip")
            else:
                self.email_public_ip, additional = dns_functions.grab_dns_record(self.email_server, True)

            # following used for identification on forwarded back email to correctly assign to right test in DB
            self.encrypted_server_info = ''
            self.test_num = ''

            self.start_time = datetime.datetime.fromtimestamp(time.time()).strftime('%Y-%m-%d %H:%M:%S')

            self.counter450 = 0
            self.counter421 = 0
            self.test9_count = 0
        except Exception as e:
            print("email filter class 143 except: " + str(e) + " Error on line {}".format(sys.exc_info()[-1].tb_lineno))

    def __enter__(self):
        return self

    def __exit__(self, type, value, traceback):
        return self

    def mail_relay(self):
        try:
            with open(self.output_folder, "w") as email_filter_output:
                print_text.print_msg("Sending mail relay tests for mail server: " + self.email_server)
                if self.email_server in self.email_relay_servers_to_bounce_emails_from:
                    self.test0(email_filter_output)  # should be valid email (so has proper SPF and Rev DNS) used to verify they are not blacklisting us

                # TEST ORDER
                time.sleep(self.pause_time)
                self.test9(email_filter_output)  # valid email from no SPF domain, should get thru unless Rev DNS used
                time.sleep(self.pause_time)
                self.test20(email_filter_output)  # identical to #10, except contains plain text alternative
                time.sleep(self.pause_time)
                self.test10(email_filter_output)  # spoofed URL <a href>
                time.sleep(self.pause_time)
                self.test11(email_filter_output)  # spoofed from, smtp from is different than body FROM
                time.sleep(self.pause_time)
                self.test5(email_filter_output)  # spoof TLD (ex. google.com becomes google.c0m)
                time.sleep(self.pause_time)
                self.test6(email_filter_output)  # spoof domain (ex. google.com becomes g00gle.com)
                time.sleep(self.pause_time)
                self.test7(email_filter_output)  # no domain (ex. jim@google.com becomes jim)
                time.sleep(self.pause_time)
                self.test8(email_filter_output)  # no top level (ex. google.com becomes google)
                time.sleep(self.pause_time)
                self.test17(email_filter_output)  # test SPF (so send from microsoft.com, instead of contoso.com)
                time.sleep(self.pause_time)
                self.test21(email_filter_output)  # test EXFIL (<img src for 22,80,443,53,8080,64999)  # you must have these ports open and listening somewhere accessible from the Internet for this test to mean anything
                time.sleep(self.pause_time)
                self.test24(email_filter_output)  # test SPF SoftFail (~all)
                time.sleep(self.pause_time)
                self.test25(email_filter_output)  # with read receipt email differing from SMTP FROM email
                time.sleep(self.pause_time)
                self.test26(email_filter_output)  # with read receipt email differing from DATA FROM email but same as SMTP FROM
                time.sleep(self.pause_time)
                self.test27(email_filter_output)  # spoof domain used in test17 by SMTP FROM for only the DATA FROM (SMTP FROM is same as test17)
                time.sleep(self.pause_time)
                self.test28(email_filter_output)  # SMTP FROM base64 encode but DATA FROM is not (shadow attack)
                time.sleep(self.pause_time)
                self.test41(email_filter_output)  # .htm attachment
                time.sleep(self.pause_time)
                self.test42(email_filter_output)  # .html attachment
                time.sleep(self.pause_time)
                self.test43(email_filter_output)  # .js attachment
                time.sleep(self.pause_time)
                self.test44(email_filter_output)  # both SMTP FROM and DATA FROM are base64 encoded (shadow attack)
                time.sleep(self.pause_time)
                self.test45(email_filter_output)  # SMTP FROM base64 encoded and DATA FROM is just username (shadow attack)
                time.sleep(self.pause_time)
                self.test46(email_filter_output)  # Resent-From (by way of) is valid internal and SMTP FROM is spoofed
                time.sleep(self.pause_time)
                self.test47(email_filter_output)  # Resent-From (by way of) is spoofed and SMTP FROM is valid internal
                time.sleep(self.pause_time)
                self.test48(email_filter_output)  # Sender (on behalf of) is spoofed and SMTP FROM is valid internal
                time.sleep(self.pause_time)
                self.test49(email_filter_output)  # Sender (on behalf of) is valid internal and SMTP FROM is spoofed
                time.sleep(self.pause_time)
                self.test50(email_filter_output)  # Sender domain is localhost
                time.sleep(self.pause_time)
                self.test51(email_filter_output)  # Sender domain is IP localhost - [127.0.0.1]
                time.sleep(self.pause_time)
                self.test52(email_filter_output)  # null sender address: <>
                time.sleep(self.pause_time)
                self.test53(email_filter_output)  # Sender address used local hostname
                time.sleep(self.pause_time)
                self.test54(email_filter_output)  # Sender address uses Public IP of local host @[200.200.200.200]
                time.sleep(self.pause_time)
                self.test55(email_filter_output)  # Sender address uses Private IP of local host
                time.sleep(self.pause_time)
                self.test56(email_filter_output)  # Sender email to use % hack where routing is valid user + % + domain
                time.sleep(self.pause_time)
                self.test57(email_filter_output)  # Sender email to use % hack where routing is valid user but not valid domain
                time.sleep(self.pause_time)
                self.test58(email_filter_output)  # Sender email to use % hack where routing is valid user + domain but routing from is Public IP
                time.sleep(self.pause_time)
                self.test59(email_filter_output)  # Sender email to use % hack where routing is valid user but not valid domain & routed from Public IP
                time.sleep(self.pause_time)
                self.test60(email_filter_output)  # SMTP FROM email to use % hack where routing is valid user & domain but routing is Public IP of email_server
                time.sleep(self.pause_time)
                self.test61(email_filter_output)  # SMTP FROM email if client email in quotes
                time.sleep(self.pause_time)
                self.test62(email_filter_output)  # SMTP FROM email if client email in quotes + % hack from valid user + valid domain
                time.sleep(self.pause_time)
                self.test63(email_filter_output)  # SMTP FROM email if client email in quotes + % hack from valid user + valid domain and routed is Public IP
                time.sleep(self.pause_time)
                self.test64(email_filter_output)  # SMTP TO email uses source routing (client_email @ domain_list)
                time.sleep(self.pause_time)
                self.test65(email_filter_output)  # SMTP TO email uses source routing (client_email @ domain_list) where client_email is encapsulated in quotes
                time.sleep(self.pause_time)
                self.test66(email_filter_output)  # SMTP TO email uses source routing (client_email @ PUBLIC IP)
                time.sleep(self.pause_time)
                self.test67(email_filter_output)  # SMTP TO email uses source routing (client_email @ Public IP of email_server)
                time.sleep(self.pause_time)
                self.test68(email_filter_output)  # base Striker URL approach
                time.sleep(self.pause_time)
                self.test69(email_filter_output)  # X-Originator-IP spoofing
                time.sleep(self.pause_time)
                self.test70(email_filter_output)  # folding/unfolding in SMTP From
                time.sleep(self.pause_time)
                self.test71(email_filter_output)  # Extremely long SMTP From (longer than 998 chars)
                time.sleep(self.pause_time)
                self.test72(email_filter_output)   # Base64 encode display name portion that can proceed email address (and put title, etc to make it long and block out the real email address when displayed in Outlook)
                time.sleep(self.pause_time)
                self.test73(email_filter_output)  # double quote client email and afterwards valid email from no SPF domain, should get thru unless Rev DNS used
                time.sleep(self.pause_time)
                self.test74(email_filter_output)  # double quote client email and afterwards valid email from no SPF domain, should get thru unless Rev DNS used
                time.sleep(self.pause_time)
                self.test29(email_filter_output)  # .exe attachment with renamed extension as .txt
                time.sleep(self.pause_time)
                self.test30(email_filter_output)  # .exe attachment with renamed extension as .txt inside zip
                time.sleep(self.pause_time)
                self.test31(email_filter_output)  # .chm attachment
                time.sleep(self.pause_time)
                self.test32(email_filter_output)  # .dll attachment
                time.sleep(self.pause_time)
                self.test33(email_filter_output)  # .mui attachment
                time.sleep(self.pause_time)
                self.test34(email_filter_output)  # .mui attachment without LN extension
                time.sleep(self.pause_time)
                self.test35(email_filter_output)  # .msi attachment
                time.sleep(self.pause_time)
                self.test36(email_filter_output)  # .jar attachment
                time.sleep(self.pause_time)
                self.test37(email_filter_output)  # .scr attachment
                time.sleep(self.pause_time)
                self.test38(email_filter_output)  # .ps1 attachment
                time.sleep(self.pause_time)
                self.test39(email_filter_output)  # .vbs attachment
                time.sleep(self.pause_time)
                self.test40(email_filter_output)  # .sct attachment
                time.sleep(self.pause_time)
                self.test22(email_filter_output)  # test .hta files
                time.sleep(self.pause_time)
                self.test23(email_filter_output)  # test Word Doc w/ Macro files
                time.sleep(self.pause_time)
                self.test12(email_filter_output)  # test .exe
                time.sleep(self.pause_time)
                self.test13(email_filter_output)  # test .exe in zip
                time.sleep(self.pause_time)
                self.test14(email_filter_output)  # test eicar
                time.sleep(self.pause_time)
                self.test15(email_filter_output)  # test eicar in zip
                time.sleep(self.pause_time)
                self.test16(email_filter_output)  # test eicar in zip in zip
                time.sleep(self.pause_time)
                self.test18(email_filter_output)  # test .gadget
                time.sleep(self.pause_time)
                self.test19(email_filter_output)  # test .bat
                time.sleep(self.pause_time)

                self.test3(email_filter_output)  # send to valid internal from valid internal
                time.sleep(self.pause_time)
                self.test4(email_filter_output)  # send to valid internal from invalid internal
                time.sleep(self.pause_time)
                if self.email_server not in self.email_relay_servers_to_bounce_emails_from:
                    time.sleep(self.pause_time)
                    self.test1(email_filter_output)  # open relay to from anyone external to anyone external
                    time.sleep(self.pause_time)
                    self.test2(email_filter_output)  # open relay from valid internal to anyone external

                #test .docm
                #test embedded exe in pdf
                #.psh
                #.re
                #.res
                # spoof msgRoot['In-Reply-To'] (maybe resend all tests to see if that helps get through SPAM filter
                # spoof msgRoot['References']
                # spoof msgRoot['Thread-Topic']
                # spoof msgRoot['Thread-Index']
                # More headers to spoof at: https://tools.ietf.org/html/rfc4021 & https://www.iana.org/assignments/message-headers/message-headers.xhtml
                # do test 49 & 46 where 'resent-from' or 'sender' is not a valid email but just user portion or name
                # More headers to spoof http://www.rdns.org/mailtraq/mail/relaying/relay.html (UUCP style bang paths, etc)
                # microsoft word wizards: http://projectwoman.com/2014/10/calendar-wizard-in-word-2013-yes.html
                # calendar invites
                # https://en.wikipedia.org/wiki/MIME#Encoded-Word
                # outlook filter rule
                # forward outlook rule, calendar, ... (as if from internal to another internal)

                # More possible dangerous file types to test out in the future: http://en.wikipedia.org/wiki/User:Ruud_Koot/Dangerous_file_types
                # this one is really cool, reversing the name: http://www.howtogeek.com/127154/how-hackers-can-disguise-malicious-programs-with-fake-file-extensions/
        except Exception as e:
            print("email filter class 161 except: " + str(e) + " Error on line {}".format(sys.exc_info()[-1].tb_lineno))

    def email_identification(self):
        try:
            #reset counter for each email to send out
            self.counter450 = 0
            self.counter421 = 0

            info = self.db_object.get("Engagement", ["id"], [1])
            client_number = info["client_number"]
            engagement_number = info["engagement_number"]

            #self.encrypted_server_info = base64.b64encode(hmac.new(HASH_KEY, msg=self.email_server + ';' + self.port + ';' + self.test_num + ';' + self.start_time, digestmod=hashlib.sha512).digest()).decode()
            self.encrypted_server_info = "\n\n EmailTest#:" + self.email_server + ';' + self.port + ';' + \
                                         self.test_num + ';' + self.start_time + ";" + self.scope_entry + ";" +\
                                         self.location_name + "\nRandomization String: " + str(self.identification_code)

        except Exception as e:
            print("email filter class 172 except: " + str(e) + " Error on line {}".format(sys.exc_info()[-1].tb_lineno))

    # send out the email
    def sending_email(self, email_from, email_to, message, email_filter_output, data_from, data_to, read_receipt_to=None, attachment=None, bywayof=None, onbehalfof=None):
        try:
            if not self.bad_receipient:
                # Not sure why '\' added before '-' automatically so removing it ;)
                if "-" in email_to and "\\" in email_to:
                    email_to = email_to.replace("\\", "")

                individual_email_path = self.output_folder[:self.output_folder.rfind("/") + 1] + "individual_emails/"
                common.create_path(individual_email_path)
                individual_email_file = individual_email_path + email_to[0] + "_" + str(self.start_time).replace(":","").replace(" ", "") + ".txt"
                with open(individual_email_file, "w") as email_filter_output_to:
                    email_filter_output_to.write(message)

                message_for_log = message.replace("\n","<br>").replace("\t", " ").replace('"', "'")
                # strip off base64 encoded attachments
                if "Content-Disposition: attachment; filename='" in message_for_log:
                    file_name_pos = message_for_log.find("Content-Disposition: attachment; filename='") + 43
                    tmp = message_for_log[43:]
                    end_file_name_pos = tmp.find("'")
                    message_for_log = message_for_log[:file_name_pos + end_file_name_pos]

                t = None
                available_fd = None
                #if self.test_num == "10":
                # Capture output (replies) to verify commands external email server supports
                # get available file descriptor
                t = tempfile.TemporaryFile()
                available_fd = t.fileno()
                t.close()
                # make copy of stdout
                os.dup2(2, available_fd)
                # create new tempfile and direct pythons stdout there
                t = tempfile.TemporaryFile()
                os.dup2(t.fileno(), 2)

                if self.port == "465":  # then use SMTP_SSL
                    try:
                        smtp = smtplib.SMTP_SSL(self.email_server, int(self.port))
                        smtp.set_debuglevel(5)
                        smtp.ehlo(self.smtp_ehlo_server)
                        smtp.login(self.smtp_username, self.smtp_passwd)
                        smtp.sendmail(email_from, email_to, message)
                        smtp.quit()
                        print_text.print_msg("Successfully sent Test " + self.test_num + " to " + self.email_server + ".")
                        email_filter_output.write(self.start_time + "\t" + self.email_server + "\t" + str(self.port) + "\t" + self.test_num + "\t" + email_from + "\t" + email_to[0] + "\t" + message_for_log + "\t" + self.start_time + "\tSuccessfully sent. TEST#: " + self.test_num + " SMTP_FROM: " + email_from + " SMTP_TO: " + email_to[0] + " DATA_FROM: " + str(data_from) + " DATA_TO: " + str(data_to) + " READ_RECEIPT_TO: " + str(read_receipt_to) + " BY WAY OF: " + str(bywayof) + " On Behalf Of: " + str(onbehalfof) + " Attachment: " + str(attachment) + "EOL\n")
                    except Exception as e:
                        print_text.print_error("Error: unable to send email Test " + self.test_num + " to " + self.email_server + ".  " + str(e))
                        email_filter_output.write(self.start_time + "\t" + self.email_server + "\t" + str(self.port) + "\t" + self.test_num + "\t" + email_from + "\t" + email_to[0] + "\t" + message_for_log + "\t" + self.start_time + "\tFailed to send. " + str(e) + " TEST#: " + self.test_num + " SMTP_FROM: " + email_from + " SMTP_TO: " + email_to[0] + " DATA_FROM: " + str(data_from) + " DATA_TO: " + str(data_to) + " READ_RECEIPT_TO: " + str(read_receipt_to) + " BY WAY OF: " + str(bywayof) + " On Behalf Of: " + str(onbehalfof) + " Attachment: " + str(attachment) + "EOL\n")

                        if "smtprecipientsrefused" in str(e).lower():
                            self.bad_receipient = True
                        else:
                            # try to resend the email after waiting 15 seconds
                            if ("450" in str(e) or "451" in str(e)) and self.counter450 < 3:
                                time.sleep(15)
                                self.sending_email(email_from, email_to, message, email_filter_output,
                                                   data_from, data_to, read_receipt_to, attachment)
                                self.counter450 += 1
                            elif ("450" in str(e) or "451" in str(e)) and self.count450 >= 3:
                                self.counter450 = 0
                            if "421" in str(e) and self.counter421 < 3:
                                # try to resend but wait longer time between b/c probably being rate limited
                                if self.pause_time < 3600:
                                    self.pause_time = self.pause_time * 2
                                    time.sleep(self.counter421 * self.pause_time)
                                else:
                                    time.sleep(self.counter421 * 421)
                                self.sending_email(email_from, email_to, message, email_filter_output,
                                                       data_from, data_to, read_receipt_to, attachment)
                                self.counter421 += 1
                            elif "421" in str(e) and self.counter421 >= 3:
                                self.counter421 = 0
                else:
                    try:
                        smtp = smtplib.SMTP(self.email_server, int(self.port))
                        smtp.set_debuglevel(True)
                        smtp.ehlo(self.smtp_ehlo_server)
                        smtp.sendmail(email_from, email_to, message)
                        print_text.print_msg("Successfully sent Test " + self.test_num + " to " + self.email_server + ".")
                        smtp.quit()
                        email_filter_output.write(self.start_time + "\t" + self.email_server + "\t" + str(self.port) + "\t" + self.test_num + "\t" + email_from + "\t" + email_to[0] + "\t" + message_for_log + "\t" + self.start_time + "\tSuccessfully sent. TEST#: " + self.test_num + " SMTP_FROM: " + email_from + " SMTP_TO: " + email_to[0] + " DATA_FROM: " + str(data_from) + " DATA_TO: " + str(data_to) + " READ_RECEIPT_TO: " + str(read_receipt_to) + " BY WAY OF: " + str(bywayof) + " On Behalf Of: " + str(onbehalfof) + " Attachment: " + str(attachment) + "EOL\n")
                    except Exception as e:
                        print("email filter class 316 except: " + str(e) + " Error on line {}".format(sys.exc_info()[-1].tb_lineno))
                        print_text.print_error("Error: unable to send email Test " + self.test_num + " to " + self.email_server + ".  " + str(e))
                        email_filter_output.write(self.start_time + "\t" + self.email_server + "\t" + str(self.port) + "\t" + self.test_num + "\t" + email_from + "\t" + email_to[0] + "\t" + message_for_log + "\t" + self.start_time + "\tFailed to send. " + str(e) + " TEST#: " + self.test_num + " SMTP_FROM: " + email_from + " SMTP_TO: " + email_to[0] + " DATA_FROM: " + str(data_from) + " DATA_TO: " + str(data_to) + " READ_RECEIPT_TO: " + str(read_receipt_to) + " BY WAY OF: " + str(bywayof) + " On Behalf Of: " + str(onbehalfof) + " Attachment: " + str(attachment) + "EOL\n")

                        if "smtprecipientsrefused" in str(e).lower():
                            self.bad_receipient = True
                        else:
                            # try to resend the email after waiting 15 seconds
                            if "450" in str(e) and self.counter450 > 3:
                                time.sleep(15 * self.pause_time)
                                self.sending_email(email_from, email_to, message, email_filter_output, data_from, data_to,
                                                   read_receipt_to, attachment)
                                self.counter450 += 1
                            if "421" in str(e) and self.counter421 > 3:
                                # try to resend but wait longer time between b/c probably being rate limited
                                if self.pause_time < 3600:
                                    self.pause_time = self.pause_time * 2
                                    time.sleep(self.counter421 * 421)
                                    self.sending_email(email_from, email_to, message, email_filter_output,
                                                       data_from, data_to, read_receipt_to, attachment)
                                    self.counter421 += 1

                if t is not None and available_fd is not None:
                    # grab stderr from temp file
                    sys.stderr.flush()
                    t.flush()
                    t.seek(0)
                    stderr_output = t.read()
                    t.close()
                    # put back stderr
                    os.dup2(available_fd, 2)
                    os.close(available_fd)

                    if self.test_num == "10":
                        # Check for 'TURN', 'ATRN', and 'ETRN' server allowed commands
                        for line in stderr_output.decode('utf-8').split("\n"):
                            if "250-ETRN" in line and 'reply:' in line:
                                email_filter_output.write(self.start_time + "\t" + self.email_server + "\t" + str(self.port) + "\t250-ETRN\t" + email_from + "\t" + email_to[0] + "\t \t" + self.start_time + "\tEOL\n")
                            if "TURN" in line and 'reply:' in line:
                                email_filter_output.write(self.start_time + "\t" + self.email_server + "\t" + str(self.port) + "\t250-TURN\t" + email_from + "\t" + email_to[0] + "\t \t" + self.start_time + "\tEOL\n")
                            if "ATRN" in line and 'reply:' in line:
                                email_filter_output.write(self.start_time + "\t" + self.email_server + "\t" + str(self.port) + "\t250-ATRN\t" + email_from + "\t" + email_to[0] + "\t \t" + self.start_time + "\tEOL\n")
                    individual_email_path_out_file = individual_email_path + "/" + self.email_server + "_test#" + self.test_num + ".txt"
                    with open(individual_email_path_out_file, 'w') as ieof:
                        ieof.write(stderr_output.decode('utf-8'))
                    print(stderr_output)
        except Exception as e:
                    print("email filter class 330 except: " + str(e) + " Error on line {}".format(sys.exc_info()[-1].tb_lineno))

    # client should receive this otherwise they are blacklisting you
    def test0(self, email_filter_output):
        try:
            self.test_num = str(self.test_num_prefix + 0)

            # create the encrypted email identification text at bottom of every email
            self.email_identification()

            bodytext = "This is a mail relay test " + self.test_num + ", and represents a valid email from ISSG's IP range through " + self.email_server + self.test_additional_msg + ". \n\n	Please forward to " + self.forward_email_to + " prior to deleting this message.\n\n Thank you." + self.encrypted_server_info
            subject = "Testing Mail Relay " + self.test_num + " through " + self.email_server + ". Forward to " + self.forward_email_to + "!"
            email_from = self.forward_email_to
            email_to = [self.client_email]
            bodyhtml = "<html><body>" + bodytext.replace("\n", "<br>").replace(
                "Please forward to " + self.forward_email_to + " prior to deleting this message",
                "<b>Please forward to <a href='mailto:" + self.forward_email_to + "'>" + self.forward_email_to + "</a> prior to deleting this message</b>") + "</body></html>"
            bodyhtml = bodyhtml + self.test_additional_body_txt

            # Create the root message and fill in the from, to, and subject headers
            msgRoot = MIMEMultipart('related')
            msgRoot['Subject'] = subject
            msgRoot['From'] = email_from
            msgRoot['To'] = self.client_email
            if self.send_read_receipt_to is not None:
                msgRoot['Disposition-Notification-To'] = self.send_read_receipt_to
            msgRoot.preamble = 'This is a multi-part message in MIME format.'
            # Encapsulate the plain and HTML versions of the message body in an
            # 'alternative' part, so message agents can decide which they want to display.
            msgAlternative = MIMEMultipart('alternative')
            msgRoot.attach(msgAlternative)
            msgText = MIMEText(bodytext)
            msgAlternative.attach(msgText)
            # We reference the image in the IMG SRC attribute by the ID we give it below
            msgText = MIMEText(bodyhtml, 'html')
            msgAlternative.attach(msgText)
            self.sending_email(email_from, email_to, msgRoot.as_string(), email_filter_output, msgRoot['From'], msgRoot['To'], msgRoot['Disposition-Notification-To'])
        except Exception as e:
            print("email filter class 244 except: " + str(e) + " Error on line {}".format(sys.exc_info()[-1].tb_lineno))

    # open relay
    def test1(self, email_filter_output):
        self.test_num = str(self.test_num_prefix + 1)

        # create the encrypted email identification text at bottom of every email (unencrypted shows scanner IP and path of client dir being worked on so can dump results back to that same location)
        self.email_identification()

        bodytext = "This is a mail relay test " + self.test_num + ", from an external address to an external address through " + self.email_server + self.test_additional_msg + ". \n\n Please forward to " + self.forward_email_to + " prior to deleting this message.\n\n Thank you." + self.encrypted_server_info
        bodyhtml = "<html><body>" + bodytext.replace("\n", "<br>").replace(
            "Please forward to " +self.forward_email_to + " prior to deleting this message",
            "<b>Please forward to <a href='mailto:" +self.forward_email_to + "'>" + self.forward_email_to + "</a> prior to deleting this message</b>") + "</body></html>"
        bodyhtml = bodyhtml + self.test_additional_body_txt

        subject = "Testing Mail Relay " + self.test_num + " through " + self.email_server + self.test_additional_msg + ". Forward to " + self.forward_email_to + "!"
        email_from = 'notification@' + self.spoof_domains_no_spf_dmarc_dkim[0]
        email_to = [self.forward_email_to]
        # Create the root message and fill in the from, to, and subject headers
        msgRoot = MIMEMultipart('related')
        msgRoot['Subject'] = subject
        msgRoot['From'] = email_from
        msgRoot['To'] =self.forward_email_to
        msgRoot.preamble = 'This is a multi-part message in MIME format.'
        # Encapsulate the plain and HTML versions of the message body in an
        # 'alternative' part, so message agents can decide which they want to display.
        msgAlternative = MIMEMultipart('alternative')
        msgRoot.attach(msgAlternative)
        msgText = MIMEText(bodytext)
        msgAlternative.attach(msgText)
        # We reference the image in the IMG SRC attribute by the ID we give it below
        msgText = MIMEText(bodyhtml, 'html')
        msgAlternative.attach(msgText)

        self.sending_email(email_from, email_to, msgRoot.as_string(), email_filter_output, msgRoot['From'],
                           msgRoot['To'], msgRoot['Disposition-Notification-To'])

    # half open relay
    def test2(self, email_filter_output):
        self.test_num = str(self.test_num_prefix + 2)

        # create the encrypted email identification text at bottom of every email (unencrypted shows scanner IP and path of client dir being worked on so can dump results back to that same location)
        self.email_identification()

        bodytext = "This is a mail relay test " + self.test_num + ", from an internal address to an external address through " + self.email_server + self.test_additional_msg + ". \n\n Please forward to " + self.forward_email_to + " prior to deleting this message.\n\n Thank you." + self.encrypted_server_info
        subject = "Testing Mail Relay " + self.test_num + " through " + self.email_server + self.test_additional_msg + ". Forward to " + self.forward_email_to + "!"
        email_from = self.client_email
        email_to = [self.forward_email_to]  # [self.forward_email_to]

        bodyhtml = "<html><body>" + bodytext.replace("\n", "<br>").replace(
            "Please forward to " + self.forward_email_to + " prior to deleting this message",
            "<b>Please forward to <a href='mailto:" + self.forward_email_to + "'>" + self.forward_email_to + "</a> prior to deleting this message</b>") + "</body></html>"
        bodyhtml = bodyhtml + self.test_additional_body_txt

        # Create the root message and fill in the from, to, and subject headers
        msgRoot = MIMEMultipart('related')
        msgRoot['Subject'] = subject
        msgRoot['From'] = self.client_email
        msgRoot['To'] = self.forward_email_to
        if self.send_read_receipt_to is not None:
            msgRoot['Disposition-Notification-To'] = self.send_read_receipt_to
        msgRoot.preamble = 'This is a multi-part message in MIME format.'
        # Encapsulate the plain and HTML versions of the message body in an
        # 'alternative' part, so message agents can decide which they want to display.
        msgAlternative = MIMEMultipart('alternative')
        msgRoot.attach(msgAlternative)
        msgText = MIMEText(bodytext)
        msgAlternative.attach(msgText)
        # We reference the image in the IMG SRC attribute by the ID we give it below
        msgText = MIMEText(bodyhtml, 'html')
        msgAlternative.attach(msgText)

        self.sending_email(email_from, email_to, msgRoot.as_string(), email_filter_output, msgRoot['From'],
                           msgRoot['To'], msgRoot['Disposition-Notification-To'])

    # valid internal spoof
    def test3(self, email_filter_output):
        self.test_num = str(self.test_num_prefix + 3)

        # create the encrypted email identification text at bottom of every email (unencrypted shows scanner IP and path of client dir being worked on so can dump results back to that same location)
        self.email_identification()

        bodytext = "This is a mail relay test " + self.test_num + ", from an internal address to an internal address through " + self.email_server + self.test_additional_msg + ". \n\n Please forward to " + self.forward_email_to + " prior to deleting this message.\n\n Thank you." + self.encrypted_server_info
        subject = "Testing Mail Relay " + self.test_num + " through " + self.email_server + self.test_additional_msg + ". Forward to " + self.forward_email_to + "!"
        email_from = self.client_email
        email_to = [self.client_email]
        bodyhtml = "<html><body>" + bodytext.replace("\n", "<br>").replace(
            "Please forward to " + self.forward_email_to + " prior to deleting this message",
            "<b>Please forward to <a href='mailto:" + self.forward_email_to + "'>" + self.forward_email_to + "</a> prior to deleting this message</b>") + "</body></html>"
        bodyhtml = bodyhtml + self.test_additional_body_txt

        # Create the root message and fill in the from, to, and subject headers
        msgRoot = MIMEMultipart('related')
        msgRoot['Subject'] = subject
        msgRoot['From'] = self.client_email
        msgRoot['To'] = self.client_email
        if self.send_read_receipt_to is not None:
            msgRoot['Disposition-Notification-To'] = self.send_read_receipt_to
        msgRoot.preamble = 'This is a multi-part message in MIME format.'
        # Encapsulate the plain and HTML versions of the message body in an
        # 'alternative' part, so message agents can decide which they want to display.
        msgAlternative = MIMEMultipart('alternative')
        msgRoot.attach(msgAlternative)
        msgText = MIMEText(bodytext)
        msgAlternative.attach(msgText)
        # We reference the image in the IMG SRC attribute by the ID we give it below
        msgText = MIMEText(bodyhtml, 'html')
        msgAlternative.attach(msgText)

        self.sending_email(email_from, email_to, msgRoot.as_string(), email_filter_output, msgRoot['From'],
                           msgRoot['To'], msgRoot['Disposition-Notification-To'])

    # invalid internal spoof
    def test4(self, email_filter_output):
        self.test_num = str(self.test_num_prefix + 4)

        # create the encrypted email identification text at bottom of every email (unencrypted shows scanner IP and path of client dir being worked on so can dump results back to that same location)
        self.email_identification()

        bodytext = "This is a mail relay test " + self.test_num + ", from an invalid internal address to an internal address through " + self.email_server + self.test_additional_msg + ". \n\n	Please forward to " + self.forward_email_to + " prior to deleting this message.\n\n Thank you." + self.encrypted_server_info
        subject = "Testing Mail Relay " + self.test_num + " through " + self.email_server + self.test_additional_msg + ". Forward to " + self.forward_email_to + "!"
        email_from = 'clawasneverhere@' + self.domain
        email_to = [self.client_email]
        bodyhtml = "<html><body>" + bodytext.replace("\n", "<br>").replace(
            "Please forward to " + self.forward_email_to + " prior to deleting this message",
            "<b>Please forward to <a href='mailto:" + self.forward_email_to + "'>" + self.forward_email_to + "</a> prior to deleting this message</b>") + "</body></html>"
        bodyhtml = bodyhtml + self.test_additional_body_txt

        # Create the root message and fill in the from, to, and subject headers
        msgRoot = MIMEMultipart('related')
        msgRoot['Subject'] = subject
        msgRoot['From'] = 'clawasneverhere@' + self.domain
        msgRoot['To'] = self.client_email
        if self.send_read_receipt_to is not None:
            msgRoot['Disposition-Notification-To'] = self.send_read_receipt_to
        msgRoot.preamble = 'This is a multi-part message in MIME format.'
        # Encapsulate the plain and HTML versions of the message body in an
        # 'alternative' part, so message agents can decide which they want to display.
        msgAlternative = MIMEMultipart('alternative')
        msgRoot.attach(msgAlternative)
        msgText = MIMEText(bodytext)
        msgAlternative.attach(msgText)
        # We reference the image in the IMG SRC attribute by the ID we give it below
        msgText = MIMEText(bodyhtml, 'html')
        msgAlternative.attach(msgText)

        self.sending_email(email_from, email_to, msgRoot.as_string(), email_filter_output, msgRoot['From'],
                           msgRoot['To'], msgRoot['Disposition-Notification-To'])

    # spoof tld
    def test5(self, email_filter_output):
        self.test_num = str(self.test_num_prefix + 5)

        # create the encrypted email identification text at bottom of every email (unencrypted shows scanner IP and path of client dir being worked on so can dump results back to that same location)
        self.email_identification()

        client_username = self.client_email[:self.client_email.find("@") + 1]
        bodytext = "This is a mail relay test " + self.test_num + ", from a spoofed address with an invalid top level domain to an internal address through " + self.email_server + self.test_additional_msg + ". \n\n	Please forward to " + self.forward_email_to + " prior to deleting this message.\n\n Thank you." + self.encrypted_server_info
        subject = "Testing Mail Relay " + self.test_num + " through " + self.email_server + self.test_additional_msg + ". Forward to " + self.forward_email_to + "!"
        tld = self.domain[self.domain.rfind("."):]
        dm = self.domain[:self.domain.rfind(".")]
        spoof_domain = dm + tld[:-1] + "0"  # replaces last character of tld w/ z (ie. google.com would be google.co0)
        if "com" in tld:
            spoof_domain = dm + tld.replace("com", "c0m")
        elif "net" in tld:
            spoof_domain = dm + tld.replace("net", "n3t")
        elif "us" in tld:
            spoof_domain = dm + tld.replace("us", "7s")
        elif "org" in tld:
            spoof_domain = dm + tld.replace("org", "0rg")
        email_from = client_username + spoof_domain
        email_to = [self.client_email]
        bodyhtml = "<html><body>" + bodytext.replace("\n", "<br>").replace(
            "Please forward to " + self.forward_email_to + " prior to deleting this message",
            "<b>Please forward to <a href='mailto:" + self.forward_email_to + "'>" + self.forward_email_to + "</a> prior to deleting this message</b>") + "</body></html>"
        bodyhtml = bodyhtml + self.test_additional_body_txt

        # Create the root message and fill in the from, to, and subject headers
        msgRoot = MIMEMultipart('related')
        msgRoot['Subject'] = subject
        msgRoot['From'] = email_from
        msgRoot['To'] = self.client_email
        if self.send_read_receipt_to is not None:
            msgRoot['Disposition-Notification-To'] = self.send_read_receipt_to
        msgRoot.preamble = 'This is a multi-part message in MIME format.'
        # Encapsulate the plain and HTML versions of the message body in an
        # 'alternative' part, so message agents can decide which they want to display.
        msgAlternative = MIMEMultipart('alternative')
        msgRoot.attach(msgAlternative)
        msgText = MIMEText(bodytext)
        msgAlternative.attach(msgText)
        # We reference the image in the IMG SRC attribute by the ID we give it below
        msgText = MIMEText(bodyhtml, 'html')
        msgAlternative.attach(msgText)
        self.sending_email(email_from, email_to, msgRoot.as_string(), email_filter_output, msgRoot['From'],
                           msgRoot['To'], msgRoot['Disposition-Notification-To'])

    # spoof domain
    def test6(self, email_filter_output):
        self.test_num = str(self.test_num_prefix + 6)

        # create the encrypted email identification text at bottom of every email (unencrypted shows scanner IP and path of client dir being worked on so can dump results back to that same location)
        self.email_identification()
        client_username = self.client_email[:self.client_email.find("@") + 1]
        bodytext = "This is a mail relay test " + self.test_num + ", from an email address with a spoofed domain name to an internal address through " + self.email_server + self.test_additional_msg + ". \n\n	Please forward to " + self.forward_email_to + " prior to deleting this message.\n\n Thank you." + self.encrypted_server_info
        subject = "Testing Mail Relay " + self.test_num + " through " + self.email_server + self.test_additional_msg + ". Forward to " + self.forward_email_to + "!"
        dm = self.domain[:self.domain.rfind(".")]  # ie google
        tld = self.domain[self.domain.rfind("."):]  # ie .com
        spoof_domain = None
        already_tried_spoof_domain = []
        repetition = 0
        while repetition < self.repeat:
            stillvalid = True # make sure found a unregistered domain - will only send test 6 if stillvalid is False
            count_iterations = 0 # make sure we break out of this madness at some point !
            registered_domain_no_spf_sent = 0 #used to keep track of # of times registered domain found w/ no SPF and test 9 sent using it
            while True or count_iterations > 200:
                # Trying to find 1-off domain that is not registered
                if "l" in dm and dm.replace("l", "1") not in already_tried_spoof_domain:
                    spoof_domain = dm.replace("l", "1")
                elif "o" in dm and dm.replace("o", "0") not in already_tried_spoof_domain:
                    spoof_domain = dm.replace("o", "0")
                elif "e" in dm and dm.replace("e", "3") not in already_tried_spoof_domain:
                    spoof_domain = dm.replace("e", "3")
                elif "i" in dm and dm.replace("i", "l") not in already_tried_spoof_domain:
                    spoof_domain = dm.replace("i", "l")
                elif "t" in dm and dm.replace("t", "7") not in already_tried_spoof_domain:
                    spoof_domain = dm.replace("t", "7")
                elif "s" in dm and dm.replace("s", "5") not in already_tried_spoof_domain:
                    spoof_domain = dm.replace("s", "5")
                elif dm[:-1] + "0" not in already_tried_spoof_domain:
                    spoof_domain = dm[:-1] + "0"
                else:
                    tmpdm = dm
                    tmplist = list(tmpdm)
                    char_pos_in_domain = 0
                    while tmpdm not in already_tried_spoof_domain or char_pos_in_domain > len(dm):
                        tmplist[char_pos_in_domain] = random.choice(string.ascii_letters)
                        tmpdm = ''.join(tmplist)
                        if tmpdm not in already_tried_spoof_domain:
                            spoof_domain = tmpdm
                            break
                        char_pos_in_domain += 1

                    # if makes thru entire domain and not find invalid domain then break and try appending to domain random characters
                    if char_pos_in_domain >= len(dm):
                        alphabet_letters = string.ascii_letters
                        # try appending character to domain
                        for letter in alphabet_letters:
                            if dm + letter not in already_tried_spoof_domain:
                                spoof_domain = dm + letter
                                break
                        # Try prepending character to domain
                        if spoof_domain is None:
                            for letter in alphabet_letters:
                                if letter + dm not in already_tried_spoof_domain:
                                    spoof_domain = letter + dm
                                    break
                        # Could prepend/append 2 characters but for now just breaking out
                        if spoof_domain is None:
                            break

                already_tried_spoof_domain.append(spoof_domain)

                try:
                    result = socket.gethostbyname(spoof_domain + tld)  # finds out if IP associated with spoofed domain, we want this to FAIL or else try another replacement
                    if network.is_private(result):
                        break
                    else:
                        # Check if has SPF record, if not then add to domain to test from that is registered and no SPF (Test 9)
                        records = dns.resolver.query(spoof_domain + tld, 'TXT')
                        no_spf = True
                        for record in records:
                            if "v=spf" in record:
                                no_spf = False
                                break
                        if no_spf and registered_domain_no_spf_sent > 3:
                            self.test9(email_filter_output, [spoof_domain + tld])
                            registered_domain_no_spf_sent += 1

                except Exception as e:
                    stillvalid = False
                    break  # means not valid domain which is what we want

                count_iterations += 1

            if count_iterations > 200:
                email_filter_output.write(print_text.print_error("Could not find a spoofed / unregistered domain to use close to the clients."))
                break
            elif not stillvalid:
                # print_text.print_bold("THIS IS the spoof domain: " + spoof_domain)
                email_from = client_username + spoof_domain + tld
                email_to = [self.client_email]
                bodyhtml = "<html><body>" + bodytext.replace("\n", "<br>").replace(
                    "Please forward to " + self.forward_email_to + " prior to deleting this message",
                    "<b>Please forward to <a href='mailto:" + self.forward_email_to + "'>" + self.forward_email_to + "</a> prior to deleting this message</b>") + "</body></html>"
                bodyhtml = bodyhtml + self.test_additional_body_txt

                # Create the root message and fill in the from, to, and subject headers
                msgRoot = MIMEMultipart('related')
                msgRoot['Subject'] = subject
                msgRoot['From'] = email_from
                msgRoot['To'] = self.client_email
                if self.send_read_receipt_to is not None:
                    msgRoot['Disposition-Notification-To'] = self.send_read_receipt_to
                msgRoot.preamble = 'This is a multi-part message in MIME format.'
                # Encapsulate the plain and HTML versions of the message body in an
                # 'alternative' part, so message agents can decide which they want to display.
                msgAlternative = MIMEMultipart('alternative')
                msgRoot.attach(msgAlternative)
                msgText = MIMEText(bodytext)
                msgAlternative.attach(msgText)
                # We reference the image in the IMG SRC attribute by the ID we give it below
                msgText = MIMEText(bodyhtml, 'html')
                msgAlternative.attach(msgText)

                self.sending_email(email_from, email_to, msgRoot.as_string(), email_filter_output, msgRoot['From'],
                                   msgRoot['To'], msgRoot['Disposition-Notification-To'])

            repetition += 1

    # no tld
    def test7(self, email_filter_output):
        self.test_num = str(self.test_num_prefix + 7)

        # create the encrypted email identification text at bottom of every email (unencrypted shows scanner IP and path of client dir being worked on so can dump results back to that same location)
        self.email_identification()

        client_notoplevel = self.client_email[:self.client_email.rfind(".")]
        bodytext = "This is a mail relay test " + self.test_num + ", from an email address with no top level domain to an internal address through " + self.email_server + self.test_additional_msg + ". \n\n	Please forward to " + self.forward_email_to + " prior to deleting this message.\n\n Thank you." + self.encrypted_server_info
        subject = "Testing Mail Relay " + self.test_num + " through " + self.email_server + self.test_additional_msg + ". Forward to " + self.forward_email_to + "!"
        email_from = client_notoplevel
        email_to = [self.client_email]
        bodyhtml = "<html><body>" + bodytext.replace("\n", "<br>").replace(
            "Please forward to " + self.forward_email_to + " prior to deleting this message",
            "<b>Please forward to <a href='mailto:" + self.forward_email_to + "'>" + self.forward_email_to + "</a> prior to deleting this message</b>") + "</body></html>"
        bodyhtml = bodyhtml + self.test_additional_body_txt

        # Create the root message and fill in the from, to, and subject headers
        msgRoot = MIMEMultipart('related')
        msgRoot['Subject'] = subject
        msgRoot['From'] = email_from
        msgRoot['To'] = self.client_email
        if self.send_read_receipt_to is not None:
            msgRoot['Disposition-Notification-To'] = self.send_read_receipt_to
        msgRoot.preamble = 'This is a multi-part message in MIME format.'
        # Encapsulate the plain and HTML versions of the message body in an
        # 'alternative' part, so message agents can decide which they want to display.
        msgAlternative = MIMEMultipart('alternative')
        msgRoot.attach(msgAlternative)
        msgText = MIMEText(bodytext)
        msgAlternative.attach(msgText)
        # We reference the image in the IMG SRC attribute by the ID we give it below
        msgText = MIMEText(bodyhtml, 'html')
        msgAlternative.attach(msgText)

        self.sending_email(email_from, email_to, msgRoot.as_string(), email_filter_output, msgRoot['From'],
                           msgRoot['To'], msgRoot['Disposition-Notification-To'])

    # no domain
    def test8(self, email_filter_output):
        self.test_num = str(self.test_num_prefix + 8)

        # create the encrypted email identification text at bottom of every email (unencrypted shows scanner IP and path of client dir being worked on so can dump results back to that same location)
        self.email_identification()


        bodytext = "This is a mail relay test " + self.test_num + ", from an email address alias with no domain to an internal address through " + self.email_server + self.test_additional_msg + ". \n\n	Please forward to " + self.forward_email_to + " prior to deleting this message.\n\n Thank you." + self.encrypted_server_info
        subject = "Testing Mail Relay " + self.test_num + " through " + self.email_server + self.test_additional_msg + ". Forward to " + self.forward_email_to + "!"
        email_from = self.client_username
        email_to = [self.client_email]
        bodyhtml = "<html><body>" + bodytext.replace("\n", "<br>").replace(
            "Please forward to " + self.forward_email_to + " prior to deleting this message",
            "<b>Please forward to <a href='mailto:" + self.forward_email_to + "'>" + self.forward_email_to + "</a> prior to deleting this message</b>") + "</body></html>"
        bodyhtml = bodyhtml + self.test_additional_body_txt

        # Create the root message and fill in the from, to, and subject headers
        msgRoot = MIMEMultipart('related')
        msgRoot['Subject'] = subject
        msgRoot['From'] = email_from
        msgRoot['To'] = self.client_email
        if self.send_read_receipt_to is not None:
            msgRoot['Disposition-Notification-To'] = self.send_read_receipt_to
        msgRoot.preamble = 'This is a multi-part message in MIME format.'
        # Encapsulate the plain and HTML versions of the message body in an
        # 'alternative' part, so message agents can decide which they want to display.
        msgAlternative = MIMEMultipart('alternative')
        msgRoot.attach(msgAlternative)
        msgText = MIMEText(bodytext)
        msgAlternative.attach(msgText)
        # We reference the image in the IMG SRC attribute by the ID we give it below
        msgText = MIMEText(bodyhtml, 'html')
        msgAlternative.attach(msgText)

        self.sending_email(email_from, email_to, msgRoot.as_string(), email_filter_output, msgRoot['From'],
                           msgRoot['To'], msgRoot['Disposition-Notification-To'])

    # no spf so even if they check SPF records we are good. Only be blocked if they block any domain that does not have SPF records, or do RevDNS lookup
    def test9(self, email_filter_output, domain_to_use=None):
        """ domain_to_use - list """
        if domain_to_use is None:
            domain_to_use = self.spoof_domains_no_spf_dmarc_dkim

        for sdnsdd in domain_to_use:
            self.test_num = str(self.test_num_prefix + 9) + "." + str(self.test9_count)
            self.test9_count += 1

            # create the encrypted email identification text at bottom of every email (unencrypted shows scanner IP and path of client dir being worked on so can dump results back to that same location)
            self.email_identification()

            bodytext = "This is a mail relay test " + self.test_num + ", from a spoofed valid external address to an internal address through " + self.email_server + self.test_additional_msg + ". \n\n	Please forward to " + self.forward_email_to + " prior to deleting this message.\n\n Thank you." + self.encrypted_server_info
            subject = "Testing Mail Relay " + self.test_num + " through " + self.email_server + self.test_additional_msg + ". Forward to " + self.forward_email_to + "!"
            email_from = self.invalid_user_name + '@' + sdnsdd
            email_to = [self.client_email]
            bodyhtml = "<html><body>" + bodytext.replace("\n", "<br>").replace(
                "Please forward to " + self.forward_email_to + " prior to deleting this message",
                "<b>Please forward to <a href='mailto:" + self.forward_email_to + "'>" + self.forward_email_to + "</a> prior to deleting this message</b>") + "</body></html>"
            bodyhtml = bodyhtml + self.test_additional_body_txt

            # Create the root message and fill in the from, to, and subject headers
            msgRoot = MIMEMultipart('related')
            msgRoot['Subject'] = subject
            msgRoot['From'] = email_from
            msgRoot['To'] = self.client_email
            if self.send_read_receipt_to is not None:
                msgRoot['Disposition-Notification-To'] = self.send_read_receipt_to
            msgRoot.preamble = 'This is a multi-part message in MIME format.'
            # Encapsulate the plain and HTML versions of the message body in an
            # 'alternative' part, so message agents can decide which they want to display.
            msgAlternative = MIMEMultipart('alternative')
            msgRoot.attach(msgAlternative)
            msgText = MIMEText(bodytext)
            msgAlternative.attach(msgText)

            msgText = MIMEText(bodyhtml, 'html')
            msgAlternative.attach(msgText)

            self.sending_email(email_from, email_to, msgRoot.as_string(), email_filter_output, msgRoot['From'], msgRoot['To'], msgRoot['Disposition-Notification-To'])

    # masked url (hidden link) - no Plain text alternative
    def test10(self, email_filter_output):
        self.test_num = str(self.test_num_prefix + 10)

        # create the encrypted email identification text at bottom of every email (unencrypted shows scanner IP and path of client dir being worked on so can dump results back to that same location)
        self.email_identification()

        additional_headers = '\nContent-Type: Multipart/Related; boundary="00123"\n MIME-version: 1.0\n\n--00123\nContent-Type: Text/HTML; charset=ISO-8859-1\n)Content-Transfer-Encoding: 7bit'
        body = "<html>This is a mail relay test " + self.test_num + ", from a spoofed valid external address to an internal address through " + self.email_server + self.test_additional_msg + " with an masked url. \n\n<a href='http://www.yahoo.com'>www.google.com</a>\n\n	<b>Please forward to <a href=mailto:" + self.forward_email_to + "'>" + self.forward_email_to + "</a> prior to deleting this message</b>.\n\n Thank you." + self.encrypted_server_info + "</body></html>"
        body = body.replace("\n", "<br>")
        body = body + self.test_additional_body_txt
        subject = "Testing Mail Relay " + self.test_num + " through " + self.email_server + self.test_additional_msg + ". Forward to " + self.forward_email_to + "!"
        email_from = self.invalid_user_name + '@' + self.spoof_domains_no_spf_dmarc_dkim[0]  # self.invalid_user_name+'@'+self.spoof_domain_no_spf_dmarc_dkim[0]+' '
        email_to = [self.client_email]
        message = "From: " + email_from + "\nTo: " + email_to[
            0] + "\nSubject: " + subject + additional_headers + "\n\n" + body
        self.sending_email(email_from, email_to, message, email_filter_output, email_from, email_to)

    # mixed spoofed internal username w/ valid external to internal address
    # spoofed DATA FROM but not SMTP FROM
    def test11(self, email_filter_output):
        self.test_num = str(self.test_num_prefix + 11)

        # create the encrypted email identification text at bottom of every email (unencrypted shows scanner IP and path of client dir being worked on so can dump results back to that same location)
        self.email_identification()

        bodytext = "This is a mail relay test " + self.test_num + ", from a spoofed internal address mixed with valid external address to an internal address through " + self.email_server + self.test_additional_msg + ". \n\n	Please forward to " + self.forward_email_to + " prior to deleting this message.\n\n Thank you." + self.encrypted_server_info
        subject = "Testing Mail Relay " + self.test_num + " through " + self.email_server + self.test_additional_msg + ". Forward to " + self.forward_email_to + "!"
        email_from_spoof = self.invalid_user_name + '@' + self.spoof_domains_no_spf_dmarc_dkim[0]
        email_from = email_from_spoof
        email_to = [self.client_email]
        bodyhtml = "<html><body>" + bodytext.replace("\n", "<br>").replace(
            "Please forward to " + self.forward_email_to + " prior to deleting this message",
            "<b>Please forward to <a href='mailto:" + self.forward_email_to + "'>" + self.forward_email_to + "</a> prior to deleting this message</b>") + "</body></html>"
        bodyhtml = bodyhtml + self.test_additional_body_txt

        # Create the root message and fill in the from, to, and subject headers
        msgRoot = MIMEMultipart('related')
        msgRoot['Subject'] = subject
        msgRoot['From'] = self.client_email
        msgRoot['To'] = self.client_email
        if self.send_read_receipt_to is not None:
            msgRoot['Disposition-Notification-To'] = self.send_read_receipt_to
        msgRoot.preamble = 'This is a multi-part message in MIME format.'
        # Encapsulate the plain and HTML versions of the message body in an
        # 'alternative' part, so message agents can decide which they want to display.
        msgAlternative = MIMEMultipart('alternative')
        msgRoot.attach(msgAlternative)
        msgText = MIMEText(bodytext)
        msgAlternative.attach(msgText)

        msgText = MIMEText(bodyhtml, 'html')
        msgAlternative.attach(msgText)

        self.sending_email(email_from, email_to, msgRoot.as_string(), email_filter_output, msgRoot['From'],
                           msgRoot['To'], msgRoot['Disposition-Notification-To'])

    # .exe attachment
    def test12(self, email_filter_output):
        self.test_num = str(self.test_num_prefix + 12)

        # create the encrypted email identification text at bottom of every email (unencrypted shows scanner IP and path of client dir being worked on so can dump results back to that same location)
        self.email_identification()

        bodytext = "This is a mail relay test " + self.test_num + ", from an external address to an internal address through " + self.email_server + self.test_additional_msg + " with an executable attachement. \n\n Note: The executable file is benign. \n\n Please forward to " + self.forward_email_to + " prior to deleting this message.\n\n Thank you." + self.encrypted_server_info
        subject = "Testing Mail Relay " + self.test_num + " through " + self.email_server + self.test_additional_msg + ". Forward to " + self.forward_email_to + "!"
        email_from = self.invalid_user_name + '@' + self.spoof_domains_no_spf_dmarc_dkim[0]
        email_to = [self.client_email]
        bodyhtml = "<html><body>" + bodytext.replace("\n", "<br>").replace(
            "Please forward to " + self.forward_email_to + " prior to deleting this message",
            "<b>Please forward to <a href='mailto:" + self.forward_email_to + "'>" + self.forward_email_to + "</a> prior to deleting this message</b>") + "</body></html>"
        bodyhtml = bodyhtml + self.test_additional_body_txt

        # attachmentfile = 'emailrelay/email_attachments/benign_exe_attachment.txt'
        attachmentfile = self.attachment_path + 'calc.exe'
        if os.path.isfile(attachmentfile):
            # Create the root message and fill in the from, to, and subject headers
            msgRoot = MIMEMultipart('related')
            msgRoot['Subject'] = subject
            msgRoot['From'] = email_from
            msgRoot['To'] = self.client_email
            if self.send_read_receipt_to is not None:
                msgRoot['Disposition-Notification-To'] = self.send_read_receipt_to
            msgRoot.preamble = 'This is a multi-part message in MIME format.'
            # Encapsulate the plain and HTML versions of the message body in an
            # 'alternative' part, so message agents can decide which they want to display.
            msgAlternative = MIMEMultipart('alternative')
            msgRoot.attach(msgAlternative)
            msgText = MIMEText(bodytext)
            msgAlternative.attach(msgText)

            msgText = MIMEText(bodyhtml, 'html')
            msgAlternative.attach(msgText)

            # attach the file
            part = MIMEBase('application', "octet-stream")
            part.set_payload(open(attachmentfile, "rb").read())
            encoders.encode_base64(part)
            part.add_header('Content-Disposition', 'attachment; filename="test.exe"')
            msgRoot.attach(part)

            # send out the email
            self.sending_email(email_from, email_to, msgRoot.as_string(), email_filter_output, msgRoot['From'], msgRoot['To'], msgRoot['Disposition-Notification-To'], ".exe")
        else:
            print_text.print_error("Missing email_attachments/calc.exe file which contains the benign exe for Mail Relay Test " + self.test_num)

    # exe in zip file
    def test13(self, email_filter_output):
        self.test_num = str(self.test_num_prefix + 13)

        # create the encrypted email identification text at bottom of every email (unencrypted shows scanner IP and path of client dir being worked on so can dump results back to that same location)
        self.email_identification()

        bodytext = "This is a mail relay test " + self.test_num + ", from an external address to an internal address through " + self.email_server + self.test_additional_msg + " with an executable enclosed in a zip file attachement. \n\n Note: The executable file is benign. \n\n Please forward to " + self.forward_email_to + " prior to deleting this message.\n\n Thank you." + self.encrypted_server_info
        subject = "Testing Mail Relay " + self.test_num + " through " + self.email_server + self.test_additional_msg + ". Forward to " + self.forward_email_to + "!"
        email_from = self.invalid_user_name + '@' + self.spoof_domains_no_spf_dmarc_dkim[0]
        email_to = [self.client_email]
        bodyhtml = "<html><body>" + bodytext.replace("\n", "<br>").replace(
            "Please forward to " + self.forward_email_to + " prior to deleting this message",
            "<b>Please forward to <a href='mailto:" + self.forward_email_to + "'>" + self.forward_email_to + "</a> prior to deleting this message</b>") + "</body></html>"
        bodyhtml = bodyhtml + self.test_additional_body_txt

        attachmentfile = self.attachment_path + 'calc.zip'
        if os.path.isfile(attachmentfile):
            # Create the root message and fill in the from, to, and subject headers
            msgRoot = MIMEMultipart('related')
            msgRoot['Subject'] = subject
            msgRoot['From'] = email_from
            msgRoot['To'] = self.client_email
            if self.send_read_receipt_to is not None:
                msgRoot['Disposition-Notification-To'] = self.send_read_receipt_to
            msgRoot.preamble = 'This is a multi-part message in MIME format.'
            # Encapsulate the plain and HTML versions of the message body in an
            # 'alternative' part, so message agents can decide which they want to display.
            msgAlternative = MIMEMultipart('alternative')
            msgRoot.attach(msgAlternative)
            msgText = MIMEText(bodytext)
            msgAlternative.attach(msgText)

            msgText = MIMEText(bodyhtml, 'html')
            msgAlternative.attach(msgText)

            # attach the file
            part = MIMEBase('application', "octet-stream")
            part.set_payload(open(attachmentfile, "rb").read())
            encoders.encode_base64(part)
            part.add_header('Content-Disposition', 'attachment; filename="testexe.zip"')
            msgRoot.attach(part)

            # send out the email
            self.sending_email(email_from, email_to, msgRoot.as_string(), email_filter_output, msgRoot['From'], msgRoot['To'], msgRoot['Disposition-Notification-To'], ".exe.zip")
        else:
            print_text.print_error("Missing email_attachments/calc.zip file which contains the benign exe wrapped inside a zip file for Mail Relay Test " + self.test_num)

    # eicar
    def test14(self, email_filter_output):
        self.test_num = str(self.test_num_prefix + 14)

        # create the encrypted email identification text at bottom of every email (unencrypted shows scanner IP and path of client dir being worked on so can dump results back to that same location)
        self.email_identification()

        bodytext = "This is a mail relay test " + self.test_num + ", from an external address to an internal address through " + self.email_server + self.test_additional_msg + " with an eicar test file attachment. \n\n Note: This file is a benign test file that is designed to test the effectiveness of anti-virus software. For more information about this file, please visit http://www.eicar.org/86-0-Intended-use.html. \n\n Please forward to " + self.forward_email_to + " prior to deleting this message.\n\n Thank you." + self.encrypted_server_info
        subject = "Testing Mail Relay " + self.test_num + " through " + self.email_server + self.test_additional_msg + ". Forward to " + self.forward_email_to + "!"
        email_from = self.invalid_user_name + '@' + self.spoof_domains_no_spf_dmarc_dkim[0]
        email_to = [self.client_email]
        bodyhtml = "<html><body>" + bodytext.replace("\n", "<br>").replace(
            "Please forward to " + self.forward_email_to + " prior to deleting this message",
            "<b>Please forward to <a href='mailto:" + self.forward_email_to + "'>" + self.forward_email_to + "</a> prior to deleting this message</b>") + "</body></html>"
        bodyhtml = bodyhtml + self.test_additional_body_txt

        attachmentfile = self.attachment_path + 'eicar.txt'
        if os.path.isfile(attachmentfile):
            # Create the root message and fill in the from, to, and subject headers
            msgRoot = MIMEMultipart('related')
            msgRoot['Subject'] = subject
            msgRoot['From'] = email_from
            msgRoot['To'] = self.client_email
            if self.send_read_receipt_to is not None:
                msgRoot['Disposition-Notification-To'] = self.send_read_receipt_to
            msgRoot.preamble = 'This is a multi-part message in MIME format.'
            # Encapsulate the plain and HTML versions of the message body in an
            # 'alternative' part, so message agents can decide which they want to display.
            msgAlternative = MIMEMultipart('alternative')
            msgRoot.attach(msgAlternative)
            msgText = MIMEText(bodytext)
            msgAlternative.attach(msgText)

            msgText = MIMEText(bodyhtml, 'html')
            msgAlternative.attach(msgText)

            # attach the file
            part = MIMEBase('application', "octet-stream")
            part.set_payload(open(attachmentfile, "rb").read())
            encoders.encode_base64(part)
            part.add_header('Content-Disposition', 'attachment; filename="eicar.com"')
            msgRoot.attach(part)
            # send out the email
            self.sending_email(email_from, email_to, msgRoot.as_string(), email_filter_output, msgRoot['From'], msgRoot['To'], msgRoot['Disposition-Notification-To'], "eicar")
        else:
            print_text.print_error("Missing email_attachments/eicar.txt file which contains the eicar file for Mail Relay Test " + self.test_num)

    # eicar in zip file
    def test15(self, email_filter_output):
        self.test_num = str(self.test_num_prefix + 15)

        # create the encrypted email identification text at bottom of every email (unencrypted shows scanner IP and path of client dir being worked on so can dump results back to that same location)
        self.email_identification()

        bodytext = "This is a mail relay test " + self.test_num + ", from an external address to an internal address through " + self.email_server + self.test_additional_msg + " with an eicar test file enclosed in a zip file as an attachment. \n\n Note: This file is a benign test file that is designed to test the effectiveness of anti-virus software. For more information about this file, please visit http://www.eicar.org/86-0-Intended-use.html. \n\n Please forward to " + self.forward_email_to + " prior to deleting this message.\n\n Thank you." + self.encrypted_server_info
        subject = "Testing Mail Relay " + self.test_num + " through " + self.email_server + self.test_additional_msg + ". Forward to " + self.forward_email_to + "!"
        email_from = self.invalid_user_name + '@' + self.spoof_domains_no_spf_dmarc_dkim[0]
        email_to = [self.client_email]
        bodyhtml = "<html><body>" + bodytext.replace("\n", "<br>").replace(
            "Please forward to " + self.forward_email_to + " prior to deleting this message",
            "<b>Please forward to <a href='mailto:" + self.forward_email_to + "'>" + self.forward_email_to + "</a> prior to deleting this message</b>") + "</body></html>"
        bodyhtml = bodyhtml + self.test_additional_body_txt

        attachmentfile = self.attachment_path + 'eicar.zip'
        if os.path.isfile(attachmentfile):
            # Create the root message and fill in the from, to, and subject headers
            msgRoot = MIMEMultipart('related')
            msgRoot['Subject'] = subject
            msgRoot['From'] = email_from
            msgRoot['To'] = self.client_email
            if self.send_read_receipt_to is not None:
                msgRoot['Disposition-Notification-To'] = self.send_read_receipt_to
            msgRoot.preamble = 'This is a multi-part message in MIME format.'
            # Encapsulate the plain and HTML versions of the message body in an
            # 'alternative' part, so message agents can decide which they want to display.
            msgAlternative = MIMEMultipart('alternative')
            msgRoot.attach(msgAlternative)
            msgText = MIMEText(bodytext)
            msgAlternative.attach(msgText)

            msgText = MIMEText(bodyhtml, 'html')
            msgAlternative.attach(msgText)
            # attach the file
            part = MIMEBase('application', "octet-stream")
            part.set_payload(open(attachmentfile, "rb").read())
            encoders.encode_base64(part)
            part.add_header('Content-Disposition', 'attachment; filename="eicar.zip"')
            msgRoot.attach(part)
            # send out the email
            self.sending_email(email_from, email_to, msgRoot.as_string(), email_filter_output, msgRoot['From'], msgRoot['To'], msgRoot['Disposition-Notification-To'], "eicar.zip")
        else:
            print_text.print_error("Missing email_attachments/eicar.zip file which contains eicar wrapped inside a zip file for Mail Relay Test " + self.test_num)

    # eicar in zip inside another zip
    def test16(self, email_filter_output):
        self.test_num = str(self.test_num_prefix + 16)

        # create the encrypted email identification text at bottom of every email (unencrypted shows scanner IP and path of client dir being worked on so can dump results back to that same location)
        self.email_identification()

        bodytext = "This is a mail relay test " + self.test_num + ", from an external address to an internal address through " + self.email_server + self.test_additional_msg + " with an eicar test file enclosed in a zip file within another zip file as an attachment. \n\n Note: This file is a benign test file that is designed to test the effectiveness of anti-virus software. For more information about this file, please visit http://www.eicar.org/86-0-Intended-use.html. \n\n Please forward to " + self.forward_email_to + " prior to deleting this message.\n\n Thank you." + self.encrypted_server_info
        subject = "Testing Mail Relay " + self.test_num + " through " + self.email_server + self.test_additional_msg + ". Forward to " + self.forward_email_to + "!"
        email_from = self.invalid_user_name + '@' + self.spoof_domains_no_spf_dmarc_dkim[0]
        email_to = [self.client_email]
        bodyhtml = "<html><body>" + bodytext.replace("\n", "<br>").replace(
            "Please forward to " + self.forward_email_to + " prior to deleting this message",
            "<b>Please forward to <a href='mailto:" + self.forward_email_to + "'>" + self.forward_email_to + "</a> prior to deleting this message</b>") + "</body></html>"
        bodyhtml = bodyhtml + self.test_additional_body_txt

        attachmentfile = self.attachment_path + 'eicar_zip.zip'
        if os.path.isfile(attachmentfile):
            # Create the root message and fill in the from, to, and subject headers
            msgRoot = MIMEMultipart('related')
            msgRoot['Subject'] = subject
            msgRoot['From'] = email_from
            msgRoot['To'] = self.client_email
            if self.send_read_receipt_to is not None:
                msgRoot['Disposition-Notification-To'] = self.send_read_receipt_to
            msgRoot.preamble = 'This is a multi-part message in MIME format.'
            # Encapsulate the plain and HTML versions of the message body in an
            # 'alternative' part, so message agents can decide which they want to display.
            msgAlternative = MIMEMultipart('alternative')
            msgRoot.attach(msgAlternative)
            msgText = MIMEText(bodytext)
            msgAlternative.attach(msgText)

            msgText = MIMEText(bodyhtml, 'html')
            msgAlternative.attach(msgText)
            # attach the file
            part = MIMEBase('application', "octet-stream")
            part.set_payload(open(attachmentfile, "rb").read())
            encoders.encode_base64(part)
            part.add_header('Content-Disposition', 'attachment; filename="eicar2.zip"')
            msgRoot.attach(part)
            # send out the email
            self.sending_email(email_from, email_to, msgRoot.as_string(), email_filter_output, msgRoot['From'], msgRoot['To'], msgRoot['Disposition-Notification-To'], "eicar.zip.zip")
        else:
            print_text.print_error("Missing email_attachments/eicar_zip.zip file which contains eicar wrapped inside a zip file inside another zip file for Mail Relay Test " + self.test_num)

    # checking SPF (meaning sending from domain that has SPF entries for their domain and we are sending from IP that is not apart of their SPF records)
    def test17(self, email_filter_output):
        self.test_num = str(self.test_num_prefix + 17)

        # create the encrypted email identification text at bottom of every email (unencrypted shows scanner IP and path of client dir being worked on so can dump results back to that same location)
        self.email_identification()

        bodytext = "This is a mail relay test " + self.test_num + ", from a spoofed valid external address but not from a valid SPF location to an internal address through " + self.email_server + self.test_additional_msg + ". \n\n	Please forward to " + self.forward_email_to + " prior to deleting this message.\n\n Thank you." + self.encrypted_server_info
        subject = "Testing Mail Relay " + self.test_num + " through " + self.email_server + self.test_additional_msg + ". Forward to " + self.forward_email_to + "!"
        email_from = self.invalid_user_name + '@' + self.spoof_domain_with_spf_hardfail
        email_to = [self.client_email]
        bodyhtml = "<html><body>" + bodytext.replace("\n", "<br>").replace(
            "Please forward to " + self.forward_email_to + " prior to deleting this message",
            "<b>Please forward to <a href='mailto:" + self.forward_email_to + "'>" + self.forward_email_to + "</a> prior to deleting this message</b>") + "</body></html>"
        bodyhtml = bodyhtml + self.test_additional_body_txt

        # Create the root message and fill in the from, to, and subject headers
        msgRoot = MIMEMultipart('related')
        msgRoot['Subject'] = subject
        msgRoot['From'] = email_from
        msgRoot['To'] = self.client_email
        if self.send_read_receipt_to is not None:
            msgRoot['Disposition-Notification-To'] = self.send_read_receipt_to
        msgRoot.preamble = 'This is a multi-part message in MIME format.'
        # Encapsulate the plain and HTML versions of the message body in an
        # 'alternative' part, so message agents can decide which they want to display.
        msgAlternative = MIMEMultipart('alternative')
        msgRoot.attach(msgAlternative)
        msgText = MIMEText(bodytext)
        msgAlternative.attach(msgText)

        msgText = MIMEText(bodyhtml, 'html')
        msgAlternative.attach(msgText)

        self.sending_email(email_from, email_to, msgRoot.as_string(), email_filter_output, msgRoot['From'],
                           msgRoot['To'], msgRoot['Disposition-Notification-To'])

    # checking .gadget exensions
    def test18(self, email_filter_output):
        self.test_num = str(self.test_num_prefix + 18)

        # create the encrypted email identification text at bottom of every email (unencrypted shows scanner IP and path of client dir being worked on so can dump results back to that same location)
        self.email_identification()

        bodytext = "This is a mail relay test " + self.test_num + ", from an external address to an internal address through " + self.email_server + self.test_additional_msg + " with an .gadget test file attachment. \n\n Note: This file is a benign test file that is designed to test effectiveness of filtering .gadget files.. \n\n Please forward to " + self.forward_email_to + " prior to deleting this message.\n\n Thank you." + self.encrypted_server_info
        subject = "Testing Mail Relay " + self.test_num + " through " + self.email_server + self.test_additional_msg + ". Forward to " + self.forward_email_to + "!"
        email_from = self.invalid_user_name + '@' + self.spoof_domains_no_spf_dmarc_dkim[0]
        email_to = [self.client_email]
        bodyhtml = "<html><body>" + bodytext.replace("\n", "<br>").replace(
            "Please forward to " + self.forward_email_to + " prior to deleting this message",
            "<b>Please forward to <a href='mailto:" + self.forward_email_to + "'>" + self.forward_email_to + "</a> prior to deleting this message</b>") + "</body></html>"
        bodyhtml = bodyhtml + self.test_additional_body_txt

        attachmentfile = self.attachment_path + 'thankyou.gadget'
        if os.path.isfile(attachmentfile):
            # Create the root message and fill in the from, to, and subject headers
            msgRoot = MIMEMultipart('related')
            msgRoot['Subject'] = subject
            msgRoot['From'] = email_from
            msgRoot['To'] = self.client_email
            if self.send_read_receipt_to is not None:
                msgRoot['Disposition-Notification-To'] = self.send_read_receipt_to
            msgRoot.preamble = 'This is a multi-part message in MIME format.'
            # Encapsulate the plain and HTML versions of the message body in an
            # 'alternative' part, so message agents can decide which they want to display.
            msgAlternative = MIMEMultipart('alternative')
            msgRoot.attach(msgAlternative)
            msgText = MIMEText(bodytext)
            msgAlternative.attach(msgText)

            msgText = MIMEText(bodyhtml, 'html')
            msgAlternative.attach(msgText)
            # attach the file
            part = MIMEBase('application', "octet-stream")
            part.set_payload(open(attachmentfile, "rb").read())
            encoders.encode_base64(part)
            part.add_header('Content-Disposition', 'attachment; filename="thankyou.gadget"')
            msgRoot.attach(part)
            # send out the email
            self.sending_email(email_from, email_to, msgRoot.as_string(), email_filter_output, msgRoot['From'], msgRoot['To'], msgRoot['Disposition-Notification-To'], ".gadget")
        else:
            print_text.print_error(
                "Missing email_attachments/thankyou.gadget file for Mail Relay Test " + self.test_num)

    # .bat
    def test19(self, email_filter_output):
        self.test_num = str(self.test_num_prefix + 19)

        # create the encrypted email identification text at bottom of every email (unencrypted shows scanner IP and path of client dir being worked on so can dump results back to that same location)
        self.email_identification()

        bodytext = "This is a mail relay test " + self.test_num + ", from an external address to an internal address through " + self.email_server + self.test_additional_msg + " with an .bat test file attachment. \n\n Note: This file is a benign test file that is designed to test the effectiveness of filtering .bat files. \n\n Please forward to " + self.forward_email_to + " prior to deleting this message.\n\n Thank you." + self.encrypted_server_info
        subject = "Testing Mail Relay " + self.test_num + " through " + self.email_server + self.test_additional_msg + ". Forward to " + self.forward_email_to + "!"
        email_from = self.invalid_user_name + '@' + self.spoof_domains_no_spf_dmarc_dkim[0]
        email_to = [self.client_email]
        bodyhtml = "<html><body>" + bodytext.replace("\n", "<br>").replace(
            "Please forward to " + self.forward_email_to + " prior to deleting this message",
            "<b>Please forward to <a href='mailto:" + self.forward_email_to + "'>" + self.forward_email_to + "</a> prior to deleting this message</b>") + "</body></html>"
        bodyhtml = bodyhtml + self.test_additional_body_txt

        attachmentfile = self.attachment_path + 'ver.bat'
        if os.path.isfile(attachmentfile):
            # Create the root message and fill in the from, to, and subject headers
            msgRoot = MIMEMultipart('related')
            msgRoot['Subject'] = subject
            msgRoot['From'] = email_from
            msgRoot['To'] = self.client_email
            if self.send_read_receipt_to is not None:
                msgRoot['Disposition-Notification-To'] = self.send_read_receipt_to
            msgRoot.preamble = 'This is a multi-part message in MIME format.'
            # Encapsulate the plain and HTML versions of the message body in an
            # 'alternative' part, so message agents can decide which they want to display.
            msgAlternative = MIMEMultipart('alternative')
            msgRoot.attach(msgAlternative)
            msgText = MIMEText(bodytext)
            msgAlternative.attach(msgText)

            msgText = MIMEText(bodyhtml, 'html')
            msgAlternative.attach(msgText)
            # attach the file
            part = MIMEBase('application', "octet-stream")
            part.set_payload(open(attachmentfile, "rb").read())
            encoders.encode_base64(part)
            part.add_header('Content-Disposition', 'attachment; filename="login.bat"')
            msgRoot.attach(part)
            # send out the email
            self.sending_email(email_from, email_to, msgRoot.as_string(), email_filter_output, msgRoot['From'], msgRoot['To'], msgRoot['Disposition-Notification-To'], ".bat")
        else:
            print_text.print_error(
                "Missing email_attachments/ver.bat file for Mail Relay Test " + self.test_num)

    # Identical to Test10 except also contains plain text alternative (spoofing URL address)
    def test20(self, email_filter_output):
        self.test_num = str(self.test_num_prefix + 20)

        # create the encrypted email identification text at bottom of every email (unencrypted shows scanner IP and path of client dir being worked on so can dump results back to that same location)
        self.email_identification()

        bodytext = "This is a mail relay test " + self.test_num + ", from a spoofed valid external address to an internal address through " + self.email_server + self.test_additional_msg + " with an masked url with a plain text alternative email message. \n\nhttp://www.yahoo.com\n\n	Please forward to " + self.forward_email_to + " prior to deleting this message.\n\n Thank you." + self.encrypted_server_info
        subject = "Testing Mail Relay " + self.test_num + " through " + self.email_server + self.test_additional_msg + ". Forward to " + self.forward_email_to + "!"
        email_from = self.invalid_user_name + '@' + self.spoof_domains_no_spf_dmarc_dkim[0]  # self.invalid_user_name+'@'+self.spoof_domain_no_spf_dmarc_dkim[0]+' '
        email_to = [self.client_email]
        bodyhtml = "<html><body>" + bodytext.replace("\n", "<br>").replace("http://www.yahoo.com",
                                                                     "<a href='http://www.yahoo.com'>http://www.google.com</a>").replace(
            "Please forward to " + self.forward_email_to + " prior to deleting this message",
            "<b>Please forward to <a href='mailto:" + self.forward_email_to + "'>" + self.forward_email_to + "</a> prior to deleting this message</b>") + "</body></html>"
        bodyhtml = bodyhtml + self.test_additional_body_txt

        # Create the root message and fill in the from, to, and subject headers
        msgRoot = MIMEMultipart('related')
        msgRoot['Subject'] = subject
        msgRoot['From'] = email_from
        msgRoot['To'] = self.client_email
        if self.send_read_receipt_to is not None:
            msgRoot['Disposition-Notification-To'] = self.send_read_receipt_to
        msgRoot.preamble = 'This is a multi-part message in MIME format.'
        # Encapsulate the plain and HTML versions of the message body in an
        # 'alternative' part, so message agents can decide which they want to display.
        msgAlternative = MIMEMultipart('alternative')
        msgRoot.attach(msgAlternative)
        msgText = MIMEText(bodytext)
        msgAlternative.attach(msgText)

        msgText = MIMEText(bodyhtml, 'html')
        msgAlternative.attach(msgText)

        self.sending_email(email_from, email_to, msgRoot.as_string(), email_filter_output, msgRoot['From'],
                           msgRoot['To'], msgRoot['Disposition-Notification-To'])

    # EXFIL
    def test21(self, email_filter_output):
        self.test_num = str(self.test_num_prefix + 21)

        # create the encrypted email identification text at bottom of every email (unencrypted shows scanner IP and path of client dir being worked on so can dump results back to that same location)
        self.email_identification()

        bodytext = "This is a mail relay test " + self.test_num + ", testing exfil paths. \nPort 80:<img src='http://exfil.issgs.net/starwars.jpg?" + self.encrypted_server_info + "' width=5>\nPort:8080<img src='http://exfil.issgs.net:8080/starwars.jpg?" + self.encrypted_server_info + "' width=5>\nPort:443<img src='http://exfil.issgs.net:443/starwars.jpg?" + self.encrypted_server_info + "' width=5>\nPort:64999<img src='http://exfil.issgs.net:64999/starwars.jpg?" + self.encrypted_server_info + "' width=5><br>"  + self.encrypted_server_info
        subject = "Testing Mail Relay " + self.test_num + " through " + self.email_server + self.test_additional_msg + ". Forward to " + self.forward_email_to + "!"
        email_from = self.invalid_user_name + '@' + self.spoof_domains_no_spf_dmarc_dkim[0]
        email_to = [self.client_email]
        bodyhtml = "<html><body>" + bodytext.replace("\n", "<br>").replace(
            "Please forward to " + self.forward_email_to + " prior to deleting this message",
            "<b>Please forward to <a href='mailto:" + self.forward_email_to + "'>" + self.forward_email_to + "</a> prior to deleting this message</b>") + "</body></html>"
        bodyhtml = bodyhtml + self.test_additional_body_txt

        # Create the root message and fill in the from, to, and subject headers
        msgRoot = MIMEMultipart('related')
        msgRoot['Subject'] = subject
        msgRoot['From'] = email_from
        msgRoot['To'] = self.client_email
        if self.send_read_receipt_to is not None:
            msgRoot['Disposition-Notification-To'] = self.send_read_receipt_to
        msgRoot.preamble = 'This is a multi-part message in MIME format.'
        # Encapsulate the plain and HTML versions of the message body in an
        # 'alternative' part, so message agents can decide which they want to display.
        msgAlternative = MIMEMultipart('alternative')
        msgRoot.attach(msgAlternative)
        msgText = MIMEText(bodytext)
        msgAlternative.attach(msgText)

        msgText = MIMEText(bodyhtml, 'html')
        msgAlternative.attach(msgText)

        # send out the email
        self.sending_email(email_from, email_to, msgRoot.as_string(), email_filter_output, msgRoot['From'],
                           msgRoot['To'], msgRoot['Disposition-Notification-To'])

    # hta attachment
    def test22(self, email_filter_output):
        self.test_num = str(self.test_num_prefix + 22)

        # create the encrypted email identification text at bottom of every email (unencrypted shows scanner IP and path of client dir being worked on so can dump results back to that same location)
        self.email_identification()

        bodytext = "This is a mail relay test " + self.test_num + ", from an external address to an internal address through " + self.email_server + self.test_additional_msg + " with an .HTA attachement. \n\n Note: The HTA file is benign. \n\n Please forward to " + self.forward_email_to + " prior to deleting this message.\n\n Thank you." + self.encrypted_server_info
        subject = "Testing Mail Relay " + self.test_num + " through " + self.email_server + self.test_additional_msg + ". Forward to " + self.forward_email_to + "!"
        email_from = self.invalid_user_name + '@' + self.spoof_domains_no_spf_dmarc_dkim[0]
        email_to = [self.client_email]
        bodyhtml = "<html><body>" + bodytext.replace("\n", "<br>").replace(
            "Please forward to " + self.forward_email_to + " prior to deleting this message",
            "<b>Please forward to <a href='mailto:" + self.forward_email_to + "'>" + self.forward_email_to + "</a> prior to deleting this message</b>") + "</body></html>"
        bodyhtml = bodyhtml + self.test_additional_body_txt

        attachmentfile = self.attachment_path + 'test.hta'
        if os.path.isfile(attachmentfile):
            # Create the root message and fill in the from, to, and subject headers
            msgRoot = MIMEMultipart('related')
            msgRoot['Subject'] = subject
            msgRoot['From'] = email_from
            msgRoot['To'] = self.client_email
            if self.send_read_receipt_to is not None:
                msgRoot['Disposition-Notification-To'] = self.send_read_receipt_to
            msgRoot.preamble = 'This is a multi-part message in MIME format.'
            # Encapsul
            # ate the plain and HTML versions of the message body in an
            # 'alternative' part, so message agents can decide which they want to display.
            msgAlternative = MIMEMultipart('alternative')
            msgRoot.attach(msgAlternative)
            msgText = MIMEText(bodytext)
            msgAlternative.attach(msgText)

            msgText = MIMEText(bodyhtml, 'html')
            msgAlternative.attach(msgText)

            # attach the file
            part = MIMEBase('application', "octet-stream")
            part.set_payload(open(attachmentfile, "rb").read())
            encoders.encode_base64(part)
            part.add_header('Content-Disposition', 'attachment; filename="test.hta"')
            msgRoot.attach(part)

            # send out the email
            self.sending_email(email_from, email_to, msgRoot.as_string(), email_filter_output, msgRoot['From'], msgRoot['To'], msgRoot['Disposition-Notification-To'], ".hta")
        else:
            print_text.print_error(
                "Missing " + attachmentfile + " file for Mail Relay Test " + self.test_num)

    # Word Doc w/ Macro attachment
    def test23(self, email_filter_output):
        self.test_num = str(self.test_num_prefix + 23)

        # create the encrypted email identification text at bottom of every email (unencrypted shows scanner IP and path of client dir being worked on so can dump results back to that same location)
        self.email_identification()

        bodytext = "This is a mail relay test " + self.test_num + ", from an external address to an internal address through " + self.email_server + self.test_additional_msg + " with an attachment of a Word Document that contains a non-malicious macro. \n\n Note: The Word Doc file and Macro are benign. \n\n Please forward to " + self.forward_email_to + " prior to deleting this message.\n\n Thank you." + self.encrypted_server_info
        subject = "Testing Mail Relay " + self.test_num + " through " + self.email_server + self.test_additional_msg + ". Forward to " + self.forward_email_to + "!"
        email_from = self.invalid_user_name + '@' + self.spoof_domains_no_spf_dmarc_dkim[0]
        email_to = [self.client_email]
        bodyhtml = "<html><body>" + bodytext.replace("\n", "<br>").replace(
            "Please forward to " + self.forward_email_to + " prior to deleting this message",
            "<b>Please forward to <a href='mailto:" + self.forward_email_to + "'>" + self.forward_email_to + "</a> prior to deleting this message</b>") + "</body></html>"
        bodyhtml = bodyhtml + self.test_additional_body_txt

        attachmentfile = self.attachment_path + 'test.doc'
        if os.path.isfile(attachmentfile):
            # Create the root message and fill in the from, to, and subject headers
            msgRoot = MIMEMultipart('related')
            msgRoot['Subject'] = subject
            msgRoot['From'] = email_from
            msgRoot['To'] = self.client_email
            if self.send_read_receipt_to is not None:
                msgRoot['Disposition-Notification-To'] = self.send_read_receipt_to
            msgRoot.preamble = 'This is a multi-part message in MIME format.'
            # Encapsulate the plain and HTML versions of the message body in an
            # 'alternative' part, so message agents can decide which they want to display.
            msgAlternative = MIMEMultipart('alternative')
            msgRoot.attach(msgAlternative)
            msgText = MIMEText(bodytext)
            msgAlternative.attach(msgText)

            msgText = MIMEText(bodyhtml, 'html')
            msgAlternative.attach(msgText)

            # attach the file
            part = MIMEBase('application', "octet-stream")
            part.set_payload(open(attachmentfile, "rb").read())
            encoders.encode_base64(part)
            part.add_header('Content-Disposition', 'attachment; filename="test.doc"')
            msgRoot.attach(part)

            # send out the email
            self.sending_email(email_from, email_to, msgRoot.as_string(), email_filter_output, msgRoot['From'], msgRoot['To'], msgRoot['Disposition-Notification-To'], ".doc (with macro)")
        else:
            print_text.print_error(
                "Missing " + attachmentfile + " file which contains a macro for Mail Relay Test " + self.test_num)

    # checking SPF with SoftFail (meaning we send from domain that has a SoftFail SPF entry to end (~all) intead of HardFail (-all)
    def test24(self, email_filter_output):
        self.test_num = str(self.test_num_prefix + 24)

        # create the encrypted email identification text at bottom of every email (unencrypted shows scanner IP and path of client dir being worked on so can dump results back to that same location)
        self.email_identification()

        bodytext = "This is a mail relay test " + self.test_num + ", from a spoofed valid external address but not from a valid SPF location to an internal address through " + self.email_server + self.test_additional_msg + " and whose SPF entry ends with a SoftFail (~all) instead of a HardFail (-all). \n\n	Please forward to " + self.forward_email_to + " prior to deleting this message.\n\n Thank you." + self.encrypted_server_info
        subject = "Testing Mail Relay " + self.test_num + " through " + self.email_server + self.test_additional_msg + ". Forward to " + self.forward_email_to + "!"
        email_from = self.invalid_user_name + '@' + self.spoof_domain_with_spf_softfail
        email_to = [self.client_email]
        bodyhtml = "<html><body>" + bodytext.replace("\n", "<br>").replace(
            "Please forward to " + self.forward_email_to + " prior to deleting this message",
            "<b>Please forward to <a href='mailto:" + self.forward_email_to + "'>" + self.forward_email_to + "</a> prior to deleting this message</b>") + "</body></html>"
        bodyhtml = bodyhtml + self.test_additional_body_txt

        # Create the root message and fill in the from, to, and subject headers
        msgRoot = MIMEMultipart('related')
        msgRoot['Subject'] = subject
        msgRoot['From'] = email_from
        msgRoot['To'] = self.client_email
        if self.send_read_receipt_to is not None:
            msgRoot['Disposition-Notification-To'] = self.send_read_receipt_to
        msgRoot.preamble = 'This is a multi-part message in MIME format.'
        # Encapsulate the plain and HTML versions of the message body in an
        # 'alternative' part, so message agents can decide which they want to display.
        msgAlternative = MIMEMultipart('alternative')
        msgRoot.attach(msgAlternative)
        msgText = MIMEText(bodytext)
        msgAlternative.attach(msgText)

        msgText = MIMEText(bodyhtml, 'html')
        msgAlternative.attach(msgText)

        self.sending_email(email_from, email_to, msgRoot.as_string(), email_filter_output, msgRoot['From'],
                           msgRoot['To'], msgRoot['Disposition-Notification-To'])

    # testing if can send email FROM but have read receipt back to different email
    def test25(self, email_filter_output):
        self.test_num = str(self.test_num_prefix + 25)

        # create the encrypted email identification text at bottom of every email (unencrypted shows scanner IP and path of client dir being worked on so can dump results back to that same location)
        self.email_identification()

        bodytext = "This is a mail relay test " + self.test_num + ", with a different SEND TO Delivery Notification (read receipt) than the SMTP FROM through " + self.email_server + self.test_additional_msg + ". \n\n	Please forward to " + self.forward_email_to + " prior to deleting this message.\n\n Thank you." + self.encrypted_server_info
        subject = "Testing Mail Relay " + self.test_num + " through " + self.email_server + self.test_additional_msg + ". Forward to " + self.forward_email_to + "!"
        email_from = self.invalid_user_name + '@' + self.spoof_domains_no_spf_dmarc_dkim[0]
        email_to = [self.client_email]
        bodyhtml = "<html><body>" + bodytext.replace("\n", "<br>").replace(
            "Please forward to " + self.forward_email_to + " prior to deleting this message",
            "<b>Please forward to <a href='mailto:" + self.forward_email_to + "'>" + self.forward_email_to + "</a> prior to deleting this message</b>") + "</body></html>"
        bodyhtml = bodyhtml + self.test_additional_body_txt

        # Create the root message and fill in the from, to, and subject headers
        msgRoot = MIMEMultipart('related')
        msgRoot['Subject'] = subject
        msgRoot['From'] = email_from
        msgRoot['To'] = self.client_email
        msgRoot['Disposition-Notification-To'] = self.send_read_receipt_to
        msgRoot.preamble = 'This is a multi-part message in MIME format.'
        # Encapsulate the plain and HTML versions of the message body in an
        # 'alternative' part, so message agents can decide which they want to display.
        msgAlternative = MIMEMultipart('alternative')
        msgRoot.attach(msgAlternative)
        msgText = MIMEText(bodytext)
        msgAlternative.attach(msgText)

        msgText = MIMEText(bodyhtml, 'html')
        msgAlternative.attach(msgText)

        self.sending_email(email_from, email_to, msgRoot.as_string(), email_filter_output, msgRoot['From'],
                           msgRoot['To'], msgRoot['Disposition-Notification-To'])

    # similiar to test25 but SMTP FROM = READ RECEIPT FROM (combo of test 27 & test 25)
    def test26(self, email_filter_output):
        self.test_num = str(self.test_num_prefix + 26)

        # create the encrypted email identification text at bottom of every email (unencrypted shows scanner IP and path of client dir being worked on so can dump results back to that same location)
        self.email_identification()

        bodytext = "This is a mail relay test " + self.test_num + ", with a different SEND TO Delivery Notification (read receipt) than the DATA FROM  but same as SMTP FROM through " + self.email_server + self.test_additional_msg + ". \n\n	Please forward to " + self.forward_email_to + " prior to deleting this message.\n\n Thank you." + self.encrypted_server_info
        subject = "Testing Mail Relay " + self.test_num + " through " + self.email_server + self.test_additional_msg + ". Forward to " + self.forward_email_to + "!"
        email_from = self.forward_email_to
        email_to = [self.client_email]
        bodyhtml = "<html><body>" + bodytext.replace("\n", "<br>").replace(
            "Please forward to " + self.forward_email_to + " prior to deleting this message",
            "<b>Please forward to <a href='mailto:" + self.forward_email_to + "'>" + self.forward_email_to + "</a> prior to deleting this message</b>") + "</body></html>"
        bodyhtml = bodyhtml + self.test_additional_body_txt

        # Create the root message and fill in the from, to, and subject headers
        msgRoot = MIMEMultipart('related')
        msgRoot['Subject'] = subject
        msgRoot['From'] = self.invalid_user_name + '@' + self.spoof_domains_no_spf_dmarc_dkim[0]
        msgRoot['To'] = self.client_email
        msgRoot['Disposition-Notification-To'] = email_from
        msgRoot.preamble = 'This is a multi-part message in MIME format.'
        # Encapsulate the plain and HTML versions of the message body in an
        # 'alternative' part, so message agents can decide which they want to display.
        msgAlternative = MIMEMultipart('alternative')
        msgRoot.attach(msgAlternative)
        msgText = MIMEText(bodytext)
        msgAlternative.attach(msgText)

        msgText = MIMEText(bodyhtml, 'html')
        msgAlternative.attach(msgText)

        self.sending_email(email_from, email_to, msgRoot.as_string(), email_filter_output, msgRoot['From'],
                           msgRoot['To'], msgRoot['Disposition-Notification-To'])

    # spoofed DATA FROM but not SMTP FROM for domain with valid SPF (HardFail from test17)
    def test27(self, email_filter_output):
        self.test_num = str(self.test_num_prefix + 27)

        # create the encrypted email identification text at bottom of every email (unencrypted shows scanner IP and path of client dir being worked on so can dump results back to that same location)
        self.email_identification()

        bodytext = "This is a mail relay test " + self.test_num + ", from a spoofed external address with HardFail SPF entry mixed with valid external address through " + self.email_server + self.test_additional_msg + ". \n\n	Please forward to " + self.forward_email_to + " prior to deleting this message.\n\n Thank you." + self.encrypted_server_info
        subject = "Testing Mail Relay " + self.test_num + " through " + self.email_server + self.test_additional_msg + ". Forward to " + self.forward_email_to + "!"
        email_from_spoof = self.invalid_user_name + '@' + self.spoof_domains_no_spf_dmarc_dkim[0]
        email_from = email_from_spoof
        email_to = [self.client_email]
        bodyhtml = "<html><body>" + bodytext.replace("\n", "<br>").replace(
            "Please forward to " + self.forward_email_to + " prior to deleting this message",
            "<b>Please forward to <a href='mailto:" + self.forward_email_to + "'>" + self.forward_email_to + "</a> prior to deleting this message</b>") + "</body></html>"
        bodyhtml = bodyhtml + self.test_additional_body_txt

        # Create the root message and fill in the from, to, and subject headers
        msgRoot = MIMEMultipart('related')
        msgRoot['Subject'] = subject
        msgRoot['From'] = self.invalid_user_name + '@' + self.spoof_domain_with_spf_hardfail
        msgRoot['To'] = self.client_email
        if self.send_read_receipt_to is not None:
            msgRoot['Disposition-Notification-To'] = self.send_read_receipt_to
        msgRoot.preamble = 'This is a multi-part message in MIME format.'
        # Encapsulate the plain and HTML versions of the message body in an
        # 'alternative' part, so message agents can decide which they want to display.
        msgAlternative = MIMEMultipart('alternative')
        msgRoot.attach(msgAlternative)
        msgText = MIMEText(bodytext)
        msgAlternative.attach(msgText)

        msgText = MIMEText(bodyhtml, 'html')
        msgAlternative.attach(msgText)

        self.sending_email(email_from, email_to, msgRoot.as_string(), email_filter_output, msgRoot['From'],
                           msgRoot['To'], msgRoot['Disposition-Notification-To'])

    # SMTP FROM base64 encode but DATA FROM is not (shadow attack)
    def test28(self, email_filter_output):
        """ Thanks to Forrest for this one. """
        try:
            self.test_num = str(self.test_num_prefix + 28)

            # create the encrypted email identification text at bottom of every email (unencrypted shows scanner IP and path of client dir being worked on so can dump results back to that same location)
            self.email_identification()

            bodytext = "This is a mail relay test " + self.test_num + ", from a internal address that has the username base64 encoded and no domain portion (shadow attack) and the DATA FROM is a valid internal address that is not base64 encoded through " + self.email_server + self.test_additional_msg + ". \n\n	Please forward to " + self.forward_email_to + " prior to deleting this message.\n\n Thank you." + self.encrypted_server_info
            subject = "Testing Mail Relay " + self.test_num + " through " + self.email_server + self.test_additional_msg + ". Forward to " + self.forward_email_to + "!"
            #email_from_spoof = self.invalid_user_name + '@' + self.spoof_domains_no_spf_dmarc_dkim[0]
            email_from = "=?UTF-8?B?" + base64.b64encode(self.client_username.encode('utf-8')).decode('utf-8') + "?= <>"
            email_to = [self.client_email]
            bodyhtml = "<html><body>" + bodytext.replace("\n", "<br>").replace(
                "Please forward to " + self.forward_email_to + " prior to deleting this message",
                "<b>Please forward to <a href='mailto:" + self.forward_email_to + "'>" + self.forward_email_to + "</a> prior to deleting this message</b>") + "</body></html>"
            bodyhtml = bodyhtml + self.test_additional_body_txt

            # Create the root message and fill in the from, to, and subject headers
            msgRoot = MIMEMultipart('related')
            msgRoot['Subject'] = subject
            msgRoot['From'] = self.client_email
            msgRoot['To'] = self.client_email
            if self.send_read_receipt_to is not None:
                msgRoot['Disposition-Notification-To'] = self.send_read_receipt_to
            msgRoot.preamble = 'This is a multi-part message in MIME format.'
            # Encapsulate the plain and HTML versions of the message body in an
            # 'alternative' part, so message agents can decide which they want to display.
            msgAlternative = MIMEMultipart('alternative')
            msgRoot.attach(msgAlternative)
            msgText = MIMEText(bodytext)
            msgAlternative.attach(msgText)

            msgText = MIMEText(bodyhtml, 'html')
            msgAlternative.attach(msgText)

            self.sending_email(email_from, email_to, msgRoot.as_string(), email_filter_output, msgRoot['From'], msgRoot['To'], msgRoot['Disposition-Notification-To'])
        except Exception as e:
            print("email filter class 1416 except: " + str(e) + " Error on line {}".format(sys.exc_info()[-1].tb_lineno))


    # .exe attachment but with extension changed to .txt
    def test29(self, email_filter_output):
        self.test_num = str(self.test_num_prefix + 29)

        # create the encrypted email identification text at bottom of every email (unencrypted shows scanner IP and path of client dir being worked on so can dump results back to that same location)
        self.email_identification()

        bodytext = "This is a mail relay test " + self.test_num + ", from an external address to an internal address through " + self.email_server + self.test_additional_msg + " with an executable attachement but the .exe extension has been changed to .txt. \n\n Note: The executable file is benign. \n\n Please forward to " + self.forward_email_to + " prior to deleting this message.\n\n Thank you." + self.encrypted_server_info
        subject = "Testing Mail Relay " + self.test_num + " through " + self.email_server + self.test_additional_msg + ". Forward to " + self.forward_email_to + "!"
        email_from = self.invalid_user_name + '@' + self.spoof_domains_no_spf_dmarc_dkim[0]
        email_to = [self.client_email]
        bodyhtml = "<html><body>" + bodytext.replace("\n", "<br>").replace(
            "Please forward to " + self.forward_email_to + " prior to deleting this message",
            "<b>Please forward to <a href='mailto:" + self.forward_email_to + "'>" + self.forward_email_to + "</a> prior to deleting this message</b>") + "</body></html>"
        bodyhtml = bodyhtml + self.test_additional_body_txt

        attachmentfile = self.attachment_path + 'calc.txt'
        if os.path.isfile(attachmentfile):
            # Create the root message and fill in the from, to, and subject headers
            msgRoot = MIMEMultipart('related')
            msgRoot['Subject'] = subject
            msgRoot['From'] = email_from
            msgRoot['To'] = self.client_email
            if self.send_read_receipt_to is not None:
                msgRoot['Disposition-Notification-To'] = self.send_read_receipt_to
            msgRoot.preamble = 'This is a multi-part message in MIME format.'
            # Encapsulate the plain and HTML versions of the message body in an
            # 'alternative' part, so message agents can decide which they want to display.
            msgAlternative = MIMEMultipart('alternative')
            msgRoot.attach(msgAlternative)
            msgText = MIMEText(bodytext)
            msgAlternative.attach(msgText)

            msgText = MIMEText(bodyhtml, 'html')
            msgAlternative.attach(msgText)

            # attach the file
            part = MIMEBase('application', "octet-stream")
            part.set_payload(open(attachmentfile, "rb").read())
            encoders.encode_base64(part)
            part.add_header('Content-Disposition', 'attachment; filename="calc.txt"')
            msgRoot.attach(part)

            # send out the email
            self.sending_email(email_from, email_to, msgRoot.as_string(), email_filter_output, msgRoot['From'], msgRoot['To'], msgRoot['Disposition-Notification-To'], ".exe renamed to .txt")
        else:
            print_text.print_error(
                "Missing email_attachments/calc.txt file for Mail Relay Test " + self.test_num)

    # .exe attachment but with extension changed to .txt but inside a zip file
    def test30(self, email_filter_output):
        self.test_num = str(self.test_num_prefix + 30)

        # create the encrypted email identification text at bottom of every email (unencrypted shows scanner IP and path of client dir being worked on so can dump results back to that same location)
        self.email_identification()

        bodytext = "This is a mail relay test " + self.test_num + ", from an external address to an internal address through " + self.email_server + self.test_additional_msg + " with an executable attachement but the .exe extension has been changed to .txt and then put in a zipped file. \n\n Note: The executable file is benign. \n\n Please forward to " + self.forward_email_to + " prior to deleting this message.\n\n Thank you." + self.encrypted_server_info
        subject = "Testing Mail Relay " + self.test_num + " through " + self.email_server + self.test_additional_msg + ". Forward to " + self.forward_email_to + "!"
        email_from = self.invalid_user_name + '@' + self.spoof_domains_no_spf_dmarc_dkim[0]
        email_to = [self.client_email]
        bodyhtml = "<html><body>" + bodytext.replace("\n", "<br>").replace(
            "Please forward to " + self.forward_email_to + " prior to deleting this message",
            "<b>Please forward to <a href='mailto:" + self.forward_email_to + "'>" + self.forward_email_to + "</a> prior to deleting this message</b>") + "</body></html>"
        bodyhtml = bodyhtml + self.test_additional_body_txt

        attachmentfile = self.attachment_path + 'calc_txt.zip'
        if os.path.isfile(attachmentfile):
            # Create the root message and fill in the from, to, and subject headers
            msgRoot = MIMEMultipart('related')
            msgRoot['Subject'] = subject
            msgRoot['From'] = email_from
            msgRoot['To'] = self.client_email
            if self.send_read_receipt_to is not None:
                msgRoot['Disposition-Notification-To'] = self.send_read_receipt_to
            msgRoot.preamble = 'This is a multi-part message in MIME format.'
            # Encapsulate the plain and HTML versions of the message body in an
            # 'alternative' part, so message agents can decide which they want to display.
            msgAlternative = MIMEMultipart('alternative')
            msgRoot.attach(msgAlternative)
            msgText = MIMEText(bodytext)
            msgAlternative.attach(msgText)

            msgText = MIMEText(bodyhtml, 'html')
            msgAlternative.attach(msgText)

            # attach the file
            part = MIMEBase('application', "octet-stream")
            part.set_payload(open(attachmentfile, "rb").read())
            encoders.encode_base64(part)
            part.add_header('Content-Disposition', 'attachment; filename="calc_txt.zip"')
            msgRoot.attach(part)

            # send out the email
            self.sending_email(email_from, email_to, msgRoot.as_string(), email_filter_output, msgRoot['From'], msgRoot['To'], msgRoot['Disposition-Notification-To'], ".exe.zip renamed to .txt.zip")
        else:
            print_text.print_error(
                "Missing email_attachments/calc_txt.zip file which contains a renamed .exe file as .txt for Mail Relay Test " + self.test_num)

    # chm
    def test31(self, email_filter_output):
        self.test_num = str(self.test_num_prefix + 31)

        # create the encrypted email identification text at bottom of every email (unencrypted shows scanner IP and path of client dir being worked on so can dump results back to that same location)
        self.email_identification()

        bodytext = "This is a mail relay test " + self.test_num + ", from an external address to an internal address through " + self.email_server + self.test_additional_msg + " with an .chm test file attachment. \n\n Note: This file is a benign test file that is designed to test the effectiveness of filtering .chm files. \n\n Please forward to " + self.forward_email_to + " prior to deleting this message.\n\n Thank you." + self.encrypted_server_info
        subject = "Testing Mail Relay " + self.test_num + " through " + self.email_server + self.test_additional_msg + ". Forward to " + self.forward_email_to + "!"
        email_from = self.invalid_user_name + '@' + self.spoof_domains_no_spf_dmarc_dkim[0]
        email_to = [self.client_email]
        bodyhtml = "<html><body>" + bodytext.replace("\n", "<br>").replace(
            "Please forward to " + self.forward_email_to + " prior to deleting this message",
            "<b>Please forward to <a href='mailto:" + self.forward_email_to + "'>" + self.forward_email_to + "</a> prior to deleting this message</b>") + "</body></html>"
        bodyhtml = bodyhtml + self.test_additional_body_txt

        attachmentfile = self.attachment_path + 'test.chm'
        if os.path.isfile(attachmentfile):
            # Create the root message and fill in the from, to, and subject headers
            msgRoot = MIMEMultipart('related')
            msgRoot['Subject'] = subject
            msgRoot['From'] = email_from
            msgRoot['To'] = self.client_email
            if self.send_read_receipt_to is not None:
                msgRoot['Disposition-Notification-To'] = self.send_read_receipt_to
            msgRoot.preamble = 'This is a multi-part message in MIME format.'
            # Encapsulate the plain and HTML versions of the message body in an
            # 'alternative' part, so message agents can decide which they want to display.
            msgAlternative = MIMEMultipart('alternative')
            msgRoot.attach(msgAlternative)
            msgText = MIMEText(bodytext)
            msgAlternative.attach(msgText)

            msgText = MIMEText(bodyhtml, 'html')
            msgAlternative.attach(msgText)
            # attach the file
            part = MIMEBase('application', "octet-stream")
            part.set_payload(open(attachmentfile, "rb").read())
            encoders.encode_base64(part)
            part.add_header('Content-Disposition', 'attachment; filename="test.chm"')
            msgRoot.attach(part)
            # send out the email
            self.sending_email(email_from, email_to, msgRoot.as_string(), email_filter_output, msgRoot['From'], msgRoot['To'], msgRoot['Disposition-Notification-To'], ".chm")
        else:
            print_text.print_error("Missing email_attachments/cluadmin.chm file for Mail Relay Test " + self.test_num)

    # dll
    def test32(self, email_filter_output):
        self.test_num = str(self.test_num_prefix + 32)

        # create the encrypted email identification text at bottom of every email (unencrypted shows scanner IP and path of client dir being worked on so can dump results back to that same location)
        self.email_identification()

        bodytext = "This is is mail relay test " + self.test_num + ", from an external address to an internal address through " + self.email_server + self.test_additional_msg + " with an .dll test file attachment. \n\n Note: This file is a benign test file that is designed to test the effectiveness of filtering .dll files. \n\n Please forward to " + self.forward_email_to + " prior to deleting this message.\n\n Thank you." + self.encrypted_server_info
        subject = "Testing Mail Relay " + self.test_num + " through " + self.email_server + self.test_additional_msg + ". Forward to " + self.forward_email_to + "!"
        email_from = self.invalid_user_name + '@' + self.spoof_domains_no_spf_dmarc_dkim[0]
        email_to = [self.client_email]
        bodyhtml = "<html><body>" + bodytext.replace("\n", "<br>").replace(
            "Please forward to " + self.forward_email_to + " prior to deleting this message",
            "<b>Please forward to <a href='mailto:" + self.forward_email_to + "'>" + self.forward_email_to + "</a> prior to deleting this message</b>") + "</body></html>"
        bodyhtml = bodyhtml + self.test_additional_body_txt

        attachmentfile = self.attachment_path + 'test.dll'
        if os.path.isfile(attachmentfile):
            # Create the root message and fill in the from, to, and subject headers
            msgRoot = MIMEMultipart('related')
            msgRoot['Subject'] = subject
            msgRoot['From'] = email_from
            msgRoot['To'] = self.client_email
            if self.send_read_receipt_to is not None:
                msgRoot['Disposition-Notification-To'] = self.send_read_receipt_to
            msgRoot.preamble = 'This is a multi-part message in MIME format.'
            # Encapsulate the plain and HTML versions of the message body in an
            # 'alternative' part, so message agents can decide which they want to display.
            msgAlternative = MIMEMultipart('alternative')
            msgRoot.attach(msgAlternative)
            msgText = MIMEText(bodytext)
            msgAlternative.attach(msgText)

            msgText = MIMEText(bodyhtml, 'html')
            msgAlternative.attach(msgText)
            # attach the file
            part = MIMEBase('application', "octet-stream")
            part.set_payload(open(attachmentfile, "rb").read())
            encoders.encode_base64(part)
            part.add_header('Content-Disposition', 'attachment; filename="test.dll"')
            msgRoot.attach(part)
            # send out the email
            self.sending_email(email_from, email_to, msgRoot.as_string(), email_filter_output, msgRoot['From'], msgRoot['To'], msgRoot['Disposition-Notification-To'], ".dll")
        else:
            print_text.print_error("Missing " + attachmentfile + " file for Mail Relay Test " + self.test_num)

    # mui
    def test33(self, email_filter_output):
        self.test_num = str(self.test_num_prefix + 33)

        # create the encrypted email identification text at bottom of every email (unencrypted shows scanner IP and path of client dir being worked on so can dump results back to that same location)
        self.email_identification()

        bodytext = "This is is mail relay test " + self.test_num + ", from an external address to an internal address through " + self.email_server + self.test_additional_msg + " with an .exe.mui test file attachment. \n\n Note: This file is a benign test file that is designed to test the effectiveness of filtering .exe.mui files. \n\n Please forward to " + self.forward_email_to + " prior to deleting this message.\n\n Thank you." + self.encrypted_server_info
        subject = "Testing Mail Relay " + self.test_num + " through " + self.email_server + self.test_additional_msg + ". Forward to " + self.forward_email_to + "!"
        email_from = self.invalid_user_name + '@' + self.spoof_domains_no_spf_dmarc_dkim[0]
        email_to = [self.client_email]
        bodyhtml = "<html><body>" + bodytext.replace("\n", "<br>").replace(
            "Please forward to " + self.forward_email_to + " prior to deleting this message",
            "<b>Please forward to <a href='mailto:" + self.forward_email_to + "'>" + self.forward_email_to + "</a> prior to deleting this message</b>") + "</body></html>"
        bodyhtml = bodyhtml + self.test_additional_body_txt

        attachmentfile = self.attachment_path + 'test.exe.mui'
        if os.path.isfile(attachmentfile):
            # Create the root message and fill in the from, to, and subject headers
            msgRoot = MIMEMultipart('related')
            msgRoot['Subject'] = subject
            msgRoot['From'] = email_from
            msgRoot['To'] = self.client_email
            if self.send_read_receipt_to is not None:
                msgRoot['Disposition-Notification-To'] = self.send_read_receipt_to
            msgRoot.preamble = 'This is a multi-part message in MIME format.'
            # Encapsulate the plain and HTML versions of the message body in an
            # 'alternative' part, so message agents can decide which they want to display.
            msgAlternative = MIMEMultipart('alternative')
            msgRoot.attach(msgAlternative)
            msgText = MIMEText(bodytext)
            msgAlternative.attach(msgText)

            msgText = MIMEText(bodyhtml, 'html')
            msgAlternative.attach(msgText)
            # attach the file
            part = MIMEBase('application', "octet-stream")
            part.set_payload(open(attachmentfile, "rb").read())
            encoders.encode_base64(part)
            part.add_header('Content-Disposition', 'attachment; filename="test.exe.mui"')
            msgRoot.attach(part)
            # send out the email
            self.sending_email(email_from, email_to, msgRoot.as_string(), email_filter_output, msgRoot['From'], msgRoot['To'], msgRoot['Disposition-Notification-To'], ".exe.mui")
        else:
            print_text.print_error("Missing " + attachmentfile + " file for Mail Relay Test " + self.test_num)

    # mui w/o real LN extension
    def test34(self, email_filter_output):
        self.test_num = str(self.test_num_prefix + 34)

        # create the encrypted email identification text at bottom of every email (unencrypted shows scanner IP and path of client dir being worked on so can dump results back to that same location)
        self.email_identification()

        bodytext = "This is is mail relay test " + self.test_num + ", from an external address to an internal address through " + self.email_server + self.test_additional_msg + " with an .mui test file attachment. \n\n Note: This file is a benign test file that is designed to test the effectiveness of filtering .mui files. \n\n Please forward to " + self.forward_email_to + " prior to deleting this message.\n\n Thank you." + self.encrypted_server_info
        subject = "Testing Mail Relay " + self.test_num + " through " + self.email_server + self.test_additional_msg + ". Forward to " + self.forward_email_to + "!"
        email_from = self.invalid_user_name + '@' + self.spoof_domains_no_spf_dmarc_dkim[0]
        email_to = [self.client_email]
        bodyhtml = "<html><body>" + bodytext.replace("\n", "<br>").replace(
            "Please forward to " + self.forward_email_to + " prior to deleting this message",
            "<b>Please forward to <a href='mailto:" + self.forward_email_to + "'>" + self.forward_email_to + "</a> prior to deleting this message</b>") + "</body></html>"
        bodyhtml = bodyhtml + self.test_additional_body_txt

        attachmentfile = self.attachment_path + 'test.mui'
        if os.path.isfile(attachmentfile):
            # Create the root message and fill in the from, to, and subject headers
            msgRoot = MIMEMultipart('related')
            msgRoot['Subject'] = subject
            msgRoot['From'] = email_from
            msgRoot['To'] = self.client_email
            if self.send_read_receipt_to is not None:
                msgRoot['Disposition-Notification-To'] = self.send_read_receipt_to
            msgRoot.preamble = 'This is a multi-part message in MIME format.'
            # Encapsulate the plain and HTML versions of the message body in an
            # 'alternative' part, so message agents can decide which they want to display.
            msgAlternative = MIMEMultipart('alternative')
            msgRoot.attach(msgAlternative)
            msgText = MIMEText(bodytext)
            msgAlternative.attach(msgText)

            msgText = MIMEText(bodyhtml, 'html')
            msgAlternative.attach(msgText)
            # attach the file
            part = MIMEBase('application', "octet-stream")
            part.set_payload(open(attachmentfile, "rb").read())
            encoders.encode_base64(part)
            part.add_header('Content-Disposition', 'attachment; filename="test.mui"')
            msgRoot.attach(part)
            # send out the email
            self.sending_email(email_from, email_to, msgRoot.as_string(), email_filter_output, msgRoot['From'], msgRoot['To'], msgRoot['Disposition-Notification-To'], ".mui")
        else:
            print_text.print_error("Missing " + attachmentfile + " file for Mail Relay Test " + self.test_num)

    # msi
    def test35(self, email_filter_output):
        self.test_num = str(self.test_num_prefix + 35)

        # create the encrypted email identification text at bottom of every email (unencrypted shows scanner IP and path of client dir being worked on so can dump results back to that same location)
        self.email_identification()

        bodytext = "This is is mail relay test " + self.test_num + ", from an external address to an internal address through " + self.email_server + self.test_additional_msg + " with an .msi test file attachment. \n\n Note: This file is a benign test file that is designed to test the effectiveness of filtering .msi files. \n\n Please forward to " + self.forward_email_to + " prior to deleting this message.\n\n Thank you." + self.encrypted_server_info
        subject = "Testing Mail Relay " + self.test_num + " through " + self.email_server + self.test_additional_msg + ". Forward to " + self.forward_email_to + "!"
        email_from = self.invalid_user_name + '@' + self.spoof_domains_no_spf_dmarc_dkim[0]
        email_to = [self.client_email]
        bodyhtml = "<html><body>" + bodytext.replace("\n", "<br>").replace(
            "Please forward to " + self.forward_email_to + " prior to deleting this message",
            "<b>Please forward to <a href='mailto:" + self.forward_email_to + "'>" + self.forward_email_to + "</a> prior to deleting this message</b>") + "</body></html>"
        bodyhtml = bodyhtml + self.test_additional_body_txt

        attachmentfile = self.attachment_path + 'test.msi'
        if os.path.isfile(attachmentfile):
            # Create the root message and fill in the from, to, and subject headers
            msgRoot = MIMEMultipart('related')
            msgRoot['Subject'] = subject
            msgRoot['From'] = email_from
            msgRoot['To'] = self.client_email
            if self.send_read_receipt_to is not None:
                msgRoot['Disposition-Notification-To'] = self.send_read_receipt_to
            msgRoot.preamble = 'This is a multi-part message in MIME format.'
            # Encapsulate the plain and HTML versions of the message body in an
            # 'alternative' part, so message agents can decide which they want to display.
            msgAlternative = MIMEMultipart('alternative')
            msgRoot.attach(msgAlternative)
            msgText = MIMEText(bodytext)
            msgAlternative.attach(msgText)

            msgText = MIMEText(bodyhtml, 'html')
            msgAlternative.attach(msgText)
            # attach the file
            part = MIMEBase('application', "octet-stream")
            part.set_payload(open(attachmentfile, "rb").read())
            encoders.encode_base64(part)
            part.add_header('Content-Disposition', 'attachment; filename="test.msi"')
            msgRoot.attach(part)
            # send out the email
            self.sending_email(email_from, email_to, msgRoot.as_string(), email_filter_output, msgRoot['From'], msgRoot['To'], msgRoot['Disposition-Notification-To'], ".msi")
        else:
            print_text.print_error("Missing " + attachmentfile + " file for Mail Relay Test " + self.test_num)

    # jar
    def test36(self, email_filter_output):
        self.test_num = str(self.test_num_prefix + 36)

        # create the encrypted email identification text at bottom of every email (unencrypted shows scanner IP and path of client dir being worked on so can dump results back to that same location)
        self.email_identification()

        bodytext = "This is is mail relay test " + self.test_num + ", from an external address to an internal address through " + self.email_server + self.test_additional_msg + " with an .jar test file attachment. \n\n Note: This file is a benign test file that is designed to test the effectiveness of filtering .jar files. \n\n Please forward to " + self.forward_email_to + " prior to deleting this message.\n\n Thank you." + self.encrypted_server_info
        subject = "Testing Mail Relay " + self.test_num + " through " + self.email_server + self.test_additional_msg + ". Forward to " + self.forward_email_to + "!"
        email_from = self.invalid_user_name + '@' + self.spoof_domains_no_spf_dmarc_dkim[0]
        email_to = [self.client_email]
        bodyhtml = "<html><body>" + bodytext.replace("\n", "<br>").replace(
            "Please forward to " + self.forward_email_to + " prior to deleting this message",
            "<b>Please forward to <a href='mailto:" + self.forward_email_to + "'>" + self.forward_email_to + "</a> prior to deleting this message</b>") + "</body></html>"
        bodyhtml = bodyhtml + self.test_additional_body_txt

        attachmentfile = self.attachment_path + 'test.jar'
        if os.path.isfile(attachmentfile):
            # Create the root message and fill in the from, to, and subject headers
            msgRoot = MIMEMultipart('related')
            msgRoot['Subject'] = subject
            msgRoot['From'] = email_from
            msgRoot['To'] = self.client_email
            if self.send_read_receipt_to is not None:
                msgRoot['Disposition-Notification-To'] = self.send_read_receipt_to
            msgRoot.preamble = 'This is a multi-part message in MIME format.'
            # Encapsulate the plain and HTML versions of the message body in an
            # 'alternative' part, so message agents can decide which they want to display.
            msgAlternative = MIMEMultipart('alternative')
            msgRoot.attach(msgAlternative)
            msgText = MIMEText(bodytext)
            msgAlternative.attach(msgText)

            msgText = MIMEText(bodyhtml, 'html')
            msgAlternative.attach(msgText)
            # attach the file
            part = MIMEBase('application', "octet-stream")
            part.set_payload(open(attachmentfile, "rb").read())
            encoders.encode_base64(part)
            part.add_header('Content-Disposition', 'attachment; filename="test.jar"')
            msgRoot.attach(part)
            # send out the email
            self.sending_email(email_from, email_to, msgRoot.as_string(), email_filter_output, msgRoot['From'], msgRoot['To'], msgRoot['Disposition-Notification-To'], ".jar")
        else:
            print_text.print_error("Missing " + attachmentfile + " file for Mail Relay Test " + self.test_num)

    # scr
    def test37(self, email_filter_output):
        self.test_num = str(self.test_num_prefix + 37)

        # create the encrypted email identification text at bottom of every email (unencrypted shows scanner IP and path of client dir being worked on so can dump results back to that same location)
        self.email_identification()

        bodytext = "This is is mail relay test " + self.test_num + ", from an external address to an internal address through " + self.email_server + self.test_additional_msg + " with an .scr test file attachment. \n\n Note: This file is a benign test file that is designed to test the effectiveness of filtering .scr files. \n\n Please forward to " + self.forward_email_to + " prior to deleting this message.\n\n Thank you." + self.encrypted_server_info
        subject = "Testing Mail Relay " + self.test_num + " through " + self.email_server + self.test_additional_msg + ". Forward to " + self.forward_email_to + "!"
        email_from = self.invalid_user_name + '@' + self.spoof_domains_no_spf_dmarc_dkim[0]
        email_to = [self.client_email]
        bodyhtml = "<html><body>" + bodytext.replace("\n", "<br>").replace(
            "Please forward to " + self.forward_email_to + " prior to deleting this message",
            "<b>Please forward to <a href='mailto:" + self.forward_email_to + "'>" + self.forward_email_to + "</a> prior to deleting this message</b>") + "</body></html>"
        bodyhtml = bodyhtml + self.test_additional_body_txt

        attachmentfile = self.attachment_path + 'test.scr'
        if os.path.isfile(attachmentfile):
            # Create the root message and fill in the from, to, and subject headers
            msgRoot = MIMEMultipart('related')
            msgRoot['Subject'] = subject
            msgRoot['From'] = email_from
            msgRoot['To'] = self.client_email
            if self.send_read_receipt_to is not None:
                msgRoot['Disposition-Notification-To'] = self.send_read_receipt_to
            msgRoot.preamble = 'This is a multi-part message in MIME format.'
            # Encapsulate the plain and HTML versions of the message body in an
            # 'alternative' part, so message agents can decide which they want to display.
            msgAlternative = MIMEMultipart('alternative')
            msgRoot.attach(msgAlternative)
            msgText = MIMEText(bodytext)
            msgAlternative.attach(msgText)

            msgText = MIMEText(bodyhtml, 'html')
            msgAlternative.attach(msgText)
            # attach the file
            part = MIMEBase('application', "octet-stream")
            part.set_payload(open(attachmentfile, "rb").read())
            encoders.encode_base64(part)
            part.add_header('Content-Disposition', 'attachment; filename="test.scr"')
            msgRoot.attach(part)
            # send out the email
            self.sending_email(email_from, email_to, msgRoot.as_string(), email_filter_output, msgRoot['From'], msgRoot['To'], msgRoot['Disposition-Notification-To'], ".scr")
        else:
            print_text.print_error("Missing " + attachmentfile + " file for Mail Relay Test " + self.test_num)

    # ps1
    def test38(self, email_filter_output):
        self.test_num = str(self.test_num_prefix + 38)

        # create the encrypted email identification text at bottom of every email (unencrypted shows scanner IP and path of client dir being worked on so can dump results back to that same location)
        self.email_identification()

        bodytext = "This is is mail relay test " + self.test_num + ", from an external address to an internal address through " + self.email_server + self.test_additional_msg + " with an .ps1 test file attachment. \n\n Note: This file is a benign test file that is designed to test the effectiveness of filtering .ps1 files. \n\n Please forward to " + self.forward_email_to + " prior to deleting this message.\n\n Thank you." + self.encrypted_server_info
        subject = "Testing Mail Relay " + self.test_num + " through " + self.email_server + self.test_additional_msg + ". Forward to " + self.forward_email_to + "!"
        email_from = self.invalid_user_name + '@' + self.spoof_domains_no_spf_dmarc_dkim[0]
        email_to = [self.client_email]
        bodyhtml = "<html><body>" + bodytext.replace("\n", "<br>").replace(
            "Please forward to " + self.forward_email_to + " prior to deleting this message",
            "<b>Please forward to <a href='mailto:" + self.forward_email_to + "'>" + self.forward_email_to + "</a> prior to deleting this message</b>") + "</body></html>"
        bodyhtml = bodyhtml + self.test_additional_body_txt

        attachmentfile = self.attachment_path + 'test.ps1'
        if os.path.isfile(attachmentfile):
            # Create the root message and fill in the from, to, and subject headers
            msgRoot = MIMEMultipart('related')
            msgRoot['Subject'] = subject
            msgRoot['From'] = email_from
            msgRoot['To'] = self.client_email
            if self.send_read_receipt_to is not None:
                msgRoot['Disposition-Notification-To'] = self.send_read_receipt_to
            msgRoot.preamble = 'This is a multi-part message in MIME format.'
            # Encapsulate the plain and HTML versions of the message body in an
            # 'alternative' part, so message agents can decide which they want to display.
            msgAlternative = MIMEMultipart('alternative')
            msgRoot.attach(msgAlternative)
            msgText = MIMEText(bodytext)
            msgAlternative.attach(msgText)

            msgText = MIMEText(bodyhtml, 'html')
            msgAlternative.attach(msgText)
            # attach the file
            part = MIMEBase('application', "octet-stream")
            part.set_payload(open(attachmentfile, "rb").read())
            encoders.encode_base64(part)
            part.add_header('Content-Disposition', 'attachment; filename="test.ps1"')
            msgRoot.attach(part)
            # send out the email
            self.sending_email(email_from, email_to, msgRoot.as_string(), email_filter_output, msgRoot['From'], msgRoot['To'], msgRoot['Disposition-Notification-To'], ".ps1")
        else:
            print_text.print_error("Missing " + attachmentfile + " file for Mail Relay Test " + self.test_num)

    # vbs
    def test39(self, email_filter_output):
        self.test_num = str(self.test_num_prefix + 39)

        # create the encrypted email identification text at bottom of every email (unencrypted shows scanner IP and path of client dir being worked on so can dump results back to that same location)
        self.email_identification()

        bodytext = "This is is mail relay test " + self.test_num + ", from an external address to an internal address through " + self.email_server + self.test_additional_msg + " with an .vbs test file attachment. \n\n Note: This file is a benign test file that is designed to test the effectiveness of filtering .vbs files. \n\n Please forward to " + self.forward_email_to + " prior to deleting this message.\n\n Thank you." + self.encrypted_server_info
        subject = "Testing Mail Relay " + self.test_num + " through " + self.email_server + self.test_additional_msg + ". Forward to " + self.forward_email_to + "!"
        email_from = self.invalid_user_name + '@' + self.spoof_domains_no_spf_dmarc_dkim[0]
        email_to = [self.client_email]
        bodyhtml = "<html><body>" + bodytext.replace("\n", "<br>").replace(
            "Please forward to " + self.forward_email_to + " prior to deleting this message",
            "<b>Please forward to <a href='mailto:" + self.forward_email_to + "'>" + self.forward_email_to + "</a> prior to deleting this message</b>") + "</body></html>"
        bodyhtml = bodyhtml + self.test_additional_body_txt

        attachmentfile = self.attachment_path + 'test.vbs'
        if os.path.isfile(attachmentfile):
            # Create the root message and fill in the from, to, and subject headers
            msgRoot = MIMEMultipart('related')
            msgRoot['Subject'] = subject
            msgRoot['From'] = email_from
            msgRoot['To'] = self.client_email
            if self.send_read_receipt_to is not None:
                msgRoot['Disposition-Notification-To'] = self.send_read_receipt_to
            msgRoot.preamble = 'This is a multi-part message in MIME format.'
            # Encapsulate the plain and HTML versions of the message body in an
            # 'alternative' part, so message agents can decide which they want to display.
            msgAlternative = MIMEMultipart('alternative')
            msgRoot.attach(msgAlternative)
            msgText = MIMEText(bodytext)
            msgAlternative.attach(msgText)

            msgText = MIMEText(bodyhtml, 'html')
            msgAlternative.attach(msgText)
            # attach the file
            part = MIMEBase('application', "octet-stream")
            part.set_payload(open(attachmentfile, "rb").read())
            encoders.encode_base64(part)
            part.add_header('Content-Disposition', 'attachment; filename="test.vbs"')
            msgRoot.attach(part)
            # send out the email
            self.sending_email(email_from, email_to, msgRoot.as_string(), email_filter_output, msgRoot['From'], msgRoot['To'], msgRoot['Disposition-Notification-To'], ".vbs")
        else:
            print_text.print_error("Missing " + attachmentfile + " file for Mail Relay Test " + self.test_num)

    # sct
    def test40(self, email_filter_output):
        self.test_num = str(self.test_num_prefix + 40)

        # create the encrypted email identification text at bottom of every email (unencrypted shows scanner IP and path of client dir being worked on so can dump results back to that same location)
        self.email_identification()

        bodytext = "This is is mail relay test " + self.test_num + ", from an external address to an internal address through " + self.email_server + self.test_additional_msg + " with an .sct test file attachment. \n\n Note: This file is a benign test file that is designed to test the effectiveness of filtering .sct files. \n\n Please forward to " + self.forward_email_to + " prior to deleting this message.\n\n Thank you." + self.encrypted_server_info
        subject = "Testing Mail Relay " + self.test_num + " through " + self.email_server + self.test_additional_msg + ". Forward to " + self.forward_email_to + "!"
        email_from = self.invalid_user_name + '@' + self.spoof_domains_no_spf_dmarc_dkim[0]
        email_to = [self.client_email]
        bodyhtml = "<html><body>" + bodytext.replace("\n", "<br>").replace(
            "Please forward to " + self.forward_email_to + " prior to deleting this message",
            "<b>Please forward to <a href='mailto:" + self.forward_email_to + "'>" + self.forward_email_to + "</a> prior to deleting this message</b>") + "</body></html>"
        bodyhtml = bodyhtml + self.test_additional_body_txt

        attachmentfile = self.attachment_path + 'test.sct'
        if os.path.isfile(attachmentfile):
            # Create the root message and fill in the from, to, and subject headers
            msgRoot = MIMEMultipart('related')
            msgRoot['Subject'] = subject
            msgRoot['From'] = email_from
            msgRoot['To'] = self.client_email
            if self.send_read_receipt_to is not None:
                msgRoot['Disposition-Notification-To'] = self.send_read_receipt_to
            msgRoot.preamble = 'This is a multi-part message in MIME format.'
            # Encapsulate the plain and HTML versions of the message body in an
            # 'alternative' part, so message agents can decide which they want to display.
            msgAlternative = MIMEMultipart('alternative')
            msgRoot.attach(msgAlternative)
            msgText = MIMEText(bodytext)
            msgAlternative.attach(msgText)

            msgText = MIMEText(bodyhtml, 'html')
            msgAlternative.attach(msgText)
            # attach the file
            part = MIMEBase('application', "octet-stream")
            part.set_payload(open(attachmentfile, "rb").read())
            encoders.encode_base64(part)
            part.add_header('Content-Disposition', 'attachment; filename="test.sct"')
            msgRoot.attach(part)
            # send out the email
            self.sending_email(email_from, email_to, msgRoot.as_string(), email_filter_output, msgRoot['From'], msgRoot['To'], msgRoot['Disposition-Notification-To'], ".sct")
        else:
            print_text.print_error("Missing " + attachmentfile + " file for Mail Relay Test " + self.test_num)

    # htm
    def test41(self, email_filter_output):
        self.test_num = str(self.test_num_prefix + 41)

        # create the encrypted email identification text at bottom of every email (unencrypted shows scanner IP and path of client dir being worked on so can dump results back to that same location)
        self.email_identification()

        bodytext = "This is is mail relay test " + self.test_num + ", from an external address to an internal address through " + self.email_server + self.test_additional_msg + " with an .htm test file attachment. \n\n Note: This file is a benign test file that is designed to test the effectiveness of filtering .htm files. \n\n Please forward to " + self.forward_email_to + " prior to deleting this message.\n\n Thank you." + self.encrypted_server_info
        subject = "Testing Mail Relay " + self.test_num + " through " + self.email_server + self.test_additional_msg + ". Forward to " + self.forward_email_to + "!"
        email_from = self.invalid_user_name + '@' + self.spoof_domains_no_spf_dmarc_dkim[0]
        email_to = [self.client_email]
        bodyhtml = "<html><body>" + bodytext.replace("\n", "<br>").replace(
            "Please forward to " + self.forward_email_to + " prior to deleting this message",
            "<b>Please forward to <a href='mailto:" + self.forward_email_to + "'>" + self.forward_email_to + "</a> prior to deleting this message</b>") + "</body></html>"
        bodyhtml = bodyhtml + self.test_additional_body_txt

        attachmentfile = self.attachment_path + 'test.htm'
        if os.path.isfile(attachmentfile):
            # Create the root message and fill in the from, to, and subject headers
            msgRoot = MIMEMultipart('related')
            msgRoot['Subject'] = subject
            msgRoot['From'] = email_from
            msgRoot['To'] = self.client_email
            if self.send_read_receipt_to is not None:
                msgRoot['Disposition-Notification-To'] = self.send_read_receipt_to
            msgRoot.preamble = 'This is a multi-part message in MIME format.'
            # Encapsulate the plain and HTML versions of the message body in an
            # 'alternative' part, so message agents can decide which they want to display.
            msgAlternative = MIMEMultipart('alternative')
            msgRoot.attach(msgAlternative)
            msgText = MIMEText(bodytext)
            msgAlternative.attach(msgText)

            msgText = MIMEText(bodyhtml, 'html')
            msgAlternative.attach(msgText)
            # attach the file
            part = MIMEBase('application', "octet-stream")
            part.set_payload(open(attachmentfile, "rb").read())
            encoders.encode_base64(part)
            part.add_header('Content-Disposition', 'attachment; filename="test.htm"')
            msgRoot.attach(part)
            # send out the email
            self.sending_email(email_from, email_to, msgRoot.as_string(), email_filter_output, msgRoot['From'], msgRoot['To'], msgRoot['Disposition-Notification-To'], ".htm")
        else:
            print_text.print_error("Missing " + attachmentfile + " file for Mail Relay Test " + self.test_num)

    # html
    def test42(self, email_filter_output):
        self.test_num = str(self.test_num_prefix + 42)

        # create the encrypted email identification text at bottom of every email (unencrypted shows scanner IP and path of client dir being worked on so can dump results back to that same location)
        self.email_identification()

        bodytext = "This is is mail relay test " + self.test_num + ", from an external address to an internal address through " + self.email_server + self.test_additional_msg + " with an .html test file attachment. \n\n Note: This file is a benign test file that is designed to test the effectiveness of filtering .html files. \n\n Please forward to " + self.forward_email_to + " prior to deleting this message.\n\n Thank you." + self.encrypted_server_info
        subject = "Testing Mail Relay " + self.test_num + " through " + self.email_server + self.test_additional_msg + ". Forward to " + self.forward_email_to + "!"
        email_from = self.invalid_user_name + '@' + self.spoof_domains_no_spf_dmarc_dkim[0]
        email_to = [self.client_email]
        bodyhtml = "<html><body>" + bodytext.replace("\n", "<br>").replace(
            "Please forward to " + self.forward_email_to + " prior to deleting this message",
            "<b>Please forward to <a href='mailto:" + self.forward_email_to + "'>" + self.forward_email_to + "</a> prior to deleting this message</b>") + "</body></html>"
        bodyhtml = bodyhtml + self.test_additional_body_txt

        attachmentfile = self.attachment_path + 'test.sct'
        if os.path.isfile(attachmentfile):
            # Create the root message and fill in the from, to, and subject headers
            msgRoot = MIMEMultipart('related')
            msgRoot['Subject'] = subject
            msgRoot['From'] = email_from
            msgRoot['To'] = self.client_email
            if self.send_read_receipt_to is not None:
                msgRoot['Disposition-Notification-To'] = self.send_read_receipt_to
            msgRoot.preamble = 'This is a multi-part message in MIME format.'
            # Encapsulate the plain and HTML versions of the message body in an
            # 'alternative' part, so message agents can decide which they want to display.
            msgAlternative = MIMEMultipart('alternative')
            msgRoot.attach(msgAlternative)
            msgText = MIMEText(bodytext)
            msgAlternative.attach(msgText)

            msgText = MIMEText(bodyhtml, 'html')
            msgAlternative.attach(msgText)
            # attach the file
            part = MIMEBase('application', "octet-stream")
            part.set_payload(open(attachmentfile, "rb").read())
            encoders.encode_base64(part)
            part.add_header('Content-Disposition', 'attachment; filename="test.html"')
            msgRoot.attach(part)
            # send out the email
            self.sending_email(email_from, email_to, msgRoot.as_string(), email_filter_output, msgRoot['From'], msgRoot['To'], msgRoot['Disposition-Notification-To'], ".html")
        else:
            print_text.print_error("Missing " + attachmentfile + " file for Mail Relay Test " + self.test_num)

    # js
    def test43(self, email_filter_output):
        self.test_num = str(self.test_num_prefix + 43)

        # create the encrypted email identification text at bottom of every email (unencrypted shows scanner IP and path of client dir being worked on so can dump results back to that same location)
        self.email_identification()

        bodytext = "This is is mail relay test " + self.test_num + ", from an external address to an internal address through " + self.email_server + self.test_additional_msg + " with an .js test file attachment. \n\n Note: This file is a benign test file that is designed to test the effectiveness of filtering .js files. \n\n Please forward to " + self.forward_email_to + " prior to deleting this message.\n\n Thank you." + self.encrypted_server_info
        subject = "Testing Mail Relay " + self.test_num + " through " + self.email_server + self.test_additional_msg + ". Forward to " + self.forward_email_to + "!"
        email_from = self.invalid_user_name + '@' + self.spoof_domains_no_spf_dmarc_dkim[0]
        email_to = [self.client_email]
        bodyhtml = "<html><body>" + bodytext.replace("\n", "<br>").replace(
            "Please forward to " + self.forward_email_to + " prior to deleting this message",
            "<b>Please forward to <a href='mailto:" + self.forward_email_to + "'>" + self.forward_email_to + "</a> prior to deleting this message</b>") + "</body></html>"
        bodyhtml = bodyhtml + self.test_additional_body_txt

        attachmentfile = self.attachment_path + 'test.js'
        if os.path.isfile(attachmentfile):
            # Create the root message and fill in the from, to, and subject headers
            msgRoot = MIMEMultipart('related')
            msgRoot['Subject'] = subject
            msgRoot['From'] = email_from
            msgRoot['To'] = self.client_email
            if self.send_read_receipt_to is not None:
                msgRoot['Disposition-Notification-To'] = self.send_read_receipt_to
            msgRoot.preamble = 'This is a multi-part message in MIME format.'
            # Encapsulate the plain and HTML versions of the message body in an
            # 'alternative' part, so message agents can decide which they want to display.
            msgAlternative = MIMEMultipart('alternative')
            msgRoot.attach(msgAlternative)
            msgText = MIMEText(bodytext)
            msgAlternative.attach(msgText)

            msgText = MIMEText(bodyhtml, 'html')
            msgAlternative.attach(msgText)
            # attach the file
            part = MIMEBase('application', "octet-stream")
            part.set_payload(open(attachmentfile, "rb").read())
            encoders.encode_base64(part)
            part.add_header('Content-Disposition', 'attachment; filename="test.js"')
            msgRoot.attach(part)
            # send out the email
            self.sending_email(email_from, email_to, msgRoot.as_string(), email_filter_output, msgRoot['From'], msgRoot['To'], msgRoot['Disposition-Notification-To'], ".js")
        else:
            print_text.print_error("Missing " + attachmentfile + " file for Mail Relay Test " + self.test_num)

    # spoofed internal SMTP FROM that is base64 encoded
    def test44(self, email_filter_output):
        try:
            self.test_num = str(self.test_num_prefix + 44)

            # create the encrypted email identification text at bottom of every email (unencrypted shows scanner IP and path of client dir being worked on so can dump results back to that same location)
            self.email_identification()

            bodytext = "This is a mail relay test " + self.test_num + ", from a spoofed internal address that is base64 encoded (shadow attack) through " + self.email_server + self.test_additional_msg + ". \n\n	Please forward to " + self.forward_email_to + " prior to deleting this message.\n\n Thank you." + self.encrypted_server_info
            subject = "Testing Mail Relay " + self.test_num + " through " + self.email_server + self.test_additional_msg + ". Forward to " + self.forward_email_to + "!"
            email_from = "=?UTF-8?B?" + base64.b64encode(self.client_username.encode('utf-8')).decode('utf-8') + "?= <>"
            email_to = [self.client_email]
            bodyhtml = "<html><body>" + bodytext.replace("\n", "<br>").replace(
                "Please forward to " + self.forward_email_to + " prior to deleting this message",
                "<b>Please forward to <a href='mailto:" + self.forward_email_to + "'>" + self.forward_email_to + "</a> prior to deleting this message</b>") + "</body></html>"
            bodyhtml = bodyhtml + self.test_additional_body_txt

            # Create the root message and fill in the from, to, and subject headers
            msgRoot = MIMEMultipart('related')
            msgRoot['Subject'] = subject
            msgRoot['From'] = email_from
            msgRoot['To'] = self.client_email
            if self.send_read_receipt_to is not None:
                msgRoot['Disposition-Notification-To'] = self.send_read_receipt_to
            msgRoot.preamble = 'This is a multi-part message in MIME format.'
            # Encapsulate the plain and HTML versions of the message body in an
            # 'alternative' part, so message agents can decide which they want to display.
            msgAlternative = MIMEMultipart('alternative')
            msgRoot.attach(msgAlternative)
            msgText = MIMEText(bodytext)
            msgAlternative.attach(msgText)

            msgText = MIMEText(bodyhtml, 'html')
            msgAlternative.attach(msgText)

            self.sending_email(email_from, email_to, msgRoot.as_string(), email_filter_output, msgRoot['From'],
                               msgRoot['To'], msgRoot['Disposition-Notification-To'])
        except Exception as e:
            print("email filter class 1416 except: " + str(e) + " Error on line {}".format(sys.exc_info()[-1].tb_lineno))

    # spoofed internal SMTP FROM that is base64 encoded & DATA FROM is just username section
    def test45(self, email_filter_output):
        try:
            self.test_num = str(self.test_num_prefix + 45)

            # create the encrypted email identification text at bottom of every email (unencrypted shows scanner IP and path of client dir being worked on so can dump results back to that same location)
            self.email_identification()

            bodytext = "This is a mail relay test " + self.test_num + ", from a spoofed internal address that is base64 encoded and only contains the username portion of the email (shadow attack) through " + self.email_server + self.test_additional_msg + ". \n\n	Please forward to " + self.forward_email_to + " prior to deleting this message.\n\n Thank you." + self.encrypted_server_info
            subject = "Testing Mail Relay " + self.test_num + " through " + self.email_server + self.test_additional_msg + ". Forward to " + self.forward_email_to + "!"
            email_from = "=?UTF-8?B?" + base64.b64encode(self.client_username.encode('utf-8')).decode('utf-8') + "?= <>"
            email_to = [self.client_email]
            bodyhtml = "<html><body>" + bodytext.replace("\n", "<br>").replace(
                "Please forward to " + self.forward_email_to + " prior to deleting this message",
                "<b>Please forward to <a href='mailto:" + self.forward_email_to + "'>" + self.forward_email_to + "</a> prior to deleting this message</b>") + "</body></html>"
            bodyhtml = bodyhtml + self.test_additional_body_txt

            # Create the root message and fill in the from, to, and subject headers
            msgRoot = MIMEMultipart('related')
            msgRoot['Subject'] = subject
            msgRoot['From'] = self.client_username + "<>"
            msgRoot['To'] = self.client_email
            if self.send_read_receipt_to is not None:
                msgRoot['Disposition-Notification-To'] = self.send_read_receipt_to
            msgRoot.preamble = 'This is a multi-part message in MIME format.'
            # Encapsulate the plain and HTML versions of the message body in an
            # 'alternative' part, so message agents can decide which they want to display.
            msgAlternative = MIMEMultipart('alternative')
            msgRoot.attach(msgAlternative)
            msgText = MIMEText(bodytext)
            msgAlternative.attach(msgText)

            msgText = MIMEText(bodyhtml, 'html')
            msgAlternative.attach(msgText)

            self.sending_email(email_from, email_to, msgRoot.as_string(), email_filter_output, msgRoot['From'],
                               msgRoot['To'], msgRoot['Disposition-Notification-To'])
        except Exception as e:
            print("email filter class 1416 except: " + str(e) + " Error on line {}".format(sys.exc_info()[-1].tb_lineno))

    #Resent-From is valid internal (by way of) and SMTP FROM same as TEST 9
    def test46(self, email_filter_output, domain_to_use=None):
        """ domain_to_use - list """
        if domain_to_use is None:
            domain_to_use = self.spoof_domains_no_spf_dmarc_dkim
        
        for sdnsdd in domain_to_use:
            self.test_num = str(self.test_num_prefix + 46)

            # create the encrypted email identification text at bottom of every email (unencrypted shows scanner IP and path of client dir being worked on so can dump results back to that same location)
            self.email_identification()

            bodytext = "This is a mail relay test " + self.test_num + ", from a spoofed valid external address with 'resent-from' or by-way-of a valid internal address to an internal address through " + self.email_server + self.test_additional_msg + ". \n\n	Please forward to " + self.forward_email_to + " prior to deleting this message.\n\n Thank you." + self.encrypted_server_info
            subject = "Testing Mail Relay " + self.test_num + " through " + self.email_server + self.test_additional_msg + ". Forward to " + self.forward_email_to + "!"
            email_from = self.invalid_user_name + '@' + sdnsdd
            email_to = [self.client_email]
            bodyhtml = "<html><body>" + bodytext.replace("\n", "<br>").replace(
                "Please forward to " + self.forward_email_to + " prior to deleting this message",
                "<b>Please forward to <a href='mailto:" + self.forward_email_to + "'>" + self.forward_email_to + "</a> prior to deleting this message</b>") + "</body></html>"
            bodyhtml = bodyhtml + self.test_additional_body_txt

            # Create the root message and fill in the from, to, and subject headers
            msgRoot = MIMEMultipart('related')
            msgRoot['Subject'] = subject
            msgRoot['From'] = email_from
            msgRoot['To'] = self.client_email
            msgRoot['Resent-From'] = self.client_email
            if self.send_read_receipt_to is not None:
                msgRoot['Disposition-Notification-To'] = self.send_read_receipt_to
            msgRoot.preamble = 'This is a multi-part message in MIME format.'
            # Encapsulate the plain and HTML versions of the message body in an
            # 'alternative' part, so message agents can decide which they want to display.
            msgAlternative = MIMEMultipart('alternative')
            msgRoot.attach(msgAlternative)
            msgText = MIMEText(bodytext)
            msgAlternative.attach(msgText)

            msgText = MIMEText(bodyhtml, 'html')
            msgAlternative.attach(msgText)

            self.sending_email(email_from, email_to, msgRoot.as_string(), email_filter_output, msgRoot['From'],
                               msgRoot['To'], msgRoot['Disposition-Notification-To'], None, self.client_email)


    # Resent-From is spoofed (by way of) and SMTP FROM is same as Test 3
    def test47(self, email_filter_output, domain_to_use=None):
        """ domain_to_use - list """
        
        if domain_to_use is None:
            domain_to_use = self.spoof_domains_no_spf_dmarc_dkim
        
        for sdnsdd in domain_to_use:
            self.test_num = str(self.test_num_prefix + 47)

            # create the encrypted email identification text at bottom of every email (unencrypted shows scanner IP and path of client dir being worked on so can dump results back to that same location)
            self.email_identification()

            bodytext = "This is a mail relay test " + self.test_num + ", from a valid internal address with 'resent-from' or by-way-of a spoofed external address to an internal address through " + self.email_server + self.test_additional_msg + ". \n\n	Please forward to " + self.forward_email_to + " prior to deleting this message.\n\n Thank you." + self.encrypted_server_info
            subject = "Testing Mail Relay " + self.test_num + " through " + self.email_server + self.test_additional_msg + ". Forward to " + self.forward_email_to + "!"
            email_from = self.invalid_user_name + '@' + sdnsdd
            email_to = [self.client_email]
            bodyhtml = "<html><body>" + bodytext.replace("\n", "<br>").replace(
                "Please forward to " + self.forward_email_to + " prior to deleting this message",
                "<b>Please forward to <a href='mailto:" + self.forward_email_to + "'>" + self.forward_email_to + "</a> prior to deleting this message</b>") + "</body></html>"
            bodyhtml = bodyhtml + self.test_additional_body_txt

            # Create the root message and fill in the from, to, and subject headers
            msgRoot = MIMEMultipart('related')
            msgRoot['Subject'] = subject
            msgRoot['From'] = self.client_email
            msgRoot['To'] = self.client_email
            msgRoot['Resent-From'] = self.invalid_user_name + '@' + sdnsdd
            if self.send_read_receipt_to is not None:
                msgRoot['Disposition-Notification-To'] = self.send_read_receipt_to
            msgRoot.preamble = 'This is a multi-part message in MIME format.'
            # Encapsulate the plain and HTML versions of the message body in an
            # 'alternative' part, so message agents can decide which they want to display.
            msgAlternative = MIMEMultipart('alternative')
            msgRoot.attach(msgAlternative)
            msgText = MIMEText(bodytext)
            msgAlternative.attach(msgText)

            msgText = MIMEText(bodyhtml, 'html')
            msgAlternative.attach(msgText)

            self.sending_email(email_from, email_to, msgRoot.as_string(), email_filter_output, msgRoot['From'],
                               msgRoot['To'], msgRoot['Disposition-Notification-To'], None, email_from)

    # Sender header is spoofed external and SMTP FROM is same as Test 3
    def test48(self, email_filter_output, domain_to_use=None):
        """ :param: domain_to_use - list """
        
        if domain_to_use is None:
            domain_to_use = self.spoof_domains_no_spf_dmarc_dkim
        
        for sdnsdd in domain_to_use:
            self.test_num = str(self.test_num_prefix + 48)

            # create the encrypted email identification text at bottom of every email (unencrypted shows scanner IP and path of client dir being worked on so can dump results back to that same location)
            self.email_identification()

            bodytext = "This is a mail relay test " + self.test_num + ", from a valid internal address with 'sender' or on-behalf-of a spoofed external address to an internal address through " + self.email_server + self.test_additional_msg + ". \n\n	Please forward to " + self.forward_email_to + " prior to deleting this message.\n\n Thank you." + self.encrypted_server_info
            subject = "Testing Mail Relay " + self.test_num + " through " + self.email_server + self.test_additional_msg + ". Forward to " + self.forward_email_to + "!"
            email_from = self.invalid_user_name + '@' + sdnsdd
            email_to = [self.client_email]
            bodyhtml = "<html><body>" + bodytext.replace("\n", "<br>").replace(
                "Please forward to " + self.forward_email_to + " prior to deleting this message",
                "<b>Please forward to <a href='mailto:" + self.forward_email_to + "'>" + self.forward_email_to + "</a> prior to deleting this message</b>") + "</body></html>"
            bodyhtml = bodyhtml + self.test_additional_body_txt

            # Create the root message and fill in the from, to, and subject headers
            msgRoot = MIMEMultipart('related')
            msgRoot['Subject'] = subject
            msgRoot['From'] = self.client_email
            msgRoot['To'] = self.client_email
            msgRoot['Sender'] = email_from
            if self.send_read_receipt_to is not None:
                msgRoot['Disposition-Notification-To'] = self.send_read_receipt_to
            msgRoot.preamble = 'This is a multi-part message in MIME format.'
            # Encapsulate the plain and HTML versions of the message body in an
            # 'alternative' part, so message agents can decide which they want to display.
            msgAlternative = MIMEMultipart('alternative')
            msgRoot.attach(msgAlternative)
            msgText = MIMEText(bodytext)
            msgAlternative.attach(msgText)

            msgText = MIMEText(bodyhtml, 'html')
            msgAlternative.attach(msgText)

            self.sending_email(email_from, email_to, msgRoot.as_string(), email_filter_output, msgRoot['From'],
                               msgRoot['To'], msgRoot['Disposition-Notification-To'], None, "", email_from)

    # Sender header is spoofed external and SMTP FROM is same as Test 3
    def test49(self, email_filter_output, domain_to_use=None):
        """ domain_to_use - list """
        
        if domain_to_use is None:
            domain_to_use = self.spoof_domains_no_spf_dmarc_dkim
        
        for sdnsdd in domain_to_use:
            self.test_num = str(self.test_num_prefix + 49)

            # create the encrypted email identification text at bottom of every email (unencrypted shows scanner IP and path of client dir being worked on so can dump results back to that same location)
            self.email_identification()

            bodytext = "This is a mail relay test " + self.test_num + ", from a spoofed external address with 'sender' or on-behalf-of a valid internal address to an internal address through " + self.email_server + self.test_additional_msg + ". \n\n	Please forward to " + self.forward_email_to + " prior to deleting this message.\n\n Thank you." + self.encrypted_server_info
            subject = "Testing Mail Relay " + self.test_num + " through " + self.email_server + self.test_additional_msg + ". Forward to " + self.forward_email_to + "!"
            email_from = self.invalid_user_name + '@' + sdnsdd
            email_to = [self.client_email]
            bodyhtml = "<html><body>" + bodytext.replace("\n", "<br>").replace(
                "Please forward to " + self.forward_email_to + " prior to deleting this message",
                "<b>Please forward to <a href='mailto:" + self.forward_email_to + "'>" + self.forward_email_to + "</a> prior to deleting this message</b>") + "</body></html>"
            bodyhtml = bodyhtml + self.test_additional_body_txt

            # Create the root message and fill in the from, to, and subject headers
            msgRoot = MIMEMultipart('related')
            msgRoot['Subject'] = subject
            msgRoot['From'] = email_from
            msgRoot['To'] = self.client_email
            msgRoot['Sender'] = self.client_email
            if self.send_read_receipt_to is not None:
                msgRoot['Disposition-Notification-To'] = self.send_read_receipt_to
            msgRoot.preamble = 'This is a multi-part message in MIME format.'
            # Encapsulate the plain and HTML versions of the message body in an
            # 'alternative' part, so message agents can decide which they want to display.
            msgAlternative = MIMEMultipart('alternative')
            msgRoot.attach(msgAlternative)
            msgText = MIMEText(bodytext)
            msgAlternative.attach(msgText)

            msgText = MIMEText(bodyhtml, 'html')
            msgAlternative.attach(msgText)

            self.sending_email(email_from, email_to, msgRoot.as_string(), email_filter_output, msgRoot['From'],
                               msgRoot['To'], msgRoot['Disposition-Notification-To'], None, "", self.client_email)

    # SMTP FROM domain is localhost
    def test50(self, email_filter_output):
        """ :param: domain_to_use - list """

        self.test_num = str(self.test_num_prefix + 50)

        # create the encrypted email identification text at bottom of every email (unencrypted shows scanner IP and path of client dir being worked on so can dump results back to that same location)
        self.email_identification()

        bodytext = "This is a mail relay test " + self.test_num + ", from a spoofed external address with domain of 'localhost' through " + self.email_server + self.test_additional_msg + ". \n\n	Please forward to " + self.forward_email_to + " prior to deleting this message.\n\n Thank you." + self.encrypted_server_info
        subject = "Testing Mail Relay " + self.test_num + " through " + self.email_server + self.test_additional_msg + ". Forward to " + self.forward_email_to + "!"
        email_from = self.client_username + '@localhost'
        email_to = [self.client_email]
        bodyhtml = "<html><body>" + bodytext.replace("\n", "<br>").replace(
            "Please forward to " + self.forward_email_to + " prior to deleting this message",
            "<b>Please forward to <a href='mailto:" + self.forward_email_to + "'>" + self.forward_email_to + "</a> prior to deleting this message</b>") + "</body></html>"
        bodyhtml = bodyhtml + self.test_additional_body_txt

        # Create the root message and fill in the from, to, and subject headers
        msgRoot = MIMEMultipart('related')
        msgRoot['Subject'] = subject
        msgRoot['From'] = email_from
        msgRoot['To'] = self.client_email
        if self.send_read_receipt_to is not None:
            msgRoot['Disposition-Notification-To'] = self.send_read_receipt_to
        msgRoot.preamble = 'This is a multi-part message in MIME format.'
        # Encapsulate the plain and HTML versions of the message body in an
        # 'alternative' part, so message agents can decide which they want to display.
        msgAlternative = MIMEMultipart('alternative')
        msgRoot.attach(msgAlternative)
        msgText = MIMEText(bodytext)
        msgAlternative.attach(msgText)

        msgText = MIMEText(bodyhtml, 'html')
        msgAlternative.attach(msgText)

        self.sending_email(email_from, email_to, msgRoot.as_string(), email_filter_output, msgRoot['From'],
                               msgRoot['To'], msgRoot['Disposition-Notification-To'], None, "", self.client_email)

    # SMTP FROM domain is 127.0.0.1
    def test51(self, email_filter_output):
        """ :param: domain_to_use - list """

        self.test_num = str(self.test_num_prefix + 51)

        # create the encrypted email identification text at bottom of every email (unencrypted shows scanner IP and path of client dir being worked on so can dump results back to that same location)
        self.email_identification()

        bodytext = "This is a mail relay test " + self.test_num + ", from a spoofed external address with domain '[127.0.0.1]' through " + self.email_server + self.test_additional_msg + ". \n\n	Please forward to " + self.forward_email_to + " prior to deleting this message.\n\n Thank you." + self.encrypted_server_info
        subject = "Testing Mail Relay " + self.test_num + " through " + self.email_server + self.test_additional_msg + ". Forward to " + self.forward_email_to + "!"
        email_from = self.client_username + '@[127.0.0.1]'
        email_to = [self.client_email]
        bodyhtml = "<html><body>" + bodytext.replace("\n", "<br>").replace(
            "Please forward to " + self.forward_email_to + " prior to deleting this message",
            "<b>Please forward to <a href='mailto:" + self.forward_email_to + "'>" + self.forward_email_to + "</a> prior to deleting this message</b>") + "</body></html>"
        bodyhtml = bodyhtml + self.test_additional_body_txt

        # Create the root message and fill in the from, to, and subject headers
        msgRoot = MIMEMultipart('related')
        msgRoot['Subject'] = subject
        msgRoot['From'] = email_from
        msgRoot['To'] = self.client_email
        if self.send_read_receipt_to is not None:
            msgRoot['Disposition-Notification-To'] = self.send_read_receipt_to
        msgRoot.preamble = 'This is a multi-part message in MIME format.'
        # Encapsulate the plain and HTML versions of the message body in an
        # 'alternative' part, so message agents can decide which they want to display.
        msgAlternative = MIMEMultipart('alternative')
        msgRoot.attach(msgAlternative)
        msgText = MIMEText(bodytext)
        msgAlternative.attach(msgText)

        msgText = MIMEText(bodyhtml, 'html')
        msgAlternative.attach(msgText)

        self.sending_email(email_from, email_to, msgRoot.as_string(), email_filter_output, msgRoot['From'],
                           msgRoot['To'], msgRoot['Disposition-Notification-To'], None, "", self.client_email)

    # SMTP FROM domain is null
    def test52(self, email_filter_output):
        """ :param: domain_to_use - list """

        self.test_num = str(self.test_num_prefix + 52)

        # create the encrypted email identification text at bottom of every email (unencrypted shows scanner IP and path of client dir being worked on so can dump results back to that same location)
        self.email_identification()

        bodytext = "This is a mail relay test " + self.test_num + ", from a spoofed external address with null domain, '<>', through " + self.email_server + self.test_additional_msg + ". \n\n	Please forward to " + self.forward_email_to + " prior to deleting this message.\n\n Thank you." + self.encrypted_server_info
        subject = "Testing Mail Relay " + self.test_num + " through " + self.email_server + self.test_additional_msg + ". Forward to " + self.forward_email_to + "!"
        email_from = '<>'
        email_to = [self.client_email]
        bodyhtml = "<html><body>" + bodytext.replace("\n", "<br>").replace(
            "Please forward to " + self.forward_email_to + " prior to deleting this message",
            "<b>Please forward to <a href='mailto:" + self.forward_email_to + "'>" + self.forward_email_to + "</a> prior to deleting this message</b>") + "</body></html>"
        bodyhtml = bodyhtml + self.test_additional_body_txt

        # Create the root message and fill in the from, to, and subject headers
        msgRoot = MIMEMultipart('related')
        msgRoot['Subject'] = subject
        msgRoot['From'] = email_from
        msgRoot['To'] = self.client_email
        if self.send_read_receipt_to is not None:
            msgRoot['Disposition-Notification-To'] = self.send_read_receipt_to
        msgRoot.preamble = 'This is a multi-part message in MIME format.'
        # Encapsulate the plain and HTML versions of the message body in an
        # 'alternative' part, so message agents can decide which they want to display.
        msgAlternative = MIMEMultipart('alternative')
        msgRoot.attach(msgAlternative)
        msgText = MIMEText(bodytext)
        msgAlternative.attach(msgText)

        msgText = MIMEText(bodyhtml, 'html')
        msgAlternative.attach(msgText)

        self.sending_email(email_from, email_to, msgRoot.as_string(), email_filter_output, msgRoot['From'],
                           msgRoot['To'], msgRoot['Disposition-Notification-To'], None, "", self.client_email)

    # Sender email to use FQDN of local host
    def test53(self, email_filter_output):

        self.test_num = str(self.test_num_prefix + 53)

        local_fqdn = network.get_full_hostname_of_local_computer()

        # create the encrypted email identification text at bottom of every email (unencrypted shows scanner IP and path of client dir being worked on so can dump results back to that same location)
        self.email_identification()

        bodytext = "This is a mail relay test " + self.test_num + ", from a spoofed external address with domain of scanners local FQDN through " + self.email_server + self.test_additional_msg + ". \n\n	Please forward to " + self.forward_email_to + " prior to deleting this message.\n\n Thank you." + self.encrypted_server_info
        subject = "Testing Mail Relay " + self.test_num + " through " + self.email_server + self.test_additional_msg + ". Forward to " + self.forward_email_to + "!"
        email_from = self.client_username + '@' + local_fqdn
        email_to = [self.client_email]
        bodyhtml = "<html><body>" + bodytext.replace("\n", "<br>").replace(
            "Please forward to " + self.forward_email_to + " prior to deleting this message",
            "<b>Please forward to <a href='mailto:" + self.forward_email_to + "'>" + self.forward_email_to + "</a> prior to deleting this message</b>") + "</body></html>"
        bodyhtml = bodyhtml + self.test_additional_body_txt

        # Create the root message and fill in the from, to, and subject headers
        msgRoot = MIMEMultipart('related')
        msgRoot['Subject'] = subject
        msgRoot['From'] = email_from
        msgRoot['To'] = self.client_email
        if self.send_read_receipt_to is not None:
            msgRoot['Disposition-Notification-To'] = self.send_read_receipt_to
        msgRoot.preamble = 'This is a multi-part message in MIME format.'
        # Encapsulate the plain and HTML versions of the message body in an
        # 'alternative' part, so message agents can decide which they want to display.
        msgAlternative = MIMEMultipart('alternative')
        msgRoot.attach(msgAlternative)
        msgText = MIMEText(bodytext)
        msgAlternative.attach(msgText)

        msgText = MIMEText(bodyhtml, 'html')
        msgAlternative.attach(msgText)

        self.sending_email(email_from, email_to, msgRoot.as_string(), email_filter_output, msgRoot['From'],
                           msgRoot['To'], msgRoot['Disposition-Notification-To'], None, "", self.client_email)

    # SMTP FROM email to use External IP as domain
    def test54(self, email_filter_output):

        self.test_num = str(self.test_num_prefix + 54)

        # create the encrypted email identification text at bottom of every email (unencrypted shows scanner IP and path of client dir being worked on so can dump results back to that same location)
        self.email_identification()

        bodytext = "This is a mail relay test " + self.test_num + ", from a spoofed external address with domain as an Public IP Address through " + self.email_server + self.test_additional_msg + ". \n\n	Please forward to " + self.forward_email_to + " prior to deleting this message.\n\n Thank you." + self.encrypted_server_info
        subject = "Testing Mail Relay " + self.test_num + " through " + self.email_server + self.test_additional_msg + ". Forward to " + self.forward_email_to + "!"
        email_from = self.client_username + '@[' + self.your_public_ip + ']'
        email_to = [self.client_email]
        bodyhtml = "<html><body>" + bodytext.replace("\n", "<br>").replace(
            "Please forward to " + self.forward_email_to + " prior to deleting this message",
            "<b>Please forward to <a href='mailto:" + self.forward_email_to + "'>" + self.forward_email_to + "</a> prior to deleting this message</b>") + "</body></html>"
        bodyhtml = bodyhtml + self.test_additional_body_txt

        # Create the root message and fill in the from, to, and subject headers
        msgRoot = MIMEMultipart('related')
        msgRoot['Subject'] = subject
        msgRoot['From'] = email_from
        msgRoot['To'] = self.client_email
        if self.send_read_receipt_to is not None:
            msgRoot['Disposition-Notification-To'] = self.send_read_receipt_to
        msgRoot.preamble = 'This is a multi-part message in MIME format.'
        # Encapsulate the plain and HTML versions of the message body in an
        # 'alternative' part, so message agents can decide which they want to display.
        msgAlternative = MIMEMultipart('alternative')
        msgRoot.attach(msgAlternative)
        msgText = MIMEText(bodytext)
        msgAlternative.attach(msgText)

        msgText = MIMEText(bodyhtml, 'html')
        msgAlternative.attach(msgText)

        self.sending_email(email_from, email_to, msgRoot.as_string(), email_filter_output, msgRoot['From'],
                           msgRoot['To'], msgRoot['Disposition-Notification-To'], None, "", self.client_email)

    # SMTP FROM email to use Private IP as domain
    def test55(self, email_filter_output):

        self.test_num = str(self.test_num_prefix + 55)

        # create the encrypted email identification text at bottom of every email (unencrypted shows scanner IP and path of client dir being worked on so can dump results back to that same location)
        self.email_identification()

        bodytext = "This is a mail relay test " + self.test_num + ", from a spoofed external address with domain as a Private IP Address through " + self.email_server + self.test_additional_msg + ". \n\n	Please forward to " + self.forward_email_to + " prior to deleting this message.\n\n Thank you." + self.encrypted_server_info
        subject = "Testing Mail Relay " + self.test_num + " through " + self.email_server + self.test_additional_msg + ". Forward to " + self.forward_email_to + "!"
        email_from = self.client_username + '@[' + self.private_ip + ']'
        email_to = [self.client_email]
        bodyhtml = "<html><body>" + bodytext.replace("\n", "<br>").replace(
            "Please forward to " + self.forward_email_to + " prior to deleting this message",
            "<b>Please forward to <a href='mailto:" + self.forward_email_to + "'>" + self.forward_email_to + "</a> prior to deleting this message</b>") + "</body></html>"
        bodyhtml = bodyhtml + self.test_additional_body_txt

        # Create the root message and fill in the from, to, and subject headers
        msgRoot = MIMEMultipart('related')
        msgRoot['Subject'] = subject
        msgRoot['From'] = email_from
        msgRoot['To'] = self.client_email
        if self.send_read_receipt_to is not None:
            msgRoot['Disposition-Notification-To'] = self.send_read_receipt_to
        msgRoot.preamble = 'This is a multi-part message in MIME format.'
        # Encapsulate the plain and HTML versions of the message body in an
        # 'alternative' part, so message agents can decide which they want to display.
        msgAlternative = MIMEMultipart('alternative')
        msgRoot.attach(msgAlternative)
        msgText = MIMEText(bodytext)
        msgAlternative.attach(msgText)

        msgText = MIMEText(bodyhtml, 'html')
        msgAlternative.attach(msgText)

        self.sending_email(email_from, email_to, msgRoot.as_string(), email_filter_output, msgRoot['From'],
                           msgRoot['To'], msgRoot['Disposition-Notification-To'], None, "", self.client_email)

    # SMTP FROM email to use % hack where routing is valid user + % + domain
    def test56(self, email_filter_output):

        self.test_num = str(self.test_num_prefix + 56)

        # create the encrypted email identification text at bottom of every email (unencrypted shows scanner IP and path of client dir being worked on so can dump results back to that same location)
        self.email_identification()

        bodytext = "This is a mail relay test " + self.test_num + ", from a spoofed internal routed address using the % hack with SMTP FROM in the from: your_username%your_domain@mydomain through " + self.email_server + self.test_additional_msg + ". \n\n	Please forward to " + self.forward_email_to + " prior to deleting this message.\n\n Thank you." + self.encrypted_server_info
        subject = "Testing Mail Relay " + self.test_num + " through " + self.email_server + self.test_additional_msg + ". Forward to " + self.forward_email_to + "!"
        email_from = self.client_username + '%' + self.domain + '@' + self.testers_domain
        email_to = [self.client_email]
        bodyhtml = "<html><body>" + bodytext.replace("\n", "<br>").replace(
            "Please forward to " + self.forward_email_to + " prior to deleting this message",
            "<b>Please forward to <a href='mailto:" + self.forward_email_to + "'>" + self.forward_email_to + "</a> prior to deleting this message</b>") + "</body></html>"
        bodyhtml = bodyhtml + self.test_additional_body_txt

        # Create the root message and fill in the from, to, and subject headers
        msgRoot = MIMEMultipart('related')
        msgRoot['Subject'] = subject
        msgRoot['From'] = email_from
        msgRoot['To'] = self.client_email
        if self.send_read_receipt_to is not None:
            msgRoot['Disposition-Notification-To'] = self.send_read_receipt_to
        msgRoot.preamble = 'This is a multi-part message in MIME format.'
        # Encapsulate the plain and HTML versions of the message body in an
        # 'alternative' part, so message agents can decide which they want to display.
        msgAlternative = MIMEMultipart('alternative')
        msgRoot.attach(msgAlternative)
        msgText = MIMEText(bodytext)
        msgAlternative.attach(msgText)

        msgText = MIMEText(bodyhtml, 'html')
        msgAlternative.attach(msgText)

        self.sending_email(email_from, email_to, msgRoot.as_string(), email_filter_output, msgRoot['From'],
                           msgRoot['To'], msgRoot['Disposition-Notification-To'], None, "", self.client_email)

    # SMTP FROM email to use % hack where routing is valid user but not valid domain
    def test57(self, email_filter_output, spoofed_domain_list=None):
        
        if spoofed_domain_list is None:
            spoofed_domain_list = self.spoof_domains_no_spf_dmarc_dkim
        
        for count, sdl in enumerate(spoofed_domain_list):
            self.test_num = str(self.test_num_prefix + 57) + "." + str(count)

            # create the encrypted email identification text at bottom of every email (unencrypted shows scanner IP and path of client dir being worked on so can dump results back to that same location)
            self.email_identification()

            bodytext = "This is a mail relay test " + self.test_num + ", from a spoofed internal routed address using the % hack with SMTP FROM in the from: your_username%spoofed_domain@mydomain through " + self.email_server + self.test_additional_msg + ". \n\n	Please forward to " + self.forward_email_to + " prior to deleting this message.\n\n Thank you." + self.encrypted_server_info
            subject = "Testing Mail Relay " + self.test_num + " through " + self.email_server + self.test_additional_msg + ". Forward to " + self.forward_email_to + "!"
            email_from = self.client_username + '%' + sdl + '@' + self.testers_domain
            email_to = [self.client_email]
            bodyhtml = "<html><body>" + bodytext.replace("\n", "<br>").replace(
                "Please forward to " + self.forward_email_to + " prior to deleting this message",
                "<b>Please forward to <a href='mailto:" + self.forward_email_to + "'>" + self.forward_email_to + "</a> prior to deleting this message</b>") + "</body></html>"
            bodyhtml = bodyhtml + self.test_additional_body_txt

            # Create the root message and fill in the from, to, and subject headers
            msgRoot = MIMEMultipart('related')
            msgRoot['Subject'] = subject
            msgRoot['From'] = email_from
            msgRoot['To'] = self.client_email
            if self.send_read_receipt_to is not None:
                msgRoot['Disposition-Notification-To'] = self.send_read_receipt_to
            msgRoot.preamble = 'This is a multi-part message in MIME format.'
            # Encapsulate the plain and HTML versions of the message body in an
            # 'alternative' part, so message agents can decide which they want to display.
            msgAlternative = MIMEMultipart('alternative')
            msgRoot.attach(msgAlternative)
            msgText = MIMEText(bodytext)
            msgAlternative.attach(msgText)

            msgText = MIMEText(bodyhtml, 'html')
            msgAlternative.attach(msgText)

            self.sending_email(email_from, email_to, msgRoot.as_string(), email_filter_output, msgRoot['From'],
                               msgRoot['To'], msgRoot['Disposition-Notification-To'], None, "", self.client_email)

    # SMTP FROM email to use % hack where routing is valid user + domain but routing from is Public IP
    def test58(self, email_filter_output):

        self.test_num = str(self.test_num_prefix + 58)

        # create the encrypted email identification text at bottom of every email (unencrypted shows scanner IP and path of client dir being worked on so can dump results back to that same location)
        self.email_identification()

        bodytext = "This is a mail relay test " + self.test_num + ", from a spoofed internal routed address using the % hack with SMTP FROM in the from: your_username%your_domain@[public_ip] through " + self.email_server + self.test_additional_msg + ". \n\n	Please forward to " + self.forward_email_to + " prior to deleting this message.\n\n Thank you." + self.encrypted_server_info
        subject = "Testing Mail Relay " + self.test_num + " through " + self.email_server + self.test_additional_msg + ". Forward to " + self.forward_email_to + "!"
        email_from = self.client_username + '%' + self.domain + '@[' + self.your_public_ip + ']'
        email_to = [self.client_email]
        bodyhtml = "<html><body>" + bodytext.replace("\n", "<br>").replace(
            "Please forward to " + self.forward_email_to + " prior to deleting this message",
            "<b>Please forward to <a href='mailto:" + self.forward_email_to + "'>" + self.forward_email_to + "</a> prior to deleting this message</b>") + "</body></html>"
        bodyhtml = bodyhtml + self.test_additional_body_txt

        # Create the root message and fill in the from, to, and subject headers
        msgRoot = MIMEMultipart('related')
        msgRoot['Subject'] = subject
        msgRoot['From'] = email_from
        msgRoot['To'] = self.client_email
        if self.send_read_receipt_to is not None:
            msgRoot['Disposition-Notification-To'] = self.send_read_receipt_to
        msgRoot.preamble = 'This is a multi-part message in MIME format.'
        # Encapsulate the plain and HTML versions of the message body in an
        # 'alternative' part, so message agents can decide which they want to display.
        msgAlternative = MIMEMultipart('alternative')
        msgRoot.attach(msgAlternative)
        msgText = MIMEText(bodytext)
        msgAlternative.attach(msgText)

        msgText = MIMEText(bodyhtml, 'html')
        msgAlternative.attach(msgText)

        self.sending_email(email_from, email_to, msgRoot.as_string(), email_filter_output, msgRoot['From'],
                           msgRoot['To'], msgRoot['Disposition-Notification-To'], None, "",
                           self.client_email)

    # SMTP FROM email to use % hack where routing is valid user but not valid domain & routed from Public IP
    def test59(self, email_filter_output, spoofed_domain_list=None):
        if spoofed_domain_list is None:
            spoofed_domain_list = self.spoof_domains_no_spf_dmarc_dkim
            
        for count, sdl in enumerate(spoofed_domain_list):
            self.test_num = str(self.test_num_prefix + 59) + "." + str(count)

            # create the encrypted email identification text at bottom of every email (unencrypted shows scanner IP and path of client dir being worked on so can dump results back to that same location)
            self.email_identification()

            bodytext = "This is a mail relay test " + self.test_num + ", from a spoofed internal routed address using the % hack with SMTP FROM in the from: your_username%spoofed_domain@[public_ip] through " + self.email_server + self.test_additional_msg + ". \n\n	Please forward to " + self.forward_email_to + " prior to deleting this message.\n\n Thank you." + self.encrypted_server_info
            subject = "Testing Mail Relay " + self.test_num + " through " + self.email_server + self.test_additional_msg + ". Forward to " + self.forward_email_to + "!"
            email_from = self.client_username + '%' + sdl + '@[' + self.your_public_ip + ']'
            email_to = [self.client_email]
            bodyhtml = "<html><body>" + bodytext.replace("\n", "<br>").replace(
                "Please forward to " + self.forward_email_to + " prior to deleting this message",
                "<b>Please forward to <a href='mailto:" + self.forward_email_to + "'>" + self.forward_email_to + "</a> prior to deleting this message</b>") + "</body></html>"
            bodyhtml = bodyhtml + self.test_additional_body_txt

            # Create the root message and fill in the from, to, and subject headers
            msgRoot = MIMEMultipart('related')
            msgRoot['Subject'] = subject
            msgRoot['From'] = email_from
            msgRoot['To'] = self.client_email
            if self.send_read_receipt_to is not None:
                msgRoot['Disposition-Notification-To'] = self.send_read_receipt_to
            msgRoot.preamble = 'This is a multi-part message in MIME format.'
            # Encapsulate the plain and HTML versions of the message body in an
            # 'alternative' part, so message agents can decide which they want to display.
            msgAlternative = MIMEMultipart('alternative')
            msgRoot.attach(msgAlternative)
            msgText = MIMEText(bodytext)
            msgAlternative.attach(msgText)

            msgText = MIMEText(bodyhtml, 'html')
            msgAlternative.attach(msgText)

            self.sending_email(email_from, email_to, msgRoot.as_string(), email_filter_output, msgRoot['From'],
                               msgRoot['To'], msgRoot['Disposition-Notification-To'], None, "", self.client_email)

    # SMTP FROM email to use % hack where routing is valid user & domain but routing is Public IP of email_server
    def test60(self, email_filter_output):

        self.test_num = str(self.test_num_prefix + 60)

        # create the encrypted email identification text at bottom of every email (unencrypted shows scanner IP and path of client dir being worked on so can dump results back to that same location)
        self.email_identification()

        if self.email_public_ip is not None and network.valid_ip(self.email_public_ip):
            bodytext = "This is a mail relay test " + self.test_num + ", from a spoofed internal routed address using the % hack with SMTP FROM in the from: your_username%spoofed_domain@[your_mx_public_ip] through " + self.email_server + self.test_additional_msg + ". \n\n	Please forward to " + self.forward_email_to + " prior to deleting this message.\n\n Thank you." + self.encrypted_server_info
            subject = "Testing Mail Relay " + self.test_num + " through " + self.email_server + self.test_additional_msg + ". Forward to " + self.forward_email_to + "!"
            email_from = self.client_username + '%' + self.domain + '@[' + self.email_public_ip + ']'
            email_to = [self.client_email]
            bodyhtml = "<html><body>" + bodytext.replace("\n", "<br>").replace(
                "Please forward to " + self.forward_email_to + " prior to deleting this message",
                "<b>Please forward to <a href='mailto:" + self.forward_email_to + "'>" + self.forward_email_to + "</a> prior to deleting this message</b>") + "</body></html>"
            bodyhtml = bodyhtml + self.test_additional_body_txt

            # Create the root message and fill in the from, to, and subject headers
            msgRoot = MIMEMultipart('related')
            msgRoot['Subject'] = subject
            msgRoot['From'] = email_from
            msgRoot['To'] = self.client_email
            if self.send_read_receipt_to is not None:
                msgRoot['Disposition-Notification-To'] = self.send_read_receipt_to
            msgRoot.preamble = 'This is a multi-part message in MIME format.'
            # Encapsulate the plain and HTML versions of the message body in an
            # 'alternative' part, so message agents can decide which they want to display.
            msgAlternative = MIMEMultipart('alternative')
            msgRoot.attach(msgAlternative)
            msgText = MIMEText(bodytext)
            msgAlternative.attach(msgText)

            msgText = MIMEText(bodyhtml, 'html')
            msgAlternative.attach(msgText)

            self.sending_email(email_from, email_to, msgRoot.as_string(), email_filter_output, msgRoot['From'],
                               msgRoot['To'], msgRoot['Disposition-Notification-To'], None, "", self.client_email)

    # SMTP FROM email if client email in quotes
    def test61(self, email_filter_output):

        self.test_num = str(self.test_num_prefix + 61)

        # create the encrypted email identification text at bottom of every email (unencrypted shows scanner IP and path of client dir being worked on so can dump results back to that same location)
        self.email_identification()

        bodytext = "This is a mail relay test " + self.test_num + ", from a spoofed internal address within quotes through " + self.email_server + self.test_additional_msg + ". \n\n	Please forward to " + self.forward_email_to + " prior to deleting this message.\n\n Thank you." + self.encrypted_server_info
        subject = "Testing Mail Relay " + self.test_num + " through " + self.email_server + self.test_additional_msg + ". Forward to " + self.forward_email_to + "!"
        email_from = '"' + self.client_email + '"'
        email_to = [self.client_email]
        bodyhtml = "<html><body>" + bodytext.replace("\n", "<br>").replace(
            "Please forward to " + self.forward_email_to + " prior to deleting this message",
            "<b>Please forward to <a href='mailto:" + self.forward_email_to + "'>" + self.forward_email_to + "</a> prior to deleting this message</b>") + "</body></html>"
        bodyhtml = bodyhtml + self.test_additional_body_txt

        # Create the root message and fill in the from, to, and subject headers
        msgRoot = MIMEMultipart('related')
        msgRoot['Subject'] = subject
        msgRoot['From'] = email_from
        msgRoot['To'] = self.client_email
        if self.send_read_receipt_to is not None:
            msgRoot['Disposition-Notification-To'] = self.send_read_receipt_to
        msgRoot.preamble = 'This is a multi-part message in MIME format.'
        # Encapsulate the plain and HTML versions of the message body in an
        # 'alternative' part, so message agents can decide which they want to display.
        msgAlternative = MIMEMultipart('alternative')
        msgRoot.attach(msgAlternative)
        msgText = MIMEText(bodytext)
        msgAlternative.attach(msgText)

        msgText = MIMEText(bodyhtml, 'html')
        msgAlternative.attach(msgText)

        self.sending_email(email_from, email_to, msgRoot.as_string(), email_filter_output, msgRoot['From'],
                           msgRoot['To'], msgRoot['Disposition-Notification-To'], None, "", self.client_email)

    # SMTP FROM email if client email in quotes + % hack from valid user + valid domain
    def test62(self, email_filter_output):

        self.test_num = str(self.test_num_prefix + 62)

        # create the encrypted email identification text at bottom of every email (unencrypted shows scanner IP and path of client dir being worked on so can dump results back to that same location)
        self.email_identification()

        bodytext = "This is a mail relay test " + self.test_num + ", from a spoofed internal routed address using the % hack with SMTP FROM in the from: your_username%your_domain@mydomain within quotes through " + self.email_server + self.test_additional_msg + ". \n\n	Please forward to " + self.forward_email_to + " prior to deleting this message.\n\n Thank you." + self.encrypted_server_info
        subject = "Testing Mail Relay " + self.test_num + " through " + self.email_server + self.test_additional_msg + ". Forward to " + self.forward_email_to + "!"
        email_from = '"' + self.client_username + '%' + self.domain + '@' + self.testers_domain + '"'
        email_to = [self.client_email]
        bodyhtml = "<html><body>" + bodytext.replace("\n", "<br>").replace(
            "Please forward to " + self.forward_email_to + " prior to deleting this message",
            "<b>Please forward to <a href='mailto:" + self.forward_email_to + "'>" + self.forward_email_to + "</a> prior to deleting this message</b>") + "</body></html>"
        bodyhtml = bodyhtml + self.test_additional_body_txt

        # Create the root message and fill in the from, to, and subject headers
        msgRoot = MIMEMultipart('related')
        msgRoot['Subject'] = subject
        msgRoot['From'] = email_from
        msgRoot['To'] = self.client_email
        if self.send_read_receipt_to is not None:
            msgRoot['Disposition-Notification-To'] = self.send_read_receipt_to
        msgRoot.preamble = 'This is a multi-part message in MIME format.'
        # Encapsulate the plain and HTML versions of the message body in an
        # 'alternative' part, so message agents can decide which they want to display.
        msgAlternative = MIMEMultipart('alternative')
        msgRoot.attach(msgAlternative)
        msgText = MIMEText(bodytext)
        msgAlternative.attach(msgText)

        msgText = MIMEText(bodyhtml, 'html')
        msgAlternative.attach(msgText)

        self.sending_email(email_from, email_to, msgRoot.as_string(), email_filter_output, msgRoot['From'],
                           msgRoot['To'], msgRoot['Disposition-Notification-To'], None, "", self.client_email)

    # SMTP FROM email if client email in quotes + % hack from valid user + valid domain and routed is Public IP
    def test63(self, email_filter_output):

        self.test_num = str(self.test_num_prefix + 63)

        # create the encrypted email identification text at bottom of every email (unencrypted shows scanner IP and path of client dir being worked on so can dump results back to that same location)
        self.email_identification()

        bodytext = "This is a mail relay test " + self.test_num + ", from a spoofed internal routed address using the % hack with SMTP FROM in the from: your_username%your_domain@ip_address through " + self.email_server + self.test_additional_msg + ". \n\n	Please forward to " + self.forward_email_to + " prior to deleting this message.\n\n Thank you." + self.encrypted_server_info
        subject = "Testing Mail Relay " + self.test_num + " through " + self.email_server + self.test_additional_msg + ". Forward to " + self.forward_email_to + "!"
        email_from = '"' + self.client_username + '%' + self.domain + '"@[' + self.your_public_ip + ']'
        email_to = [self.client_email]
        bodyhtml = "<html><body>" + bodytext.replace("\n", "<br>").replace(
            "Please forward to " + self.forward_email_to + " prior to deleting this message",
            "<b>Please forward to <a href='mailto:" + self.forward_email_to + "'>" + self.forward_email_to + "</a> prior to deleting this message</b>") + "</body></html>"
        bodyhtml = bodyhtml + self.test_additional_body_txt

        # Create the root message and fill in the from, to, and subject headers
        msgRoot = MIMEMultipart('related')
        msgRoot['Subject'] = subject
        msgRoot['From'] = email_from
        msgRoot['To'] = self.client_email
        if self.send_read_receipt_to is not None:
            msgRoot['Disposition-Notification-To'] = self.send_read_receipt_to
        msgRoot.preamble = 'This is a multi-part message in MIME format.'
        # Encapsulate the plain and HTML versions of the message body in an
        # 'alternative' part, so message agents can decide which they want to display.
        msgAlternative = MIMEMultipart('alternative')
        msgRoot.attach(msgAlternative)
        msgText = MIMEText(bodytext)
        msgAlternative.attach(msgText)

        msgText = MIMEText(bodyhtml, 'html')
        msgAlternative.attach(msgText)

        self.sending_email(email_from, email_to, msgRoot.as_string(), email_filter_output, msgRoot['From'],
                           msgRoot['To'], msgRoot['Disposition-Notification-To'], None, "", self.client_email)

    # SMTP TO email uses source routing (client_email @ domain_list
    def test64(self, email_filter_output, spoofed_domain_list=None):
        if spoofed_domain_list is None:
            spoofed_domain_list = self.spoof_domains_no_spf_dmarc_dkim
            
        for count, sdl in enumerate(spoofed_domain_list):
            self.test_num = str(self.test_num_prefix + 64) + "." + str(count)

            # create the encrypted email identification text at bottom of every email (unencrypted shows scanner IP and path of client dir being worked on so can dump results back to that same location)
            self.email_identification()
            bodytext = "This is a mail relay test " + self.test_num + ", from a spoofed source routed (SMTP TO) address, using the format: your_username@your_domain@spoofed_domain through " + self.email_server + self.test_additional_msg + ". \n\n	Please forward to " + self.forward_email_to + " prior to deleting this message.\n\n Thank you." + self.encrypted_server_info
            subject = "Testing Mail Relay " + self.test_num + " through " + self.email_server + self.test_additional_msg + ". Forward to " + self.forward_email_to + "!"
            email_from = "@" + sdl + "," + self.client_email
            email_to = self.client_email #[self.client_email + "@" + sdl]
            bodyhtml = "<html><body>" + bodytext.replace("\n", "<br>").replace(
                "Please forward to " + self.forward_email_to + " prior to deleting this message",
                "<b>Please forward to <a href='mailto:" + self.forward_email_to + "'>" + self.forward_email_to + "</a> prior to deleting this message</b>") + "</body></html>"
            bodyhtml = bodyhtml + self.test_additional_body_txt

            # Create the root message and fill in the from, to, and subject headers
            msgRoot = MIMEMultipart('related')
            msgRoot['Subject'] = subject
            msgRoot['From'] = email_from
            msgRoot['To'] = self.client_email
            if self.send_read_receipt_to is not None:
                msgRoot['Disposition-Notification-To'] = self.send_read_receipt_to
            msgRoot.preamble = 'This is a multi-part message in MIME format.'
            # Encapsulate the plain and HTML versions of the message body in an
            # 'alternative' part, so message agents can decide which they want to display.
            msgAlternative = MIMEMultipart('alternative')
            msgRoot.attach(msgAlternative)
            msgText = MIMEText(bodytext)
            msgAlternative.attach(msgText)

            msgText = MIMEText(bodyhtml, 'html')
            msgAlternative.attach(msgText)

            self.sending_email(email_from, email_to, msgRoot.as_string(), email_filter_output, msgRoot['From'],
                               msgRoot['To'], msgRoot['Disposition-Notification-To'], None, "", self.client_email)

    # SMTP TO email uses source routing (client_email @ domain_list) where client_email is encapsulated in quotes
    def test65(self, email_filter_output, spoofed_domain_list=None):
        if spoofed_domain_list is None:
            spoofed_domain_list = self.spoof_domains_no_spf_dmarc_dkim
            
        for count, sdl in enumerate(spoofed_domain_list):
            self.test_num = str(self.test_num_prefix + 65) + "." + str(count)

            # create the encrypted email identification text at bottom of every email (unencrypted shows scanner IP and path of client dir being worked on so can dump results back to that same location)
            self.email_identification()
            bodytext = "This is a mail relay test " + self.test_num + ", from a spoofed source routed (SMTP TO) address, using the format: \"your_username@your_domain\"@spoofed_domain through " + self.email_server + self.test_additional_msg + ". \n\n	Please forward to " + self.forward_email_to + " prior to deleting this message.\n\n Thank you." + self.encrypted_server_info
            subject = "Testing Mail Relay " + self.test_num + " through " + self.email_server + self.test_additional_msg + ". Forward to " + self.forward_email_to + "!"
            email_from = "'" + self.client_email + '"' + '@' + sdl #self.invalid_user_name + '@' + sdl
            email_to = self.client_email #['"' + self.client_email + '"@' + sdl]
            bodyhtml = "<html><body>" + bodytext.replace("\n", "<br>").replace(
                "Please forward to " + self.forward_email_to + " prior to deleting this message",
                "<b>Please forward to <a href='mailto:" + self.forward_email_to + "'>" + self.forward_email_to + "</a> prior to deleting this message</b>") + "</body></html>"
            bodyhtml = bodyhtml + self.test_additional_body_txt

            # Create the root message and fill in the from, to, and subject headers
            msgRoot = MIMEMultipart('related')
            msgRoot['Subject'] = subject
            msgRoot['From'] = email_from
            msgRoot['To'] = self.client_email
            if self.send_read_receipt_to is not None:
                msgRoot['Disposition-Notification-To'] = self.send_read_receipt_to
            msgRoot.preamble = 'This is a multi-part message in MIME format.'
            # Encapsulate the plain and HTML versions of the message body in an
            # 'alternative' part, so message agents can decide which they want to display.
            msgAlternative = MIMEMultipart('alternative')
            msgRoot.attach(msgAlternative)
            msgText = MIMEText(bodytext)
            msgAlternative.attach(msgText)

            msgText = MIMEText(bodyhtml, 'html')
            msgAlternative.attach(msgText)

            self.sending_email(email_from, email_to, msgRoot.as_string(), email_filter_output, msgRoot['From'],
                               msgRoot['To'], msgRoot['Disposition-Notification-To'], None, "", self.client_email)

    # SMTP TO email uses source routing (client_email @ PUBLIC IP)
    def test66(self, email_filter_output, spoofed_domain_list=None):
        if spoofed_domain_list is None:
            spoofed_domain_list = self.spoof_domains_no_spf_dmarc_dkim
            
        for count, sdl in enumerate(spoofed_domain_list):
            self.test_num = str(self.test_num_prefix + 66) + "." + str(count)

            # create the encrypted email identification text at bottom of every email (unencrypted shows scanner IP and path of client dir being worked on so can dump results back to that same location)
            self.email_identification()

            bodytext = "This is a mail relay test " + self.test_num + ", from a spoofed internal routed address using the % hack with SMTP FROM in the from: your_username%your_domain@ip_address through " + self.email_server + self.test_additional_msg + ". \n\n	Please forward to " + self.forward_email_to + " prior to deleting this message.\n\n Thank you." + self.encrypted_server_info
            subject = "Testing Mail Relay " + self.test_num + " through " + self.email_server + self.test_additional_msg + ". Forward to " + self.forward_email_to + "!"
            email_from = self.client_username + '%' + self.domain + '@[' + self.your_ip_address + ']'
            email_to = self.client_email
            bodyhtml = "<html><body>" + bodytext.replace("\n", "<br>").replace(
                "Please forward to " + self.forward_email_to + " prior to deleting this message",
                "<b>Please forward to <a href='mailto:" + self.forward_email_to + "'>" + self.forward_email_to + "</a> prior to deleting this message</b>") + "</body></html>"
            bodyhtml = bodyhtml + self.test_additional_body_txt

            # Create the root message and fill in the from, to, and subject headers
            msgRoot = MIMEMultipart('related')
            msgRoot['Subject'] = subject
            msgRoot['From'] = email_from
            msgRoot['To'] = self.client_email
            if self.send_read_receipt_to is not None:
                msgRoot['Disposition-Notification-To'] = self.send_read_receipt_to
            msgRoot.preamble = 'This is a multi-part message in MIME format.'
            # Encapsulate the plain and HTML versions of the message body in an
            # 'alternative' part, so message agents can decide which they want to display.
            msgAlternative = MIMEMultipart('alternative')
            msgRoot.attach(msgAlternative)
            msgText = MIMEText(bodytext)
            msgAlternative.attach(msgText)

            msgText = MIMEText(bodyhtml, 'html')
            msgAlternative.attach(msgText)

            self.sending_email(email_from, email_to, msgRoot.as_string(), email_filter_output, msgRoot['From'],
                               msgRoot['To'], msgRoot['Disposition-Notification-To'], None, "", self.client_email)

    # SMTP TO email uses source routing (client_email @ Public IP of email_server)
    def test67(self, email_filter_output, spoofed_domain_list=None):
        if spoofed_domain_list is None:
            spoofed_domain_list = self.spoof_domains_no_spf_dmarc_dkim
            
        email_public_ip = self.email_server
        if self.email_server not in self.email_relay_servers_to_bounce_emails_from:
            if not network.valid_ip(email_public_ip):
                # check if in Recon as mx record
                email_public_ip = self.db_object.grab_column_from_single_record("Recon", ["record", "recon_type"], [self.email_server, "mx"], "associated_info")
                if email_public_ip is None or not network.valid_ip(email_public_ip):
                    # check if in Recon as dns record
                    email_public_ip = self.db_object.grab_column_from_single_record("Recon", ["record", "recon_type"],
                                                                                    [self.email_server, "dns"],
                                                                                    "associated_info")
                    if email_public_ip is None or not network.valid_ip(email_public_ip):
                        # check in scope domain
                        email_public_ip = self.db_object.grab_column_from_single_record("Scope", ["entry", "type"], [self.email_server, "DOMAIN"], "open_ip")
        else:
            email_public_ip, additional = dns_functions.grab_dns_record(self.email_server, True)

        if email_public_ip is not None and network.valid_ip(email_public_ip):
            for count, sdl in enumerate(spoofed_domain_list):
                self.test_num = str(self.test_num_prefix + 67) + "." + str(count)

                # create the encrypted email identification text at bottom of every email (unencrypted shows scanner IP and path of client dir being worked on so can dump results back to that same location)
                self.email_identification()
                bodytext = "This is a mail relay test " + self.test_num + ", from a spoofed internal routed address using the % hack with SMTP FROM in the from: your_username%spoofed_domain@[your_mx_public_ip] through " + self.email_server + self.test_additional_msg + ". \n\n	Please forward to " + self.forward_email_to + " prior to deleting this message.\n\n Thank you." + self.encrypted_server_info
                subject = "Testing Mail Relay " + self.test_num + " through " + self.email_server + self.test_additional_msg + ". Forward to " + self.forward_email_to + "!"
                email_from = self.client_username + '%' + sdl + '@[' + email_public_ip + ']' #self.invalid_user_name + "@" + sdl
                email_to = self.client_email #[self.client_email + '@[' + email_public_ip + ']']

                bodyhtml = "<html><body>" + bodytext.replace("\n", "<br>").replace(
                    "Please forward to " + self.forward_email_to + " prior to deleting this message",
                    "<b>Please forward to <a href='mailto:" + self.forward_email_to + "'>" + self.forward_email_to + "</a> prior to deleting this message</b>") + "</body></html>"
                bodyhtml = bodyhtml + self.test_additional_body_txt

                # Create the root message and fill in the from, to, and subject headers
                msgRoot = MIMEMultipart('related')
                msgRoot['Subject'] = subject
                msgRoot['From'] = email_from
                msgRoot['To'] = self.client_email
                if self.send_read_receipt_to is not None:
                    msgRoot['Disposition-Notification-To'] = self.send_read_receipt_to
                msgRoot.preamble = 'This is a multi-part message in MIME format.'
                # Encapsulate the plain and HTML versions of the message body in an
                # 'alternative' part, so message agents can decide which they want to display.
                msgAlternative = MIMEMultipart('alternative')
                msgRoot.attach(msgAlternative)
                msgText = MIMEText(bodytext)
                msgAlternative.attach(msgText)

                msgText = MIMEText(bodyhtml, 'html')
                msgAlternative.attach(msgText)

                self.sending_email(email_from, email_to, msgRoot.as_string(), email_filter_output, msgRoot['From'],
                                   msgRoot['To'], msgRoot['Disposition-Notification-To'], None, "", self.client_email)

    # URL Spoofing by using html <base href which prepends to all links
    def test68(self, email_filter_output):
        self.test_num = str(self.test_num_prefix + 68)

        # create the encrypted email identification text at bottom of every email (unencrypted shows scanner IP and path of client dir being worked on so can dump results back to that same location)
        self.email_identification()

        bodytext = "This is a mail relay test " + self.test_num + ", from a spoofed valid external address to an internal address through " + self.email_server + self.test_additional_msg + " with an 'baseStriker method' url with a plain text alternative email message. \n\nhttp://www.yahoo.com\n\n	Please forward to " + self.forward_email_to + " prior to deleting this message.\n\n Thank you." + self.encrypted_server_info
        subject = "Testing Mail Relay " + self.test_num + " through " + self.email_server + self.test_additional_msg + ". Forward to " + self.forward_email_to + "!"
        email_from = self.invalid_user_name + '@' + self.spoof_domains_no_spf_dmarc_dkim[0]  # self.invalid_user_name+'@'+self.spoof_domains_no_spf_dmarc_dkim[0]+' '
        email_to = [self.client_email]
        bodyhtml = "<html><head><base href='https://microsoft.com'></head><body>" + bodytext.replace("\n", "<br>").replace("http://www.yahoo.com",
                       "<a href='google.com'>google.com</a>").replace(
            "Please forward to " + self.forward_email_to + " prior to deleting this message",
            "<b>Please forward to <a href='mailto:" + self.forward_email_to + "'>" + self.forward_email_to + "</a> prior to deleting this message</b>") + "</body></html>"
        bodyhtml = bodyhtml + self.test_additional_body_txt

        # Create the root message and fill in the from, to, and subject headers
        msgRoot = MIMEMultipart('related')
        msgRoot['Subject'] = subject
        msgRoot['From'] = email_from
        msgRoot['To'] = self.client_email
        if self.send_read_receipt_to is not None:
            msgRoot['Disposition-Notification-To'] = self.send_read_receipt_to
        msgRoot.preamble = 'This is a multi-part message in MIME format.'
        # Encapsulate the plain and HTML versions of the message body in an
        # 'alternative' part, so message agents can decide which they want to display.
        msgAlternative = MIMEMultipart('alternative')
        msgRoot.attach(msgAlternative)
        msgText = MIMEText(bodytext)
        msgAlternative.attach(msgText)

        msgText = MIMEText(bodyhtml, 'html')
        msgAlternative.attach(msgText)

        self.sending_email(email_from, email_to, msgRoot.as_string(), email_filter_output, msgRoot['From'],
                           msgRoot['To'], msgRoot['Disposition-Notification-To'])

    # Spoof IP of originating email server
    def test69(self, email_filter_output):
        self.test_num = str(self.test_num_prefix + 69)

        # create the encrypted email identification text at bottom of every email (unencrypted shows scanner IP and path of client dir being worked on so can dump results back to that same location)
        self.email_identification()

        bodytext = "This is a mail relay test " + self.test_num + ", from a spoofed the Original Email Server's IP through " + self.email_server + self.test_additional_msg + " by modifying the SMTP header 'X-Originating-IP'.\n\n	Please forward to " + self.forward_email_to + " prior to deleting this message.\n\n Thank you." + self.encrypted_server_info
        subject = "Testing Mail Relay " + self.test_num + " through " + self.email_server + self.test_additional_msg + ". Forward to " + self.forward_email_to + "!"
        email_from = self.invalid_user_name + '@microsoft.com'# Use Microsoft b/c Spoofed X-Originating-IP is Microsoft's IP + self.spoof_domains_no_spf_dmarc_dkim[0]  # self.invalid_user_name+'@'+self.spoof_domains_no_spf_dmarc_dkim[0]+' '
        email_to = [self.client_email]
        bodyhtml = "<html><body>" + bodytext.replace("\n", "<br>").replace("Please forward to " + self.forward_email_to + " prior to deleting this message",
            "<b>Please forward to <a href='mailto:" + self.forward_email_to + "'>" + self.forward_email_to + "</a> prior to deleting this message</b>") + "</body></html>"
        bodyhtml = bodyhtml + self.test_additional_body_txt

        # Create the root message and fill in the from, to, and subject headers
        msgRoot = MIMEMultipart('related')
        msgRoot['Subject'] = subject
        msgRoot['From'] = email_from
        msgRoot['To'] = self.client_email
        if self.send_read_receipt_to is not None:
            msgRoot['Disposition-Notification-To'] = self.send_read_receipt_to
        msgRoot['X-Originating-IP'] = '23.103.156.74' # host microsoft-com.mail.protection.outlook.com (microsoft's mx record)
        msgRoot.preamble = 'This is a multi-part message in MIME format.'
        # Encapsulate the plain and HTML versions of the message body in an
        # 'alternative' part, so message agents can decide which they want to display.
        msgAlternative = MIMEMultipart('alternative')
        msgRoot.attach(msgAlternative)
        msgText = MIMEText(bodytext)
        msgAlternative.attach(msgText)

        msgText = MIMEText(bodyhtml, 'html')
        msgAlternative.attach(msgText)

        self.sending_email(email_from, email_to, msgRoot.as_string(), email_filter_output, msgRoot['From'],
                           msgRoot['To'], msgRoot['Disposition-Notification-To'])

    # Folding / Unfolding SMTP Headers (https://tools.ietf.org/html/rfc2822#section-2.2.3)
    def test70(self, email_filter_output):
        self.test_num = str(self.test_num_prefix + 70)

        # create the encrypted email identification text at bottom of every email (unencrypted shows scanner IP and path of client dir being worked on so can dump results back to that same location)
        self.email_identification()

        bodytext = "This is a mail relay test " + self.test_num + ", from a spoofed, valid, internal email using SMTP 'folding/unfolding' through " + self.email_server + self.test_additional_msg + ".\n\n	Please forward to " + self.forward_email_to + " prior to deleting this message.\n\n Thank you." + self.encrypted_server_info
        subject = "Testing Mail Relay " + self.test_num + " through " + self.email_server + self.test_additional_msg + ". Forward to " + self.forward_email_to + "!"
        email_from = " \r\n" + self.client_email
        email_to = [self.client_email]
        bodyhtml = "<html><body>" + bodytext.replace("\n", "<br>").replace(
            "Please forward to " + self.forward_email_to + " prior to deleting this message",
            "<b>Please forward to <a href='mailto:" + self.forward_email_to + "'>" + self.forward_email_to + "</a> prior to deleting this message</b>") + "</body></html>"
        bodyhtml = bodyhtml + self.test_additional_body_txt

        # Create the root message and fill in the from, to, and subject headers
        msgRoot = MIMEMultipart('related')
        msgRoot['Subject'] = subject
        msgRoot['From'] = email_from
        msgRoot['To'] = self.client_email
        if self.send_read_receipt_to is not None:
            msgRoot['Disposition-Notification-To'] = self.send_read_receipt_to
        msgRoot.preamble = 'This is a multi-part message in MIME format.'
        # Encapsulate the plain and HTML versions of the message body in an
        # 'alternative' part, so message agents can decide which they want to display.
        msgAlternative = MIMEMultipart('alternative')
        msgRoot.attach(msgAlternative)
        msgText = MIMEText(bodytext)
        msgAlternative.attach(msgText)

        msgText = MIMEText(bodyhtml, 'html')
        msgAlternative.attach(msgText)

        self.sending_email(email_from, email_to, msgRoot.as_string(), email_filter_output, msgRoot['From'],
                           msgRoot['To'], msgRoot['Disposition-Notification-To'])

    # SMTP From Header longer than 998 chars
    def test71(self, email_filter_output):
        self.test_num = str(self.test_num_prefix + 71)

        # create the encrypted email identification text at bottom of every email (unencrypted shows scanner IP and path of client dir being worked on so can dump results back to that same location)
        self.email_identification()

        bodytext = "This is a mail relay test " + self.test_num + ", from an extremely long SMTP From email address (longer than the max length of 998) through " + self.email_server + self.test_additional_msg + ".\n\n	Please forward to " + self.forward_email_to + " prior to deleting this message.\n\n Thank you." + self.encrypted_server_info
        subject = "Testing Mail Relay " + self.test_num + " through " + self.email_server + self.test_additional_msg + ". Forward to " + self.forward_email_to + "!"
        email_from = self.client_username+''.join(random.choices(string.ascii_uppercase, k=999)) + '@' + self.domain
        email_to = [self.client_email]
        bodyhtml = "<html><body>" + bodytext.replace("\n", "<br>").replace(
            "Please forward to " + self.forward_email_to + " prior to deleting this message",
            "<b>Please forward to <a href='mailto:" + self.forward_email_to + "'>" + self.forward_email_to + "</a> prior to deleting this message</b>") + "</body></html>"
        bodyhtml = bodyhtml + self.test_additional_body_txt

        # Create the root message and fill in the from, to, and subject headers
        msgRoot = MIMEMultipart('related')
        msgRoot['Subject'] = subject
        msgRoot['From'] = email_from
        msgRoot['To'] = self.client_email
        if self.send_read_receipt_to is not None:
            msgRoot['Disposition-Notification-To'] = self.send_read_receipt_to
        msgRoot.preamble = 'This is a multi-part message in MIME format.'
        # Encapsulate the plain and HTML versions of the message body in an
        # 'alternative' part, so message agents can decide which they want to display.
        msgAlternative = MIMEMultipart('alternative')
        msgRoot.attach(msgAlternative)
        msgText = MIMEText(bodytext)
        msgAlternative.attach(msgText)

        msgText = MIMEText(bodyhtml, 'html')
        msgAlternative.attach(msgText)

        self.sending_email(email_from, email_to, msgRoot.as_string(), email_filter_output, msgRoot['From'],
                           msgRoot['To'], msgRoot['Disposition-Notification-To'])

    # Base64 encode display name portion that can proceed email address (and put title, etc to make it long and block out the real email address when displayed in Outlook)
    def test72(self, email_filter_output):
        try:
            self.test_num = str(self.test_num_prefix + 72)

            # create the encrypted email identification text at bottom of every email (unencrypted shows scanner IP and path of client dir being worked on so can dump results back to that same location)
            self.email_identification()

            bodytext = "This is a mail relay test " + self.test_num + ", from a spoofed internal address, display name portion, that is base64 encoded and contains an external email address not base64 encoded (modified shadow attack) through " + self.email_server + self.test_additional_msg + ". \n\n	Please forward to " + self.forward_email_to + " prior to deleting this message.\n\n Thank you." + self.encrypted_server_info
            subject = "Testing Mail Relay " + self.test_num + " through " + self.email_server + self.test_additional_msg + ". Forward to " + self.forward_email_to + "!"
            email_from = "=?UTF-8?B?" + base64.b64encode(self.client_username.encode('utf-8') + " - Chief Information Officer - Certified Managerial Board Member".encode('utf-8') + "?= <".encode('utf-8')+self.invalid_user_name.encode('utf-8') + "@".encode('utf-8') + self.spoof_domains_no_spf_dmarc_dkim[0].encode('utf-8') + ">".encode('utf-8')).decode('utf-8')
            email_to = [self.client_email]
            bodyhtml = "<html><body>" + bodytext.replace("\n", "<br>").replace(
                "Please forward to " + self.forward_email_to + " prior to deleting this message",
                "<b>Please forward to <a href='mailto:" + self.forward_email_to + "'>" + self.forward_email_to + "</a> prior to deleting this message</b>") + "</body></html>"
            bodyhtml = bodyhtml + self.test_additional_body_txt

            # Create the root message and fill in the from, to, and subject headers
            msgRoot = MIMEMultipart('related')
            msgRoot['Subject'] = subject
            msgRoot['From'] = email_from
            msgRoot['To'] = self.client_email
            if self.send_read_receipt_to is not None:
                msgRoot['Disposition-Notification-To'] = self.send_read_receipt_to
            msgRoot.preamble = 'This is a multi-part message in MIME format.'
            # Encapsulate the plain and HTML versions of the message body in an
            # 'alternative' part, so message agents can decide which they want to display.
            msgAlternative = MIMEMultipart('alternative')
            msgRoot.attach(msgAlternative)
            msgText = MIMEText(bodytext)
            msgAlternative.attach(msgText)

            msgText = MIMEText(bodyhtml, 'html')
            msgAlternative.attach(msgText)

            self.sending_email(email_from, email_to, msgRoot.as_string(), email_filter_output, msgRoot['From'],
                               msgRoot['To'], msgRoot['Disposition-Notification-To'])
        except Exception as e:
            print("email filter class 3575 except: " + str(e) + " Error on line {}".format(sys.exc_info()[-1].tb_lineno))


    # quoting valid internal at beginning as alias than putting valid external behind
    def test73(self, email_filter_output):
        if domain_to_use is None:
            domain_to_use = self.spoof_domains_no_spf_dmarc_dkim

        valid_external = ""
        for sdnsdd in domain_to_use:
            valid_external = self.invalid_user_name + '@' + sdnsdd
            break

        self.test_num = str(self.test_num_prefix + 73)

        # create the encrypted email identification text at bottom of every email (unencrypted shows scanner IP and path of client dir being worked on so can dump results back to that same location)
        self.email_identification()

        bodytext = "This is a mail relay test " + self.test_num + ", from a spoofed internal address within quotes followed by a valid, external email address through " + self.email_server + self.test_additional_msg + ". \n\n	Please forward to " + self.forward_email_to + " prior to deleting this message.\n\n Thank you." + self.encrypted_server_info
        subject = "Testing Mail Relay " + self.test_num + " through " + self.email_server + self.test_additional_msg + ". Forward to " + self.forward_email_to + "!"
        email_from = '"' + self.client_email + '"'
        email_to = [self.client_email]
        bodyhtml = "<html><body>" + bodytext.replace("\n", "<br>").replace(
            "Please forward to " + self.forward_email_to + " prior to deleting this message",
            "<b>Please forward to <a href='mailto:" + self.forward_email_to + "'>" + self.forward_email_to + "</a> prior to deleting this message</b>") + "</body></html>"
        bodyhtml = bodyhtml + self.test_additional_body_txt

        # Create the root message and fill in the from, to, and subject headers
        msgRoot = MIMEMultipart('related')
        msgRoot['Subject'] = subject
        msgRoot['From'] = email_from
        msgRoot['To'] = '"' + self.client_username + '<' + self.client_email + '>"' + valid_external
        if self.send_read_receipt_to is not None:
            msgRoot['Disposition-Notification-To'] = self.send_read_receipt_to
        msgRoot.preamble = 'This is a multi-part message in MIME format.'
        # Encapsulate the plain and HTML versions of the message body in an
        # 'alternative' part, so message agents can decide which they want to display.
        msgAlternative = MIMEMultipart('alternative')
        msgRoot.attach(msgAlternative)
        msgText = MIMEText(bodytext)
        msgAlternative.attach(msgText)

        msgText = MIMEText(bodyhtml, 'html')
        msgAlternative.attach(msgText)

        self.sending_email(email_from, email_to, msgRoot.as_string(), email_filter_output, msgRoot['From'],
                           msgRoot['To'], msgRoot['Disposition-Notification-To'], None, "", self.client_email)


    # quoting valid internal at beginning as alias than putting valid external behind
    def test74(self, email_filter_output):
        if domain_to_use is None:
            domain_to_use = self.spoof_domains_no_spf_dmarc_dkim

        valid_external = ""
        for sdnsdd in domain_to_use:
            valid_external = self.invalid_user_name + '@' + sdnsdd
            break

        self.test_num = str(self.test_num_prefix + 74)

        # create the encrypted email identification text at bottom of every email (unencrypted shows scanner IP and path of client dir being worked on so can dump results back to that same location)
        self.email_identification()

        bodytext = "This is a mail relay test " + self.test_num + ", from a spoofed internal address within quotes followed by a valid, external email address through " + self.email_server + self.test_additional_msg + ". \n\n	Please forward to " + self.forward_email_to + " prior to deleting this message.\n\n Thank you." + self.encrypted_server_info
        subject = "Testing Mail Relay " + self.test_num + " through " + self.email_server + self.test_additional_msg + ". Forward to " + self.forward_email_to + "!"
        email_from = '"' + self.client_username + '<' + self.client_email + '>"' + valid_external
        email_to = [self.client_email]
        bodyhtml = "<html><body>" + bodytext.replace("\n", "<br>").replace(
            "Please forward to " + self.forward_email_to + " prior to deleting this message",
            "<b>Please forward to <a href='mailto:" + self.forward_email_to + "'>" + self.forward_email_to + "</a> prior to deleting this message</b>") + "</body></html>"
        bodyhtml = bodyhtml + self.test_additional_body_txt

        # Create the root message and fill in the from, to, and subject headers
        msgRoot = MIMEMultipart('related')
        msgRoot['Subject'] = subject
        msgRoot['From'] = email_from
        msgRoot['To'] = '"' + self.client_username + '<' + self.client_email + '>"' + valid_external
        if self.send_read_receipt_to is not None:
            msgRoot['Disposition-Notification-To'] = self.send_read_receipt_to
        msgRoot.preamble = 'This is a multi-part message in MIME format.'
        # Encapsulate the plain and HTML versions of the message body in an
        # 'alternative' part, so message agents can decide which they want to display.
        msgAlternative = MIMEMultipart('alternative')
        msgRoot.attach(msgAlternative)
        msgText = MIMEText(bodytext)
        msgAlternative.attach(msgText)

        msgText = MIMEText(bodyhtml, 'html')
        msgAlternative.attach(msgText)

        self.sending_email(email_from, email_to, msgRoot.as_string(), email_filter_output, msgRoot['From'],
                           msgRoot['To'], msgRoot['Disposition-Notification-To'], None, "", self.client_email)