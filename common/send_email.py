import re
import smtplib
import sys
import time
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from email.utils import formatdate, make_msgid

from common import common, print_text, database_object
from enterprise_user_conf import SMTP_EHLO_SERVER, EMAIL_SERVER, EMAIL_ADDRESS, YOUR_DOMAIN
from enterprise_conf import HASH_KEY
from setup import install_helper


def sending_email(email_server, smtp_ehlo_server, email_port, email_from, email_to, message, counter450=0):
    try:
        while counter450 < 3:
            try:
                smtp = smtplib.SMTP(email_server, int(email_port))
                smtp.ehlo(smtp_ehlo_server)
                smtp.sendmail(email_from, email_to, message)
                #print_text.print_msg("Successfully sent email to " + email_to[0] + " using " + email_server + ".")
                smtp.quit()
                counter450 = 3
            except Exception as e:
                print_text.print_error("Error: unable to send email to " + email_to[0] + " using " + email_server + ". " + str(e) + " Error on line {}".format(sys.exc_info()[-1].tb_lineno))
                # try to resend the email after waiting 15 seconds
                time.sleep(15)
                counter450 += 1
    except Exception as e:
        print("generate phishing email 138 except: " + str(e) + " Error on line {}".format(sys.exc_info()[-1].tb_lineno))

def replace_engagement_specific_text(engagement_info, log_info, text, service=None):
    """ Replace placeholder words in text. """

    if "CLIENTNAME" in text:
        text = text.replace("CLIENTNAME", engagement_info['client_name'])
    if "DOMAINNAME" in text:
        text = text.replace("DOMAINNAME", log_info['target'])
    if "EMAIL_ADDRESS" in text:
        text = text.replace("EMAIL_ADDRESS", EMAIL_ADDRESS)
    #if "EMAIL_MSG_WHERE_TO_FORWARD_BACK_TO" in text:
    #    text = text.replace("EMAIL_MSG_WHERE_TO_FORWARD_BACK_TO", EMAIL_MSG_WHERE_TO_FORWARD_BACK_TO)
    if "ENGAGEMENT" in text:
        text = text.replace("ENGAGEMENT", str(engagement_info['engagement_number']))
    if "SCENARIONAME" in text:
        text = text.replace("SCENARIONAME", log_info['target'])
    if "SERVICE" in text and service is not None:
        text = text.replace("SERVICE", service.upper())
    if "START_DATE" in text:
        text = text.replace("START_DATE", str(engagement_info['start_date']))
    if "TARGET" in text:
        text = text.replace("TARGET", log_info['target'])
    if "TOOLNAME" in text:
        text = text.replace("TOOLNAME", log_info['source'])
    if "SCOPEENTRY" in text:
        text = text.replace("SCOPEENTRY", log_info['entry'])

    return text

def generate_message(db_object, log_id, smtp_to, subject, message, service=None, replace_text=False):
    """ Actually generate notification email, but not send. """
    try:
        smtp_from = EMAIL_ADDRESS

        body = message
        body = body.replace("\n", "<br>")

        if replace_text:
            engagement_info = db_object.get("Engagement", ["id"], [1], True)
            log_info = db_object.join_view("Log", ["Scope.name"], None, ["id"], [log_id], True)
            if log_info is not None:
                log_info = log_info[0] # Should return 1 record that is a dictionary in list by itself
                subject = replace_engagement_specific_text(engagement_info, log_info, subject, service)
                body = replace_engagement_specific_text(engagement_info, log_info, body, service)

        msgRoot = MIMEMultipart('related')

        msgRoot['Subject'] = subject
        msgRoot['From'] = smtp_from
        msgRoot['To'] = smtp_to
        msgRoot['Date'] = formatdate(localtime=True)
        msgRoot['Message-Id'] = make_msgid()
        msgRoot.preamble = 'This is a multi-part message in MIME format.'

        tag_re = re.compile(r'<[^>]+>')
        body_text = body.replace("<br>", "\n")
        body_text = body_text.replace("<p>", "\n\n")
        body_text = tag_re.sub('', body_text)

        # Encapsulate the plain and HTML versions of the message body in an
        # 'alternative' part, so message agents can decide which they want to display.
        msgAlternative = MIMEMultipart('alternative')
        msgRoot.attach(msgAlternative)
        msgText = MIMEText(body_text)
        msgAlternative.attach(msgText)

        msgText = MIMEText(body, 'html')
        msgAlternative.attach(msgText)

        return msgRoot.as_string()

    except Exception as e:
        print_text.print_error("generate email except: " + str(e) + " Error on line {}".format(sys.exc_info()[-1].tb_lineno))


def email_notification(db_object, key, tool, log_id, start_or_end):
    try:
        engagement_info = db_object.get("Engagement", ["id"], [1], False)
        if key.strip() == "":
            key = HASH_KEY

        email_db_object = database_object.OurCoolDBObject('setup/email_event.db', 'common.email_db_model')
        queryset_dict = email_db_object.view("EmailEvent", None, ["event", "start_or_end"], [tool, start_or_end])

        service = None
        event = tool
        if "metasploit" in tool:
            if "bruteforce" in tool:
                event = "bruteforce"
                service = tool.replace("metasploit ", "").replace("bruteforce", "").replace("-", "")
            elif "enumeration" in tool:
                event = tool
                service = tool.replace("metasploit ", "")

        subject = ""
        tester_message = ""
        client_message = ""
        corp_message = ""

        if queryset_dict is not None:
            for query in queryset_dict:
                if query['event'] == event:
                    subject = query['subject']
                    tester_message = query['tester_msg']
                    client_message = query['client_msg']
                    corp_message = query['corp_msg']
                    event_found = True
                    break
        else:
            # add a blank email event for event + start_or_end that is not in DB
            email_event = {'event': event,
                            'tester_msg': '',
                            'client_msg': '',
                            'corp_msg': '',
                            'subject': event,
                            'start_or_end': start_or_end}
            added = install_helper.add_email_event(key, email_event)

        if tester_message is not None and tester_message.strip() != "":
            tester_email = common.get_tester() + "@" + YOUR_DOMAIN
            tester_message = generate_message(db_object, log_id, tester_email, subject, tester_message,
                                                         service, True)
            sending_email(EMAIL_SERVER, SMTP_EHLO_SERVER, "25", EMAIL_ADDRESS, [tester_email],
                                     tester_message)
        if client_message is not None and client_message.strip() != "" and engagement_info['email_client_contact']:
            client_notification_emails_to = db_object.grab_client_contacts_to_send_notification()
            if client_notification_emails_to is not None:
                for client_email in client_notification_emails_to:
                    client_message = generate_message(db_object, log_id, client_email, subject,
                                                                 client_message, service, True)
                    sending_email(EMAIL_SERVER, SMTP_EHLO_SERVER, "25", EMAIL_ADDRESS, [client_email],
                                             client_message)
        if corp_message is not None and corp_message.strip() != "" and engagement_info['email_company_contact']:
            corp_notification_emails_to = db_object.grab_corp_contacts_to_send_notification()
            if corp_notification_emails_to is not None:
                for staff_email in corp_notification_emails_to:
                    corp_message = generate_message(db_object, log_id, staff_email, subject,
                                                               corp_message, service, True)
                    sending_email(EMAIL_SERVER, SMTP_EHLO_SERVER, "25", EMAIL_ADDRESS, [staff_email],
                                                 corp_message)
    except Exception as e:
        print_text.print_error("send_email except: " + str(e) + " Error on line {}".format(sys.exc_info()[-1].tb_lineno))