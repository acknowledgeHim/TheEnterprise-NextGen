import sys
import smtplib
import time
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from email.mime.image import MIMEImage
from email.mime.base import MIMEBase
from email.utils import COMMASPACE, formatdate, make_msgid
from email import encoders
import xml.etree.ElementTree as ET
from datetime import datetime
import os
import re
import base64
from common import common, print_text
from enterprise_user_conf import SMTP_EHLO_SERVER

def generate(smtp_to, scenario, db_object):
    """ Actually generate phishing email. """
    try:
        engagement_info = db_object.get("Engagement", ["id"], [1], True)
        body = scenario.body
        signature = scenario.signature

        if "PHISHING_URL" in body:
            phish_url = scenario.phish_url.replace("'>", "/?id=" + base64.b64encode(smtp_to.encode("utf-8")).decode("utf-8") + "'>")
            body = body.replace("PHISHING_URL", phish_url)
        if "REPLACE_CURRENT_DATE" in body:
            body = body.replace("REPLACE_CURRENT_DATE", str(datetime.now()))
        if "CLIENTNAME" in body:
            body = body.replace("CLIENTNAME", engagement_info.client_name)

        if "SIGNATURE" in body:
            body = body.replace("SIGNATURE", signature)
        else:
            body = body + "<p>" + signature
        body = body.replace("\n", "<br>")

        msgRoot = MIMEMultipart('related')

        # Set optional Priority of the Email
        if scenario.priority:
            msgRoot['X-Priority'] = '1'
            msgRoot['X-MSMail-Priority'] = "High"
            msgRoot['Importance'] = "High"
        # Set optional Read Receipt
        if scenario.read_receipt_to is not None and "@" in scenario.read_receipt_to:
            msgRoot['Disposition-Notification-To'] = scenario.read_receipt_to
        # Set optional by way of
        if scenario.by_way_of is not None and "@" in scenario.by_way_of:
            msgRoot['Resent-From'] = scenario.by_way_of
        # Set optional on behalf of
        if scenario.on_behalf_of is not None and "@" in scenario.on_behalf_of:
            msgRoot['Sender'] = scenario.on_behalf_of

        msgRoot['Subject'] = scenario.subject
        msgRoot['From'] = scenario.data_from
        msgRoot['To'] = smtp_to
        msgRoot['Date'] = formatdate(localtime=True)
        msgRoot['Message-Id'] = make_msgid()
        msgRoot.preamble = 'This is a multi-part message in MIME format.'

        inline_image_path = scenario.inline_image_path

        # Find all CIDS in body to then correctly attach the images inline
        matches = common.all_regex_matches(body, r"(src='cid:[0-9a-zA-Z_.]+)") #r"(src='cid:)[0-9a-zA-Z_.]+")
        if matches is not None:
            for match in matches:
                cid = match.replace("src='cid:", "")
                f = None
                if os.path.isfile(inline_image_path + "/" + cid):
                    f = inline_image_path + "/" + cid
                elif os.path.isfile(os.getcwd() + "/tools/attack/phishing_scenarios/" + cid):
                    f = os.getcwd() + "/tools/attack/phishing_scenarios/" + cid
                elif os.path.isfile(cid):
                    f = cid
                if f is not None:
                    fp = open(f, "rb")
                    part = MIMEImage(fp.read())
                    fp.close()

                    real_cid = cid
                    if "/" in cid: #that way as part of signature or whatever you can specify a full page to an image and have it inline attached properly
                        real_cid = cid[cid.rfind("/")+1:]
                        body = body.replace(cid, real_cid)

                    part.add_header('Content-ID', '<' + real_cid + '>')
                    msgRoot.attach(part)
                else:
                    print_text.print_error("\tCould not locate the inline image using the inline image path specified as"
                                           " part of the Phishing Scenario.  Please update the inline image path so that"
                                           " it contains an entry that points to the directory where your missing inline"
                                           " image is - could not locate: " + cid)

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

        attachment = scenario.attachment
        if attachment is not None and attachment != "":
            if "," in attachment:
                attachments = attachment.split(",")
                for a in attachments:
                    part = MIMEBase('application', "octet-stream")
                    part.set_payload(open(a, "rb").read())
                    part.add_header('Content-Disposition', 'attachment; filename="' + a[a.rfind("/") + 1:] + '"')
                    encoders.encode_base64(part)
                    msgRoot.attach(part)
            else:
                part = MIMEBase('application', "octet-stream")
                part.set_payload(open(attachment, "rb").read())
                part.add_header('Content-Disposition', 'attachment; filename="'+attachment[attachment.rfind("/") + 1:]+'"')
                encoders.encode_base64(part)
                msgRoot.attach(part)

        msgRoot = msgRoot.as_string()
        message_for_log = msgRoot
        message_for_log = message_for_log.replace("\n","<br>").replace("\t", " ").replace('"', "'")
        # Strip out images that are base64 encoded - don't want those stored in DB!
        while "Content-Transfer-Encoding: base64" in message_for_log:
            tmp_before = message_for_log[:message_for_log.find("Content-Transfer-Encoding: base64")]
            tmp = message_for_log[message_for_log.find("Content-Transfer-Encoding: base64") + 33:]
            tmp_after = tmp[tmp.find("--===============") + 17:]
            message_for_log = tmp_before + " ATTACHMENT/IMGAGE REMOVED " + tmp_after

        return msgRoot, message_for_log
    except Exception as e:
        print_text.print_error("generate phishing email except: " + str(e) + " Error on line {}".format(sys.exc_info()[-1].tb_lineno))


# send out the email
def sending_email(email_server, email_port, email_from, email_to, message, message_for_log, phishing_output, data_from, data_to, scenario, read_receipt_to, target=None, counter450=0):
    """ Target will be the email server sent unless one of your Bounce off servers, then it will default to an MX
    record, since the email after the bounce will go that route.
    """
    try:
        start_time = datetime.fromtimestamp(time.time()).strftime('%Y-%m-%d %H:%M:%S')

        if target is None:
            target = email_server

        if email_port == "465":  # then use SMTP_SSL
            try:
                smtp = smtplib.SMTP_SSL(email_server, int(email_port))
                smtp.ehlo(SMTP_EHLO_SERVER)
                smtp.sendmail(email_from, email_to, message)
                smtp.quit()
                print_text.print_msg("Successfully sent Phishing Email to " + email_to[0] + " using " + email_server + ".")
                phishing_output.write(start_time + "~~~" + target + "~~~" + str(email_port) + "~~~" + scenario + "~~~" + email_from + "~~~" + email_to[0] + "~~~" + data_from + "~~~" + message_for_log + "~~~Successfully sent.~~~ENDOFLINE~~~\n")
            except Exception as e:
                print_text.print_error("Error: unable to send Phishing Email to " + email_to[0] + " using " + email_server + ". " + str(e) + " Error on line {}".format(sys.exc_info()[-1].tb_lineno))
                phishing_output.write(start_time + "~~~" + target + "~~~" + str(email_port) + "~~~" + scenario + "~~~" + email_from + "~~~" + email_to[0] + "~~~" + data_from + "~~~" + message_for_log + "~~~Failed to send. " + str(e) + "~~~ENDOFLINE~~~\n")
                # try to resend the email after waiting 15 seconds
                if "450" in str(e) and counter450 > 3:
                    time.sleep(15)
                    counter450 += 1
                    sending_email(email_server, email_port, email_from, email_to, message, phishing_output, data_from, data_to, scenario, read_receipt_to, target, counter450)
        else:
            try:
                smtp = smtplib.SMTP(email_server, int(email_port))
                smtp.ehlo(SMTP_EHLO_SERVER)
                smtp.sendmail(email_from, email_to, message)
                print_text.print_msg("Successfully sent Phishing Email to " + email_to[0] + " using " + email_server + ".")
                smtp.quit()
                phishing_output.write(start_time + "~~~" + target + "~~~" + str(email_port) + "~~~" + scenario + "~~~" + email_from + "~~~" + email_to[0] + "~~~" + data_from + "~~~" + message_for_log + "~~~Successfully sent.~~~ENDOFLINE~~~\n")
            except Exception as e:
                print_text.print_error("Error: unable to send Phishing Email to " + email_to[0] + " using " + email_server + ". " + str(e) + " Error on line {}".format(sys.exc_info()[-1].tb_lineno))
                phishing_output.write(start_time + "~~~" + target + "~~~" + str(email_port) + "~~~" + scenario + "~~~" + email_from + "~~~" + email_to[0] + "~~~" + data_from + "~~~" + message_for_log + "~~~Failed to send. " + str(e) + "~~~ENDOFLINE~~~\n")
                # try to resend the email after waiting 15 seconds
                if "450" in str(e) and counter450 > 3:
                    time.sleep(15)
                    counter450 += 1
                    sending_email(email_server, email_port, email_from, email_to, message, phishing_output, data_from, data_to, scenario, read_receipt_to, target, counter450)
    except Exception as e:
        print("generate phishing email 138 except: " + str(e) + " Error on line {}".format(sys.exc_info()[-1].tb_lineno))