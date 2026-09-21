import re
import os
import sys
import datetime
from common import keep_tags, network, print_text
from parsers import models_to_dictionary
from parsers. parser import Parser

def email_filter(db_path, db_object, key, hashvals):
    """
    Loop thru hashvals, verify blacklist status, update Log, send to Parser, then finally email notifications out.
    :param db_path:
    :param db_object:
    :param hashvals:
    :return:
    """
    try:
        with Parser("email filter", db_object, key, hashvals, False) as p:
            p.parse("parsers.vuln.email_filter_parser", "EmailFilterParser")

    except Exception as e:
        print("email filter parser 23 except: " + str(e) + " Error on line {}".format(sys.exc_info()[-1].tb_lineno))


def test_info(test_num):
    test_num = float(test_num)
    title = ""
    description = ""
    severity = ""
    remediation = ""
    if test_num == 0:
        title = "Valid email (Test0)"
        description = "This email is a valid email and should not have been blocked."
        severity = "info"
        remediation = "None necessary."
    elif test_num == 1:
        title = "Open Relay from anyone to anyone (Test1)"
        description = "Open relays allow anyone to send email using this email server to anyone.  Typically, the " \
                      "ISP will block this email server if this configuration continues."
        severity = "critical"
        remediation = "Create a filter to only allow your valid email servers to send email to external email addresses."
    elif test_num == 2:
        title = "Open Relay from your domain to anyone (Test2)"
        description = "Partially open relays, in this case, allowing anyone to send an email using this email server " \
                      "to anyone in the world as if they are from your domain."
        severity = "critical"
        remediation = "Create a filter to only allow your valid email servers to send email to external email addresses including emails where the SMTP FROM is an internal address."
    elif test_num == 3:
        title = "Relay from spoofed valid internal email to another valid internal email (Test3)"
        description = "This email server allows anyone to send emails as if they are from a valid internal address to" \
                      " a valid internal address."
        severity = "critical"
        remediation = "Create a filter to only allow your email servers to send email from yourself to yourself."
    elif test_num == 4:
        title = "Relay from an invalid internal email to a valid internal email (Test4)"
        description = "This email server allows anyone to send emails from an invalid user @ your domain to a " \
                      "valid internal user."
        severity = "critical"
        remediation = "Create a filter to only allow your email servers to send email from yourself to yourself.  " \
                      "Additionally, create a filter that validates if the sender user exists locally."
    elif test_num == 5:
        title = "Invalid top-level domain portion in the email from (SMTP FROM) (Test5)"
        description = "This email server accepts emails from an email address that have an invalid top-level domain."
        severity = "high"
        remediation = "Create a filter to block domains that are not valid (not registered), do not have a MX " \
                      "record, or from a domain that is a hard to distinguish, 'one-off' domain in the top-level " \
                      "domain portion.  For example, instead of mydomain.com the domain is mydomain.c0m."
    elif test_num >= 6 and test_num < 7 :
        title = "Invalid domain portion in the email from (SMTP FROM) (Test6)"
        description = "This email server accepts emails from an email address that have an invalid, unregistered domain."
        severity = "high"
        remediation = "Create a filter to block domains that are not valid (not registered), do not have a MX " \
                      "record, or from a domain that is a hard to distinguish, 'one-off' domain.  For example, " \
                      "instead of mydomain.com the domain is myd0main.com."
    elif test_num == 7:
        title = "No top-level domain specified in the email from (SMTP FROM) (Test7)"
        description = "This email server accepts emails from an email address without a top-level domain."
        severity = "high"
        remediation = "Create a filter to block emails that do not have a valid domain, in this instance, ones that " \
                      "are missing the top-level domain portion."
    elif test_num == 8:
        title = "No domain and no top-level domain specified in the email from (SMTP FROM) (Test8)"
        description = "This email server accepts emails from an email address with only the username portion of the email address."
        severity = "high"
        remediation = "Create a filter to block emails that do not have a domain portion of the email."
    elif test_num >= 9 and test_num < 10:
        title = "Email from (SMTP FROM) a valid, registered domain but does not contain an SPF record (Test9)"
        description = "This email server accepts spoofed emails from an email address whose domain does not have a valid SPF record."
        severity = "medium"
        remediation = "Create a filter to block emails that a reverse DNS lookup does not match.  This could " \
                      "potentially block legitimate traffic."
    elif test_num == 10:
        title = "URL spoofing from an external email (Test10)"
        description = "This email server accepts emails that contain spoofed URLs or HTML links, meaning that the " \
                      "link text that is displayed is not actually where the link goes and additionally, the email " \
                      "message did not have the RFC-compliant, plain-text version of the message body."
        severity = "high"
        remediation = "Create a filter to either rewrite all URLs in a message to display the actual link address " \
                      "and/or prepend a warning at the top of the message warning the user that links are not going " \
                      "where it appears.  A filter can also be created based on the if an HTML formatted message does " \
                      "not contain a plain-text alternative version of the message."
    elif test_num == 11:
        title = "Message (DATA) FROM is valid internal email while SMTP header FROM is an external email (Test11)"
        description = "This email server accepts emails where the SMTP header FROM email address is different than " \
                      "the FROM address in the message (DATA)."
        severity = "critical"
        remediation = "Create a filter that validates the FROM within the message body is the same as the address in " \
                      "the SMTP FROM header and either block it, rewrite the message FROM, and/or warn the user " \
                      "with a message."
    elif test_num == 12:
        title = "Email message with an exe attachment (Test12)"
        description = "This email server accepts emails with .exe attachments which are executable files which can " \
                      "be used to run malicious code."
        severity = "critical"
        remediation = "Create a filter to block .exe attachments.  Ensure that the filter does not simply check " \
                      "extension names but inspects a files headers to determine the actual file type."
    elif test_num == 13:
        title = "Email message with a zip attachment that contains an exe (Test13)"
        description = "This email server accepts emails with zip-ed attachments containing an .exe file."
        severity = "critical"
        remediation = "Create a filter that either blocks zip attachments or inspects the contents of zipped " \
                      "attachments to verify contents are not file types that should be blocked."
    elif test_num == 14:
        title = "Email message with anti-virus test file 'EICAR' attachment (Test14)"
        description = "This email server accepts emails with the test EICAR attachment used to ensure the anti-virus " \
                      "is checking emails.  This email should have been caught and blocked (at least the attachment " \
                      "should have been stripped) by the anti-virus."
        severity = "critical"
        remediation = "Make sure your anti-virus is inspecting all email messages that traverse your network."
    elif test_num == 15:
        title = "Email message with zip attachment that contains anti-virus test file 'EICAR' (Test15)"
        description = "This email server accepts emails with zip-ed attachments that contain the EICAR file that the" \
                      " anti-virus should have blocked or stripped out."
        severity = "critical"
        remediation = "Make sure your anti-virus is able to inspect the contents of zipped files within email attachments."
    elif test_num == 16:
        title = "Email message with a multiple layered, zip attachment that contains  the anti-virus test file 'EICAR' (Test16)"
        description = "This email server accepts emails with multiple layered, zip-ed attachments that contain the " \
                      "EICAR file that the anti-virus should have blocked or stripped out."
        severity = "critical"
        remediation = "Ensure that your email filters can inspect multiple layers of compressed file attachments."
    elif test_num == 17:
        title = "Email from a domain that has a valid 'HardFail' SPF entry (Test17)"
        severity = "critical"
        remediation = "Create a filter that blocks emails that fail an SPF check from domains that have a 'HardFail'."
    elif test_num == 18:
        title = "Email message with a gadget attachment (Test18)"
        description = "This email server accepts emails with a .gadget attachment.  .gadget attachments are " \
                      "executable files and can be used to run malicious code.  Microsoft only supported .gadget " \
                      "file execution on early Windows Vista machines."
        severity = "critical"
        remediation = "Create a filter to block .gadget attachments."
    elif test_num == 19:
        title = "Email message with a bat attachment (Test19)"
        description = "This email server accepts emails with a .bat attachment.  .bat attachments are scriptable " \
                      "files which can run other files and/or execute malicious code."
        severity = "critical"
        remediation = "Create a filter to block .bat attachments."
    elif test_num == 20:
        title = "URL spoofing identical with plain-text alternative (Test20)"
        description = "This email server accepts emails that contain spoofed URLs or HTML links, meaning that the " \
                      "link text that is displayed is not actually where the link goes."
        severity = "high"
        remediation = "Create a filter to either rewrite all URLs in a message to display the actual link address " \
                      "and/or prepend a warning at the top of the message warning the user that links are not going " \
                      "where it appears."
    elif test_num == 21:
        title = "External content in the email message (Test21)"
        description = "This email server accepts emails that contain external content.  Although, several client " \
                      "email applications (like Microsoft Outlook) provide a warning message before pulling the" \
                      " message, the necessity of allowing such messages through the filters should be examined to " \
                      "provide added protections."
        severity = "low"
        remediation = "Create a filter to either block emails that contain external content or strip out the " \
                      "external content."
    elif test_num == 22:
        title = "Email message with an hta attachment (Test22)"
        description = "This email server accepts emails with a .hta attachment.  .hta attachments are scriptable " \
                      "files which can run other files and/or execute malicious code."
        severity = "critical"
        remediation = "Create a filter to block .hta attachments."
    elif test_num == 23:
        title = "Email message with a Microsoft Office document that contained a macro (Test23)"
        description = "This email server accepts emails that have an Microsoft Office document that contained a " \
                      "macro.  Macros can contain malicious code."
        severity = "critical"
        remediation = "Create a filter to block Office documents that have macros or strip out the macro."
    elif test_num == 24:
        title = "Email from (SMTP FROM) a domain that has 'SoftFail' SPF entry (Test24)"
        description = "This email server accepts emails that are spoofed from a domain that has a valid SPF record " \
                      "but uses the 'SoftFail' to end the SPF record.  'SoftFail' should only be used during the " \
                      "initial configuration and testing of SPF for a domain.  Since, blocking these 'SoftFail' SPF " \
                      "records could drop potentially valid emails, two courses of actions should be pursued.  First " \
                      "validate that your clients and vendors, specifically ones where email communication is " \
                      "frequent.  Second, if you have confirmed that you do not want to block these emails or put " \
                      "them in a junk folder, at the very least, prepend a warning message for the recipient if the " \
                      "message only passes SPF because of the 'SoftFail'."
        severity = "high"
        remediation = "Create a filter that either blocks emails that fail an SPF check from domains that have a " \
                      "'SoftFail' or prepend a warning message."
    elif test_num == 25:
        title = "Email from (SMTP FORM) is different than read receipt To (NOTIFICATION TO) (Test25)"
        description = "This email server accepts emails that have a 'read receipt' (SMTP header Notification-To) " \
                      "that is different than the SMTP header FROM.  This technique can be used by an attacker to " \
                      "detect emails that are valid.  Several email clients do not accurately identify the email " \
                      "address where the read receipt is being sent."
        severity = "critical"
        remediation = "Create a filter to either block emails that have a 'read receipt' going to a different address" \
                      " than the FROM in the SMTP header. or prepend a warning message."
    elif test_num == 26:
        title = "Email from (SMTP FROM) and read receipt to (NOTIFICATION TO) are the same but different than message from (DATA FROM) (Test26)"
        description = "This email server accepts emails that have a 'read receipt' (SMTP header Notification-To) " \
                      "that is different than the message (DATA) From but is the same as the SMTP header From."
        severity = "critical"
        remediation = "Create a filter to either block emails that have a 'read receipt' going to a different address" \
                      " than than the message (DATA FROM)"
    elif test_num == 27:
        title = "Email from (SMTP FROM) a valid external address but the message from (DATA FROM) is from a domain " \
                "that has a 'HardFail' SPF entry (Test27)"
        description = "This email server accepts emails where the SMTP header From is from an external domain that " \
                      "does not have an SPF record and the message (DATA) From is from an external domain that has a " \
                      "'HardFail' SPF entry.  This can allow an attacker to spoof their identify and appear from a " \
                      "legitimate source (ie. vendor or client)."
        severity = "critical"
        remediation = "Create a filter that validates the FROM within the message body is the same as the address in " \
                      "the SMTP FROM header and either block it, rewrite the message FROM, and/or warns the user " \
                      "with a message.  Also create a filter that blocks emails that fail an SPF check from domains " \
                      "that have a 'HardFail' from both the SMTP FROM header and the message (DATA) FROM."
    elif test_num == 28:
        title = "Base64 encoded SMTP header FROM username with a null domain (Test28)"
        description = "This email server accepts emails where the SMTP header From is an internal email address " \
                      "that is base64 encoded and the message (DATA) From is the plain-text internal email address.  " \
                      "This technique can be used by an attacker to bypass email filters that do not properly decode " \
                      "base64 encoded email addresses to determine the actual plain-text email address that should be " \
                      "filter on."
        severity = "critical"
        remediation = "Create a filter that can decoded base64 address before all other filters are applied so that " \
                      "the remaining filters can take the appropriate action."
    elif test_num == 29:
        title = "Email message with an .exe attachment renamed as a .txt file (Test29)"
        description = "This email server accepts emails where a .exe attachment's file extension was renamed to a " \
                      ".txt.  Although, by itself, these files would typically not still be executable, a " \
                      "well-crafted phishing email can be devised to convince the recipient to rename the extension " \
                      "to .exe and then run it.  All filters that check attachment types, should not check just the " \
                      "extension name, which can be arbitrarily changed but should inspect the headers (possible " \
                      "PE header) within the content of the attached file."
        severity = "High"
        remediation = "Create a filter that examines an attachments file header to accurately determine the file type, " \
                      " and then renames the extensions appropriately so that additional filters can block as necessary."
    elif test_num == 30:
        title = "Email message with a Zip attachment that contains an .EXE file renamed as a .TXT file (Test30)"
        description = "This email server accepts emails that has a renamed .exe attachment to a .txt and compressed " \
                      "within a zip file.  Email filters need to be able to inspect within compressed zip files and " \
                      "then inspect the actual file headers that are part of the zip-ed contents."
        severity = "High"
        remediation = "Create a filter that can examine the contents of a zip file and look within the contents' " \
                      "header to accurately determine the file type,  and then renames the extensions appropriately " \
                      "so that additional filters can block as necessary. "
    elif test_num == 31:
        title = "Email message with a chm attachment (Test31)"
        description = "This email server accepts emails with a .chm attachment with is an executable file that can " \
                      "be used to run malicious code."
        severity = "critical"
        remediation = "Create a filter to block .chm attachments."
    elif test_num == 32:
        title = "Email message with a dll attachment (Test32)"
        description = "This email server accepts emails with a .dll attachment with is an executable file that can " \
                      "be used to run malicious code."
        severity = "High"
        remediation = "Create a filter to block .dll attachments."
    elif test_num == 33:
        title = "Email message with a mui attachment (Test33)"
        description = "This email server accepts emails with a .exe.mui attachment with is an executable file that can " \
                      "be used to run malicious code."
        severity = "Low"
        remediation = "Create a filter to block .mui attachments."
    elif test_num == 34:
        title = "Email message with a mui attachment without the corresponding LN extension (Test34)"
        description = "This email server accepts emails with a .mui attachment with is an executable file that can " \
                      "be used to run malicious code."
        severity = "Low"
        remediation = "Create a fitler to block .mui attachments."
    elif test_num == 35:
        title = "Email message with a msi attachment (Test35)"
        description = "This email server accepts emails with a .msi attachment with is an executable file that can " \
                      "be used to run malicious code."
        severity = "critical"
        remediation = "Create a filter to block .msi attachments."
    elif test_num == 36:
        title = "Email message with a jar attachment (Test36)"
        description = "This email server accepts emails with a .jar attachment with is an executable file that can " \
                      "be used to run malicious code."
        severity = "critical"
        remediation = "Create a fitler to block .jar attachments."
    elif test_num == 37:
        title = "Email message with a scr attachment (Test37)"
        description = "This email server accepts emails with a .scr attachment with is an executable file that can " \
                      "be used to run malicious code."
        severity = "high"
        remediation = "Create a filter to block .scr attachments."
    elif test_num == 38:
        title = "Email message with a ps1 attachment (Test38)"
        description = "This email server accepts emails with a .ps1 attachment with is an executable file that can " \
                      "be used to run malicious code."
        severity = "critical"
        remediation = "Create a filter to block .ps1 attachments."
    elif test_num == 39:
        title = "Email message with a vbs attachment (Test39)"
        description = "This email server accepts emails with a .vbs attachment with is an executable file that can " \
                      "be used to run malicious code."
        severity = "critical"
        remediation = "Create a filter to block .vbs attachments."
    elif test_num == 40:
        title = "Email message with a sct attachment (Test40)"
        description = "This email server accepts emails with a .sct attachment with is an executable file that can " \
                      "be used to run malicious code."
        severity = "critical"
        remediation = "Create a filter to block .sct attachments."
    elif test_num == 41:
        title = "Email message with a htm attachment (Test41)"
        description = "This email server accepts emails with a .htm attachment with is an executable file that can " \
                      "be used to run malicious code."
        severity = "high"
        remediation = "Create a filter to block .htm attachments."
    elif test_num == 42:
        title = "Email message with a html attachment (Test42)"
        description = "This email server accepts emails with a .html attachment with is an executable file that can " \
                      "be used to run malicious code."
        severity = "high"
        remediation = "Create a filter to block .html attachments."
    elif test_num == 43:
        title = "Email message with a js attachment (Test43)"
        description = "This email server accepts emails with a .js attachment with is an executable file that can " \
                      "be used to run malicious code."
        severity = "medium"
        remediation = "Create a filter to block .js attachments."
    elif test_num == 44:
        title = "Email from internal email that has been base64 encoded, SMTP FROM and DATA FROM (Test44)"
        description = "This email server accepts emails where the SMTP header From and the message (DATA) From are " \
                      "an internal email address that is base64 encoded.  This technique can be used by an attacker " \
                      "to bypass email filters that do not properly decode base64 encoded email addresses to " \
                      "determine the actual plain-text email address that should be filtered on."
        severity = "medium"
        remediation = "Create a filter to decode base64 encoded email address from both the SMTP header FROM and the" \
                      " message (DATA) FROM and then apply any additional filters to the decoded address."
    elif test_num == 45:
        title = "Email from internal email that has been base64 encoded, SMTP FROM and the DATA FROM is plain text but just the username (Test45)"
        description = "This email server accepts emails where the SMTP header From is an internal email address " \
                      "that is base64 encoded and the message (DATA) From is the plain-text username-portion of the " \
                      "internal email address.  This technique can be used by an attacker to bypass email filters " \
                      "that do not properly decode base64 encoded email addresses to determine the actual plain-text " \
                      "email address that should be filter on."
        severity = "medium"
        remediation = "Create a filter to decode base64 encoded email address from both the SMTP header FROM and the" \
                      " message (DATA) FROM, ensure that the address is valid, and apply any additional filters to " \
                      "the decoded address."
    elif test_num == 46:
        title = "Email message from external email by-way-of valid internal email (Test46)"
        description = "This email server accepts emails where the SMTP header 'Resent-From' is a valid internal " \
                      "email address and the SMTP header From is an external address.  This technique can be used " \
                      "by a malicious actor to make an email appear legitimate as several email clients will " \
                      "include the words 'by-way-of' as who sent the email making the email sound like it could have " \
                      "originated from the valid internal email address."
        severity = "medium"
        remediation = "Create a filter that validates the 'Resent-From' SMTP header to ensure it is not " \
                      "from an internal address, a domain that has a valid SPF entry - especially one that ends with" \
                      " a 'HardFail', or from an invalid or not registered domain."
    elif test_num == 47:
        title = "Email message from external email, DATA FROM is from valid internal email, and by-way-of valid internal email (Test47)"
        description = "This email server accepts emails where the message (DATA) From is a valid internal email, the " \
                      "SMTP header From and the SMTP header 'Resent-From' are from an external address.  This " \
                      "technique can be used by a malicious actor to make an email appear legitimate as several " \
                      "email clients include the words 'by-way-of' as who sent the email making the email appear like " \
                      "it came from internal 'by-way-of' an external address which might provide credibility to the " \
                      "external email as well for future use."
        severity = "medium"
        remediation = "Create a filter that validates the FROM within the message body is the same as the address in " \
                      "the SMTP FROM header and either block it, rewrite the message FROM, and/or warn the user " \
                      "with a message.  Also the 'Resent-From' SMTP header should be filtered to ensure it is not " \
                      "from an internal address, a domain that has a valid SPF entry - especially one that ends with" \
                      " a 'HardFail', or from an invalid or not registered domain."
    elif test_num == 48:
        title = "Email message SMTP FROM external email, DATA FROM is from valid internal, and email on-behalf-of " \
                "valid internal email (Test48)"
        description = "This email server accepts emails where the SMTP header From is an external email address " \
                      "and the message (DATA) From and the SMTP header 'Sender' are from a valid internal email " \
                      "address.  This technique can be used by a malicious actor to make an email more legitimate " \
                      "as several email clients include the words 'on-behalf-of' as who sent the email making the " \
                      "email appear like it came from a trusted source."
        severity = "medium"
        remediation = "Create a filter that validates the FROM within the message body is the same as the address in " \
                      "the SMTP FROM header and either block it, rewrite the message FROM, and/or warn the user " \
                      "with a message.  Also the 'Sender' SMTP header should be filtered to ensure it is not " \
                      "from an internal address, a domain that has a valid SPF entry - especially one that ends with" \
                      " a 'HardFail', or from an invalid or not registered domain."
    elif test_num == 49:
        title = "Email message from external email and on-behalf-of valid internal email (Test49)"
        description = "This email server accepts emails where the SMTP header From and the message (DATA) From as " \
                      "from an external address but the SMTP header 'Sender' is from a valid internal email address. " \
                      "This technique could allow a malicous actor to craft a more legitimate phishing email by " \
                      "making it appear to come from a trusted internal source."
        severity = "medium"
        remediation = "Create a filter that validates the 'Sender' SMTP header to ensure it is not " \
                      "from an internal address, a domain that has a valid SPF entry - especially one that ends with" \
                      " a 'HardFail', or from an invalid or not registered domain."
    elif test_num == 50:
        title = "Email message where the SMTP FROM's domain is localhost (Test50)"
        description = "This email server accepts emails where the domain portion of the SMTP header From is the word " \
                      "'localhost'.  An malicious actor can use this technique to make an email appear to come from " \
                      "a valid internal username (even though the full email address is not valid)."
        severity = "medium"
        remediation = "Create a filter that blocks emails from invalid domains including localhost."
    elif test_num == 51:
        title = "Email message where the SMTP FROM's domain is localhost IP, [127.0.0.1] (Test51)"
        description = "This email server accepts emails where the domain portion of the SMTP header From is the " \
                      "private IP address, '127.0.0.1'.  An malicious actor can use this technique to make an email " \
                      "appear to come from  a valid internal username (even though the full email address is not valid)."
        severity = "medium"
        remediation = "Create a filter that blocks emails from invalid domains including a localhost IP address."
    elif test_num == 52:
        title = "Email message where the SMTP FROM is null, <> (Test52)"
        description = "This email server accepts emails where the SMTP header From is '<>' which is an equivalent null."
        severity = "medium"
        remediation = "Create a filter to block emails from a null email address."
    elif test_num == 53:
        title = "Email message where the SMTP FROM's domain is the local FQDN of the sending computer (Test53)"
        description = "This email server accepts emails where the SMTP header From's domain portion (after the @) is " \
                      "from the sending email server's FQDN with the username portion that of a valid internal email " \
                      "address."
        severity = "medium"
        remediation = "Create a filter to block emails from invalid domains."
    elif test_num == 54:
        title = "Email message where the SMTP FROM's domain is a Public IP address (Test54)"
        description = "This email server accepts emails where the SMTP header From's domain portion (after the @) is " \
                      "a public IP address.  Accepting emails that do not contain valid registered domains " \
                      "nullifies several email protections that should be enabled through domain entries such as: " \
                      "SPF, DMARC, and DKIM."
        severity = "medium"
        remediation = "Create a filter to block emails where the domain of the SMTP FROM is a public, routable IP " \
                      "address."
    elif test_num == 55:
        title = "Email message where the SMTP FROM's domain is a private IP address, ex. @[192.168.1.1] (Test55)"
        description = "This email server accepts emails there the SMTP header From's domain portion (after the @) is " \
                      "a private, no-routable IP address.  Private IP addresses are not routable on the Internet so " \
                      "emails orginating from the Internet should not be using a private IP address.  Allowing IP " \
                      "addresses as the domain portion nullifies several email protections that should be enabled, " \
                      "such as SPF, DMARC, and DKIM."
        severity = "medium"
        remediation = "Create a filter to block emails where the domain of the SMTP FROM is a private, non-routable " \
                      "IP address"
    elif test_num == 56:
        title = "Email message where the SMTP FROM is an internal hack routed address using '%' where the @domain is external (Test56)"
        description = "This email server accepts emails where the SMTP header From and the message (DATA) From use " \
                      "hack routing.  This technique uses a valid internal username hack routed with the valid " \
                      "internal domain @ an external domain (ie user%yourdomain.com@externaldomain.com)."
        severity = "medium"
        remediation = "Create a filter to block email using hack routing, especially where the source routed domain " \
                      "is a valid internal domain."
    elif test_num == 57:
        title = "Email message where the SMTP FROM is a valid username, the hack routing domain is an external domain and the @domain is an external domain(Test57)"
        description = "This email server accepts emails where the SMTP header From and the message (DATA) From use " \
                      "hack routing.  This technique uses a valid internal username hack routed with an external " \
                      "domain @ an external domain (ie user%externaldomain.com@externaldomain.com)."
        severity = "medium"
        remediation = "Create a filter to block email using hack routing or prepend a warning message for the recipient."
    elif test_num == 58:
        title = "Email message where the SMTP FROM is an internal hack routed address using '%' where the @domain is a Public IP, ex. @[38.126.169.102] (Test58)"
        description = "This email server accepts emails where the SMTP header FROM and the message (DATA) From use " \
                      "hack routing.  This technique uses a valid internal username hack routed with the valid " \
                      "internal domain @ a public IP address (ie user@yourdomain.com@[121.1.1.1])."
        severity = "medium"
        remediation = "Create a filter to block emails where the domain of the SMTP FROM is a public, routable IP " \
                      "address and where hack routing is used, especially where the source routed domain " \
                      "is a valid internal domain."
    elif test_num == 59:
        title = "Email message where the SMTP FROM is a valid username, the hack routing domain is external and the @domain is a Public IP, ex. @[38.126.169.102] (Test59)"
        description = "This email server accepts emails where the SMTP header FROM and the message (DATA) From use " \
                      "hack routing.  This technique uses a valid internal username hack routed with an external " \
                      "domain @ a public IP address (ie user@externaldomain.com@[121.1.1.1])."
        severity = "medium"
        remediation = "Create a filter to block emails where the domain of the SMTP FROM is a public, routable IP " \
                      "address and where hack routing is used."
    elif test_num == 60:
        title = "Email message where the SMTP FROM is a valid username, the hack routing domain is a spoofed " \
                "'one-off' domain and the @domain is the Public IP of your domain's MX record (Test60)"
        description = "This email server accepts emails where the SMTP header FROM and the message (DATA) From use " \
                      "hack routing.  This technique uses a valid internal username hack routed with an external " \
                      "domain @ the public IP address of your email server's MX record."
        severity = "medium"
        remediation = "Create a filter to block emails where the domain of the SMTP FROM is the public, routable IP " \
                      "address of your domain's MX record and where hack routing is used."
    elif test_num == 61:
        title = "Email message where the SMTP FROM is an internal address encapsulated within quotes (Test61)"
        description = "This email server accepts emails where the SMTP header From and the message (DATA) From are " \
                      "from a valid, internal email address that is encapsulated by quotes.  This technique can be " \
                      "used to evade other filters that block spoofing sending emails as if from an internal address " \
                      "by encapsulating the address in quotes."
        severity = "high"
        remediation = "Create a filter to strip quotes from email addresses and ONLY allow your email servers to send" \
                      " email from yourself to yourself."
    elif test_num == 62:
        title = "Email message where the SMTP FROM is an internal hack routed address using '%' where the @domain is external all encapsulated within quotes (Test62)"
        description = "This email server accepts emails where the SMTP header From and the message (DATA) From are " \
                      "from a hack routed email address that is encapsulated in quotes.  This technique uses a " \
                      "valid, internal username hack routed with the valid internal domain @ an external domain." \
                      "This technique can be used to evade other filters that block spoofing sending emails as if " \
                      "from an internal address by encapsulating the address in quotes, including ones that filter " \
                      "or block hack routed addresses (ie \"user%youdomain.com@externaldomain.com\")."
        severity = "medium"
        remediation = "Create a filter to strip quotes from email addresses and block email using hack routing, " \
                      "especially where the source routed domain is a valid internal domain."
    elif test_num == 63:
        title = "Email message where the SMTP FROM is a valid username, the hack routing domain is external and the @domain is a Public IP, ex. @[38.126.169.102], encapsulated within qoutes (Test63)"
        description = "This email server accepts emails where the SMTP header From and the message (DATA) From are " \
                      "from a hack routed email address that is encapsulated in quotes.  This technique uses a " \
                      "valid, internal username hack routed with the valid internal domain @ a public IP." \
                      "This technique can be used to evade other filters that block spoofing sending emails as if " \
                      "from an internal address by encapsulating the address in quotes, including ones that filter " \
                      "or block hack routed addresses (ie \"user%youdomain.com\"@[121.1.1.1])."
        severity = "medium"
        remediation = "Create a filter to strip quotes from email addresses and block email using hack routing, " \
                      "especially where the source routed domain is a public, routable IP address."
    elif test_num == 64:
        title = "Email message where the SMTP FROM uses source routing where the source domain is a 'one-off' domain " \
                "and the email address is a valid internal address (Test64)"
        description = "This email server accepts emails where the SMTP header From and the message (DATA) From are " \
                      "from a source routed email address.  This technique uses an external domain source " \
                      "routed with the valid internal email address (ie @externaldomain,user@yourdomain.com)."
        severity = "high"
        remediation = "Create filter to block source routed email addresses especially where the domain is a " \
                      "valid internal domain."
    elif test_num == 65:
        title = "Email message where the SMTP FROM uses source routing where the source domain is a 'one-off' domain and the email address is a valid internal address encapsulated within quotes (Test65)"
        description = "This email server accepts emails where the SMTP header From and the message (DATA) From are " \
                      "from a source routed email address where the email address portion is encapsulated in quotes. " \
                      " This technique uses an external domain source routed with the valid internal email address " \
                      "(ie @externaldomain,\"user@yourdomain.com\")."
        severity = "medium"
        remediation = "Create filter to strip qoutes and block source routed email addresses especially where the domain is a " \
                      "valid internal domain."
    elif test_num == 66:
        title = "Email message where the SMTP FROM uses source routing where the source domain is a Public IP and the email address is a valid internal address (Test66)"
        description = "This email server accepts emails where the SMTP header From and the message (DATA) From are " \
                      "from a source routed email address.  This technique uses a public IP address source routed " \
                      "with the valid internal email address (ie @[121.1.1.1],user@yourdomain.com)."
        severity = "medium"
        remediation = "Create filter to block source routed email addresses especially where the domain is a " \
                      "valid internal domain and the source routed address is a public, routable IP address."
    elif test_num == 67:
        title = "Email message where the SMTP FROM uses source routing where the source dmain is the MX Public IP and the email address is a valid internal address (Test67)"
        description = "This email server accepts emails where the SMTP header From and the message (DATA) From are " \
                      "from a source routed email address.  This technique uses the public IP address of one of your " \
                      "MX records source routed with the valid internal email address."
        severity = "medium"
        remediation = "Create filter to block source routed email addresses especially where the domain is a " \
                      "valid internal domain and the source routed address is the public, routable IP address of " \
                      "your MX record."
    elif test_num == 68:
        title = "Email message where the spoofed URL is masked using a base path (Test68)"
        description = "This email server accepts emails where the message has a base path that gets applied to all " \
                      "links and helps obfuscate the link address."
        severity = "medium"
        remediation = "Create a filter to either block messages that have a base path HTML tag, remove this tag, or " \
                      "rewrite all HTML links in the message so that it is apparent to the end user where the link is " \
                      "destined."
    elif test_num == 69:
        title = "Email message where the X-Originator-IP is spoofed to appear to come from a valid email gateway (Test69)"
        description = "This email server accepts emails where the X-Originator-IP has been spoofed to appear to come " \
                      "from a valid email gateway."
        severity = "medium"
        remediation = "Create a filter to block messages that are coming from the Internet and spoofing the X-Originator-IP " \
                      "SMTP header field."
    elif test_num == 70:
        title = "Email message where the SMTP From header contains line breaks (folding/unfolding)(Test70)"
        description = "This email server accepts emails where the SMTP From header has line breaks (folding/unfolding) " \
                      "which can make the email appear to come from a valid source."
        severity = "medium"
        remediation = "Create a filter to either block messages that have a new line in the SMTP From header field or " \
                      "sanitize the field first (strip out all new line characters) before other filters are applied" \
                      " to ensure the remaining filters can adequately block malicious traffic."
    elif test_num == 71:
        title = "Email message where the SMTP From header is over the maximum specified 998 characters (Test71)"
        description = "This email server accepts emails where the SMTP From header is longer than the 998 maximum " \
                      "characters specified in the RFC.  This technique can be used by malicious actors to hide " \
                      "malicious sources or appear to come from a more legitimate source."
        severity = "medium"
        remediation = "Create a filter to either block messages that have SMTP header fields longer than the maximum " \
                      "998 characters."
    elif test_num == 72:
        title = "Email message where the SMTP From header's display name portion of the From address is long in order " \
                "to hide the actual SMTP From email address (Test72)"
        description = "This email server accepts emails where the SMTP From header's display name portion is extremely " \
                      "long and can be used to make the real source (which is probably not legitimate) SMTP From email " \
                      "address less obvious."
        severity = "medium"
        remediation = "Create filter to either block messages that have excesively long SMTP From display name portions " \
                      "of the email address or prepend a warning to the user showing just the actual email address that " \
                      "the email is coming from."

    return title, description, severity, remediation

class EmailFilterParser():
    """ Parse EmailFilterParser files. """
    def __init__(self, db_object, location_id, scope_id, file_path_name, ext, just_file_name, target, log_id, output_path, tester_device_list, modified_by, modified_date):
        if "/" in target:
            target = target.replace("/", "_")
        self.db_object = db_object
        self.output_path = output_path
        self.location_id = location_id
        self.scope_id = scope_id
        self.tool = "email filter"
        self.target = target
        self.log_id = log_id
        self.ext = ext
        self.tester_device_list = tester_device_list
        self.file_path = file_path_name
        self.file_name = just_file_name
        self.modified_by = modified_by
        self.modified_date = modified_date

    def __enter__(self):
        return self

    def __exit__(self, type, value, traceback):
        return self

    def parse(self):
        """ Parse .txt files. """
        try:
            if self.ext == "txt":
                # check if used relay server
                email_relay_servers = []
                if os.path.isfile('tools/vuln/emailfilter.yaml'):
                    import yaml
                    yaml_config = yaml.safe_load(open('tools/vuln/emailfilter.yaml'))
                    if "email_relay_servers_to_bounce_emails_from" in yaml_config and yaml_config[
                        'email_relay_servers_to_bounce_emails_from'] != "":
                        if ";" in yaml_config['email_relay_servers_to_bounce_emails_from']:
                            email_relay_servers = yaml_config[
                                'email_relay_servers_to_bounce_emails_from'].split(";")
                        else:
                            email_relay_servers = [
                                yaml_config['email_relay_servers_to_bounce_emails_from']]
                if len(email_relay_servers) == 0:
                    # check if global var in enterprise_user_conf.py
                    try:
                        from enterprise_user_conf import EMAIL_RELAY_SERVERS_TO_BOUNCE_EMAILS_FROM
                        email_relay_server_string = EMAIL_RELAY_SERVERS_TO_BOUNCE_EMAILS_FROM
                        if ";" in email_relay_server_string:
                            email_relay_servers = email_relay_server_string.split(";")
                        else:
                            email_relay_servers = [email_relay_server_string]
                    except:
                        pass

                # get all mx_records by scope_id
                mx_records_dict = models_to_dictionary.mx_records_by_scope_dictionary(self.db_object)

                result_list = []
                engagement_device = []
                already_added_target = []

                with open(self.file_path, 'r') as f:
                    dfile = f.read()
                    dfile_lines = dfile.split("EOL\n")
                    for record in dfile_lines:
                        parts = record.split("\t")
                        if len(parts) == 9:
                            test_num = str(parts[3])
                            if test_num.isnumeric():
                                test_num_int = float(test_num)
                                if test_num_int > 1000:
                                    test_num = test_num[1:]
                                    test_num = test_num.lstrip("0") #remove any preceeding 0 from test_num

                                title, description, severity, remediation = test_info(test_num)

                                target = parts[1]
                                target_name = parts[1]
                                if target in email_relay_servers and target.strip() != "":
                                    if str(self.scope_id) in mx_records_dict:
                                        target = parts[1] + ' -> ' + mx_records_dict[str(self.scope_id)][0]
                                        target_name = mx_records_dict[str(self.scope_id)][0]

                                if target != "":
                                    if target_name not in already_added_target:
                                        already_added_target.append(target_name)
                                        engagement_device.append(["", target_name, None, None, None, None, None, None, None, None,
                                                      self.modified_by, self.modified_date, self.tool, self.scope_id])

                                    output = parts[8]
                                    output = keep_tags.clean_text(output)
                                    tester_output = keep_tags.clean_text(tester_output)
                                    if "Failed to send" not in output:
                                        tester_output = parts[6]
                                        start_time = datetime.datetime.strptime(parts[0], '%Y-%m-%d %H:%M:%S')
                                        result_list.append([self.tool, "emailfilter-" + test_num, target, parts[2],
                                                            "tcp", tester_output, output, start_time, start_time,
                                                            'email filter test # ' + str(test_num), title,
                                                            description, remediation, "", severity, "configuration", "", "",
                                                            self.modified_by])
                output_dictionary = {}
                output_dictionary["devices"] = engagement_device
                output_dictionary["devices_fields_to_update"] = [('target_name', 'c')]
                output_dictionary["results"] = result_list
                output_dictionary["results_fields_to_update"] = [('output', 'c')]

                return output_dictionary
            else:
                print_text.print_error("Unsupported file for parsing found, skipping it!")
                return {}
        except Exception as e:
            print(self.tool + " parser 117 except: " + str(e) + " Error on line {}".format(sys.exc_info()[-1].tb_lineno))
        return {}
