import sys
import html
from lxml import etree
from common import keep_tags, network

# For some reason AdminAuditLog had a bunch of binary characters that I had to strip out using:
# tr -cd '\11\12\15\40-\176' < file_with_binary_characters > clean_file

class AdminAuditLogParser():
    """ Parse Exchange Admin Audit Log files. """

    def __init__(self, db_object, location_id, scope_id, file_path_name, ext, just_file_name, target, log_id, output_path, tester_device_list, modified_by, modified_date):
        try:
            if "/" in target:
                target = target.replace("/", "_")
            self.db_object = db_object
            self.output_path = output_path
            self.location_id = location_id
            self.scope_id = scope_id
            self.tool = "exchange_adminauditlog"
            self.target = target
            self.log_id = log_id
            self.ext = ext
            self.tester_device_list = tester_device_list
            self.file_path = file_path_name
            self.file_name = just_file_name
            self.modified_by = modified_by
            self.modified_date = modified_date

            # suspicion level
            self.critical_cmdlet = {}
            self.high_cmdlet = {"Set-AdminAuditLogConfig": ["Configures what is and is not logged by Exchange Admin Audit Log.", {}]}
            self.medium_cmdlet = {}
            self.low_cmdlet = {"Set-TransportConfig": ["Modifies the transport configuration settings for Exchange.  "
                                                      "This can include having messages that are 'bounced back' forwarded to a mailbox to identify why it bounced back."]}
            self.neutral_cmdlet = {"New-AdminAuditLogSearch": ["Searching the Exchange Admin Audit Log."],
                                   "Set-ExchangeAssistanceConfig": ["Modifies the Exchange Help configurations."]}

        except Exception as e:
            print("exchange_adminauditlog_parser 50 except: " + str(e) + " Error on line {}".format(sys.exc_info()[-1].tb_lineno))

    def __enter__(self):
        return self

    def __exit__(self, type, value, traceback):
        return self

    def parse(self):
        try:
            self.tags = ""
            self.engagement_device_list = []
            self.open_port_list = []
            self.result_list = []

            self.parsed_logs = []
            if self.ext == "xml":
                return self.parser_exchange_adminauditlog_file()

        except Exception as e:
            print("exchange_adminauditlog parser 46 except: " + str(e) + " Error on line {}".format(sys.exc_info()[-1].tb_lineno))

        return None, None, None, None, None, None

    def remove_extra_spaces(self, text):
        """
        Used to remove extra spaces and tabs.
        :param text:
        :return:
        """
        if "\t" in text:
            text = text.replace("\t", " ")
        while "  " in text:
            text = text.replace("  ", " ")
        return text

    def get_xml_tag_text(self, elements, tag):
        """ Used to extract tag from current xml element. """
        tag_text = ""
        try:
            tags = list(elements.iter(tag))
            for tg in tags:
                tag_text = tg.text
                if tag_text is not None and tag_text != "":
                    tag_text = keep_tags.clean_text(tag_text)
                    break
        except Exception as e:
            print("exchange_adminauditlog parser 77 except: " + str(e) + " Error on line {}".format(sys.exc_info()[-1].tb_lineno))
        return tag_text

    def remove_tagtext_junk(self, tag_text):
        """ Used to remove burp junk. """
        try:
            if tag_text is not None:
                tag_text = tag_text.replace("<![CDATA[", "").replace("]]>", "")
                tag_text = html.unescape(tag_text)
        except Exception as e:
            print("Parser.py 137 except: " + str(e) + " Error on line {}".format(sys.exc_info()[-1].tb_lineno))
        return tag_text

    def get_xml_tag_and_remove_burp_junk(self, elements, tag):
        """ Used to extract tag from current xml element and remove burp junk leftover. """
        tag_text = self.get_xml_tag_text(elements, tag)
        return self.remove_tagtext_junk(tag_text)

    def lookup_suspicion_level(self, cmdlet):
        if cmdlet in self.critical_cmdlet:
            return "critical"
        elif cmdlet in self.high_cmdlet:
            return "high"
        elif cmdlet in self.medium_cmdlet:
            return "medium"
        elif cmdlet in self.low_cmdlet:
            return "low"
        elif cmdlet in self.neutral_cmdlet:
            return "neutral"
        return "unknown"

    def parse_exchange_adminauditlog_file(self):
        """
            Parse exchange_adminauditlog .xml files.
        """

        # don't care about cmdlet so not include
        cmdlet_to_ignore = []

        try:
            with open(self.file_path, 'rb') as xml_file:
                # loop through events in .xml file
                for _, element in etree.iterparse(xml_file, tag='Event'):
                    protocol = 'tcp'

                    # Who performed the action
                    who_ran = element.get("Caller")
                    who_ran = keep_tags.clean_text(who_ran)

                    # The powershell cmdlet run
                    cmdlet = element.get("Cmdlet")
                    cmdlet = keep_tags.clean_text(cmdlet)

                    if cmdlet not in cmdlet_to_ignore:
                        suspicion_level = self.lookup_suspicion_level(cmdlet)

                        # When it was run
                        run_date = element.get("RunDate")
                        run_date = keep_tags.clean_text(run_date)

                        # Success
                        succeeded = element.get("Succeeded")
                        succeeded = keep_tags.clean_text(succeeded)

                        # Object modified
                        object_modified = element.get("ObjectModified")
                        object_modified = keep_tags.clean_text(object_modified)

                        # External Access
                        external_access = element.get("ExternalAccess")
                        external_access = keep_tags.clean_text(external_access)

                        # Originating Server
                        originating_server = element.get("OriginatingServer")
                        originating_server = keep_tags.clean_text(originating_server)

                        cmdlet_parameter = ""
                        sep = ""
                        parameters = list(element.iter('Parameter'))
                        for parameter in parameters:
                            name = parameter.get('Name')
                            name = keep_tags.clean_text(name)

                            value = parameter.get('Value')
                            value = keep_tags.clean_text(value)

                            if name != "" and value != "":
                                if cmdlet_parameter != "":
                                    sep = "\n"
                                cmdlet_parameter = cmdlet_parameter + sep + name + ": " + value

                        # Parsed Log
                        self.parsed_logs.append((suspicion_level, who_ran, cmdlet, run_date, succeeded, object_modified,
                                                 external_access, originating_server, cmdlet_parameter,
                                                 str(self.location_id), self.modified_by, self.modified_date,
                                                 self.tool, self.scope_id))

        except Exception as e:
            print("exchange_adminauditlog_parser 160 except: " + str(e) + " Error on line {}".format(sys.exc_info()[-1].tb_lineno))

        output_dictionary = {}
        output_dictionary["forensic_log"] = self.parsed_logs
        output_dictionary["forensic_log_fields_to_update"] = [('external_access', 'c')]

        return output_dictionary
