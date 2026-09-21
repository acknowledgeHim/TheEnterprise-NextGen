import re, os
import base64
import sys
import html
import datetime
from itertools import islice
from lxml import etree
from common import keep_tags, network, common, scope_functions
from setup import engagement_scope
from parsers. parser import Parser

def burp(db_path, db_object, key, hashvals):
    """
    Loop thru hashvals, verify blacklist status, update Log, send to Parser, then finally email notifications out.
    :param db_path:
    :param db_object:
    :param hashvals:
    :return:
    """

    try:
        with Parser("burp", db_object, key, hashvals) as p:
            p.parse("parsers.vuln.web.burp_parser", "BurpParser")

    except Exception as e:
        print("burp_parser 24 except: " + str(e) + " Error on line {}".format(sys.exc_info()[-1].tb_lineno))


class BurpParser():
    """ Parse Burp .xml files. """
    def __init__(self, db_object, location_id, scope_id, file_path_name, ext, just_file_name, target, log_id, output_path, tester_device_list, modified_by, modified_date):
        try:
            if "/" in target:
                target = target.replace("/", "_")
            self.db_object = db_object
            self.output_path = output_path
            self.location_id = location_id
            self.scope_id = scope_id
            self.target = target
            self.log_id = log_id
            self.log_info = self.db_object.get("Log", ["id"], [log_id])
            self.tool = self.log_info['source']
            self.start_time = self.log_info["start_time"]
            self.end_time = self.log_info["end_time"]
            self.ext = ext
            self.tester_device_list = tester_device_list
            self.file_path = file_path_name
            self.file_name = just_file_name
            self.modified_by = modified_by
            self.modified_date = modified_date

            # Scope IPs
            self.log_info = db_object.view("Log", ['target', 'command', 'source'], ['id'], [log_id], True)
            self.curr_scope_id = None
            if not os.path.isfile(self.log_info[0]['target']) and not os.path.isdir(self.log_info[0]['target']):
                self.curr_scope_id = self.scope_id
            self.current_location_id = self.db_object.grab_current_location()
            if not isinstance(self.current_location_id, int):
                self.current_location_id = None
            self.scope_ips = scope_functions.scope_ips(db_object, self.current_location_id)
            self.scope_ip_dictionary = scope_functions.scope_dictionary(db_object, 'IP', self.current_location_id)

        except Exception as e:
            print("burp_parser 50 except: " + str(e) + " Error on line {}".format(sys.exc_info()[-1].tb_lineno))

    def __enter__(self):
        return self

    def __exit__(self, type, value, traceback):
        return self

    def parse(self):
        try:
            self.tags = ""
            self.scope_list = []
            self.engagement_device_list = []
            self.open_port_list = []
            self.result_list = []
            self.already_found_internet_accessible_login = []
            if self.ext == "xml":
                return self.parse_burp_file()

        except Exception as e:
            print("burp_parser 64 except: " + str(e) + " Error on line {}".format(sys.exc_info()[-1].tb_lineno))

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
            print("burp parser 90 except: " + str(e) + " Error on line {}".format(sys.exc_info()[-1].tb_lineno))
        return tag_text
    
    def remove_tagtext_junk(self, tag_text):
        """ Used to remove burp junk. """
        try:
            if tag_text is not None:
                tag_text = tag_text.replace("<![CDATA[", "").replace("]]>", "")
                tag_text = html.unescape(tag_text)
        except Exception as e:
            print("burp Parser.py 84 except: " + str(e) + " Error on line {}".format(sys.exc_info()[-1].tb_lineno))
        return tag_text

    def get_xml_tag_and_remove_burp_junk(self, elements, tag):
        """ Used to extract tag from current xml element and remove burp junk leftover. """
        tag_text = self.get_xml_tag_text(elements, tag)
        return self.remove_tagtext_junk(tag_text)

    def parse_burp_file(self):
        """
            Parse burp .xml files.  Returns Dictionary of Engagement Devices to Insert/Update
        """

        try:
            engagement_device_list = []
            result_list = []
            deviceport_list = []
            already_found_deviceport = []
            already_found_engagementdevice = []
            with open(self.file_path, 'rb') as xml_file:
                # loop through Hosts in .xml file
                for _, element in etree.iterparse(xml_file, tag='issues'):
                    end_time = element.get('exportTime')
                    issues = list(element.iter('issue'))
                    # Main loop
                    for issue in issues:
                        plugin_id = self.get_xml_tag_and_remove_burp_junk(issue, 'serialNumber')
                        title = self.get_xml_tag_and_remove_burp_junk(issue, 'name')
                        ip = None
                        host_name = None
                        hosts = list(issue.iter('host'))
                        for host in hosts:
                            ip = host.get('ip')
                            host_name = host.text
                            if ip != "" and host_name != "":
                                ip = keep_tags.clean_text(ip)
                                host_name = keep_tags.clean_text(host_name)
                                break

                        if ip is not None:
                            ip = common.format_website(ip)
                            port = network.return_port(host_name)
                            host_name = common.format_website(host_name)

                            # Check if in scope
                            in_scope = engagement_scope.domain_in_scope(self.db_object, host_name)
                            if not in_scope:
                                in_scope = engagement_scope.ip_in_scope(self.db_object, ip)

                            if in_scope:
                                path = keep_tags.clean_text(self.get_xml_tag_and_remove_burp_junk(issue, 'path'))

                                severity = keep_tags.clean_text(self.get_xml_tag_and_remove_burp_junk(issue, 'severity')).lower()
                                confidence = keep_tags.clean_text(self.get_xml_tag_and_remove_burp_junk(issue, 'confidence'))

                                description = keep_tags.clean_text(self.get_xml_tag_and_remove_burp_junk(issue, 'issueBackground'))
                                remediation = keep_tags.clean_text(self.get_xml_tag_and_remove_burp_junk(issue, 'remediationBackground'))

                                references = keep_tags.clean_text(self.get_xml_tag_and_remove_burp_junk(issue, 'references'))
                                if references is not None and references != "":
                                    remediation = "\n\nSee Also: " + references

                                # ----- Grabbing all the 'output' information -----
                                issue_detail = ""
                                if issue.find('.//issueDetail') is not None:
                                    issue_detail = keep_tags.clean_text(self.get_xml_tag_and_remove_burp_junk(issue, 'issueDetail'))

                                issue_detail_item = ""
                                sep = ""
                                issue_detail_items = list(issue.iter('issueDetailItem'))
                                for idi in issue_detail_items:
                                    if issue_detail_item != "":
                                        sep = "\n"
                                    issue_detail_item = issue_detail_item + sep + keep_tags.clean_text(self.remove_tagtext_junk(idi.text))
                                if issue_detail_item != "" and issue_detail_item is not None:
                                    if issue_detail is None:
                                        issue_detail = ""
                                    issue_detail = issue_detail + "\n\n" + issue_detail_item

                                output_request = None
                                output_response = None
                                if issue.find('.//request') is not None:
                                    output_request = self.get_xml_tag_and_remove_burp_junk(issue, 'request')
                                    if output_request is not None:
                                        output_request = keep_tags.clean_text(base64.b64decode(output_request))
                                # Response is entire HTTP response which is large and not necessary so not including
                                #if issue.find('.//response') is not None:
                                #    output_response = self.get_xml_tag_and_remove_junk(issue, 'response')
                                #    if output_response is not None:
                                #        output_response = keep_tags.clean_text(output_response) #base64.b64decode(
                                tester_output = None
                                if confidence is not None and confidence != "":
                                    tester_output = "Confidence Level: " + confidence
                                output = "Detail: " + issue_detail
                                if output_request != "" and output_request is not None:
                                    output = output + "<p>HTTP Request: " + str(output_request)
                                if output_response != "" and output_response is not None:
                                    output = output + "<p>HTTP Response (base64 encoded): " + str(output_response)
                                # ----- End grabbing all the 'output' information -----

                                # Result
                                self.result_list.append(['burp', plugin_id, host_name, port, "tcp",
                                                         "URL: " + host_name + path + "<p>" + output, tester_output, self.start_time, self.end_time,
                                                         "burp - " + plugin_id + " from " + self.file_name,
                                                         title, description, remediation, None, severity, "",
                                                         "", None, self.modified_by])

                                if port != "0" and ip+port not in already_found_deviceport:
                                    # Open port
                                    already_found_deviceport.append(ip+port)
                                    self.open_port_list.append((ip, port, "tcp", None, True,
                                                                self.modified_by, self.modified_date, False, self.start_time,
                                                                self.end_time, 'burp - ' + self.file_name))

                                # Engagement Device and account for virtual web servers behind a single IP (using reverse proxy)
                                for host in hosts:
                                    host_name = keep_tags.clean_text(host.text)
                                    host_name = common.format_website(host_name)
                                    if ip + str(host_name) not in already_found_engagementdevice:
                                        already_found_engagementdevice.append(ip+str(host_name))
                                        if self.curr_scope_id is not None:
                                            curr_scope_id = self.curr_scope_id
                                        if self.curr_scope_id is None:
                                            if network.valid_ip(ip):
                                                for scope_ip in self.scope_ips:
                                                    if network.check_in_network(scope_ip, ip):
                                                        curr_scope_id = self.scope_ip_dictionary[scope_ip]
                                                        break
                                        if curr_scope_id is not None:
                                            self.engagement_device_list.append(
                                                (ip, keep_tags.clean_text(host_name), None, None, None, None, None, None, None, None,
                                                 self.modified_by, self.modified_date, self.tool,
                                                 curr_scope_id))

                        # Clear xml elements that no longer need
                        issue.clear()
        except Exception as e:
            print("229 burp_parser except: " + str(e) + " Error on line {}".format(sys.exc_info()[-1].tb_lineno))

        output_dictionary = {}
        output_dictionary["devices"] = self.engagement_device_list
        output_dictionary["devices_fields_to_update"] = [('os', 'ol'), ('mac', 'c')]
        output_dictionary["results"] = self.result_list
        output_dictionary["results_fields_to_update"] = [('finding_description', 'c')]
        output_dictionary["ports"] = self.open_port_list
        output_dictionary["ports_fields_to_update"] = [('port_description', 'as')]

        return output_dictionary


