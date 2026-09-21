import html, os
import datetime
import sys
from lxml import etree
from common import keep_tags, network, common, scope_functions
from parsers. parser import Parser


def nikto_parser(db_path, db_object, key, hashvals):
    """
    Loop thru hashvals, verify blacklist status, update Log, send to Parser, then finally email notifications out.
    :param db_path:
    :param db_object:
    :param hashvals:
    :return:
    """
    try:
        with Parser("nikto", db_object, key, hashvals) as p:
            p.parse("parsers.vuln.web.nikto_parser", "NiktoParser")

    except Exception as e:
        print("nikto_parser 24 except: " + str(e) + " Error on line {}".format(sys.exc_info()[-1].tb_lineno))

class NiktoParser():
    """ Parse Nikto files. """

    def __init__(self, db_object, location_id, scope_id, file_path_name, ext, just_file_name, target, log_id, output_path, tester_device_list, modified_by, modified_date):
        try:
            self.db_object = db_object
            self.output_path = output_path
            self.location_id = location_id
            self.scope_id = scope_id
            self.tool = "nikto"
            self.target = target
            self.log_id = log_id
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
            print("nikto_parser 50 except: " + str(e) + " Error on line {}".format(sys.exc_info()[-1].tb_lineno))

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
            self.already_found_internet_accessible_login = []
            if self.ext == "xml":
                return self.parse_nikto_file()

        except Exception as e:
            print("nikto parser 47 except: " + str(e) + " Error on line {}".format(sys.exc_info()[-1].tb_lineno))

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
            print("nikto parser 77 except: " + str(e) + " Error on line {}".format(sys.exc_info()[-1].tb_lineno))
        return tag_text

    def remove_tagtext_junk(self, tag_text):
        """ Used to remove burp junk. """
        try:
            if tag_text is not None:
                tag_text = tag_text.replace("<![CDATA[", "").replace("]]>", "")
                tag_text = html.unescape(tag_text)
        except Exception as e:
            print("nikto Parser.py 84 except: " + str(e) + " Error on line {}".format(sys.exc_info()[-1].tb_lineno))
        return tag_text

    def get_xml_tag_and_remove_burp_junk(self, elements, tag):
        """ Used to extract tag from current xml element and remove burp junk leftover. """
        tag_text = self.get_xml_tag_text(elements, tag)
        return self.remove_tagtext_junk(tag_text)

    def parse_nikto_file(self):
        """
            Parse nikto .xml files.
        """
        # pluginIDs to ignore
        vd_ignore_plugins = []

        # Nikto junk findings to not include
        plugin_ids_to_ignore = []

        try:
            with open(self.file_path, 'rb') as xml_file:
                # loop through Hosts in .xml file
                for _, element in etree.iterparse(xml_file, tag='niktoscan'):
                    protocol = 'tcp'
                    command = element.get("options")
                    command = keep_tags.clean_text(command)
                    stealth = False
                    if "-evasion" in command:
                        stealth = True
                    os = None
                    mac = None
                    end_time = None

                    scan_details = list(element.iter('scandetails'))
                    for sd in scan_details:
                        ip = sd.get('targetip')
                        ip = keep_tags.clean_text(ip)
                        if network.valid_ip(ip) and ip not in self.tester_device_list:
                            host_name = sd.get('targethostname')
                            host_name = keep_tags.clean_text(host_name)
                            port = sd.get('targetport')
                            port = keep_tags.clean_text(port)
                            port_description = sd.get('targetbanner')
                            port_description = keep_tags.clean_text(port_description)
                            if "iis" in port_description.lower():
                                os = "Windows"
                            start_time = sd.get('starttime')
                            start_time = keep_tags.clean_text(start_time)
                            statistics = list(sd.iter('statistics'))
                            for stat in statistics:
                                end_time = stat.get('endtime')
                                end_time = keep_tags.clean_text(end_time)

                            start_time = datetime.datetime.strptime(start_time, '%Y-%m-%d %H:%M:%S')
                            end_time = datetime.datetime.strptime(end_time, '%Y-%m-%d %H:%M:%S')

                            # Engagement Device
                            ip = common.format_website(ip)
                            host_name = common.format_website(host_name)
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
                                    (ip, host_name, None, os, mac, None, None, None, None, None,
                                     self.modified_by, self.modified_date, self.tool, self.scope_id))

                                # Open Port.
                                self.open_port_list.append((ip, port, "tcp", port_description, True,
                                                            self.modified_by, self.modified_date, stealth, start_time,
                                                            end_time, 'nikto - ' + self.file_name))


                                #Now get the findings
                                report_items = list(element.iter('item'))
                                for report_item in report_items:
                                    plugin_id = report_item.get('id')
                                    plugin_id = keep_tags.clean_text(plugin_id)
                                    descriptions = list(report_item.iter('description'))

                                    uri = self.remove_tagtext_junk(self.get_xml_tag_text(report_item, "uri"))

                                    full_host_name = self.remove_tagtext_junk(self.get_xml_tag_text(report_item, "namelink"))
                                    if host_name is None:
                                        host_name = ip

                                    title = ""
                                    for d in descriptions:
                                        d_text = d.text
                                        d_text = keep_tags.clean_text(d_text)
                                        if "<![CDATA[" in d_text:
                                            d_text = d_text.replace("<![CDATA[", "")
                                        if "]]>" in d_text:
                                            d_text = d_text.replace("]]>")
                                        if d_text.strip() != "":
                                            title = d_text.strip()
                                            break

                                    if "'" in title:
                                        title = title.replace("'", '"')

                                    # Trying to normalize the title so it does not have target specific information
                                    additional_output = ""
                                    if "Cookie " in title:
                                        additional_output = title[title.find("Cookie"):]
                                        words = title.split()
                                        #del words[1::0]
                                        words.pop(1)
                                        title = " ".join(words)
                                    if "." in title:
                                        additional_output = title[title.find(".") + 1:]
                                        title = title[:title.find(".")]
                                    if ":" in title:
                                        additional_output = title[title.find(":")+1:]
                                        title = title[:title.find(":")]

                                    if "/" in title and title.find("/") == 0:
                                        title = ""

                                    # File/dir '/' in robots.txt returned a non-forbidden or redirect HTTP code (200)k # need to remove '/' from title like did with Cookie

                                    if title is not None and title != "":
                                        # see if osvdid tag name
                                        exploits_available = ""
                                        osvdbid = report_item.get('osvdbid')
                                        osvdbid = keep_tags.clean_text(osvdbid)
                                        if osvdbid != "0":
                                            exploits_available = "OSVDB: " + osvdbid

                                        output = ""
                                        if ", with contents:" in title:
                                            output = title + "\n"
                                            title = title[:title.find(", with contents:")]

                                        # Nikto plugin_ids are not unique, instead a plugin_id in Nikto reference a test group
                                        # checking each entry in robots.txt file has a separate finding or 'item' with same plugin_id
                                        plugin_id = plugin_id + " - " + title # this way it will be unique

                                        # Result
                                        self.result_list.append(['nikto', plugin_id, host_name,
                                                                 port, protocol, "URL: " + full_host_name + "<p>" + output + " " + additional_output,
                                                                 "", start_time, end_time, command, title, title, "", "",
                                                                 "", "", exploits_available, None, self.modified_by])

        except Exception as e:
            print("nikto_parser 227 except: " + str(e) + " Error on line {}".format(sys.exc_info()[-1].tb_lineno))

            if len(self.result_list) == 0:
                log_info = self.db_object.log_record_by_id(self.log_id)
                current_comment = log_info['comment']
                if current_comment is None:
                    current_comment = ""
                update_values = dict(id=self.log_id, comment="You probably are being blacklisted.  Here is the error: " + str(e) + current_comment, parsed=False, failed=True, rerun=True, blacklisted=True)
                self.db_object.update("Log", update_values, ["id"], [self.log_id])


        output_dictionary = {}
        output_dictionary["devices"] = self.engagement_device_list
        output_dictionary["devices_fields_to_update"] = [('os', 'ol'), ('mac', 'c')]
        output_dictionary["results"] = self.result_list
        output_dictionary["results_fields_to_update"] = [('output', 'as'), ('tester_output', 'as')]
        output_dictionary["ports"] = self.open_port_list
        output_dictionary["ports_fields_to_update"] = [('port_description', 'as')]

        return output_dictionary
