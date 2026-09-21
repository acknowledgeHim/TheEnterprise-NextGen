import re, os
import json
import base64
import sys
import datetime
from common import keep_tags, network, common, dns_functions, scope_functions
from setup import engagement_scope
from parsers.parser import Parser


def zap_parser(db_path, db_object, key, hashvals):
    """
    Loop thru hashvals, verify blacklist status, update Log, send to Parser, then finally email notifications out.
    :param db_path:
    :param db_object:
    :param hashvals:
    :return:
    """

    try:
        with Parser("zap", db_object, key, hashvals) as p:
            p.parse("parsers.vuln.web.zap_parser", "ZapParser")

    except Exception as e:
        print("zap_parser 24 except: " + str(e) + " Error on line {}".format(sys.exc_info()[-1].tb_lineno))


class ZapParser():
    """ Parse Zap .xml files. """

    def __init__(self, db_object, location_id, scope_id, file_path_name, ext, just_file_name, target, log_id,
                 output_path, tester_device_list, modified_by, modified_date):
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
            print("zap_parser 50 except: " + str(e) + " Error on line {}".format(sys.exc_info()[-1].tb_lineno))

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
            if self.ext == "txt":
                return self.parse_zap_file()

        except Exception as e:
            print("zap_parser 64 except: " + str(e) + " Error on line {}".format(sys.exc_info()[-1].tb_lineno))

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

    def parse_zap_file(self):
        """
            Parse zap .xml files.  Returns Dictionary of Engagement Devices to Insert/Update
        """

        try:
            engagement_device_list = []
            result_list = []
            deviceport_list = []
            already_found_deviceport = []
            already_found_engagementdevice = []
            with open(self.file_path, 'r') as json_file:
                contents = keep_tags.clean_text(json_file.read())
                data_dict = json.loads(contents)
                alerts = data_dict['alerts']
                for alert in alerts:
                    print("114 zap_parser alert: " + str(alert))
                    confidence = alert['confidence']
                    plugin_id = alert['pluginId']
                    description = alert['description']
                    remediation = alert['solution']
                    title = alert['name']

                    severity = alert['risk'].lower()
                    if severity == "medium":
                        severity = "2"
                    elif severity == "low":
                        severity = "1"
                    elif "ignore" in severity or "information" in severity:
                        severity = "0"
                    elif severity == "high":
                        severity = "3"
                    elif severity == "critical":
                        severity = "4"

                    reference = alert['reference']
                    url = alert['url']
                    evidence = alert['evidence']
                    host_name = common.format_website(url)
                    port = str(network.return_port(url))

                    ip = dns_functions.find_dns_records(host_name)

                    # Check if in scope
                    print("130 zap parser host_name: " + str(host_name))
                    in_scope = engagement_scope.domain_in_scope(self.db_object, host_name)
                    if not in_scope:
                        in_scope = engagement_scope.ip_in_scope(self.db_object, ip)

                    if url != "" and in_scope:
                        tester_output = None
                        if confidence is not None and confidence != "":
                            tester_output = "Confidence Level: " + confidence
                        output = "URL: " + str(url) + "<p>"

                        if evidence != "":
                            output = output + "Evidence: " + str(evidence) + "<p>"
                        if reference != "":
                            output = output + "See also: " + str(reference)

                        # Result
                        self.result_list.append(['zap', plugin_id, host_name, port, "tcp",
                                                 output, tester_output, self.start_time, self.end_time,
                                                 "zap - " + plugin_id + " from " + self.file_name,
                                                 title, description, remediation, None, severity, "",
                                                 "", None, self.modified_by])

                        if port != "0" and ip + port not in already_found_deviceport:
                            # Open port
                            already_found_deviceport.append(ip + port)
                            self.open_port_list.append((ip, port, "tcp", None, True,
                                                        self.modified_by, self.modified_date, False,
                                                        self.start_time, self.end_time, 'zap - ' + self.file_name))

                        # Engagement Device and account for virtual web servers behind a single IP (using reverse proxy)

                        if ip + str(host_name) not in already_found_engagementdevice:
                            if self.curr_scope_id is not None:
                                curr_scope_id = self.curr_scope_id
                            if self.curr_scope_id is None:
                                if network.valid_ip(ip):
                                    for scope_ip in self.scope_ips:
                                        if network.check_in_network(scope_ip, ip):
                                            curr_scope_id = self.scope_ip_dictionary[scope_ip]
                                            break
                            if curr_scope_id is not None:
                                already_found_engagementdevice.append(ip + str(host_name))
                                self.engagement_device_list.append((ip, host_name, None, None, None, None, None, None, None,
                                                                None, self.modified_by,
                                                                self.modified_date, self.tool, curr_scope_id))
        except Exception as e:
            print("150 zap_parser except: " + str(e) + " Error on line {}".format(sys.exc_info()[-1].tb_lineno))

        output_dictionary = {}
        output_dictionary["devices"] = self.engagement_device_list
        output_dictionary["devices_fields_to_update"] = [('os', 'ol'), ('mac', 'c')]
        output_dictionary["results"] = self.result_list
        output_dictionary["results_fields_to_update"] = [('finding_description', 'c')]
        output_dictionary["ports"] = self.open_port_list
        output_dictionary["ports_fields_to_update"] = [('port_description', 'as')]
        print("185 zap parser output_dictionary: " + str(output_dictionary))
        return output_dictionary


