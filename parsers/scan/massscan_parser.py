import re, os
import sys
import datetime
from itertools import islice
from lxml import etree
from common import keep_tags, network, print_text, scope_functions
from parsers. parser import Parser
from parsers.finding_for_open_port import OpenPortFinding

def massscan(db_path, db_object, key, hashvals):
    """
    Loop thru hashvals, verify blacklist status, update Log, send to Parser, then finally email notifications out.
    :param db_path:
    :param db_object:
    :param hashvals:
    :return:
    """
    try:
        with Parser("massscan", db_object, key, hashvals) as p:
            p.parse("parsers.scan.massscan_parser", "MassScanParser")

    except Exception as e:
        print("massscan_parser 73 except: " + str(e) + " Error on line {}".format(sys.exc_info()[-1].tb_lineno))


class MassScanParser():
    """ Parse MassScan files. """
    def __init__(self, db_object, location_id, scope_id, file_path_name, ext, just_file_name, target, log_id, output_path, tester_device_list, modified_by, modified_date):

        if "/" in target:
            target = target.replace("/", "_")
        self.db_object = db_object
        self.output_path = output_path
        self.location_id = location_id
        self.scope_id = scope_id
        self.tool = "massscan"
        self.target = target
        self.log_id = log_id
        self.ext = ext
        self.tester_device_list = tester_device_list
        self.file_path = file_path_name
        self.file_name = just_file_name
        self.modified_by = modified_by
        self.modified_date = modified_date

        self.already_found_result = []

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

    def __enter__(self):
        return self

    def __exit__(self, type, value, traceback):
        return self

    def parse(self):
        try:
            self.engagement_device_list = []
            self.open_port_list = []
            self.result_list = []
            self.already_found_internet_accessible_login = []
            self.stealth = False

            if self.ext == "xml":
                return self.parse_xml()

        except Exception as e:
            print("massscan_parser 93 except: " + str(e) + " Error on line {}".format(sys.exc_info()[-1].tb_lineno))

        return None, None, None, None, None, None

    def parse_xml(self):
        """ Parse MassScan xml files. """
        try:
            # check if massscan ran as stealth
            with open(self.file_path) as massscanfile:
                head_of_massscanfile = list(islice(massscanfile, 10))
                for line in head_of_massscanfile:
                    match = re.search(r"-T0|-T1|-T2", line)
                    if match:
                        self.stealth = True
                        break

            self.parse_xml_engagementdevice()

            output_dictionary = {}
            output_dictionary["devices"] = self.engagement_device_list
            output_dictionary["devices_fields_to_update"] = [('os', 'c'), ('mac', 'c')]
            output_dictionary["results"] = self.result_list
            output_dictionary["results_fields_to_update"] = [('output', 'as'), ('tester_output', 'as')]
            output_dictionary["ports"] = self.open_port_list
            output_dictionary["ports_fields_to_update"] = [('port_description', 'c')]

            return output_dictionary
        except Exception as e:
            print("massscan_parser 91 except: " + str(e) + " Error on line {}".format(sys.exc_info()[-1].tb_lineno))
            return {}

    def parse_xml_engagementdevice(self):
        """Parse MassScan .xml files.  Returns Dictionary of Engagement Devices to Insert/Update"""
        try:
            with open(self.file_path, 'rb') as xml_file:
                massscan_command = ""
                xml_file.seek(0)
                for _, element in etree.iterparse(xml_file, tag='host'):
                    host_name = ""
                    ip = None
                    osmatch = None
                    mac = None
                    addresses = list(element.iter('address'))
                    for address_node in addresses:
                        try:
                            addr_type = address_node.get('addrtype')
                            if addr_type.lower() == "mac":
                                mac = address_node.get('addr')
                                mac = keep_tags.clean_text(mac)
                            else:
                                ip = address_node.get('addr')
                        except Exception as e:
                            print("massscan_parser 120 except: " + str(e) + " Error on line {}".format(sys.exc_info()[-1].tb_lineno))
                            ip = address_node.get('addr')
                            break

                    ip = keep_tags.clean_text(ip)

                    if network.valid_ip(ip) and ip not in self.tester_device_list:
                        protocol = "tcp"
                        #get all open ports for current target
                        open_port = False

                        ports = list(element.iter('port'))
                        for port_node in ports:
                            state = "filtered"
                            service = "tcpwrapped"
                            product = ""
                            version = ""
                            states = list(port_node.iter('state'))
                            for state_node in states:
                                state = state_node.get('state')
                                state = keep_tags.clean_text(state)
                            if state.lower().strip() == "open":
                                protocol = port_node.get('protocol')
                                protocol = keep_tags.clean_text(protocol)
                                port = port_node.get('portid')
                                port = keep_tags.clean_text(port).rstrip().lstrip()
                                services = list(port_node.iter('service'))

                                for service_node in services:
                                    service = service_node.get('name')
                                    service = keep_tags.clean_text(service)

                                    if "tcpwrapped" not in service.lower():
                                        product = service_node.get('product')
                                        product = keep_tags.clean_text(product)
                                        if product is None:
                                            product = ""
                                        version = service_node.get('version')
                                        version = keep_tags.clean_text(version)
                                        if version is None:
                                            version = ""
                                        service = str(service) + " " + str(product) + " " + str(version)

                                    if "tcpwrapped" not in service.lower():
                                        full_description = str(service).strip()

                                        start_time = keep_tags.clean_text(element.get('starttime'))
                                        start_time = datetime.datetime.fromtimestamp(float(start_time))

                                        end_time = keep_tags.clean_text(element.get('endtime'))
                                        end_time = datetime.datetime.fromtimestamp(float(end_time))

                                        validated = network.nc_verify(ip, port, protocol.lower())

                                        self.open_port_list.append(
                                            (ip.strip().lstrip(), port.strip().lstrip(), protocol, full_description, validated,
                                             self.modified_by, self.modified_date,
                                             self.stealth, start_time, end_time, self.tool + " - " + self.file_path))
                                        open_port = True

                                    # Check for Findings / Results
                                    with OpenPortFinding(self.db_object, self.modified_by, self.scope_id, self.location_id) as open_port_finding:
                                        already_found_internet_accessible_login, result_list = open_port_finding.open_services_finding_result(
                                            self.already_found_result, self.result_list, ip, port, protocol,
                                            full_description, start_time, end_time, "massscan")

                                        if already_found_internet_accessible_login is not None:
                                            self.already_found_internet_accessible_login = already_found_internet_accessible_login
                                        if result_list is not None:
                                            self.result_list = result_list

                        if open_port is True:
                            #Only add Engagement Device if it has an open port
                            host_name = ip

                            osmatch = ""

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
                                    (ip, host_name, None, osmatch, mac, "", "", "", "", "",
                                    self.modified_by, self.modified_date, self.tool + " - " + self.file_path, curr_scope_id))

        except Exception as e:
            print("massscan_parser_xml 219 except: " + str(e) + " Error on line {}".format(sys.exc_info()[-1].tb_lineno))
            return None, None

