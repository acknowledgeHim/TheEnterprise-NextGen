import re
import os
import sys
import datetime
from itertools import islice
from lxml import etree
from common import keep_tags, network, print_text
from common import scope_functions
from parsers. parser import Parser
from parsers.finding_for_open_port import OpenPortFinding

def nmap(db_path, db_object, key, hashvals):
    """
    Loop thru hashvals, verify blacklist status, update Log, send to Parser, then finally email notifications out.
    :param db_path:
    :param db_object:
    :param hashvals:
    :return:
    """
    try:
        with Parser("nmap", db_object, key, hashvals) as p:
            p.parse("parsers.scan.nmap_parser", "NmapParser")

    except Exception as e:
        print("nmap_parser 73 except: " + str(e) + " Error on line {}".format(sys.exc_info()[-1].tb_lineno))


class NmapParser():
    """ Parse Nmap files. """
    def __init__(self, db_object, location_id, scope_id, file_path_name, ext, just_file_name, target, log_id, output_path, tester_device_list, modified_by, modified_date):

        if "/" in target:
            target = target.replace("/", "_")
        self.db_object = db_object
        self.output_path = output_path
        self.location_id = location_id
        self.scope_id = scope_id
        self.tool = "nmap"
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

    def script_lookup(self, result_list, ip, protocol, id, output):
        if id == "sniffer-detect" and 'Likely in promiscuous mode (tests: "11111111")' in output:
            result_list.append("nmap", "nmap_sniffer_detect", ip, "0", protocol, output, None,
                               self.modified_date, self.modified_date, "nmap -Pn -vv --script=sniffer-detect",
                               "Device had network interface card in promiscuous mode", None, None, None, None, None,
                               None, None, self.modified_by)

        return result_list

    def parse(self):
        try:
            self.engagement_device_list = []
            self.open_port_list = []
            self.result_list = []
            self.already_found_internet_accessible_login = []
            self.stealth = False

            if self.ext == "xml":
                return self.parse_xml()
            elif self.ext == "gnmap":
                return self.parse_gnmap()

        except Exception as e:
            print("nmap_parser 93 except: " + str(e) + " Error on line {}".format(sys.exc_info()[-1].tb_lineno))

        return None, None, None, None, None, None

    def parse_xml(self):
        """ Parse Nmap xml files. """
        try:
            # check if nmap ran as stealth
            with open(self.file_path) as nmapfile:
                head_of_nmapfile = list(islice(nmapfile, 10))
                for line in head_of_nmapfile:
                    match = re.search(r"-T0|-T1|-T2", line)
                    if match:
                        self.stealth = True
                        break

            self.parse_xml_engagementdevice()

            output_dictionary = {}
            output_dictionary["devices"] = self.engagement_device_list
            output_dictionary["devices_fields_to_update"] = [('os', 'ol'), ('mac', 'c')]
            output_dictionary["results"] = self.result_list
            output_dictionary["results_fields_to_update"] = [('output', 'as'), ('tester_output', 'as')]
            output_dictionary["ports"] = self.open_port_list
            output_dictionary["ports_fields_to_update"] = [('port_description', 'as')]

            return output_dictionary
        except Exception as e:
            print("nmap_parser 91 except: " + str(e) + " Error on line {}".format(sys.exc_info()[-1].tb_lineno))
            return {}

    def parse_xml_engagementdevice(self):
        """Parse Nmap .xml files.  Returns Dictionary of Engagement Devices to Insert/Update"""
        try:
            with open(self.file_path, 'rb') as xml_file:
                nmap_command = ""
                ignore_description = False
                xml_file.seek(0)
                for _, element in etree.iterparse(xml_file, tag='nmaprun'):
                    nmap_command = element.get("args")
                if " -A " not in nmap_command and " -sV " not in nmap_command and " -O " not in nmap_command:
                    ignore_description = True
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
                            print("nmap_parser 120 except: " + str(e) + " Error on line {}".format(sys.exc_info()[-1].tb_lineno))
                            ip = address_node.get('addr')
                            break

                    try:
                        elems = list(element.iter('elem'))
                        for elem in elems:
                            try:
                              key = elem.get('key')
                              if key == "DNS_DOMAIN_NAME":
                                  host_name = elem.text
                            except:
                                pass
                    except:
                        pass

                    ip = keep_tags.clean_text(ip).strip().lstrip()
                    in_scope = False
                    scope_ips = self.db_object.view("Scope", ['entry'], ['type'], ['IP'])
                    for sip in scope_ips:
                        s_ip = sip['entry']
                        if network.check_in_network(s_ip, ip):
                            in_scope = True
                            break

                    if network.valid_ip(ip) and ip not in self.tester_device_list and in_scope:
                        protocol = "tcp"
                        #get all open ports for current target
                        open_port = False
                        scripts = list(element.iter('script'))
                        for script_node in scripts:
                            id = script_node.get('id')
                            output = script_node.get('output')
                            output = keep_tags.clean_text(output)
                            result_list = self.script_lookup(self.result_list, ip, protocol, id, output)

                            if result_list is not None:
                                self.result_list = result_list

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
                                            (ip, port.strip().lstrip(), protocol, full_description, validated,
                                             self.modified_by, self.modified_date,
                                             self.stealth, start_time, end_time, self.tool + " - " + self.file_path))
                                        open_port = True

                                    # Check for Findings / Results
                                    with OpenPortFinding(self.db_object, self.modified_by, self.scope_id, self.location_id) as open_port_finding:
                                        already_found_internet_accessible_login, result_list = open_port_finding.open_services_finding_result(
                                            self.already_found_result, self.result_list, ip, port, protocol,
                                            full_description, start_time, end_time, "nmap")

                                        if already_found_internet_accessible_login is not None:
                                            self.already_found_internet_accessible_login = already_found_internet_accessible_login
                                        if result_list is not None:
                                            self.result_list = result_list

                        if open_port is True:
                            #Only add Engagement Device if it has an open port
                            host_names = list(element.iter('hostname'))
                            for hostname_node in host_names:
                                host_name = hostname_node.get('name')
                                host_name = keep_tags.clean_text(host_name)
                                if host_name != "":
                                    break
                            if host_name == "":
                                host_name = ip
                            elif ip is not None and ip != "" and network.valid_ip(ip):
                                # Check to see if host_name is just ISP concatonated name
                                dash_ip = ip.replace(".", "-")
                                if dash_ip in host_name:
                                    host_name = ip
                                else:
                                    ip_parts = list(reversed(ip.split(".")))
                                    reverse_ip = ".".join(ip_parts)
                                    if reverse_ip.replace(".", "-") in host_name:
                                        host_name = ip
                                    elif reverse_ip in host_name:
                                        host_name = ip

                            osmatches = list(element.iter('osmatch'))
                            for osmatch_node in osmatches:
                                try:
                                    os_name = osmatch_node.get("name")
                                    os_name = keep_tags.clean_text(os_name)
                                    confidence_level = osmatch_node.get("accuracy")
                                    confidence_level = keep_tags.clean_text(confidence_level)
                                    osmatch = os_name + " (" + confidence_level + "%)"
                                    break
                                except:
                                    osmatch = None
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
                                (ip, host_name, None, osmatch, mac, None, None, None, None, None,
                                 self.modified_by, self.modified_date, self.tool + " - " + self.file_path, curr_scope_id))

        except Exception as e:
            print("nmap_parser_xml 219 except: " + str(e) + " Error on line {}".format(sys.exc_info()[-1].tb_lineno))
            return None, None

    def parse_gnmap(self):
        """ Setup parsing Nmap .gnmap files. """
        try:
            self.parse_nmap_gnmap_engagementdevice()

            output_dictionary = {}
            output_dictionary["devices"] = self.engagement_device_list
            output_dictionary["devices_fields_to_update"] = [('os', 'ol')]
            output_dictionary["results"] = self.result_list
            output_dictionary["results_fields_to_update"] = [('output', 'as'), ('tester_output', 'as')]
            output_dictionary["ports"] = self.open_port_list
            output_dictionary["ports_fields_to_update"] = [('port_description', 'as')]

            return output_dictionary
        except:
            return {}

    def parse_nmap_gnmap_engagementdevice(self):
        """Parse Nmap .gnmap files.  Returns Dictionary of Engagement Devices to Insert/Update"""
        try:
            with open(self.file_path) as nmap_file:
                ignore_description = False
                for line in nmap_file:
                    if "Ports:" in line and "Host:" in line:
                        host = line[line.find("Host: ") + 6:]

                        ip = host[:host.find(" ")]
                        ip = keep_tags.clean_text(ip).strip()

                        in_scope = False
                        scope_ips = self.db_object.view("Scope", ['entry'], ['type'], ['IP'])
                        for sip in scope_ips:
                            s_ip = sip['entry']
                            if network.check_in_network(s_ip, ip):
                                in_scope = True
                                break

                        if network.valid_ip(ip) and ip not in self.tester_device_list and in_scope:
                            host_name = host[:host.find(")")]
                            host_name = host_name[host_name.find("(") + 1:]
                            host_name = keep_tags.clean_text(host_name)
                            if host_name == "":
                                host_name = ip
                            else:
                                # Check to see if host_name is just ISP concatonated name
                                tmp = ip.replace(".", "-")
                                if tmp in host_name:
                                    host_name = ip

                            open_port = False
                            portstr = line[line.find("Ports: ") + 7:]
                            portstr = keep_tags.clean_text(portstr)
                            ports = portstr.split(",")
                            for portinfo in ports:
                                infopart = portinfo.split("/")
                                if len(infopart) > 5:
                                    port = infopart[0].rstrip().lstrip()
                                    status = infopart[1]
                                    protocol = infopart[2]
                                    full_description = infopart[5]

                                    if "closed" not in status.lower() and "open" in status.lower() and "filtered" not in status.lower() and "wrapped" not in status.lower():
                                        try:
                                            validated = network.nc_verify(ip, port, protocol.lower())
                                            full_description = full_description.strip()
                                            #if ignore_description:
                                            #    full_description = ""
                                            self.open_port_list.append(
                                                 (ip.strip().lstrip(), port.strip().lstrip(), protocol, full_description, validated, self.modified_by,
                                                  self.modified_date, False, self.modified_date, self.modified_date,
                                                  self.tool + " - " + self.file_path))
                                            open_port = True

                                            # Check for Findings / Results
                                            with OpenPortFinding(self.db_object, self.modified_by, self.scope_id, self.location_id) as open_port_finding:
                                                already_found_internet_accessible_login, result_list = open_port_finding.open_services_finding_result(self.already_found_result, self.result_list, ip, port, protocol, full_description, None, None, "nmap")
                                            if already_found_internet_accessible_login is not None:
                                                self.already_found_internet_accessible_login = already_found_internet_accessible_login
                                            if result_list is not None:
                                                self.result_list = result_list
                                        except AttributeError as e:
                                            print("nmap_parser_gnmap except: " + str(e) + " Error on line {}".format(
                                                sys.exc_info()[-1].tb_lineno))
                                            pass
                                        except Exception as e:
                                            print("nmap_parser_gnmap except: " + str(e) + " Error on line {}".format(
                                                sys.exc_info()[-1].tb_lineno))
                            if open_port is True:
                                if self.curr_scope_id is not None:
                                    curr_scope_id = self.curr_scope_id
                                if self.curr_scope_id is None:
                                    if network.valid_ip(ip):
                                        for scope_ip in self.scope_ips:
                                            if network.check_in_network(scope_ip, ip):
                                                curr_scope_id = self.scope_ip_dictionary[scope_ip]
                                                break
                                if curr_scope_id is not None:
                                    self.engagement_device_list.append((ip, host_name, None, None, None, None, None,
                                                            None, None, None, self.modified_by, self.modified_date,
                                                            self.tool + " - " + self.file_path, curr_scope_id))
        except Exception as e:
            print("nmap_parser_gnmap except: " + str(e) + " Error on line {}".format(sys.exc_info()[-1].tb_lineno))
            return None, None
        return self.engagement_device_list, self.open_port_list

