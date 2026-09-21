import re
import sys, os
import datetime
from itertools import islice
from lxml import etree
from common import keep_tags, network, print_text, scope_functions
from parsers. parser import Parser

def ping(db_path, db_object, key, hashvals):
    """
    Loop thru hashvals, verify blacklist status, update Log, send to Parser, then finally email notifications out.
    :param db_path:
    :param db_object:
    :param hashvals:
    :return:
    """
    try:
        with Parser("nmap", db_object, key, hashvals) as p:
            p.parse("parsers.scan.ping_parser", "PingParser")

    except Exception as e:
        print("nmap_ping_parser 23 except: " + str(e) + " Error on line {}".format(sys.exc_info()[-1].tb_lineno))


class PingParser():
    """ Parse Nmap ping files. """
    def __init__(self, db_object, location_id, scope_id, file_path_name, ext, just_file_name, target, log_id, output_path, tester_device_list, modified_by, modified_date):

        if "/" in target:
            target = target.replace("/", "_")
        self.db_object = db_object
        self.output_path = output_path
        self.location_id = location_id
        self.scope_id = scope_id
        self.tool = "nmap ping"
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

    def __enter__(self):
        return self

    def __exit__(self, type, value, traceback):
        return self

    def parse(self):
        try:
            self.engagement_device_list = []
            if self.ext == "xml":
                return self.parse_xml()
            elif self.ext == "gnmap":
                return self.parse_gnmap()

        except Exception as e:
            print("nmap_ping_parser 93 except: " + str(e) + " Error on line {}".format(sys.exc_info()[-1].tb_lineno))

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
            output_dictionary["devices_fields_to_update"] = [('info', 'as'), ('mac', 'c')]

            return output_dictionary
        except Exception as e:
            print("nmap_ping_parser 91 except: " + str(e) + " Error on line {}".format(sys.exc_info()[-1].tb_lineno))
            return {}

    def parse_xml_engagementdevice(self):
        """Parse Nmap .xml files.  Returns Dictionary of Engagement Devices to Insert/Update"""
        try:
            with open(self.file_path, 'rb') as xml_file:
                for _, element in etree.iterparse(xml_file, tag='host'):
                    host_name = ""
                    ip = None
                    mac_vendor = None
                    mac = None
                    info = None
                    addresses = list(element.iter('address'))
                    for address_node in addresses:
                        try:
                            addr_type = address_node.get('addrtype')
                            if addr_type.lower() == "mac":
                                mac = address_node.get('addr')
                                mac = keep_tags.clean_text(mac)
                                mac_vendor = address_node.get('vendor')
                            else:
                                ip = address_node.get('addr')
                        except Exception as e:
                            print("nmap_ping_parser 120 except: " + str(e) + " Error on line {}".format(sys.exc_info()[-1].tb_lineno))
                            ip = address_node.get('addr')
                            break

                    if network.valid_ip(ip) and ip not in self.tester_device_list:
                        if mac_vendor is not None:
                            info = "MAC Vendor: " + mac_vendor
                        ip = keep_tags.clean_text(ip)

                        host_names = list(element.iter('hostname'))
                        for hostname_node in host_names:
                            host_name = hostname_node.get('name')
                            host_name = keep_tags.clean_text(host_name)
                            if host_name != "":
                                break
                        if host_name == "":
                            host_name = ip

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
                                (ip, host_name, None, None, mac, None, info, None, None, None,
                                 self.modified_by, self.modified_date, self.tool, curr_scope_id))
        except Exception as e:
            print("nmap_ping_parser_xml 219 except: " + str(e) + " Error on line {}".format(sys.exc_info()[-1].tb_lineno))
            return None, None

    def parse_gnmap(self):
        """ Setup parsing Nmap .gnmap files. """
        try:
            self.parse_nmap_gnmap_engagementdevice()

            output_dictionary = {}
            output_dictionary["devices"] = self.engagement_device_list
            output_dictionary["devices_fields_to_update"] = [('info', 'c')]

            return output_dictionary
        except:
            return {}

    def parse_nmap_gnmap_engagementdevice(self):
        """Parse Nmap .gnmap files.  Returns Dictionary of Engagement Devices to Insert/Update"""
        try:
            with open(self.file_path) as nmap_file:
                for line in nmap_file:
                    if "Status: Up" in line and "Host:" in line:
                        host = line[line.find("Host: ") + 6:]

                        ip = host[:host.find(" ")]
                        ip = keep_tags.clean_text(ip)
                        if network.valid_ip(ip) and ip not in self.tester_device_list:
                            host_name = host[:host.find(")")]
                            host_name = host_name[host_name.find("(") + 1:]
                            host_name = keep_tags.clean_text(host_name)
                            if host_name == "":
                                host_name = ip

                            self.engagement_device_list.append((ip, host_name, None, None, None, None, None,
                                                        None, None, None, self.modified_by,
                                                        self.modified_date, self.file_name, self.scope_id))
        except Exception as e:
            print("nmap_ping_parser_gnmap except: " + str(e) + " Error on line {}".format(sys.exc_info()[-1].tb_lineno))
            return None, None
        return self.engagement_device_list

