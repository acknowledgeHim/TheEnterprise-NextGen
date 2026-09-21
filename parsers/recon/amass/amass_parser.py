import re
import json
import sys
import datetime
from common import keep_tags, network, print_text
from parsers import models_to_dictionary
from parsers.parser import Parser

def amass(db_path, db_object, key, hashvals):
    """
    Loop thru hashvals, verify blacklist status, update Log, send to Parser, then finally email notifications out.
    :param db_path:
    :param db_object:
    :param hashvals:
    :return:
    """
    try:
        with Parser("amass", db_object, key, hashvals, False) as p:
            p.parse("parsers.recon.amass.amass_parser", "AmassParser")

    except Exception as e:
        print("amass_parser 23 except: " + str(e) + " Error on line {}".format(sys.exc_info()[-1].tb_lineno))


class AmassParser():
    """ Parse AmassParser files. """
    def __init__(self, db_object, location_id, scope_id, file_path_name, ext, just_file_name, target, log_id, output_path, tester_device_list, modified_by, modified_date):
        if "/" in target:
            target = target.replace("/", "_")
        self.db_object = db_object
        self.output_path = output_path
        self.location_id = location_id
        self.scope_id = scope_id
        scope_e = db_object.view("Scope", ['entry'], ['id'], [str(self.scope_id)])
        self.scope_entry = scope_e[0]['entry']
        print("35 amass_parser self.scope_entry: " + str(self.scope_entry))
        self.target = target
        self.log_id = log_id
        self.log_info = self.db_object.view("Log",[],['id'], [log_id], True)[0]
        self.tool = self.log_info['source']
        self.ext = ext
        self.tester_device_list = tester_device_list
        self.file_path = file_path_name
        self.file_name = just_file_name
        self.modified_by = modified_by
        self.modified_date = modified_date

        self.scope_ips = models_to_dictionary.scope_dict(db_object, "IP")
        self.scope_domains = models_to_dictionary.scope_dict(db_object, "DOMAIN")

    def __enter__(self):
        return self

    def __exit__(self, type, value, traceback):
        return self

    def parse(self):
        """ Parse .json & .do files. """
        try:
            self.recon_list = []
            if self.ext == "json":
                self.parse_json_file()
                output_dictionary = {}
                output_dictionary["recon"] = self.recon_list
                output_dictionary["recon_fields_to_update"] = [('info', 'as'), ('associated_info', 'as'),
                                                               ('description', 'as')]
                return output_dictionary
            elif self.ext == "do":
                self.parse_do_file()
                output_dictionary = {}
                output_dictionary["recon"] = self.recon_list
                output_dictionary["recon_fields_to_update"] = [('info', 'as'), ('associated_info', 'as'), ('description', 'as')]
                return output_dictionary
            else:
                print_text.print_error("Unsupported file for parsing found, skipping it!")
                return {}
        except Exception as e:
            print("amass parser 139 except: " + str(e) + " Error on line {}".format(sys.exc_info()[-1].tb_lineno))
        return {}

    def parse_do_file(self):
        with open(self.file_path) as amass_file:
            amass_results = amass_file.readlines()
            for record_amass in amass_results:
                record = json.loads(record_amass)
                if isinstance(record, dict):
                    record_type = ""
                    name = ""
                    domain = ""
                    service = ""
                    target_name = ""
                    target_domain = ""
                    addr = ""
                    asn = ""
                    cidr = ""
                    desc = ""
                    tag = ""
                    source = ""
                    timestamp = self.modified_date
                    if "type" in record:
                        record_type = record['type']
                    if "name" in record:
                        name = record['name']
                    if "domain" in record:
                        domain = record['domain']
                    if "service" in record:
                        service = record['service']
                    if "target_name" in record:
                        target_name = record['target_name']
                    if "target_domain" in record:
                        target_domain = record['target_domain']
                    if "addr" in record:
                        addr = record['addr']
                    if "asn" in record:
                        asn = record['asn']
                    if "cidr" in record:
                        cdir = record['cidr']
                    if "desc" in record:
                        desc = record['desc']
                    if "tag" in record:
                        tag = record['tag']
                    if "source" in record:
                        source = record['source']

                    if record_type == "domain" and self.scope_entry in domain:
                        self.recon_list.append([self.scope_id, "DOMAIN", domain, service, addr, desc, "",
                                           self.tool + "(" + source + ")", self.modified_by, timestamp])
                    elif record_type == "ns":
                        if target_domain == "":
                            target_domain = domain
                        self.recon_list.append([self.scope_id, "NS", target_name, "For Domain: " + target_domain, addr, desc, "",
                                           self.tool + "(" + source + ")", self.modified_by, timestamp])
                    elif record_type == "a" and name != "" and self.scope_entry in domain:
                        self.recon_list.append(
                            [self.scope_id, "DOMAIN", name, service, addr, desc, "",
                             self.tool + "(" + source + ")", self.modified_by, timestamp])
                    elif record_type == "infractructure" and asn != "":
                        self.recon_list.append(
                            [self.scope_id, "ASN", asn, "CIDR: " + cidr, addr, desc, "",
                             self.tool + "(" + source + ")", self.modified_by, timestamp])
                    elif record_type == "aaaa" and name != "" and self.scope_entry in domain:
                        self.recon_list.append(
                            [self.scope_id, "DOMAIN", name, service, addr, desc, "",
                             self.tool + "(" + source + ")", self.modified_by, timestamp])

    def parse_json_file(self):
        try:
            with open(self.file_path) as amass_file:
                timestamp = self.modified_date
                amass_results = amass_file.readlines()
                for record_amass in amass_results:
                    record = json.loads(record_amass)
                    if isinstance(record, dict):
                        record_type = ""
                        name = ""
                        domain = ""
                        service = ""
                        addr = ""
                        asn = ""
                        cidr = ""
                        desc = ""
                        source = ""
                        if "name" in record:
                            name = record['name']
                        if "domain" in record:
                            domain = record['domain']
                        if "source" in record:
                            source = record['source']
                        if timestamp == "":
                            timestamp = self.modified_date
                        if "addresses" in record:
                            addresses = record['addresses']
                            sep = ""
                            for address in addresses:
                                if addr != "":
                                    sep = ", "
                                addr = addr + sep + address['ip']
                                if "asn" in address:
                                    asn = address['asn']
                                if "cidr" in address:
                                    tmp_cidr = address['cidr']
                                    if isinstance(tmp_cidr, dict) and "IP" in tmp_cidr:
                                        cidr = tmp_cidr['IP']
                                        if "Mask" in tmp_cidr:
                                            cidr = cidr + "/" + tmp_cidr['Mask']
                                if "desc" in address:
                                    desc = address['desc']
                                if asn != "":
                                    self.recon_list.append(
                                        [self.scope_id, "ASN", asn, "CIDR: " + cidr, addr, desc, "",
                                        self.tool + "(" + source + ")", self.modified_by, timestamp])

                        if name != "":
                            self.recon_list.append([self.scope_id, "DOMAIN", name, service, addr, desc, "",
                                               self.tool + "(" + source + ")", self.modified_by, timestamp])
        except Exception as e:
            print("amass parser 193 except: " + str(e) + " Error on line {}".format(sys.exc_info()[-1].tb_lineno))