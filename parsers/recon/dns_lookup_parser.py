import re
import sys
import datetime
from common import keep_tags, network, print_text
from parsers. parser import Parser

def dns(db_path, db_object, key, hashvals):
    """
    Loop thru hashvals, verify blacklist status, update Log, send to Parser, then finally email notifications out.
    :param db_path:
    :param db_object:
    :param hashvals:
    :return:
    """
    try:
        with Parser("dns lookup", db_object, key, hashvals, False) as p:
            p.parse("parsers.recon.dns_lookup_parser", "DNSQueryParser")

    except Exception as e:
        print("dns_parser 23 except: " + str(e) + " Error on line {}".format(sys.exc_info()[-1].tb_lineno))


class DNSQueryParser():
    """ Parse DNSQueryParser files. """
    def __init__(self, db_object, location_id, scope_id, file_path_name, ext, just_file_name, target, log_id, output_path, tester_device_list, modified_by, modified_date):

        if "/" in target:
            target = target.replace("/", "_")
        self.db_object = db_object
        self.output_path = output_path
        self.location_id = location_id
        self.scope_id = scope_id
        self.tool = "dns lookup"
        self.target = target
        self.log_id = log_id
        self.ext = ext
        self.tester_device_list = tester_device_list
        self.file_path = file_path_name
        self.file_name = just_file_name
        self.modified_by = modified_by
        self.modified_date = modified_date

        domain = self.file_path[self.file_path.rfind("__") + 2:]
        self.domain = domain[:domain.rfind(".txt")]

    def __enter__(self):
        return self

    def __exit__(self, type, value, traceback):
        return self

    def parse(self):
        """ Parse .txt files. """
        try:
            if self.ext == "txt":
                people_list = []
                recon_list = []
                result_list = []
                engagement_device = []
                spf_record = None
                dkim_record = None
                dmarc_record = None
                spf_allow_all = ""
                spf_soft_fail = ""
                spf_neutral = ""
                with open(self.file_path, 'r') as domain_file:
                    for record in domain_file:
                        if '"' in record:
                            record = record.replace('"', '')
                        part = record.split("\t")
                        if "\tTXT\t" in record:
                            record_recon = True
                            if "v=spf" in part[2]:
                                record_recon = False
                                if " all" in part[2] or " +all" in part[2]:
                                    spf_allow_all = spf_allow_all + part[2].replace('"', '') + "\n"
                                elif " ~all" in part[2]:
                                    spf_soft_fail = spf_soft_fail + part[2].replace('"', '') + "\n"
                                elif " ?all" in part[2]:
                                    spf_neutral = spf_neutral + part[2].replace('"', '') + "\n"
                                if spf_record is None:
                                    spf_record = part
                                    spf_record[1] = "SPF"
                                else:
                                    spf_record[2] = spf_record[2] + "; " + part[2].replace('"', '')
                            elif "k=rsa" in part[2]:
                                record_recon = False
                                if dkim_record is None:
                                    dkim_record = part
                                    dkim_record[1] = "DKIM"
                                else:
                                    dkim_record[2] = dkim_record[2] + "; " + part[2].replace('"', '')
                            elif "v=dmarc" in part[2]:
                                record_recon = False
                                if dmarc_record is None:
                                    dmarc_record = part
                                    dmarc_record[1] = "DMARC"
                                else:
                                    dmarc_record[2] = dmarc_record[2] + "; " + part[2].replace('"', '')
                            if record_recon:
                                recon_list.append(record.split("\t") + [self.modified_by, self.modified_date])
                        elif "\tvendor\t" in record:
                            parts = record.split("\t")
                            location_id = self.db_object.grab_column_from_single_record("Scope", ["id"], [parts[0]], "location_id")
                            people_list.append([location_id, None, None, "ISP", None, None, parts[2], None, None, None, True, False,
                                 self.tool, self.modified_by, self.modified_date])
                        else:
                            recon_list.append(record.split("\t") + [self.modified_by, self.modified_date])

                        if "Valid Domain Date Range" in part[5]:
                            expires_soon = datetime.datetime.today() + datetime.timedelta(weeks=12) # 3 months

                            domain_end_date = part[5]
                            domain_end_date = domain_end_date[domain_end_date.rfind(" - ")+3:]
                            domain_end_datetime = datetime.datetime.strptime(domain_end_date, "%Y-%m-%d")

                            if domain_end_datetime < datetime.datetime.combine(expires_soon, datetime.datetime.min.time()):
                                engagement_device.append([None, self.domain, "", "", "", "", "", "", "", "",
                                        self.modified_by, self.modified_date, self.tool, self.scope_id])
                                result_list.append(["dns lookup", "dns_lookup-domain_expires_soon", self.domain, "53", "tcp",
                                     "Registration expires : " + domain_end_date, "", "", "", "equivalent cmd: dig " + self.domain,
                                     "Domain expires soon", "", "", "", "", "", "", "", self.modified_by])

                if dmarc_record is None:
                    engagement_device.append([None, self.domain, "", "", "", "", "", "", "", "",
                         self.modified_by, self.modified_date, self.tool, self.scope_id])
                    result_list.append(["dns lookup", "dns_lookup-noDMARC", self.domain, "53", "tcp",
                                        "Domain does not use DMARC.", "", "", "",
                                        "equivalent cmd: dig -t txt " + self.domain, "Missing DMARC entry for domain",
                                        "", "", "", "", "", "", "", self.modified_by])
                else:
                    recon_list.append(dmarc_record + [self.modified_by, self.modified_date])

                if dkim_record is None:
                    engagement_device.append([None, self.domain, "", "", "", "", "", "", "", "",
                         self.modified_by, self.modified_date, self.tool, self.scope_id])
                    result_list.append(["dns lookup", "dns_lookup-noDKIM", self.domain, "53", "tcp",
                                        "Domain does not use DKIM.", "", "", "",
                                        "equivalent cmd: dig -t txt " + self.domain,
                                        "Missing DKIM entry for domain", "", "", "", "", "", "", "", self.modified_by])
                else:
                    recon_list.append(dkim_record + [self.modified_by, self.modified_date])

                if spf_record is None:
                    engagement_device.append([None, self.domain, "", "", "", "", "", "", "", "",
                                              self.modified_by, self.modified_date, self.tool, self.scope_id])
                    result_list.append(["dns lookup", "dns_lookup-noSPF", self.domain, "53", "tcp",
                                        "Domain does not have an SPF entry.", "", "", "",
                                        "equivalent cmd: dig -t txt " + self.domain,
                                        "Missing SPF entry for domain", "", "", "", "", "", "", "", self.modified_by])
                else:
                    # insert SPF entry(s)
                    recon_list.append(spf_record + [self.modified_by, self.modified_date])

                if spf_allow_all != "":
                    engagement_device.append([None, self.domain, "", "", "", "", "", "", "", "",
                                            self.modified_by, self.modified_date, self.tool, self.scope_id])
                    result_list.append(["dns lookup", "dns_lookup-SPFallowall", self.domain, "53", "tcp",
                                        spf_allow_all, "", "", "", "equivalent cmd: dig " + self.domain,
                                        "Domain's SPF entry has ' all', '+all', or does not have an 'all' entry, which possibly negates SPF", "", "", "", "", "", "", "",
                                        self.modified_by])

                if spf_neutral != "":
                    engagement_device.append([None, self.domain, "", "", "", "", "", "", "", "",
                         self.modified_by, self.modified_date, self.tool, self.scope_id])
                    result_list.append(["dns lookup", "dns_lookup-SPFneutral", self.domain, "53", "tcp",
                         spf_soft_fail, "", "", "", "equivalent cmd: dig " + self.domain,
                         "Domain's SPF entry has neutral '?all' entry, not hard fail '-all'", "", "", "", "", "", "",
                         "", self.modified_by])

                if spf_soft_fail != "":
                    engagement_device.append([None, self.domain, "", "", "", "", "", "", "", "",
                                              self.modified_by, self.modified_date, self.tool, self.scope_id])
                    result_list.append(["dns lookup", "dns_lookup-SPFsoftfail", self.domain, "53", "tcp",
                                        spf_soft_fail, "", "", "", "equivalent cmd: dig " + self.domain,
                                        "Domain's SPF entry has soft fail '~all' entry, not hard fail '-all'", "", "", "", "", "", "", "",
                                        self.modified_by])

                output_dictionary = {}
                output_dictionary["recon"] = recon_list
                output_dictionary["recon_fields_to_update"] = [('info', 'as'), ('associated_info', 'as'), ('description', 'as'),
                                                               ('organization', 'as')]
                output_dictionary["devices"] = engagement_device
                output_dictionary["devices_fields_to_update"] = [('mac', 'c')]
                output_dictionary["person"] = people_list
                output_dictionary["person_fields_to_update"] = [('email', 'c')]
                output_dictionary["results"] = result_list
                output_dictionary["results_fields_to_update"] = [('output', 'as'), ('tester_output', 'as')]

                return output_dictionary
            else:
                print_text.print_error("Unsupported file for parsing found, skipping it!")
                return {}
        except Exception as e:
            print("dns lookup parser 117 except: " + str(e) + " Error on line {}".format(sys.exc_info()[-1].tb_lineno))
        return {}
