import sys
import datetime
from common import keep_tags, network, print_text
from parsers. parser import Parser

def dnsfootprint(db_path, db_object, key, hashvals):
    """
    Loop thru hashvals, verify blacklist status, update Log, send to Parser, then finally email notifications out.
    :param db_path:
    :param db_object:
    :param hashvals:
    :return:
    """
    try:
        with Parser("dnsfootprint", db_object, key, hashvals, False) as p:
            p.parse("parsers.recon.dnsfootprint_parser", "DNSPerlScriptParser")

    except Exception as e:
        print("dnsfootprint_parser 23 except: " + str(e) + " Error on line {}".format(sys.exc_info()[-1].tb_lineno))


class DNSPerlScriptParser():
    """ Parse DNSPerlScriptParser files. """
    def __init__(self, db_object, location_id, scope_id, file_path_name, ext, just_file_name, target, log_id, output_path, tester_device_list, modified_by, modified_date):

        if "/" in target:
            target = target.replace("/", "_")
        self.db_object = db_object
        self.output_path = output_path
        self.location_id = location_id
        self.scope_id = scope_id
        self.tool = "dnsfootprint"
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
                with open(self.file_path, 'r') as domain_file:
                    only_text = domain_file.read()
                    expires_soon = datetime.datetime.today() + datetime.timedelta(weeks=12)  # 3 months
                    try:
                        lines = only_text.split("\n")
                        scope_id = None
                        expiration_date = None
                        dnssec_state = ""
                        mx_server_section = False
                        bruteforced_names_section = False
                        zone_transfer_section = False
                        for line in lines:
                            if scope_id is not None:
                                if "Registry Expiry Date: " in line:
                                    expiration_date = line[line.find("Registry Expiry Date: ") + 22:]
                                    expiration_date = expiration_date[:expiration_date.find("T")]
                                    expires_on = datetime.datetime.strptime(expiration_date, "%Y-%m-%d")
                                    if expires_on < datetime.datetime.combine(expires_soon, datetime.datetime.min.time()):
                                        title = "Domain exipres soon"
                                        plugin_id = "dnsperlscript-dns_expires"
                                        engagement_device.append([None, self.domain, None, None, None, None, None, None,
                                                                  None, None, self.modified_by, self.modified_date,
                                                                  self.file_name, self.scope_id])
                                        result_list.append([self.tool, plugin_id, self.domain, "0",
                                             "tcp", "Domain expires: " + str(expiration_date), "", "", "",
                                             "dig -t " + self.domain, title, "If the domain is not registered on time, "
                                             "a malicious actor may be able to steal the domain to impersonate the owner.",
                                             "Renew the domain before it expires.", "", "medium", "configuration", "",
                                             "", self.modified_by])
                                if "Name Server: " in line:
                                    recon_list.append([self.engagement_id, self.client_id, scope_id, "NS",
                                                       line[line.find("Name Server: ") + 13:].lower(), None, None, None,
                                                       None,
                                                       "dnsperlscript", self.modified_by, self.modified_date])
                                if "DNSSEC: " in line:
                                    dnssec_state = line[line.find("DNSSEC: ") + 8:]
                                    if "unsigned" in dnssec_state:
                                        title = "Domain not using DNSSEC"
                                        plugin_id = "dnsperlscript-no_dnssec"
                                        engagement_device.append([None, self.domain, None, None, None, None, None, None,
                                                                  None, None, self.modified_by, self.modified_date,
                                                                  self.file_name, self.scope_id])
                                        result_list.append([self.tool, plugin_id, self.domain, "0", "tcp",
                                            "DNSSEC state: " + dnssec_state, None, self.modified_date, self.modified_date,
                                            "dig " + self.domain, True, title, "DNSSEC provides security controls "
                                            "(validate authenticity)", "Configure and use DNSSEC.", "", "medium",
                                            "configuration", "", "", self.modified_by])
                                if "*  Mail servers   " in line:
                                    mx_server_section = True
                                if mx_server_section and "." in line:
                                    mx = line
                                    priority = ""
                                    if "\t" in mx:
                                        priority = mx[mx.find("\t") + 1:]
                                        if priority.isnumeric():
                                            priority = "Priority: " + priority
                                        mx = mx[:mx.find("\t")]
                                    recon_list.append([self.scope_id, "MX", mx.lower(), priority, None, None, None,
                                                       "dnsperlscript", self.modified_by, self.modified_date])
                                if "*  SPF record" in line:
                                    mx_server_section = False
                                if "v=spf" in line:
                                    recon_list.append([self.scope_id, "SPF", line.lower(), None, None, None, None,
                                                       "dnsperlscript", self.modified_by, self.modified_date])

                                    if "?all" in line:
                                        engagement_device.append([None, self.domain, None, None, None, None, None, None,
                                                                  None, None, self.modified_by, self.modified_date,
                                                                  self.file_name, self.scope_id])
                                        title = "Neutral SPF termination"
                                        plugin_id = "dnsperlscript-neutral_spf"
                                        result_list.append([self.tool, plugin_id, self.domain, "0", "tcp", line, None,
                                                        self.modified_date, self.modified_date, "dig " + self.domain,
                                                        True, title, "Neutral SPF nullifies SPF.",
                                                        "End all SPF entries with a 'HardFail', -all.", "", "medium",
                                                        "configuration", "", "", self.modified_by])
                                    elif "~all" in line:
                                        engagement_device.append([None, self.domain, None, None, None, None, None, None,
                                                                  None, None, self.modified_by, self.modified_date,
                                                                  self.file_name, self.scope_id])
                                        title = "SoftFail SPF termination"
                                        plugin_id = "dnsperlscript-softfail_spf"
                                        result_list.append([self.tool, plugin_id, self.domain, "0", "tcp", line, None,
                                                            self.modified_date, self.modified_date,
                                                            "dig " + self.domain,
                                                            True, title, "SoftFail SPF weakens.",
                                                            "End all SPF entries with a 'HardFail', -all.", "",
                                                            "medium", "configuration", "", "", self.modified_by])
                                    elif "all" not in line[-5:]:
                                        engagement_device.append([None, self.domain, None, None, None, None, None, None,
                                                                  None, None, self.modified_by, self.modified_date,
                                                                  self.file_name, self.scope_id])
                                        title = "No HardFail SPF termination"
                                        plugin_id = "dnsperlscript-no_hardfail_spf"
                                        result_list.append([self.tool, plugin_id, self.domain, "0", "tcp", line, None,
                                                            self.modified_date, self.modified_date,
                                                            "dig " + self.domain, True, title, "No HardFail SPF.",
                                                            "End all SPF entries with a 'HardFail', -all.", "",
                                                            "medium", "configuration", "", "", self.modified_by])
                                if "*  Zone transfer" in line:
                                    zone_transfer_section = True
                                    bruteforced_names_section = False
                                    mx_server_section = False
                                if bruteforced_names_section and "\t" in line:
                                    parts = line.split("\t")
                                    if len(parts) == 4:
                                        recon_list.append([self.scope_id, parts[3], parts[0].lower(), None, parts[2],
                                                   None, None, "dnsperlscript", self.modified_by, self.modified_date])

                                if "*  Zone transfer" in line:
                                    zone_transfer_section = True
                                    bruteforced_names_section = False
                                    mx_server_section = False
                                if zone_transfer_section:
                                    if "*" not in line and "zone tranfer failed" not in line.lower() and "zone transfer" in line.lower() and self.tool_id is not None:
                                        parts = line.split(" ")
                                        engagement_device.append([None, self.domain, None, None, None, None, None, None,
                                                                  None, None, self.modified_by, self.modified_date,
                                                                  self.file_name, self.scope_id])
                                        title = "DNS zone transfer"
                                        plugin_id = "dnsperlscript-zone_transfer"
                                        result_list.append([self.tool, plugin_id, self.domain, "0", "tcp", line, None, self.modified_date,
                                            self.modified_date, "dig " + self.domain, True, title,
                                            "DNS zone transfer was allowed which dumps the entire contents of the DNS zone.",
                                            "Do not allow zone transfers.", "", "medium", "configuration", "", "",
                                            self.modified_by])
                    except Exception as e:
                        print_text.print_error("\tDNSfootprint.pl parsing error: " + str(e))

                output_dictionary = {}
                output_dictionary["recon"] = recon_list
                output_dictionary["recon_fields_to_update"] = [('info', 'as'), ('associated_info', 'as'),
                                                               ('description', 'as'), ('organization', 'as')]
                output_dictionary["devices"] = engagement_device
                output_dictionary["devices_fields_to_update"] = [('mac', 'c')]
                output_dictionary["results"] = result_list
                output_dictionary["results_fields_to_update"] = [('output', 'as'), ('tester_output', 'as')]

                return output_dictionary
            else:
                print_text.print_error("Unsupported file for parsing found, skipping it!")
                return {}
        except Exception as e:
            print("dnsfootprint parser 117 except: " + str(e) + " Error on line {}".format(sys.exc_info()[-1].tb_lineno))
        return {}