import sys
from lxml import etree
from common import print_text, dns_functions
from common import common, network
from parsers. parser import Parser

def theharvester_parser(db_path, db_object, key, hashvals):
    """
    Loop thru hashvals, verify blacklist status, update Log, send to Parser, then finally email notifications out.
    :param db_path:
    :param db_object:
    :param hashvals:
    :return:
    """
    try:
        with Parser("theharvester-google-files", db_object, key, hashvals, False) as p:
            p.parse("parsers.recon.theharvester_lookup_parser", "TheHarvesterParser")

    except Exception as e:
        print("theharvester parser 23 except: " + str(e) + " Error on line {}".format(sys.exc_info()[-1].tb_lineno))


class TheHarvesterParser():
    """ Parse TheHarvesterParser files. """
    def __init__(self, db_object, location_id, scope_id, file_path_name, ext, just_file_name, target, log_id, output_path, tester_device_list, modified_by, modified_date):
        if "/" in target:
            target = target.replace("/", "_")
        self.db_object = db_object
        self.log_info = self.db_object.log_record_by_id(log_id)
        self.output_path = output_path
        self.location_id = location_id
        self.scope_id = scope_id
        self.tool = self.log_info['source']
        if "(" in self.tool:
            self.tool = self.tool[self.tool.find("(") + 1:]
            self.tool = self.tool[:self.tool.find(")")]
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
            state_names = ["alaska", "alabama", "arkansas", "american samoa", "arizona", "california", "colorado", "connecticut", "district ", "of Columbia", "delaware", "florida", "georgia", "guam", "hawaii", "iowa", "idaho", "illinois", "indiana", "kansas", "kentucky", "louisiana", "massachusetts", "maryland", "maine", "michigan", "minnesota", "missouri", "mississippi", "montana", "north carolina", "north dakota", "nebraska", "new hampshire", "new jersey", "new mexico", "nevada", "new york", "ohio", "oklahoma", "oregon", "pennsylvania", "puerto rico", "rhode island", "south carolina", "south dakota", "tennessee", "texas", "utah", "virginia", "virgin islands", "vermont", "wisconsin", "west virginia", "wyoming"] #washington
            job_titles = ["manager", "director", "committee", "supervisor", "president", "officer", "audit", "business",
                          "bankrupt", "debt", "branch", "regional", "college", "university", "financial", "insurance",
                          "company", "click", "clique", "service", "client", "processing", "officer", "healthcare",
                          "administration", "professions", "greater", "marketing", "planning", "\\", "community",
                          "mechanical", "engineering", "department", "medical", "assistant", "mortgage", "construction",
                          "principal", "funding", "registered", "representative", "apparel", "view", "contract",
                          "vehicle", "market", "valley", "resources", "research", "development", "international",
                          "operations", "agency", "credit", "federal", "union", "teller", "service", "brokerage"]

            if self.ext == "xml":
                recon_list = []
                people_list = []
                with open(self.file_path, 'rb') as xml_file:
                    for _, element in etree.iterparse(xml_file, tag='theHarvester', huge_tree=True):
                        # people
                        people = list(element.iter('person'))
                        for person_item in people:
                            person = person_item.text
                            first = person
                            last = ""
                            if " " in person:
                                first = person[:person.find(" ")]
                                last = person[last.find(" ")+1:]
                            if first.lower() not in state_names and last.lower() not in state_names and \
                                    first.lower() not in job_titles and last.lower() not in job_titles:
                                people_list.append([self.location_id, person, "", "", "", "", "", "", "", "", False,
                                                    False, self.tool, self.modified_by, self.modified_date])
                            #recon_list.append([self.scope_id, "person", person, "", "", "", "", self.file_name, self.modified_by, self.modified_date])

                        # emails
                        emails = list(element.iter('email'))
                        for email_item in emails:
                            email = email_item.text
                            people_list.append([self.location_id, "", email, "", "", "", "", "", "", "", False, False,
                                                self.tool, self.modified_by, self.modified_date])
                            #recon_list.append([self.scope_id, "email", email, "", "", "", "", self.file_name, self.modified_by, self.modified_date])

                        # hosts
                        hosts = list(element.iter('host'))
                        for host_item in hosts:
                            host_name = host_item[1].text
                            host_ip = host_item[0].text
                            real_ip = ""

                            valid_info = "Search result is outdated as the domain no longer resolves to IP, " + host_ip + ".  "

                            if network.private_ip(host_ip):
                                host_ip = ""
                                valid_info = "Host no longers resolves to a valid IP address."

                            domain_ip, information, description, organization, nameservers = dns_functions.domain_information(host_name, False)
                            if domain_ip == host_ip:
                                valid_info = "The DNS still resolves to the same IP from the search result, " + host_ip + ".  "
                                real_ip = host_ip
                            if organization is None:
                                organization = ""

                            information = valid_info + information
                            if real_ip is not None and real_ip.strip() != "":
                                recon_list.append([self.scope_id, "DOMAIN", host_name, information, real_ip , description, organization, self.tool, self.modified_by, self.modified_date])

                        # files
                        files = list(element.iter('file'))
                        for file_item in files:
                            f = file_item.text
                            recon_list.append([self.scope_id, "file", f, "", "", "", "", self.file_name, self.modified_by,
                                 self.modified_date])

                output_dictionary = {}
                if len(recon_list) > 0:
                    output_dictionary["recon"] = recon_list
                    output_dictionary["recon_fields_to_update"] = [('record', 'c')]
                if len(people_list) > 0:
                    output_dictionary["person"] = people_list
                    output_dictionary["person_fields_to_update"] = [('person_info', 'c'), ('organization', 'c'),
                                                                    ('person_description', 'c'), ('title', 'c'),
                                                                    ('name', 'c'), ('email', 'c'),
                                                                    ('associated_info', 'c'), ('source', 'as')]

                return output_dictionary
            else:
                print_text.print_error("Unsupported file for parsing found, skipping it!")
                return {}
        except Exception as e:
            print("theharvester parser 92 except: " + str(e) + " Error on line {}".format(sys.exc_info()[-1].tb_lineno))
        return {}
