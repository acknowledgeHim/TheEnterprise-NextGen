import sys
import time
import webbrowser
from lxml import etree
from common import print_text, dns_functions
from common import common, network
from parsers. parser import Parser

def linkedint(db_path, db_object, key, hashvals):
    """
    Loop thru hashvals, verify blacklist status, update Log, send to Parser, then finally email notifications out.
    :param db_path:
    :param db_object:
    :param hashvals:
    :return:
    """
    try:
        with Parser("linkedint", db_object, key, hashvals, False) as p:
            p.parse("parsers.recon.linkedint_parser", "LinkedIntParser")

    except Exception as e:
        print("linkedint parser 23 except: " + str(e) + " Error on line {}".format(sys.exc_info()[-1].tb_lineno))


class LinkedIntParser():
    """ Parse linkedintParser files. """
    def __init__(self, db_object, location_id, scope_id, file_path_name, ext, just_file_name, target, log_id, output_path, tester_device_list, modified_by, modified_date):

        if "/" in target:
            target = target.replace("/", "_")
        self.db_object = db_object
        self.output_path = output_path
        self.location_id = location_id
        self.scope_id = scope_id
        self.tool = "linkedint"
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
            # Try and open html report in web browser
            if self.ext == "html":
                webbrowser.open(self.file_path)
                time.sleep(30)

            if self.ext == "xml":
                #recon_list = []
                people_list = []
                with open(self.file_path, 'rb') as xml_file:
                    for _, element in etree.iterparse(xml_file, tag='LinkedInt'):
                        names = list(element.iter('name'))
                        occupations = list(element.iter('occupation'))
                        locations = list(element.iter('location'))
                        emails = list(element.iter('email'))
                        for count, name in enumerate(names):
                            # people
                            name = name.text
                            occupation = occupations[count].text
                            location = locations[count].text
                            email = emails[count].text
                            if "\\" in email:
                                email = email.replace("\\", "")

                            people_list.append([self.location_id, name, email, "", "", "", "", occupation, "", location, False,
                                                False, self.tool, self.modified_by, self.modified_date])

                            #recon_list.append([self.scope_id, "person", name, location , "", "", occupation,
                            #                   self.tool + " - " + self.file_name, self.modified_by, self.modified_date])

                            # email
                            #recon_list.append([self.scope_id, "email", email, "", "", "", "",
                            #                   self.tool + " - " + self.file_name, self.modified_by, self.modified_date])

                output_dictionary = {}
                if len(people_list) > 0:
                    output_dictionary["person"] = people_list
                    output_dictionary["person_fields_to_update"] = [('person_info', 'c'), ('organization', 'c'),
                                                                    ('person_description', 'c'), ('title', 'c'),
                                                                    ('name', 'c'), ('email', 'c'),
                                                                    ('associated_info', 'c')]
                return output_dictionary
            else:
                print_text.print_error("Unsupported file for parsing found, skipping it!")
                return {}
        except Exception as e:
            print("linkedint parser 92 except: " + str(e) + " Error on line {}".format(sys.exc_info()[-1].tb_lineno))
        return {}
