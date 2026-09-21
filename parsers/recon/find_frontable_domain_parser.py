import sys
from common import print_text
from parsers. parser import Parser

def find_frontable_domain(db_path, db_object, key, hashvals):
    """
    Loop thru hashvals, verify blacklist status, update Log, send to Parser, then finally email notifications out.
    :param db_path:
    :param db_object:
    :param hashvals:
    :return:
    """
    try:
        with Parser("find frontable domains", db_object, key, hashvals, False) as p:
            p.parse("parsers.recon.find_frontable_domain_parser", "FindFrontableDomainsParser")

    except Exception as e:
        print("findfrontabledomains parser 23 except: " + str(e) + " Error on line {}".format(sys.exc_info()[-1].tb_lineno))


class FindFrontableDomainsParser():
    """ Parse FindFrontableDomainsParser files. """
    def __init__(self, db_object, location_id, scope_id, file_path_name, ext, just_file_name, target, log_id, output_path, tester_device_list, modified_by, modified_date):

        if "/" in target:
            target = target.replace("/", "_")
        self.db_object = db_object
        self.output_path = output_path
        self.location_id = location_id
        self.scope_id = scope_id
        self.tool = "find frontable domains"
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
                recon_list = []
                with open(self.file_path, 'r') as f:
                    domain_section = True
                    frontable_section = False
                    for record in f:
                        # reached the end of the results
                        if "-----------------------------" in record:
                            domain_section = False

                        if frontable_section:
                            parts = record.split(" ")
                            recon_list.append([self.scope_id, "Frontable Domain", parts[4], parts[0] + " - " + parts[5],
                                               "", "", "", self.tool + " - " + self.file_name, self.modified_by,
                                               self.modified_date])

                        if "starting search for frontable domain" in record:
                            frontable_section = True

                        # strip all non ascii chars
                        record = ''.join(i for i in record if ord(i)<128)
                        if domain_section:
                            if "[-]" not in record and "." in record and "[~]" not in record and "..." not in record:
                                record = record.replace("[92m", "").replace("ESC[0m", "").replace("[0m", "").\
                                    replace("\x1b", "").rstrip("\n")
                                name = record
                                if "From http://" in record and ": " in record:
                                    name = name[name.find(": ") + 2:]
                                recon_list.append([self.scope_id, "DOMAIN", name, "" , "", "", "",
                                               self.tool + " - " + self.file_name, self.modified_by, self.modified_date])

                output_dictionary = {}
                if len(recon_list) > 0:
                    output_dictionary["recon"] = recon_list
                    output_dictionary["recon_fields_to_update"] = [('info', 'c'), ('organization', 'c')]

                return output_dictionary
            else:
                print_text.print_error("Unsupported file for parsing found, skipping it!")
                return {}
        except Exception as e:
            print("findfrontabledomains parser 92 except: " + str(e) + " Error on line {}".format(sys.exc_info()[-1].tb_lineno))
        return {}
