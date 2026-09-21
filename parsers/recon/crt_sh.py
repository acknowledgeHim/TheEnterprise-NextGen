import sys, json
from common import print_text, keep_tags
from parsers. parser import Parser

def crt_sh(db_path, db_object, key, hashvals):
    """
    Loop thru hashvals, verify blacklist status, update Log, send to Parser, then finally email notifications out.
    :param db_path:
    :param db_object:
    :param hashvals:
    :return:
    """
    try:
        with Parser("crt_sh", db_object, key, hashvals, False) as p:
            p.parse("parsers.recon.crt_sh", "CRTSHParser")

    except Exception as e:
        print("crtsh parser 23 except: " + str(e) + " Error on line {}".format(sys.exc_info()[-1].tb_lineno))


class CRTSHParser():
    """ Parse CRTSHParser files. """
    def __init__(self, db_object, location_id, scope_id, file_path_name, ext, just_file_name, target, log_id, output_path, tester_device_list, modified_by, modified_date):

        if "/" in target:
            target = target.replace("/", "_")
        self.db_object = db_object
        self.output_path = output_path
        self.location_id = location_id
        self.scope_id = scope_id
        self.tool = "crt_sh"
        self.target = target
        self.log_id = log_id
        self.ext = ext
        self.tester_device_list = tester_device_list
        self.file_path = file_path_name
        self.file_name = just_file_name
        self.modified_by = modified_by
        self.modified_date = modified_date

        domain = self.file_path[self.file_path.rfind("__") + 2:]
        self.domain = domain[:domain.rfind(".json")]

    def __enter__(self):
        return self

    def __exit__(self, type, value, traceback):
        return self

    def parse(self):
        """ Parse .txt files. """
        try:
            if self.ext == "json":
                try:
                    recon_list = []
                    with open(self.file_path) as domain_file:
                        contents = keep_tags.clean_text(domain_file.read())
                        result_dict = json.load(contents)

                    records = result_dict['data']
                    wildcard = False
                    for record in records:
                        recon_type = "DOMAIN"
                        if "*." in record['name_value']:
                            recon_type = "WILDCARD"
                            wildcard = True
                        ip = ""
                        if "ip" in record:
                            ip = record['ip']
                        recon_list.append([self.scope_id, recon_type, record['name_value'], record['issuer_name'],
                                           ip, "", "", self.tool, self.modified_by, self.modified_date])
                    # remove domains since was wildcard
                    if wildcard:
                        updated_recon_list = []
                        for recon in recon_list:
                            if recon[1] != "DOMAIN":
                                updated_recon_list.append(recon)
                        recon_list = updated_recon_list

                except Exception as e:
                    print_text.print_error("\t File was not valid json. Error: " + str(e))

                output_dictionary = {}
                output_dictionary["recon"] = recon_list
                output_dictionary["recon_fields_to_update"] = [('info', 'as'), ('associated_info', 'as')]

                return output_dictionary
            else:
                print_text.print_error("Unsupported file for parsing found, skipping it!")
                return {}
        except Exception as e:
            print("crt_sh parser 75 except: " + str(e) + " Error on line {}".format(sys.exc_info()[-1].tb_lineno))
        return {}