import sys, json
from common import print_text, keep_tags
from parsers. parser import Parser

def blacksheepwall(db_path, db_object, key, hashvals):
    """
    Loop thru hashvals, verify blacklist status, update Log, send to Parser, then finally email notifications out.
    :param db_path:
    :param db_object:
    :param hashvals:
    :return:
    """
    try:
        with Parser("blacksheepwall", db_object, key, hashvals, False) as p:
            p.parse("parsers.recon.blacksheepwall_parser", "BlackSheepWallParser")

    except Exception as e:
        print("blacksheepwall parser 23 except: " + str(e) + " Error on line {}".format(sys.exc_info()[-1].tb_lineno))


class BlackSheepWallParser():
    """ Parse BlackSheepWallParser files. """
    def __init__(self, db_object, location_id, scope_id, file_path_name, ext, just_file_name, target, log_id, output_path, tester_device_list, modified_by, modified_date):

        if "/" in target:
            target = target.replace("/", "_")
        self.db_object = db_object
        self.output_path = output_path
        self.location_id = location_id
        self.scope_id = scope_id
        self.tool = "dns bruteforce"
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
                try:
                    recon_list = []
                    with open(self.file_path, 'r') as domain_file:
                        contents = domain_file.read()
                        contents = keep_tags.clean_text(contents)
                    result_dict = json.loads(contents)
                    for record in result_dict:
                        recon_list.append([self.scope_id, "DOMAIN", record['hostname'], None, record['ip'], None, None,
                                           self.tool, self.modified_by, self.modified_date])
                except Exception as e:
                    print_text.print_error("\t File was not valid json.")


                output_dictionary = {}
                output_dictionary["recon"] = recon_list
                output_dictionary["recon_fields_to_update"] = [('info', 'as'), ('associated_info', 'as'), ('description', 'as'),
                                                               ('organization', 'as')]

                return output_dictionary
            else:
                print_text.print_error("Unsupported file for parsing found, skipping it!")
                return {}
        except Exception as e:
            print("blacksheepwall parser 75 except: " + str(e) + " Error on line {}".format(sys.exc_info()[-1].tb_lineno))
        return {}