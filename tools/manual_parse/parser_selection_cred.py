import sys
from datetime import datetime
from common import print_text, common
from tools.manual_parse.generic_parser_selection import GenericParserSelection
from enterprise_conf import TOOLS_DICT

class ParserSelection(GenericParserSelection):
    """ Manual Parse files"""
    def __init__(self, db_object, full_client_engagement_path):
        try:
            GenericParserSelection.__init__(self, db_object, full_client_engagement_path)
        except Exception as e:
            print_text.print_error("tool parser selection cred except: " + str(e) + " Error on line {}".format(sys.exc_info()[-1].tb_lineno))
        return

    def __enter__(self):
        return self

    def __exit__(self, type, value, traceback):
        return self

    def secretsdump_domainshashes_files(self):
        """
        All .txt or .ntds output files.
        """
        try:
            self.tool = "secretsdump (domain pwdhashes)"
            self.output_folder = self.output_folder + TOOLS_DICT[self.tool][1]
            self.timestamp = datetime.now().timestamp()
            # Now the output folder will put in folder with timestamp on it to distinguish itself
            self.output_folder = self.output_folder + "/" + str(self.timestamp) + "/"
            common.makedirs(self.output_folder)

            targets, commands = self.get_targets(self.tool, self.output_folder)
            self.run_group(targets, commands, "FUNCTION:tools.manual_parse.parse_selection.parse")
        except Exception as e:
            print_text.print_error("tool parser selection secretsdump (domain pwdhashes) except: " + str(e) + " Error on line {}".format(sys.exc_info()[-1].tb_lineno))

    def secretsdump_domainpwdhistory_files(self):
        """
        All .txt or .ntds output files.
        """
        try:
            self.tool = "secretsdump (domain pwdhistory)"
            self.output_folder = self.output_folder + TOOLS_DICT[self.tool][1]
            self.timestamp = datetime.now().timestamp()
            # Now the output folder will put in folder with timestamp on it to distinguish itself
            self.output_folder = self.output_folder + "/" + str(self.timestamp) + "/"
            common.makedirs(self.output_folder)

            targets, commands = self.get_targets(self.tool, self.output_folder)
            self.run_group(targets, commands, "FUNCTION:tools.manual_parse.parse_selection.parse")
        except Exception as e:
            print_text.print_error("tool parser selection secretsdump (domain pwdhistory) except: " + str(e) + " Error on line {}".format(sys.exc_info()[-1].tb_lineno))


