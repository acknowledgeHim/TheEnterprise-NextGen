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
            print_text.print_error("tool parser selection nessus_files except: " + str(e) + " Error on line {}".format(sys.exc_info()[-1].tb_lineno))
        return

    def __enter__(self):
        return self

    def __exit__(self, type, value, traceback):
        return self

    def nikto_files(self):
        """
        All nikto XML output files.
        """
        try:
            self.tool = "nikto"
            self.output_folder = self.output_folder + TOOLS_DICT[self.tool][1]
            self.timestamp = datetime.now().timestamp()
            # Now the output folder will put in folder with timestamp on it to distinguish itself
            self.output_folder = self.output_folder + "/" + str(self.timestamp) + "/"
            common.makedirs(self.output_folder)

            targets, commands = self.get_targets(self.tool, self.output_folder)
            self.run_group(targets, commands, "FUNCTION:tools.manual_parse.parse_selection.parse")
        except Exception as e:
            print_text.print_error("tool parser selection nikto_files except: " + str(e) + " Error on line {}".format(sys.exc_info()[-1].tb_lineno))

    def nessus_files(self):
        """
        All .NESSUS output files.
        """
        try:
            self.tool = "nessus"
            self.output_folder = self.output_folder + TOOLS_DICT[self.tool][1]
            self.timestamp = datetime.now().timestamp()
            # Now the output folder will put in folder with timestamp on it to distinguish itself
            self.output_folder = self.output_folder + "/" + str(self.timestamp) + "/"
            common.makedirs(self.output_folder)

            targets, commands = self.get_targets(self.tool, self.output_folder)
            self.run_group(targets, commands, "FUNCTION:tools.manual_parse.parse_selection.parse")
        except Exception as e:
            print_text.print_error("tool parser selection nessus_files except: " + str(e) + " Error on line {}".format(sys.exc_info()[-1].tb_lineno))


    def emailfilter_files(self):
        """
            Email filter output files.
        """
        try:
            self.tool = "email filter"
            self.output_folder = self.output_folder + TOOLS_DICT[self.tool][1]
            self.timestamp = datetime.now().timestamp()
            # Now the output folder will put in folder with timestamp on it to distinguish itself
            self.output_folder = self.output_folder + "/" + str(self.timestamp) + "/"
            common.makedirs(self.output_folder)

            targets, commands = self.get_targets(self.tool, self.output_folder)
            self.run_group(targets, commands, "FUNCTION:tools.manual_parse.parse_selection.parse")
        except Exception as e:
            print_text.print_error("tool parser selection nessus_files except: " + str(e) + " Error on line {}".format(
                sys.exc_info()[-1].tb_lineno))

    def dirsearch_files(self):
        """
            dirsearch output files.
        """
        try:
            self.tool = "dirsearch"
            self.output_folder = self.output_folder + TOOLS_DICT[self.tool][1]
            self.timestamp = datetime.now().timestamp()
            # Now the output folder will put in folder with timestamp on it to distinguish itself
            self.output_folder = self.output_folder + "/" + str(self.timestamp) + "/"
            common.makedirs(self.output_folder)

            targets, commands = self.get_targets(self.tool, self.output_folder)
            self.run_group(targets, commands, "FUNCTION:tools.manual_parse.parse_selection.parse")
        except Exception as e:
            print_text.print_error("tool parser selection dirsearch_files except: " + str(e) + " Error on line {}".format(
                sys.exc_info()[-1].tb_lineno))

    def burp_files(self):
        """
            burp output files.
        """
        try:
            self.tool = "burp"
            self.output_folder = self.output_folder + TOOLS_DICT[self.tool][1]
            self.timestamp = datetime.now().timestamp()
            # Now the output folder will put in folder with timestamp on it to distinguish itself
            self.output_folder = self.output_folder + "/" + str(self.timestamp) + "/"
            common.makedirs(self.output_folder)

            targets, commands = self.get_targets(self.tool, self.output_folder)
            self.run_group(targets, commands, "FUNCTION:tools.manual_parse.parse_selection.parse")
        except Exception as e:
            print_text.print_error("tool parser selection burp_files except: " + str(e) + " Error on line {}".format(
                sys.exc_info()[-1].tb_lineno))

    def zap_files(self):
        """
            zap output files.
        """
        try:
            self.tool = "zap"
            self.output_folder = self.output_folder + TOOLS_DICT[self.tool][1]
            self.timestamp = datetime.now().timestamp()
            # Now the output folder will put in folder with timestamp on it to distinguish itself
            self.output_folder = self.output_folder + "/" + str(self.timestamp) + "/"
            common.makedirs(self.output_folder)

            targets, commands = self.get_targets(self.tool, self.output_folder)
            self.run_group(targets, commands, "FUNCTION:tools.manual_parse.parse_selection.parse")
        except Exception as e:
            print_text.print_error("tool parser selection zap_files except: " + str(e) + " Error on line {}".format(
                sys.exc_info()[-1].tb_lineno))

