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
            print_text.print_error("tool parser selection recon except: " + str(e) + " Error on line {}".format(sys.exc_info()[-1].tb_lineno))
        return

    def __enter__(self):
        return self

    def __exit__(self, type, value, traceback):
        return self

    def dns_lookup_files(self):
        """
        All dns lookup output files.
        """
        try:
            self.tool = "dns lookup"

            self.output_folder = self.output_folder + TOOLS_DICT[self.tool][1]
            self.timestamp = datetime.now().timestamp()
            # Now the output folder will put in folder with timestamp on it to distinguish itself
            self.output_folder = self.output_folder + "/" + str(self.timestamp) + "/"
            common.makedirs(self.output_folder)

            targets, commands = self.get_targets(self.tool, self.output_folder)
            self.run_group(targets, commands, "FUNCTION:tools.manual_parse.parse_selection.parse")
        except Exception as e:
            print_text.print_error("tool parser selection recon except: " + str(e) + " Error on line {}".format(sys.exc_info()[-1].tb_lineno))

    def dns_bruteforce_files(self):
        """
        All dns bruteforce output files.
        """
        try:
            self.tool = "dns bruteforce"
            self.output_folder = self.output_folder + TOOLS_DICT[self.tool][1]
            self.timestamp = datetime.now().timestamp()
            # Now the output folder will put in folder with timestamp on it to distinguish itself
            self.output_folder = self.output_folder + "/" + str(self.timestamp) + "/"
            common.makedirs(self.output_folder)

            targets, commands = self.get_targets(self.tool, self.output_folder)
            self.run_group(targets, commands, "FUNCTION:tools.manual_parse.parse_selection.parse")
        except Exception as e:
            print_text.print_error("tool parser selection recon except: " + str(e) + " Error on line {}".format(sys.exc_info()[-1].tb_lineno))


    def dns_zonetransfer_files(self):
        """
        All dns transfer output files.
        """
        try:
            self.tool = "dns zonetransfer"
            self.output_folder = self.output_folder + TOOLS_DICT[self.tool][1]
            self.timestamp = datetime.now().timestamp()
            # Now the output folder will put in folder with timestamp on it to distinguish itself
            self.output_folder = self.output_folder + "/" + str(self.timestamp) + "/"
            common.makedirs(self.output_folder)

            targets, commands = self.get_targets(self.tool, self.output_folder)
            self.run_group(targets, commands, "FUNCTION:tools.manual_parse.parse_selection.parse")
        except Exception as e:
            print_text.print_error("tool parser selection recon except: " + str(e) + " Error on line {}".format(sys.exc_info()[-1].tb_lineno))

    def linkedint_files(self):
        """
        All linkedint output files.
        """
        try:
            self.tool = "linkedint"
            self.output_folder = self.output_folder + TOOLS_DICT[self.tool][1]
            self.timestamp = datetime.now().timestamp()
            # Now the output folder will put in folder with timestamp on it to distinguish itself
            self.output_folder = self.output_folder + "/" + str(self.timestamp) + "/"
            common.makedirs(self.output_folder)

            targets, commands = self.get_targets(self.tool, self.output_folder)
            self.run_group(targets, commands, "FUNCTION:tools.manual_parse.parse_selection.parse")
        except Exception as e:
            print_text.print_error("tool parser selection recon except: " + str(e) + " Error on line {}".format(sys.exc_info()[-1].tb_lineno))

    def shodan_files(self):
        """
        All dns transfer output files.
        """
        try:
            self.tool = "shodan"
            self.output_folder = self.output_folder + TOOLS_DICT[self.tool][1]
            self.timestamp = datetime.now().timestamp()
            # Now the output folder will put in folder with timestamp on it to distinguish itself
            self.output_folder = self.output_folder + "/" + str(self.timestamp) + "/"
            common.makedirs(self.output_folder)

            targets, commands = self.get_targets(self.tool, self.output_folder)
            self.run_group(targets, commands, "FUNCTION:tools.manual_parse.parse_selection.parse")
        except Exception as e:
            print_text.print_error("tool parser selection recon except: " + str(e) + " Error on line {}".format(sys.exc_info()[-1].tb_lineno))

    def theharvester_files(self):
        """
        All theharvester output files.
        """
        try:
            self.tool = "theharvester"
            self.output_folder = self.output_folder + TOOLS_DICT[self.tool][1]
            self.timestamp = datetime.now().timestamp()
            # Now the output folder will put in folder with timestamp on it to distinguish itself
            self.output_folder = self.output_folder + "/" + str(self.timestamp) + "/"
            common.makedirs(self.output_folder)

            targets, commands = self.get_targets(self.tool, self.output_folder)
            self.run_group(targets, commands, "FUNCTION:tools.manual_parse.parse_selection.parse")
        except Exception as e:
            print_text.print_error("tool parser selection recon except: " + str(e) + " Error on line {}".format(sys.exc_info()[-1].tb_lineno))