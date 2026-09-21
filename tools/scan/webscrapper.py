import sys
import os
from common import print_text, common
from common.tool import Tool

class WebScrapper(Tool):
    def __init__(self, db_object, full_client_engagement_path):
        try:
            tool = "webscrapper"
            self.output_folder = full_client_engagement_path + tool

            Tool.__init__(self, db_object, self.output_folder, tool)

            self.websites = self.db_object.all_websites()

        except Exception as e:
            print_text.print_error("tool webscrapper except: " + str(e) + " Error on line {}".format(sys.exc_info()[-1].tb_lineno))
        return

    def __enter__(self):
        return self

    def __exit__(self, type, value, traceback):
        return self

    def get_targets(self):
        """Retrieve website entries that haven't been scanned

        :return: list of websites to scan
        """
        try:
            self.setup_already_done_checks()

            # Scrapy base cmd
            scrapy_cmd = "scrapy runspider "
            #scrapy_cmd = "scrapy genspider "

            base_dir = os.path.dirname(os.path.realpath(__file__))

            commands = []
            targets = []
            for website_entry in self.websites:
                sentry = website_entry['entry']
                website_scrapy_file = self.output_folder + common.format_target(sentry) + ".py"
                with open('tools/scan/webscrapper_template.py', 'r') as web_template:
                    webscrap_template = web_template.read()
                    if "PLACEHOLDERname" in webscrap_template:
                        webscrap_template = webscrap_template.replace("PLACEHOLDERname", common.format_website(sentry))
                    if "PLACEHOLDERstart_urls" in webscrap_template:
                        webscrap_template = webscrap_template.replace("PLACEHOLDERstart_urls", sentry)
                    if "PLACEHOLDERallowed_domains" in webscrap_template:
                        webscrap_template = webscrap_template.replace("PLACEHOLDERallowed_domains", common.format_website(sentry))
                    if "PLACEHOLDERresult_file" in webscrap_template:
                        webscrap_template = webscrap_template.replace("PLACEHOLDERresult_file", self.output_folder + "webscrapper__s" + str(website_entry['id']) + "__" + common.format_target(sentry) + ".txt")
                with open(website_scrapy_file, 'w') as web_scrapy_file:
                    web_scrapy_file.write(webscrap_template)

                if sentry + ";" + str(website_entry['id']) not in self.already_scanned:
                    targets.append(sentry)
                    commands.append([scrapy_cmd + website_scrapy_file, website_entry['id'], website_entry['location_id']])
                    #commands.append([scrapy_cmd + common.format_website(sentry) + " " + sentry, website_entry['id'], website_entry['location_id']])

            if len(targets) == 0 and len(self.already_scanned) >0:
                print_text.print_error("\tYou've already scanned all Websites in the scope and you have specified to not re-run any tools.")
            print("66 webscrapper commands: " + str(commands))
            return targets, commands
        except Exception as e:
            print_text.print_error("tool webscrapper except: " + str(e) + " Error on line {}".format(sys.exc_info()[-1].tb_lineno))

    def scan(self):
        """
        """
        try:
            targets, commands = self.get_targets()
            self.run_group(targets, commands, "")
        except Exception as e:
            print_text.print_error("tool webscrapper except: " + str(e) + " Error on line {}".format(sys.exc_info()[-1].tb_lineno))
