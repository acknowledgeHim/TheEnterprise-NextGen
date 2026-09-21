import sys
import os
import time
import json
import random
import string
from zapv2 import ZAPv2
from common import print_text, common
from enterprise_user_conf import PENTEST_DIR, ZAP_API_KEY


def zap_run(command, scope_id, location_id, db_object, log_id, zap_args):
    """ Connect to ZAP API and execute """

    try:
        zap_values = json.loads(zap_args)

        command = command.replace('"', '')
        output_file_path = command[:command.find(";")]
        target = command[command.find(";")+1:]

        # Output file name
        output_file = output_file_path + "zap__" + str(log_id) + "__" + common.format_target(target) + ".txt"
        common.create_path(output_file_path)

        with ZAPAutomation(zap_values, output_file, target, log_id, db_object, False) as zap_scan:
            return zap_scan.scan()

    except Exception as e:
        print_text.print_error("zap_run except: " +  str(e) + " Error on line {}".format(sys.exc_info()[-1].tb_lineno))


class ZAPAutomation():
    def __init__(self, zap_values, output_file, target, log_id, db_object, delete_scan=False):
        try:
            self.output_file = output_file
            self.target = target
            self.target_formatted_for_printing = common.format_target(target)
            self.log_id = log_id
            self.db_object = db_object
            self.api_key = ZAP_API_KEY  #zap_values['zap_api_key']
            self.zap_proxy = {} #{'http': 'http://127.0.0.1:8080', 'https': 'https://127.0.0.1:8080'}

            self.zap_prox = zap_values['zap_proxy']
            if "http://" in zap_values['zap_proxy']:
                self.zap_prox = self.zap_prox.replace("http://", "")
            if "https://" in zap_values['zap_proxy']:
                self.zap_prox = self.zap_prox.replace("https://", "")
            self.zap_proxy['http'] = "http://" + self.zap_prox
            self.zap_proxy['https'] = "https://" + self.zap_prox

            print_text.print_msg('Connecting to ZAP server.')
            self.zap = ZAPv2(apikey=self.api_key, proxies=self.zap_proxy)

            print_text.print_italic("ZAP server accessing " + self.target)
            self.zap.urlopen(self.target)

            # Give the sites tree a chance to get updated
            time.sleep(3)
        except Exception as e:
            print_text.print_error("zap_run except: " + str(e) + " Error on line {}".format(sys.exc_info()[-1].tb_lineno))

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        return self

    def update_log(self, scan_id, msg='ZAP scan'):
        # Update Log record w/ PID
        update_values = dict(id=self.log_id, comment=msg + "\nZAP Proxy:" + json.dumps(self.zap_prox) + "\nZAP API KEY:" + self.api_key + "\n", pid='ScanID:' + str(scan_id))
        self.db_object.update("Log", update_values, "id")

    def scan(self):
        """ Spider, than Passive Scan, the Active Scan"""
        try:
            print_text.print_msg("ZAP server spidering " + self.target)
            scan_id = self.zap.spider.scan(self.target)
            self.update_log(scan_id, 'ZAP spider started.')
            time.sleep(3)

            # Loop until the spider has finished
            while int(self.zap.spider.status(scan_id)) < 100:
                print_text.print_italic("ZAP server spider progress for " + self.target + " is " + self.zap.spider.status(scan_id) + "%")
                time.sleep(2)
            print_text.print_msg("ZAP server spider for " + self.target + " has completed.")

            print_text.print_msg("ZAP server passive scan for " + self.target)
            #self.zap.pscan.setScanOnlyInScope = True
            # Loop until passive scan has finished
            while int(self.zap.pscan.records_to_scan) > 0:
                print_text.print_italic("ZAP server records to passive scan for " + self.target + " is " + self.zap.pscan.records_to_scan)
                time.sleep(2)
            print_text.print_msg("ZAP server passive scan for " + self.target + " has completed.")

            print_text.print_msg("ZAP server active scan for " + self.target)
            scan_id = self.zap.ascan.scan(self.target)
            self.update_log(scan_id, 'ZAP active scan started.')
            # Loop until active scan has finished
            while int(self.zap.ascan.status(scan_id)) < 100:
                print_text.print_italic("ZAP server active scan progress for " + self.target + " is " + self.zap.ascan.status(scan_id) + "%")
                time.sleep(5)
            print_text.print_msg("ZAP server active scan for " + self.target + " has completed.")

            data = {'hosts': self.zap.core.hosts, 'alerts': self.zap.core.alerts()}#, 'urls': self.zap.core.urls()}

            serialize_data = json.dumps(data)
            print("104 zap_run data: " + str(data))

            with open(self.output_file, "w") as zap_file:
                zap_file.write(serialize_data + "\n")

            xml_file = self.output_file.replace(".txt", ".xml")

            self.generate_xml_report(xml_file)

            return True
        except Exception as e:
            print("zap_run 119 except: " + str(e) + " Error on line {}".format(sys.exc_info()[-1].tb_lineno))

        return "FAILED"

    def generate_xml_report(self, xml_file):
        """ Generate XML report at any time for ZAP data. """
        xml_data = self.zap.core.xmlreport(self.api_key)
        print("123 zap_run xml_data: " + str(xml_data))
        with open(xml_file, "w") as xml_f:
            xml_f.write(xml_data)

    def stop_scan(self, scan_id, output_path):
        """ Used to stop spider and active scans. """

        self.generate_xml_report(output_path)
        try:
            self.zap.spider.stop(scan_id, self.api_key)
        except Exception as e:
            print_text.print_error("Could not stop ZAP spider ScanID:" + str(scan_id))
        try:
            self.zap.ascan.stop(scan_id, self.api_key)
        except Exception as e:
            print_text.print_error("Could not stop ZAP active scan ScanID:" + str(scan_id))

class ZAPReport():
    def __init__(self, db_object, full_client_engagement_path):
        self.db_object = db_object
        self.output_path = full_client_engagement_path

    def __enter__(self):
        return self

    def __exit__(self, type, value, traceback):
        return self

    def generate(self):
        pass




