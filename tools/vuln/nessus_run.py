import requests
from requests.packages.urllib3.exceptions import InsecureRequestWarning
import time
import json
import sys
from common import print_text, common, network

requests.packages.urllib3.disable_warnings(InsecureRequestWarning)

def nessus_run(command, scope_id, location_id, db_object, log_id, nessus_args):
    """ Connect to Nessus API and execute """

    try:
        nessus_values = json.loads(nessus_args)

        command = command.replace('"', '')
        output_file_path = command[:command.find(";")]
        target = command[command.find(";")+1:]

        scope_repo = db_object.get("Scope", ['id'], [scope_id])
        original_entry = scope_repo['original_entry']
        if "-" in original_entry:
            if "/" in target:
                if network.valid_ip(target[:target.find("/")]):
                    target = network.return_range_of_ips_from_cidr(target, True)

        # Output file name
        output_file = output_file_path + "nessus__" + str(log_id) + "__" + target.replace("/", "_") + ".nessus"

        # Get client name to be used to name scan + target
        client_name = db_object.grab_column_from_single_record("Engagement", ["id"], [1], "client_name")

        common.create_path(output_file_path)
        with NessusAutomation(nessus_values, output_file, client_name, target, log_id, db_object, False) as nessus_scan:
            return nessus_scan.scan()

    except Exception as e:
        print_text.print_error("nessus_run except: " +  str(e) +  " Error on line {}".format(sys.exc_info()[-1].tb_lineno))


class NessusAutomation():
    def __init__(self, nessus_values, output_file, client_name, target, log_id, db_object, delete_scan=False):
        try:
            self.url = nessus_values['nessus_server']

            self.output_file = output_file
            self.client_name = client_name
            if "http://" in target:
                target = target.replace("http://", "")
            elif "https://" in target:
                target = target.replace("https://", "")
            self.target = target
            self.log_id = log_id
            self.db_object = db_object
            self.delete_scan = delete_scan
            self.token = None
            self.verify = False
            self.user = nessus_values['nessus_username']
            self.passwd = nessus_values['nessus_password']
            self.policy = ""
            if "nessus_policy" in nessus_values:
                self.policy = nessus_values['nessus_policy']
            self.scan_id = ""
            self.creds_worked = False

            print_text.print_msg('Logging into Nessus server.')
            self.token = self.login(self.user, self.passwd)
        except Exception as e:
            print_text.print_error(
                "nessus_run except: " + str(e) + " Error on line {}".format(sys.exc_info()[-1].tb_lineno))

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        return self


    def scan(self):
        try:
            msg = ""
            if self.token is not None:
                print_text.print_msg('Adding new scan.')
                policies = self.get_policies()

                uuid = None
                policy_id = None
                if self.policy in policies:
                    policy_id = policies[self.policy][1]
                    uuid = policies[self.policy][0]

                    if policy_id is not None:
                        try:
                            tmp = int(policy_id)
                        except:
                            # Update Log record w/ PID
                            comment = "Nessus scan not started because the policy you entered does not match a policy on the Nessus server selected."
                            update_values = dict(id=self.log_id, comment=comment)
                            self.db_object.update("Log", update_values, "id")
                            return "Failed. " + comment
                else:
                    # Update Log record w/ PID
                    comment = "Nessus scan not started because the policy you entered does not match a policy on the Nessus server selected."
                    update_values = dict(id=self.log_id, comment=comment)
                    self.db_object.update("Log", update_values, "id")
                    return "Failed. " + comment

                scan_data = self.add(self.client_name + "_" + common.format_target(self.target), 'Create a new scan with API', self.target, policy_id, uuid)
                self.scan_id = scan_data['id']

                print_text.print_msg('Updating Nessus scan with new targets.')
                self.update(scan_data['name'], scan_data['description'], self.target)

                # Update Log record w/ PID
                update_values = dict(id=self.log_id, comment="Nessus scan started", pid='ScanID:' + str(self.scan_id))
                self.db_object.update("Log", update_values, "id")

                print_text.print_msg('Launching new Nessus scan.')
                scan_uuid = self.launch()
                history_ids = self.get_history_ids()
                history_id = history_ids[scan_uuid]
                while True:
                    if self.status(history_id) == "completed":
                        break
                    print_text.print_msg("Nessus scan: " + str(self.scan_id) + " is still running!  Will check again in 180 secs.")
                    time.sleep(180)

                print_text.print_msg('Exporting the completed Nessus scan.')
                file_id = self.export(history_id)
                self.download(file_id, self.output_file)

                # Export scan as PDF as well - NOT CURRENTLY WORKING FOR PDF export ?
                file_id = self.export_html(history_id)
                self.download(file_id, self.output_file.replace(".nessus", ".html"))

                if self.delete_scan:
                    print_text.print_msg('Deleting the Nessus scan.')
                    self.history_delete(history_id)
                    self.delete()

                print_text.print_msg('Logging out of Nessus server.')

                self.logout()

                return True
            else:
                return "Failed. Not able to login.  Either can reach Nessus server or invalid credentials specified."
        except Exception as e:
            print("nessus_run 119 except: " + str(e) + " Error on line {}".format(sys.exc_info()[-1].tb_lineno))
            msg = "Error: " + str(e) + " Error on line {}".format(sys.exc_info()[-1].tb_lineno)
        return "Failed. " + msg

    def build_url(self, resource):
        return '{0}{1}'.format(self.url, resource)


    def connect(self, method, resource, data=None, params=None):
        """
        Send a request
        Send a request to Nessus based on the specified data. If the session token
        is available add it to the request. Specify the content type as JSON and
        convert the data to JSON format.
        """
        try:
            headers = {'X-Cookie': 'token={0}'.format(self.token),
                       'content-type': 'application/json'}

            data = json.dumps(data)
            if method == 'POST':
                r = requests.post(self.build_url(resource), data=data, headers=headers, verify=self.verify)
            elif method == 'PUT':
                r = requests.put(self.build_url(resource), data=data, headers=headers, verify=self.verify)
            elif method == 'DELETE':
                r = requests.delete(self.build_url(resource), data=data, headers=headers, verify=self.verify)
            else:
                r = requests.get(self.build_url(resource), params=params, headers=headers, verify=self.verify)

            # if creds worked then we are all good
            if r.status_code == 200 and not self.creds_worked:
                self.creds_worked = True

            # Exit if there is an error.
            if r.status_code != 200:
                e = r.json()
                print_text.print_error(e['error'])
                if e['error'] == "Invalid Credentials" and not self.creds_worked:
                    # Update Log Comment with this error!
                    update_values = dict(id=self.log_id,
                                         comment="Failed.  You entered invalid credential for the Nessus server you specified.  "
                                                 "Try starting the Nessus scan again and re-enter the credential.")
                    self.db_object.update("Log", update_values, "id")
                    return None
                else:
                    #time.sleep(105) #sleep random seconds before trying to reconnect
                    print_text.print_italic("Attempting reconnect to Nessus server...")
                    self.token = self.login(self.user, self.passwd)
                    if self.token != "" and self.token is not None:
                        print_text.print_msg("Reconnected to Nessus server!")
                        return self.connect(method, resource, data, params)
                    else:
                        # Update Log Comment with this error!
                        update_values = dict(id=self.log_id, comment="Nessus server returned this error: " + str(e['error']))
                        self.db_object.update("Log", update_values, "id")
            elif "/stop" in resource and "/scans/" in resource:
                return None

            # When downloading a scan we need the raw contents not the JSON data.
            if 'download' in resource:
                return r.content

            if method != "DELETE":
                # All other responses should be JSON data. Return raw content if they are not.
                try:
                    return r.json()
                except Exception as e:
                    update_values = dict(id=self.log_id, comment="Nessus server returned this error: " + str(e))
                    self.db_object.update("Log", update_values, "id")
                    print_text.print_error("207 nessus_run except: " + str(r.content) + " Error on line {}".format(sys.exc_info()[-1].tb_lineno))
                    return r.content
            else:
                return r.content
        except Exception as e:
            print_text.print_error("212 nessus_run except: " + str(e) + " Error on line {}".format(sys.exc_info()[-1].tb_lineno))


    def login(self, usr, pwd):
        """
        Login to nessus.
        """
        try:
            login = {'username': usr, 'password': pwd}
            data = self.connect('POST', '/session', data=login)
            if data is None:
                return None
            elif 'token' not in data:
                return None
            return data['token']
        except Exception as e:
            print_text.print_error("nessus_run except: " + str(e) + " Error on line {}".format(sys.exc_info()[-1].tb_lineno))
        return None

    def logout(self):
        """
        Logout of nessus.
        """

        self.connect('DELETE', '/session')


    def get_policies(self):
        """
        Get scan policies
        Get all of the scan policies but return only the title and the uuid of
        each policy.
        """
        data_policies = self.connect('GET', '/policies')

        policy_dict = dict((p['name'], [p['template_uuid'], p['id']]) for p in data_policies['policies'])

        data = self.connect('GET', '/editor/policy/templates')
        for policy in data['templates']:
            if policy['title'] not in policy_dict:
                policy_dict[policy['title']] = [policy['uuid'], None]

        return policy_dict

    def get_history_ids(self):
        """
        Get history ids
        Create a dictionary of scan uuids and history ids so we can lookup the
        history id by uuid.
        """
        data = self.connect('GET', '/scans/{0}'.format(self.scan_id))

        return dict((h['uuid'], h['history_id']) for h in data['history'])


    def get_scan_history(self, sid, hid):
        """
        Scan history details
        Get the details of a particular run of a scan.
        """
        params = {'history_id': hid}
        data = self.connect('GET', '/scans/{0}'.format(sid), params)

        return data['info']


    def add(self, name, desc, targets, pid, uuid):
        """
        Add a new scan
        Create a new scan using the uuid (if Custom templat need policy_id), name, description and targets. The
        scan will be created in the default folder for the user. Return the id of
        the newly created scan.
        Note: Policy ID can be found from logging into the scanner -> Policies -> click the User Created Policy ->
            view the URL and the policy_id is as follows in the URL: /policies/<policy_id>/config
        """
        try:
            settings = {'scanner_id': 1, 'name': name, 'description': desc, 'text_targets': targets}
            scan = {'uuid': uuid}
            if pid is not None: #Custom Scan needs policy_id as well
                settings['policy_id'] = pid

            scan['settings'] = settings

            data = self.connect('POST', '/scans', data=scan)

            return data['scan']
        except Exception as e:
            # Update Log record w/ PID
            update_values = dict(id=self.log_id, comment="Nessus scan not added, error: " + str(e))
            self.db_object.update("Log", update_values, "id")
            return "FAILED"


    def update(self, name, desc, targets, pid=None):
        """
        Update a scan
        Update the name, description, targets, or policy of the specified scan. If
        the name and description are not set, then the policy name and description
        will be set to None after the update. In addition the targets value must
        be set or you will get an "Invalid 'targets' field" error.
        """

        # if targets is an IP/CIDR convert to IP range or else Nessus won't scan last IP in CIDR b/c thinks it is broadcast which might not be

        scan = {}
        scan['settings'] = {}
        scan['settings']['name'] = name
        scan['settings']['desc'] = desc
        scan['settings']['text_targets'] = targets

        if pid is not None:
            scan['uuid'] = pid

        data = self.connect('PUT', '/scans/{0}'.format(self.scan_id), data=scan)

        return data


    def launch(self):
        """
        Launch a scan
        """

        data = self.connect('POST', '/scans/{0}/launch'.format(self.scan_id))

        return data['scan_uuid']


    def status(self, hid):
        """
        Check the status of a scan run
        Get the historical information for the particular scan and hid. Return
        the status if available. If not return unknown.
        """

        d = self.get_scan_history(self.scan_id, hid)
        return d['status']


    def export_status(self, fid):
        """
        Check export status
        Check to see if the export is ready for download.
        """

        data = self.connect('GET', '/scans/{0}/export/{1}/status'.format(self.scan_id, fid))

        return data['status'] == 'ready'


    def export(self, hid):
        """
        Make an export request
        Request an export of the scan results for the specified scan and
        historical run. In this case the format is hard coded as nessus but the
        format can be any one of nessus, html, pdf, csv, or db. Once the request
        is made, we have to wait for the export to be ready.
        """

        data = {'history_id': hid,
                'format': 'nessus'}

        data = self.connect('POST', '/scans/{0}/export'.format(self.scan_id), data=data)

        fid = data['file']

        while self.export_status(fid) is False:
            time.sleep(5)

        return fid

    def export_html(self, hid):
        """
        Make an PDF export request
        Request an export of the scan results for the specified scan and
        historical run. In this case the format is hard coded as nessus but the
        format can be any one of nessus, html, pdf, csv, or db. Once the request
        is made, we have to wait for the export to be ready.
        """

        data = {'history_id': hid,
                'format': 'html',
                'chapters': 'vuln_by_plugin'}
        #data = {'history_id': hid,
        #        'format': 'pdf',
        #        'definition': {'chapters': 'vuln_by_plugin'} }

        data = self.connect('POST', '/scans/{0}/export'.format(self.scan_id), data=data)

        fid = data['file']

        while self.export_status(fid) is False:
            time.sleep(5)

        return fid

    def download(self, fid, output_file):
        """
        Download the scan results
        Download the scan results stored in the export file specified by fid for
        the scan specified by sid.
        """

        data = self.connect('GET', '/scans/{0}/export/{1}/download'.format(self.scan_id, fid))

        filename = output_file # + 'nessus_{0}_{1}.nessus'.format(sid, fid)

        print_text.print_msg('Saving scan results to {0}.'.format(filename))
        with open(filename, 'w') as f:
            f.write(data.decode('utf-8'))


    def stop(self, scan_id, modified_by):
        """ Stops running scan. """
        try:
            self.connect('POST', '/scans/' + str(scan_id) + '/stop')

            # Update Log record w/ PID
            update_values = dict(id=self.log_id, comment="Nessus scan stopped by " + modified_by)
            self.db_object.update("Log", update_values, "id")
        except Exception as e:
            print_text.print_error("nessus_run except: " + str(e) + " Error on line {}".format(sys.exc_info()[-1].tb_lineno))

    def delete(self):
        """
        Delete a scan
        This deletes a scan and all of its associated history. The scan is not
        moved to the trash folder, it is deleted.
        """

        self.connect('DELETE', '/scans/{0}'.format(self.scan_id))


    def history_delete(self, hid):
        """
        Delete a historical scan.
        This deletes a particular run of the scan and not the scan itself. the
        scan run is defined by the history id.
        """

        self.connect('DELETE', '/scans/{0}/history/{1}'.format(self.scan_id, hid))


