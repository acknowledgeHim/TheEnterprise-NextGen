import sys
from common import print_text, network
from common.entry_db_middle_man import MiddleMan
from common.manual import Entry
from common.selection import Selection


class GenericResult(MiddleMan):
    """
    Generic Result middleman used by EngagementDevice, DevicePort and Result
    """
    def __init__(self, db_object, full_client_engagement_path, DB_TABLE_NAME, MANUAL_FIELDS, COLUMN_NAMES, HEADER_NAMES, JOIN_TABLES):
        MiddleMan.__init__(self, db_object, full_client_engagement_path, DB_TABLE_NAME, MANUAL_FIELDS, COLUMN_NAMES, HEADER_NAMES)
        self.JOIN_TABLES = JOIN_TABLES
        return

    def __enter__(self):
        return self

    def __exit__(self, type, value, traceback):
        return self


    def add(self, engagement_scope_lookup=False, passed_field_values=None, passed_table_name=None):
        """
        Add entry to repo
        Overrides db.Interaction.add
        Returns number of entries added or 0 if failed.
        """
        try:
            table_name = self.DB_TABLE_NAME
            if passed_table_name is not None:
                table_name = passed_table_name

            field_values = {}
            scopes = self.db_object.dictionary_list("Scope", "entry")

            if len(scopes) > 0:
                if passed_field_values is None:
                    with Entry(table_name, self.MANUAL_FIELDS) as me:
                        field_values = me.user_input_fields(input_text='Please enter the')
                else:
                    field_values = passed_field_values

                tmp_field_values = self.pick_foreign_keys(field_values, passed_table_name)

                if tmp_field_values is not None:
                    field_values = tmp_field_values
                    number_rows_added = self.db_object.add(table_name, field_values)
            return field_values
        except Exception as e:
            print_text.print_error("\tResult: Failed to add entry to repository except: " + str(e) + \
                                   " Error on line {}".format(sys.exc_info()[-1].tb_lineno))

    def pick_foreign_keys(self, field_values, passed_table_name=None):
        """
        Pick the corresponding Foreign Key entry (DevicePort picks EngagementDevice, EngagementDevice picks Scope, etc)
        :param field_values: manually entered values to insert into DB
        :return:
        """
        try:
            testing_location = self.db_object.grab_current_location()

            table_name = self.DB_TABLE_NAME
            if passed_table_name is not None:
                table_name = passed_table_name

            scopes = self.db_object.dictionary_list("Scope", "entry")
            scopes_count_numbers = self.db_object.dictionary_list("Scope", "id")

            if table_name == "EngagementDevice":
                if len(scopes) > 0:
                    if len(scopes) == 1:
                        scope_id = scopes_count_numbers[0]
                    else:
                        # check to see if can minimize the scope entries to select
                        if network.valid_ip(field_values['target_ip']):
                            if testing_location == "all_locations":
                                networks_info = self.db_object.join_view("Scope", ["Location.name"], ["id", "entry", "name"],
                                                                                                ["type"], ["IP"], True)
                            else:
                                networks_info = self.db_object.join_view("Scope", ["Location.name"],
                                                                         ["id", "entry", "name"],
                                                                         ["type", "location_id"], ["IP", testing_location], True)
                            networks = []
                            ids = []
                            for netw in networks_info:
                                ids.append(netw['id'])
                                networks.append(netw['entry'])
                            in_networks, net_rows = network.find_networks_ip_is_in(field_values['target_ip'], networks)
                            if len(in_networks) > 0:
                                scopes = []
                                scopes_count_numbers = []
                                for nrow in net_rows:
                                    scopes.append(networks_info[nrow]['entry'] + " (" + networks_info[nrow]['name'] + ")")
                                    scopes_count_numbers.append(networks_info[nrow]['id'])

                        if len(scopes) == 1:
                            scope_id = scopes_count_numbers[0]
                        else:
                            with Selection('Select the Scope of this entry', scopes, None) as selection:
                                scope_id = selection.select_option(scopes_count_numbers)
                    field_values['scope_id'] = scope_id

            elif table_name == "DevicePort":
                devices_info = self.db_object.join_view("EngagementDevice", ["Scope.Location.name"], None, None, None, None)
                devices = []
                ids = []
                ips = []
                engagement_devices = ['Add New']
                engagement_devices_count_numbers = [0]
                for netw in devices_info:
                    ids.append(netw['id'])
                    devices.append(netw['target_name'])
                    if network.valid_ip(netw['target_name']):
                        ips.append(netw['target_name'])
                    else:
                        ips.append(netw['target_ip'])

                    engagement_devices.append(netw['target_name'] + " (" + netw['name'] + ")")
                    engagement_devices_count_numbers.append(netw['id'])

                if network.valid_ip(field_values['ip']):
                    # Gets all Engagement Devices that have IP same as DevicePort or Result
                    in_networks, net_rows = network.find_networks_ip_is_in(field_values['ip'], ips)
                    if len(in_networks) > 0:
                        engagement_devices = ['Add New']
                        engagement_devices_count_numbers = [0]
                        for nrow in net_rows:
                            engagement_devices.append(
                                devices_info[nrow]['target_name'] + " (" + devices_info[nrow]['name'] + ")")
                            engagement_devices_count_numbers.append(devices_info[nrow]['id'])
                if len(engagement_devices_count_numbers) == 2:
                    device_id = engagement_devices_count_numbers[1]
                else:
                    with Selection('Select the Device for this entry', engagement_devices, None) as selection:
                        device_id = selection.select_option(engagement_devices_count_numbers)

                # Default add new engagement device
                if device_id == 0:
                    added_fields = GenericResult.add(self, True, {'target_ip': field_values['ip'], 'target_name': field_values['ip'], 'source': 'manual'}, "EngagementDevice")
                    if added_fields is not None and 'hashval' in added_fields and 'scope_id' in added_fields:
                        device_id = self.db_object.grab_column_from_single_record("EngagementDevice", ['hashval'], [added_fields['hashval']], 'id')

                field_values['engagementdevice_id'] = device_id
            elif table_name == "Result" or table_name == "Credential":
                # Try to match Engagement Device by IP, than by Target, then just have to pick from all
                devices_info = self.db_object.join_view("EngagementDevice", ["Location.name"], None, None, None, None)
                devices = []
                ids = []
                ips = []
                engagement_devices = ['Add New']
                engagement_devices_count_numbers = [0]
                for netw in devices_info:
                    ids.append(netw['id'])
                    devices.append(netw['target_name'])
                    if network.valid_ip(netw['target_name']):
                        ips.append(netw['target_name'])
                    else:
                        ips.append(netw['target_ip'])

                    engagement_devices.append(netw['target_name'] + " (" + netw['name'] + ")")
                    engagement_devices_count_numbers.append(netw['id'])

                if network.valid_ip(field_values['target_name']):
                    # Gets all Engagement Devices that have IP same as Result
                    in_networks, net_rows = network.find_networks_ip_is_in(field_values['target_name'], ips)
                    if len(in_networks) > 0:
                        engagement_devices = ['Add New']
                        engagement_devices_count_numbers = [0]
                        for nrow in net_rows:
                            engagement_devices.append(devices_info[nrow]['target_name'] + " (" + devices_info[nrow]['name'] + ")")
                            engagement_devices_count_numbers.append(devices_info[nrow]['id'])
                else:
                    devices_info = self.db_object.join_view("EngagementDevice", ["Location.name"], None, ["target_name"],
                                                                                     [field_values['target_name']], True)
                    if len(devices_info) > 0:
                        engagement_devices = ['Add New']
                        engagement_devices_count_numbers = [0]
                        for dinfo in devices_info:
                            engagement_devices.append(
                                dinfo['target_name'] + " (" + dinfo['name'] + ")")
                            engagement_devices_count_numbers.append(dinfo['id'])

                if len(engagement_devices_count_numbers) == 2:
                    device_id = engagement_devices_count_numbers[1]
                else:
                    with Selection('Select the Device for this entry', engagement_devices, None) as selection:
                        device_id = selection.select_option(engagement_devices_count_numbers)

                # Default add new engagement device
                if device_id == 0:
                    ip = None
                    if network.valid_ip(field_values['target_name']):
                        ip = field_values['target_name']
                    added_fields = GenericResult.add(self, True,
                                        {'target_ip': ip, 'target_name': field_values['target_name'], 'source': 'manual'},
                                        "EngagementDevice")
                    if added_fields is not None and 'hashval' in added_fields and 'scope_id' in added_fields:
                        device_id = self.db_object.grab_column_from_single_record("EngagementDevice", ['hashval'],
                                                                               [added_fields['hashval']], 'id')
                field_values['engagementdevice_id'] = device_id

            elif table_name == "Phishing":
                locations = self.db_object.dictionary_list("Location", "name")
                count_numbers = self.db_object.dictionary_list("id")

                if len(locations) > 0:
                    number_rows_added = 0
                    with Entry(table_name, self.MANUAL_FIELDS) as me:
                        field_values = me.user_input_fields(input_text='Please enter the')

                    if len(locations) == 1:
                        location_id = count_numbers[0]
                    else:
                        with Selection('Select the Location of this entry', locations, None) as selection:
                            location_id = selection.select_option(count_numbers)
                    field_values['location_id'] = location_id
            elif table_name == "Person":
                pass
            else:  # Recon / Company
                if len(scopes) == 1:
                    scope_id = scopes_count_numbers[0]
                else:
                    with Selection('Select the Scope of this entry', scopes, None) as selection:
                        scope_id = selection.select_option(scopes_count_numbers)
                field_values['scope_id'] = scope_id


            return field_values
        except Exception as e:
            print_text.print_error("\tResult: Failed to add entry to repository except: " + str(e) + \
                                   " Error on line {}".format(sys.exc_info()[-1].tb_lineno))

    def update(self, engagement_scope_lookup=False):
        """
        Grabs all records from DB to display so user can select which record to edit.
        Users selects record.
        Uses manual.Entry to ask for updated values for each field.
        Saves changes to DB using Interaction.update
        """
        try:
            number_entries = self.db_object.count_records(self.DB_TABLE_NAME)

            if number_entries > 200:
                with Selection(
                        'There are more than 200 records in this table, select the column to filter the records on',
                        self.HEADER_NAMES[0], None) as selection:
                    column_id = selection.select_option()

                manual_fields = [['the search string for column ' + self.HEADER_NAMES[0][
                    int(column_id) - 1] + ' to filter the records', self.COLUMN_NAMES[int(column_id) - 1], ''],
                                 ['Y - that records must match exactly your string or N - your string can be '
                                  'contained within a records ' + self.COLUMN_NAMES[int(column_id) - 1] +
                                  " column", 'equal', r'^(?:Y|N)$']]
                with Entry(self.DB_TABLE_NAME, manual_fields) as me:
                    field_values = me.user_input_fields(input_text='Please enter ')

                equal = field_values['equal']

                selected_record, selected_record_num = self.db_object.select_to_edit_or_delete(self.DB_TABLE_NAME,
                                                       self.COLUMN_NAMES, self.HEADER_NAMES, "modify",
                                                       self.JOIN_TABLES, self.COLUMN_NAMES[int(column_id) - 1],
                                                       field_values[self.COLUMN_NAMES[int(column_id) - 1]], equal)
            else:
                selected_record, selected_record_num = self.db_object.select_to_edit_or_delete(self.DB_TABLE_NAME,
                                                            self.COLUMN_NAMES, self.HEADER_NAMES, "modify",
                                                            self.JOIN_TABLES)
            update_fields = selected_record

            with Entry(self.DB_TABLE_NAME, self.MANUAL_FIELDS) as me:
                field_values = me.user_input_fields(update_fields, input_text='Please enter the')

            field_values['id'] = update_fields['id']

            tmp_field_values = self.pick_foreign_keys(field_values)
            if tmp_field_values is not None:
                field_values = tmp_field_values

            self.db_object.update(self.DB_TABLE_NAME, field_values)
        except Exception as e:
            print("result class 312 except: " + str(e) + " Error on line {}".format(sys.exc_info()[-1].tb_lineno))

    def join_view(self):
        """ Overwrite join_view in entry_db_middleman.py """
        return MiddleMan.join_view(self, self.JOIN_TABLES)

    def join_view_filter(self):
        """ Overwrite join_view_filter in entry_db_middleman.py """
        return MiddleMan.join_view_filter(self, self.JOIN_TABLES)


    def delete(self):
        """ Overwrite delete in entry_db_middleman.py. """
        return MiddleMan.delete(self, self.JOIN_TABLES)
