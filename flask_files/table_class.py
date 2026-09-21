import sys
import os
import importlib
from common import common, keep_tags
from flask_files import common_flask
from common.database_object import OurCoolDBObject
from sqlalchemy import inspect


from result.deviceport import JOIN_TABLES as DevicePortJoinTables
from result.result import JOIN_TABLES as ResultJoinTables
from result.recon import JOIN_TABLES as ReconJoinTables
from result.engagementdevice import JOIN_TABLES as EngagementDeviceJoinTables
from result.phished import JOIN_TABLES as PhishedJoinTables
from setup.scope import JOIN_TABLES as ScopeJoinTables
from menus.log import JOIN_TABLES as LogJoinTables
from setup.tester_device import JOIN_TABLES as TesterJoinTables
from result.credential import JOIN_TABLES as CredentialJoinTables
from result.person import JOIN_TABLES as PersonJoinTables

class TableClass():

    def __init__(self, db_object, table_name, modify=True, json_data=None, current_user=common.get_tester(), request=None):
        try:
            self.table_name = table_name
            self.db_object = db_object
            self.modify = modify
            self.json_data = json_data
            self.headers = []
            self.current_user = current_user

            self.global_filters = []
            self.global_filter_values = []

            foreign_filter = None
            if request is not None:
                args = request.args
                if 'i' in args:
                    inspector = inspect(self.engine)
                    for tname in inspector.get_table_names():
                        if tname == table_name:
                            for column in inspector.get_columns(table_name):
                                column_name = column['name']
                                if "_id" == column_name:
                                    pass
        except Exception as e:
            print("flask_files/table_class 47 except: " + str(e) + " Error on line {}".format(sys.exc_info()[-1].tb_lineno))

        return

    def __enter__(self):
        return self

    def __exit__(self, type, value, traceback):
        # print sys.exc_info()
        return self

    def extract_header(self, key, count):
        header = key
        skip = False
        if header == "id":
            if self.modify:
                self.id_index = count
                skip = True
                self.indexes_to_skip.append(count)
        elif header == "hashval":
            skip = True
            self.indexes_to_skip.append(count)
        elif self.join_tables is not None:
            for jt in self.join_tables:
                if header + "." in jt.lower() or header.replace("_", "") + "." in jt.lower():
                    self.indexes_to_skip.append(count)
                    skip = True
                elif "." + header in jt.lower():
                    header = jt[:jt.find(".")]
        header = header.replace("_", " ")
        self.headers[count] = header
        return header, skip

    def filtering(self):
        """ Sets up filtering / searching """
        filter_cols = []
        filter_vals = []
        try:
            columns = self.json_data['columns']
            for cnt, col in enumerate(columns):
                ind_search = col["search"]["value"].strip()
                if ind_search != "" and self.all_columns[cnt] != "edit" and self.all_columns[cnt] != "delete":
                    filter_cols.append(self.all_columns[cnt])
                    filter_vals.append(ind_search)

        except Exception as e:
            print("flask_files/table_class 69 except: " + str(e) + " Error on line {}".format(sys.exc_info()[-1].tb_lineno))
        return filter_cols, filter_vals

    def sorting(self):
        """ Sets up sorting. """
        try:
            self.json_columns = self.json_data['columns']

            columns_to_sort = []
            orders = self.json_data['order']
            for cnt, column_order in enumerate(orders):
                sort_it = True
                if self.join_tables is not None:
                    for jt in self.join_tables:
                        if self.all_columns[int(column_order["column"])] in jt:
                            sort_it = False
                            break
                if sort_it:
                    columns_to_sort.append([self.all_columns[int(column_order["column"])], column_order['dir']])
        except Exception as e:
            print("flask_files/table_class 81 except: " + str(e) + " Error on line {}".format(sys.exc_info()[-1].tb_lineno))
        return columns_to_sort

    def paging(self):
        """ Sets up paging. """
        pages = None
        if 'start' in self.json_data and 'length' in self.json_data:
            pages = [int(self.json_data['start']), int(self.json_data['length'])]
        return pages

    def create_table_header(self, all_records, foreign_display_name):
        data = ""
        datatable_columns = ""
        try:
            if self.table_name != "CurrentLocation" and self.table_name != "Engagement" and self.table_name != "Job":
                data = "<button class='black_text' onclick='dialog_html(\"/add?table=" + self.table_name + "\");'" \
                    " name='Insert " + self.table_name + "' value='Insert " + self.table_name + "'>" \
                    "Insert " + self.table_name + "</button>"

                if len(all_records) > 0:
                    data = data + " | <button class='black_text' " \
                                  "onclick='dialog_html(\"/truncate?table=" + self.table_name + "\");'> Delete All " + \
                           self.table_name + " Records</button>"

                if self.table_name == "EngagementDevice":
                    data = data + " | <button class='black_text' onclick='dialog_html(\"/merge?table=" + self.table_name + "\");'" \
                        " name='Merge " + self.table_name + "s' value='Merge " + self.table_name + "s'>" \
                        "Merge " + self.table_name + "s</button>"

                if self.table_name == "Scope":
                    data = data + " | <button class='black_text' onclick='dialog_html(\"/file_upload?table=Scope\");'"\
                        " name='Upload Scope File' value='Upload Scope File'>Upload Scope File</button>"

            data = data + "<table id=datatables_table class='display table-striped table-bordered' width=100% cellspacing=0>"
            sep = ""
            data = data + "<thead><tr>"
            for col in self.all_columns:
                if datatable_columns != "":
                    sep = ", "
                colname_displayed = col
                if col in foreign_display_name:
                    colname_displayed = foreign_display_name[col] + " (" + col + ")"
                self.headers.append(col)
                if "_" in colname_displayed:
                    colname_displayed = colname_displayed.replace("_", " ")
                data = data + "<th>" + colname_displayed + "</th>"
                datatable_columns = datatable_columns + sep + '{"data": "' + str(col) + '"}'

            if self.modify:
                if self.table_name != "Job":
                    data = data + "<th>edit</th><th>delete</th>"
                    datatable_columns = datatable_columns + ', {"data": "edit"}, {"data": "delete"}'
                else:
                    data = data + "<th>kill job</th>"
                    datatable_columns = datatable_columns + ', {"data": "delete"}'
            data = data + "</tr></thead><tbody>"

            if "<tbody>" in data:
                data = data + "</tbody><tfoot><tr>"
                data = data + "".join(["<th>" + str(header) + "</th>" for header in self.headers])
                data = data + "</tr></tfoot>"
            data = data + "</table>"
        except Exception as e:
            print("flask_files/table_class except: " + str(e) + " Error on line {}".format(sys.exc_info()[-1].tb_lineno))

        return data, datatable_columns

    def common_view(self):
        try:
            table_columns = self.db_object.table_column_names(self.table_name)

            all_columns = list(table_columns)
            if "hashval" in all_columns:
                all_columns.remove('hashval')
            if "id" in all_columns:
                all_columns.remove('id')

            self.all_columns = [x for x in all_columns if "_id" not in x]

            self.join_tables = None
            try:
                if self.table_name == "Scope":
                    self.join_tables = ScopeJoinTables
                elif self.table_name == "DevicePort":
                    self.join_tables = DevicePortJoinTables
                elif self.table_name == "Result":
                    self.join_tables = ResultJoinTables
                elif self.table_name == "Recon":
                    self.join_tables = ReconJoinTables
                elif self.table_name == "EngagementDevice":
                    self.join_tables = EngagementDeviceJoinTables
                elif self.table_name == "Credential":
                    self.join_tables = CredentialJoinTables
                elif self.table_name == "Phished":
                    self.join_tables = PhishedJoinTables
                elif self.table_name == "Log":
                    self.join_tables = LogJoinTables
                elif self.table_name == "TesterDevice":
                    self.join_tables = TesterJoinTables
                elif self.table_name == "Person":
                    self.join_tables = PersonJoinTables
            except Exception as e:
                print("flask_files/table_class 52 except: " + str(e) + " Error on line {}".format(
                    sys.exc_info()[-1].tb_lineno))
                self.join_tables = None

            foreign_display_name = {}
            if self.join_tables is not None:
                for jt in self.join_tables:
                    foreign_parts = jt.split(".")
                    foreign_colname = foreign_parts[-1]

                    if "_id" not in foreign_colname:
                        self.all_columns.append(foreign_colname)
                        foreign_display_name[foreign_colname] = foreign_parts[-2]

            equal = []
            filter_columns = []
            filter_values = []

            if self.global_filters is not None and len(self.global_filters) > 0:
                filter_columns = self.global_filters
                equal.append(True)
            if self.global_filter_values is not None and len(self.global_filter_values) > 0:
                filter_values = self.global_filter_values

            column_names = None

            # Filter by current testing location
            model = ""
            if self.table_name != "EmailEvent" and self.table_name != "FlaskUser":
                current_location = self.db_object.grab_current_location()
                if current_location is None:
                    current_location = self.db_object.grab_column_from_single_record("Location", ["name"], ["main"], "id")
                if "location_id" in table_columns:
                    if current_location is not None and current_location != "all_locations":
                        filter_columns.append("location_id")
                        filter_values.append(int(current_location))
                elif "scope_id" in table_columns:
                    if current_location is not None and current_location != "all_locations":
                        filter_columns.append("Scope.location_id")
                        filter_values.append(int(current_location))
                elif "engagementdevice_id" in table_columns:
                    if current_location is not None and current_location != "all_locations":
                        filter_columns.append("EngagementDevice.Scope.location_id")
                        filter_values.append(int(current_location))
            else:
                model = "&model=event"
                column_names = table_columns

            if len(filter_columns) == 0 or len(filter_values) == 0:
                filter_columns = None
                filter_values = None

            if self.json_data is not None:
                filter_cols, filter_vals = self.filtering()
                sorting = self.sorting()
                pages = self.paging()
            else:
                filter_cols = None
                filter_vals = None
                pages = [0, 1]
                sorting = [('id','asc')]

            if filter_cols is not None and filter_vals is not None and len(filter_cols) > 0 and len(filter_vals) > 0:
                if filter_columns is not None:
                    filter_columns = filter_columns + filter_cols
                    filter_values = filter_values + filter_vals
                else:
                    filter_columns = filter_cols
                    filter_values = filter_vals

            if self.join_tables is not None:
                if filter_columns is not None:
                    for count, fc in enumerate(filter_columns):
                        for jt in self.join_tables:
                            if fc in jt and fc != jt:
                                filter_columns[count] = jt
                        equal.append(False)

                all_records = self.db_object.join_view(self.table_name, self.join_tables, None, filter_columns,
                                                       filter_values, equal, sorting, pages)
                unfiltered_records = self.db_object.join_view(self.table_name, self.join_tables)
                filtered_records = self.db_object.join_view(self.table_name, self.join_tables, None, filter_columns,
                                                       filter_values, equal)
            else:
                if filter_columns is not None:
                    for filter_column in filter_columns:
                        equal.append(False)
                else:
                    equal = True

                all_records = self.db_object.view(self.table_name, column_names, filter_columns, filter_values, equal,
                                                  sorting, pages)
                unfiltered_records = self.db_object.view(self.table_name, column_names)
                filtered_records = self.db_object.view(self.table_name, column_names, filter_values, equal)
            if all_records is None:
                all_records = []
                unfiltered_records = []
                filtered_records = []
        except Exception as e:
            print("flask_files/table_class except: " + str(e) + " Error on line {}".format(sys.exc_info()[-1].tb_lineno), file=sys.stderr)
            model = ""
            all_records = []
            self.all_columns = []
            unfiltered_records = []
            filtered_records = []
        return model, unfiltered_records, filtered_records, all_records, foreign_display_name

    def ajax_view(self):
        """" Create ajax response for the actual table data. """

        if self.table_name != "Job":
            model, unfiltered_records, filtered_records, all_records, foreign_display_name = self.common_view()
        else:
            from menus import job
            active_jobs = job.get_active_tasks(self.db_object.engagement_path)
            model = "Job"
            all_records, valid_ids, valid_information = job.get_running_jobs(self.db_object, "Active", active_jobs, False)
            unfiltered_records = all_records
            filtered_records = all_records

        try:
            total_records = len(unfiltered_records)
            self.id_index = None
            self.indexes_to_skip = []

            draw = int(self.json_data['draw'])
            records = []
            for row_count, record in enumerate(all_records):
                can_edit = True
                self.id_index = record['id']
                record_dict = {}
                for key, value in record.items():
                    value = keep_tags.clean_text(value)
                    if key in self.all_columns:
                        if self.table_name == "CurrentLocation" and key == "current_location" and value != "all_locations":
                            value = self.db_object.grab_column_from_single_record("Location", ["id"], [value], "name")
                        if self.table_name == "CurrentLocation" and key == "modified_by" and self.current_user != value:
                            can_edit = False
                    if key == 'target_name' and value is not None:
                        value = '<a href=detail?i=' + value + '&table=DevicePort>' + value + '</a>'
                    elif key == "open_ip" and value is not None:
                        value = '<a href=http://' + value + ' target=_blank>' + value + '</a>'

                    record_dict[key] = str(value)
                    if 'port_description' in record:
                        port_description = record['port_description']
                        if port_description is None:
                            port_description = ""
                        if self.table_name == "DevicePort" and "port_description" in record and \
                            ('http' in port_description.lower() or 'web' in port_description.lower() or 'www' in port_description.lower()):
                            proto = 'http'
                            if 'https' in port_description.lower() or record['port'] == '443':
                                proto = 'https'
                            record_dict['ip'] = "<a href=" + proto + "://" + record['ip'] + ":" + record['port'] + " target=_blank>" + record['ip'] + "</a>"

                if self.modify and self.id_index is not None:
                    if self.table_name != "Job":
                        if can_edit:
                            record_dict['edit'] = "<img onclick='dialog_html(\"/edit?table=" + self.table_name + \
                                  "&ident=" + str(record['id']) + model + "\");' src=/static/images/edit.png height=20>"
                        else:
                            record_dict['edit'] = ""
                    record_dict['delete'] = ''
                    if self.table_name != "Engagement" and self.table_name != "CurrentLocation":  # Not allowed to Delete an Engagement or CurrentLocation!

                        record_dict['delete'] = "<img onclick='confirm_delete(\"/delete?table=" + self.table_name + \
                                "&ident=" + str(record['id']) + model + "\");' src=/static/images/delete.png height=20>"

                records.append(record_dict)

            return {'draw': draw, 'recordsTotal': total_records, 'recordsFiltered': len(filtered_records), 'data': records}
        except Exception as e:
            print("flask_files/table_class except: " + str(e) + " Error on line {}".format(sys.exc_info()[-1].tb_lineno))

    def list_view(self):
        """
        List view page using template that is passed.
        Determines which fields are encrypted and excludes those fields as sortable fields.

        :return: the HTTP response from engageview.PageView
        """
        try:
            model, unfiltered_records, filtered_records, all_records, foreign_display_name = self.common_view()

            return self.create_table_header(all_records, foreign_display_name)

        except Exception as e:
            print("flask_files/table_class except: " + str(e) + " Error on line {}".format(sys.exc_info()[-1].tb_lineno))

    def job_view(self):
        try:
            pass
        except Exception as e:
            print("flask_files/table_class except: " + str(e) + " Error on line {}".format(sys.exc_info()[-1].tb_lineno))
