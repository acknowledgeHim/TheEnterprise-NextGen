import sys
import time
import importlib
from random import randint
from sqlalchemy import event
from sqlalchemy import func
from sqlalchemy.engine import Engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy import create_engine
from sqlalchemy import inspect
from sqlalchemy.orm import aliased
from sqlalchemy import or_
from common import print_text
from common import common, keep_tags
from common import encryption
from common import sqlalchemy_model

class Interaction():
    """Class for adding manual user inputs
    View, add, update, or remove records in DB.
    This class is used as interaction for SqlCipher Object.

    Attributes:
        db_object -- (Model[sqlcipher]): SqlCipher Object
        db_table_name -- (str): Table Name
    """

    def __enter__(self):
        return self

    def __exit__(self, type, value, traceback):
        return self


    def __init__(self, db_file, tester=None):
        self.msg = ""
        self.tester = common.get_tester()
        if tester is not None:
            self.tester = tester
        self.db_file = db_file
        self.initialize(self.db_file)
        return


    @event.listens_for(Engine, "connect")
    def set_sqlite_pragma(dbapi_connection, connection_record):
        """ Turn on foreign key support, not on by default for sqlite. """
        cursor = dbapi_connection.cursor()
        cursor.execute("PRAGMA foreign_keys=ON")
        cursor.close()


    def initialize(self, db_file):
        # Setup Engine
        # check_same_thread=False: every Flask request builds a brand-new Interaction/engine
        # (see common_flask.create_db_object, called per-route) and none of them are ever
        # explicitly closed/disposed, so the old one is only reclaimed whenever Python's GC
        # gets to it - which, under Werkzeug's dev server, is not reliably the same OS thread
        # that created it. SQLite's default same-thread check then raises
        # "SQLite objects created in a thread can only be used in that same thread" from deep
        # inside connection-pool teardown, on an unrelated later request. That's caught by this
        # class's own blanket except-return-None handling (see view(), etc.), so it doesn't
        # surface as an error - it just makes random queries silently return no results.
        self.engine = create_engine('sqlite:///' + db_file, connect_args={"check_same_thread": False})

        # Setup Session (handles db conversation for us)
        Session = sessionmaker(bind=self.engine)
        self.session = Session()

        self.print_message = True


    def table_column_names(self, table_name):
        """
        Grab column names for table_name.
        :return: list of column names
        """

        SubClass = getattr(importlib.import_module(self.module_path), table_name)

        return [column.key for column in SubClass.__table__.columns]


    def count_records(self, table_name):
        """
        Total number of records in the table.
        :return:
        """

        SubClass = getattr(importlib.import_module(self.module_path), table_name)

        return self.session.query(getattr(SubClass, "id")).count()


    def setup_connection(self, table_name, field_values, action='add', equal=True, columns_to_filter=None, values_to_filter=None):
        """

        :param action: add / update / delete
        :param print_message:
        :return: Tuple (True/False, hashval)
        """
        try:
            self.print_message = True

            SubClass = getattr(importlib.import_module(self.module_path), table_name)

            except_msg = "database is locked"
            count = 0
            while "database is locked" in except_msg:
                if "database is locked" in except_msg and count != 0:
                    print_text.print_msg("Database was in use, so retrying operation!")
                try:
                    if action == 'add':
                        self.session.add(SubClass(**field_values))
                        #self.session.execute(SubClass.__table__.insert(), field_values)
                    elif action == 'add multiple':
                        self.session.bulk_insert_mappings(SubClass, field_values)
                    elif action == 'update':
                        queryset = self.session.query(SubClass)
                        if columns_to_filter is not None and values_to_filter is not None:
                            if "id" in columns_to_filter:
                                queryset = queryset.filter(getattr(SubClass, 'id') == field_values['id'])
                            else:
                                if equal:
                                    for count, col in enumerate(columns_to_filter):
                                        queryset = queryset.filter(getattr(SubClass, col)==values_to_filter[count])
                                else:
                                    for count, col in enumerate(columns_to_filter):
                                        queryset = queryset.filter(getattr(SubClass, col).ilike("%" + str(values_to_filter[count]) + "%"))#.like("%%%s%%%" % values_to_filter[count]))

                            queryset.update(field_values)

                        else:
                            return False, None

                    elif action == 'delete':
                        self.session.query(SubClass).filter_by(**field_values).delete()
                    elif action == 'delete where':
                        queryset = self.session.query(SubClass)
                        for key, value in field_values.items():
                            queryset = queryset.filter(getattr(SubClass, key).ilike("%" + str(value) + "%")) #.ilike("%%%s%%%" % value))
                        queryset.delete(synchronize_session='fetch') #synchronize_session=False

                    elif action == 'truncate':
                        self.session.query(SubClass).delete()

                    self.session.commit()

                    if self.print_message and (table_name != "Log" or action == "add"):
                        msg = table_name + " successfully " + action + "."
                        print_text.print_msg(msg)
                        self.msg = self.msg + msg + "\n"

                    if 'delete' not in action and 'truncate' not in action:
                        if isinstance(field_values, list):
                            return True, field_values[0]['hashval']
                        return True, field_values['hashval']
                    else:
                        return True, None

                except Exception as e:
                    print("common.sqlalchemy_db  103 except: " + str(e) + " Error on line {}".format(sys.exc_info()[-1].tb_lineno))
                    extra_text = ""
                    msg = ""
                    if "UNIQUE constraint failed" in str(e) and "hashval" in str(e):
                        extra_text = "  It appears this record is already in the repository!"
                        msg = extra_text
                    if "database is locked" not in str(e): # don't print this error if db was locked bc will retry
                        msg = "Failed to " + action + " " + table_name + " to repository." + extra_text
                        print_text.print_error("\t" + msg)
                    self.msg = self.msg + msg + "\n" + str(e) + "\n"
                    except_msg = str(e)

                    # Rollback changes since errored out
                    self.session.rollback()

                    time.sleep(randint(5, 45))

                count += 1

        except Exception as e:
            print("common.sqlalchemy_db  111 except: " + str(e) + " Error on line {}".format(sys.exc_info()[-1].tb_lineno))
            extra_text = ""
            if "UNIQUE constraint failed" in str(e) and "hashval" in str(e):
                extra_text = "  It appears this record is already in the repository!"
            print_text.print_error("\tFailed to  " + action + " " + table_name + " to repository." + extra_text)
            except_msg = str(e)
            self.msg = self.msg + except_msg + "\n"

        return except_msg, None


    def add(self, table_name, field_values, print_message=True):
        """
        :param field_values: Add entry to DB.
        :return: True/False

        Attributes:
            fields_values -- typically none but could be set to have present values to be inserted with manual user inputs as well
        """
        try:
            if "modified_by" not in field_values or field_values['modified_by'] == "":
                field_values['modified_by'] = self.tester

            # Sanitize input
            new_field_values = {}
            for key, value in field_values.items():
                new_field_values[key] = keep_tags.clean_text(value)
            field_values = new_field_values

            required_fields = sqlalchemy_model.retrieve_required_fields(table_name)
            hash_fields = sqlalchemy_model.retrieve_hash_fields(table_name)
            field_values = encryption.get_hash_string(hash_fields, field_values)

            missing_required = False
            for required_field in required_fields:
                if required_field not in field_values:
                    msg = required_field + " can not be blank.  Did not add " + table_name + "!"
                    print_text.print_error("\t" + msg)
                    self.msg = self.msg + msg + "\n"
                    missing_required = True
                    return msg, None

            if not missing_required:
                return self.setup_connection(table_name, field_values, 'add')
        except Exception as e:
            print("common.sqlalchemy_db  150 except: " + str(e) + " Error on line {}".format(sys.exc_info()[-1].tb_lineno))
            self.msg = self.msg + str(e) + "\n"

    def add_multiple(self, table_name, field_values):
        """
        Bulk inserts.
        :param list_of_field_values: list of dictionaries
        :return: # of rows inserted, 0 if none
        """
        return self.setup_connection(table_name, field_values, 'add multiple')

    def create_or_update(self, table_name, field_values):
        """
        Attempt to create if already exists then update.
        :param table_name: string
        :param field_values: dictionary
        :return:
        """
        SubClass = getattr(importlib.import_module(self.module_path), table_name)

        required_fields = sqlalchemy_model.retrieve_required_fields(table_name)

        except_msg = "database is locked"
        while "database is locked" in except_msg:
            try:
                if "hashval" in field_values:
                    filter_columns = ["hashval"]
                    filter_values = [field_values['hashval']]
                else:
                    filter_columns = []
                    filter_values = []
                    for key, value in field_values.items():
                        if key in required_fields and key != "hashval":
                            filter_columns.append(key)
                            filter_values.append(value)

                if "hashval" not in field_values:
                    required_fields = sqlalchemy_model.retrieve_required_fields(table_name)
                    hash_fields = sqlalchemy_model.retrieve_hash_fields(table_name)
                    field_values = encryption.get_hash_string(hash_fields, field_values)

                try:
                    record = self.session.add(SubClass(**field_values))
                    self.session.commit()
                    return record, True
                except Exception as e:
                    print("common.sqlalchemy_db  226 except: " + str(e) + " Error on line {}".format(sys.exc_info()[-1].tb_lineno))
                    success, record = self.update(table_name, field_values, filter_columns, filter_values, True)
                    if success:
                        return record, False
            except Exception as e:
                self.session.rollback()
                print("common.sqlalchemy_db  239 except: " + str(e) + " Error on line {}".format(sys.exc_info()[-1].tb_lineno))
                extra_text = ""
                if "UNIQUE constraint failed" in str(e) and "hashval" in str(e):
                    extra_text = "  It appears this record is already in the repository!"
                msg = "Failed to create or get " + table_name + " to repository." + extra_text
                print_text.print_error("\t" + msg)
                except_msg = str(e)
                self.msg = self.msg + msg + "\n" + except_msg + "\n"
                time.sleep(randint(5, 45))
        return None, False


    def get_or_create(self, table_name, field_values):
        """

        :param field_values: dictionary of values to add or get existing
        :return: returns tuple with record instance & True/False if added
        """

        SubClass = getattr(importlib.import_module(self.module_path), table_name)

        required_fields = sqlalchemy_model.retrieve_required_fields(table_name)

        except_msg = "database is locked"
        while "database is locked" in except_msg:
            try:
                if "hashval" in field_values:
                    filter_columns = ["hashval"]
                    filter_values = [field_values['hashval']]
                else:
                    filter_columns = []
                    filter_values = []
                    for key, value in field_values.items():
                        if key in required_fields and key != "hashval":
                            filter_columns.append(key)
                            filter_values.append(value)

                record = self.get(table_name, filter_columns, filter_values, True)

                if record is None:
                    self.print_message = False
                    if "hashval" not in field_values:
                        required_fields = sqlalchemy_model.retrieve_required_fields(table_name)
                        hash_fields = sqlalchemy_model.retrieve_hash_fields(table_name)
                        field_values = encryption.get_hash_string(hash_fields, field_values)

                    record = self.session.add(SubClass(**field_values))

                    self.session.commit()
                    self.print_message = True
                    return record, True
                else:
                    return record, False

            except Exception as e:
                self.session.rollback()
                print("common.sqlalchemy_db  73 except: " + str(e) + " Error on line {}".format(sys.exc_info()[-1].tb_lineno))
                extra_text = ""
                if "UNIQUE constraint failed" in str(e) and "hashval" in str(e):
                    extra_text = "  It appears this record is already in the repository!"
                msg = "Failed to create or get " + table_name + " to repository." + extra_text
                print_text.print_error("\t" + msg)
                except_msg = str(e)
                self.msg = self.msg + msg + "\n" + except_msg + "\n"
                time.sleep(randint(5, 45))
        return None, False


    def edit(self, table_name, row_to_upate, filter_columns=None, filter_values=None, equal=True):
        """
        Grabs record that is going to be edited.
        :param row_to_upate: int representing the table's row.id
        :return: return selected record & row to update or none, none if it fails (could not find record)
        """
        try:
            import os
            SubClass = getattr(importlib.import_module(self.module_path), table_name)

            queryset = self.session.query(SubClass)

            if filter_values is None and filter_columns is None and row_to_upate is None:
                return None
            elif filter_values is None and filter_columns is None:
                queryset = queryset.filter(getattr(SubClass, "id") == row_to_upate)
            else:
                for count, col in enumerate(filter_columns):
                    if equal:
                        queryset = queryset.filter(func.lower(getattr(SubClass, col)) == func.lower(filter_values[count]))
                    else:
                        queryset = queryset.filter(getattr(SubClass, col).ilike("%" + str(filter_values[count]) + "%"))#ilike("%%%s%%%" % filter_values[count]))

            queryset = queryset.first()

            if queryset is not None:
                return {c.key: getattr(queryset, c.key) for c in inspect(queryset).mapper.column_attrs}

        except Exception as e:
            print("220 sqlalchemy_db.py except: " + str(e) + " Error on line {}".format(sys.exc_info()[-1].tb_lineno))
            print_text.print_error("\tFailed to grab selected records value for " + table_name + ".  Make sure you typed the correct Row # and try again!")
            self.msg = self.msg + str(e) + "\n"
        return None


    def update(self, table_name, field_values, columns_to_filter=None, values_to_filter=None, equal=True):
        """

        :param field_values: dictionary of values to update
        :param columns_to_filter: select record to update by this field/column name
        :param values_to_filter: select recrod to update using this value for field/column name passed
        :return: Tuple (True/False, hashval of last updated)
        """
        try:
            # Look for all tables that are dependant to this table's id and update them accordingly
            # if change engagementdevice scope need to change its location and all locations / scopes for devices associated with EngagementDevice
            #self.update_all_tables_that_have_specified_foreign_key(table_name + "_id", {table_name + "_id": field_values['id']},
            #                                                       [table_name + "_id"], [field_values['id']], True)
            result = False, None

            if "id" in field_values:
                columns_to_filter = ["id"]
                values_to_filter = [field_values['id']]
            elif columns_to_filter is None or values_to_filter is None:
                return None

            if "modified_by" not in field_values or field_values['modified_by'] == "":
                field_values['modified_by'] = self.tester

            hash_fields = sqlalchemy_model.retrieve_hash_fields(table_name)

            # Sanitize input
            new_field_values = {}
            for key, value in field_values.items():
                new_field_values[key] = keep_tags.clean_text(value)
            field_values = new_field_values

            current_records = self.view(table_name, None, columns_to_filter, values_to_filter, equal)
            if current_records is not None:
                for record in current_records:
                    # loop through values and if not there then add (necessary to recalculate the hash)
                    for key, value in record.items():
                        if key not in field_values:
                            field_values[key] = value

                    tmp_field_values = encryption.get_hash_string(hash_fields, field_values)
                    result = self.setup_connection(table_name, tmp_field_values, 'update', equal, columns_to_filter, values_to_filter)
                return result
        except Exception as e:
            print("247 sqlalchemy_db.py except: " + str(e) + " Error on line {}".format(
                sys.exc_info()[-1].tb_lineno))
            self.msg = self.msg + str(e) + "\n"
        return result


    def update_all_tables_that_have_specified_foreign_key(self, foreign_key, field_values, columns_to_filter, values_to_filter, equal=True):
        """
        Used to update all tables that have a foreign key that was changed. (Ex. When superscope entry entered all
        entries pointing to old scope must be re-mapped to superscope now)
        :param foreign_key: string
        :param field_values: dictionary
        :param columns_to_filter: list
        :param values_to_filter: list
        :param equal: True/False
        :return:
        """
        inspector = inspect(self.engine)
        for table_name in inspector.get_table_names():
            for column in inspector.get_columns(table_name):
                column_name = column['name']
                if foreign_key + "_id" == column_name:
                    self.update(table_name, field_values, columns_to_filter, values_to_filter, equal)


    def delete(self, table_name, row_to_delete):
        """
        Delete individual record
        :param row_to_delete:
        :return:
        """
        field_values = {'id': row_to_delete}
        return self.setup_connection(table_name, field_values, 'delete', True)


    def delete_where(self, table_name, columns_to_filter, values_to_filter, equal=True, look_for_foreign_constraints=True):
        """

        :param columns_to_match:
        :param values_to_match:
        :param equal:
        :param look_for_foreign_constraints:
        :return:
        """
        field_values = {}
        for count, col in enumerate(columns_to_filter):
            field_values[col] = values_to_filter[count]
        if equal:
            result = self.setup_connection(table_name, field_values, 'delete', equal)
        else:
            result = self.setup_connection(table_name, field_values, 'delete where', equal)


    def truncate(self, table_name):
        """
        Empty out all records for a table.
        :param table_name:
        :return:
        """
        return self.setup_connection(table_name, None, 'truncate')


    def get(self, table_name, filter_column, filter_value, equal=True):
        """
        Alias for edit.
        :param filter_column: list of columns to filter on
        :param filter_value: list of values to filter on
        :return: record object
        """
        return self.edit(table_name, None, filter_column, filter_value, equal)


    def queryset_to_dict(self, queryset):
        """
        Convert a model table queryset to list of dictionaries
        :param queryset:
        :return:
        """
        try:
            result = []
            for row in queryset:
                if hasattr(row, '_asdict'):
                    # SQLAlchemy Core Row - what a query for specific columns (rather than
                    # whole-entity) returns. In 1.4 this no longer subclasses tuple, so the
                    # isinstance(..., tuple) checks callers use to route here (e.g. view())
                    # never match it and everything ends up here regardless. It isn't a mapped
                    # entity, so inspect(row).mapper below raises for it - it already knows its
                    # own columns, so just use those instead.
                    result.append(dict(row._asdict()))
                else:
                    result.append({c.key: getattr(row, c.key) for c in inspect(row).mapper.column_attrs})
            return result
        except Exception as e:
            print("common.sqlalchemy_db 389 except: " + str(e) + " Error on line {}".format(
                sys.exc_info()[-1].tb_lineno))
            self.msg = self.msg + str(e) + "\n"
        return None

    def queryset_join_to_dict(self, queryset):
        """

        :param queryset: list of multiple sqlalchemy table models
        :return: list of dictionaries or None
        """
        try:
            result = []
            for obj in queryset:
                result.append(self.queryset_to_dict(obj))

            single_result = []
            for count, r in enumerate(result):
                new_dict = {}
                for inner in r:
                    # only keep first id, which should be the main table's ID
                    if "id" in new_dict and "id" in inner:
                        del inner['id']
                    new_dict = {**new_dict, **inner}
                single_result.append(new_dict)
            return single_result
        except Exception as e:
            print("common.sqlalchemy_db 419 except: " + str(e) + " Error on line {}".format(sys.exc_info()[-1].tb_lineno))
            self.msg = self.msg + str(e) + "\n"
            return None

    def view(self, table_name, columns_to_return=None, filter_columns=None, filter_values=None, equal=True, sort=[('id','asc')], pages=None):
        """

        :param columns_to_return: list of columns to return
        :param filter_columns: list of columns to filter on
        :param filter_values: list of values associated to a column in list of columns to filter on
        :param equal: if filter values should be equal or not equal
        :param sort: tuple (column_to_sort_by, direction to sort)
        :param pages: list where [0]=start & [1]=length
        :return: a list of dictionaries
        """
        try:
            if isinstance(columns_to_return, list) and len(columns_to_return) == 0:
                columns_to_return = None

            queryset = self.session
            SubClass = getattr(importlib.import_module(self.module_path), table_name)

            if columns_to_return is not None:
                queryset = queryset.query(*[getattr(SubClass, column) for column in columns_to_return])
            else:
                queryset = queryset.query(SubClass)

            if filter_values is not None and filter_columns is not None:

                for count, col in enumerate(filter_columns):
                    if isinstance(equal, bool) and equal:
                        queryset = queryset.filter(getattr(SubClass, col) == filter_values[count])
                    elif isinstance(equal, bool) :
                        queryset = queryset.filter(getattr(SubClass, col).ilike("%" + str(filter_values[count]) + "%"))
                    elif isinstance(equal, list) and len(equal) > count:
                        cur_equal = equal[count]
                        if cur_equal:
                            queryset = queryset.filter(getattr(SubClass, col) == filter_values[count])
                        else:
                            queryset = queryset.filter(getattr(SubClass, col).ilike("%" + str(filter_values[count]) + "%"))

            # Sorting / Ordering
            for s in sort:
                TmpSubClass = SubClass
                sort_col = s[0]
                if "." in s[0]:
                    parts = s[0].split(".")
                    TmpSubClass = getattr(importlib.import_module(self.module_path), parts[-2])
                    sort_col = parts[-1]
                if s[1] == 'asc':
                    queryset = queryset.order_by(getattr(TmpSubClass, sort_col).asc())
                else:
                    queryset = queryset.order_by(getattr(TmpSubClass, sort_col).desc())

            if pages is not None:
                queryset = queryset.slice(pages[0], pages[1])

            queryset = queryset.all()

            if len(queryset) > 0:
                if isinstance(queryset, tuple) or (isinstance(queryset, list) and isinstance(queryset[0], tuple)):
                    # KeyedTuple (or list of KeyedTuple)
                    return [u._asdict() for u in queryset]
                else:
                    return self.queryset_to_dict(queryset)

        except Exception as e:
            print("common.sqlalchemy_db 461 except: " + str(e) + " Error on line {}".format(sys.exc_info()[-1].tb_lineno))
            msg = "Failed to grab selected records value."
            print_text.print_error("\t" + msg)
            self.msg = self.msg + msg + "\n" + str(e) + "\n"
        return None

    def join_view(self, table_name, join_tables, columns_to_return=None, filter_columns=None, filter_values=None, equal=True, sorting=[('id','asc')], pages=None, or_filter=False):
        """
        Working with multiple table joins by group_by(on primary table, table_name)
        :param join_tables: list of TableName.fieldname
        :param columns_to_return: list
        :param filter_columns: list
        :param filter_values: list
        :param equal: True/False
        :param sorting: list of tuple (column_to_sort_by, direction to sort)
        :param pages: list where [0] = start & [1] = length
        :return: list of dictionaries of records
        """
        try:
            SubClass = getattr(importlib.import_module(self.module_path), table_name)

            JoinClasses = []
            JoinClassesExplicit = []
            for join_table in join_tables:
                join_table_parts = join_table.split(".")
                join_table_parts = join_table_parts[ :-1]  # remove the column name to return for now
                DependantTable = SubClass
                for count, part in enumerate(join_table_parts):  # list of tables to join are in reverse order
                    TmpSubClass = getattr(importlib.import_module(self.module_path), part)
                    if TmpSubClass not in JoinClasses:
                        JoinClassesExplicit.append((TmpSubClass, TmpSubClass.id == getattr(DependantTable, part.lower() + "_id")))
                        JoinClasses.append(TmpSubClass)
                    DependantTable = TmpSubClass # move to next

            instances = [SubClass] + JoinClasses

            queryset = self.session.query(*instances).join(*JoinClassesExplicit)

            if filter_values is not None and filter_columns is not None:
                for count, col in enumerate(filter_columns):
                    TmpSubClass = SubClass
                    if "." in col:
                        parts = col.split(".")
                        TmpSubClass = getattr(importlib.import_module(self.module_path), parts[-2])
                        col = parts[-1]

                    if not or_filter:
                        if isinstance(equal, bool) and equal:
                            queryset = queryset.filter(getattr(TmpSubClass, col) == filter_values[count])
                        elif isinstance(equal, bool):
                            queryset = queryset.filter(getattr(TmpSubClass, col).ilike("%" + str(filter_values[count]) + "%"))
                        elif isinstance(equal, list) and len(equal) > count:
                            cur_equal = equal[count]
                            if cur_equal:
                                queryset = queryset.filter(getattr(TmpSubClass, col) == filter_values[count])
                            else:
                                queryset = queryset.filter(getattr(TmpSubClass, col).ilike("%" + str(filter_values[count]) + "%"))

                if or_filter:
                    queryset = queryset.filter(getattr(TmpSubClass,col).in_(filter_values))

            queryset = queryset.group_by(getattr(SubClass, "id"))

            # Sorting / Ordering
            for s in sorting:
                TmpSubClass = SubClass
                sort_col = s[0]
                if "." in s[0]:
                    parts = s[0].split(".")
                    TmpSubClass = getattr(importlib.import_module(self.module_path), parts[-2])
                    sort_col = parts[-1]
                if s[1].lower() == 'asc':
                    queryset = queryset.order_by(getattr(TmpSubClass, sort_col).asc())
                else:
                    queryset = queryset.order_by(getattr(TmpSubClass, sort_col).desc())

            if pages is not None:
                queryset = queryset.slice(pages[0], pages[1] + pages[0])

            queryset = queryset.all()

            if isinstance(queryset, list):
                return self.queryset_join_to_dict(queryset)
            elif isinstance(queryset, tuple):
                # KeyedTuple
                return self.queryset_to_dict(queryset)
            else:
                return [u._asdict() for u in queryset]

        except Exception as e:
            print("common.sqlalchemy_db 471 except: " + str(e) + " Error on line {}".format(
                sys.exc_info()[-1].tb_lineno))
            msg = "Failed to grab selected records value."
            print_text.print_error("\t" + msg)
            self.msg = self.msg + msg + "\n" + str(e) + "\n"
        return None


    def view_filter_regex(self, table_name, columns_to_return, filter_columns, filter_values, regexes, join_tables=None, sort=[('id','asc')]):
        """
        Calls view and then does regex check for records returned.
        :param columns_to_return: list
        :param filter_columns: list
        :param filter_values: list
        :param regexes: dictionary (key is column name & value is regex to check that column entry against)
        :return: list of dictionary: records that have regex in them
        """
        valid_records = []
        try:
            if join_tables is None:
                list_of_dicts = self.view(table_name, columns_to_return, filter_columns, filter_values, sort)
            else:
                list_of_dicts = self.join_view(table_name, join_tables, columns_to_return, filter_columns, filter_values, sort)

            for lod in list_of_dicts:
                for key, value in regexes.items():
                    if common.regex_exist_in_entry(lod[key], value, False) != "":
                        valid_records.append(lod)
                        break

            return valid_records
        except Exception as e:
            print("common.sqlalchemy_db except: " + str(e) + " Error on line {}".format(
                sys.exc_info()[-1].tb_lineno))
            self.msg = self.msg + str(e) + "\n"

    def join_view_filter(self, table_name, join_tables, columns_to_return, filter_columns, filter_values, equal, sort=[('id','asc')]):
        """
        Alias for join_view
        :param join_tables: list of TableName.fieldname
        :param columns_to_return: list
        :param filter_columns: list
        :param filter_values: list
        :param equal: True/False
        :return: list of dictionaries of records
        """
        return self.join_view(table_name, join_tables, columns_to_return, filter_columns, filter_values, equal, sort)


    def queryset_list_filter(self, table_name, columns_to_return, filter_columns, filter_values):
        """
        Alias for view.
        :param columns_to_return:
        :param filter_columns:
        :param filter_values:
        :return:
        """
        return self.view(table_name, columns_to_return, filter_columns, filter_values)


    def queryset_list(self, table_name, column_name):
        """
        Alias for view.
        Returns list of just the values from the column specified
        :param column_name: string
        :return:
        """
        return self.view(table_name, [column_name])


    def dictionary_list(self, table_name, column_name, filter_columns=None, filter_values=None, equal=True, join_tables=None):
        """
        Alias for view but formatted for just list of single field values.
        :param column_name:
        :param filter_columns:
        :param filter_values:
        :param equal:
        :return: list of values for column_name specified
        """
        records = self.view(table_name, [column_name], filter_columns, filter_values, equal)
        values = []
        if records is not None:
            for record in records:
                values.append(record[column_name])

        return values

    def dictionary_list_multiple_fields(self, table_name, column_names, filter_columns=None, filter_values=None, equal=True, separator=" - "):
        """ Converts returned list of dictionaries to single list where column names are string with separator. """
        try:
            join_tables = []
            cols = []
            for col in column_names:
                if "." in col:
                    join_tables.append(col)
                    col = col[col.rfind(".") + 1:]
                cols.append(col)

            if len(join_tables) > 0:
                records = self.join_view(table_name, join_tables, None, filter_columns, filter_values, equal)
            else:
                records = self.view(table_name, column_names, filter_columns, filter_values, equal)

            values = []
            if records is not None:
                for record in records:
                    tmp = ""
                    for col in column_names:
                        if "." in col:
                            col = col[col.rfind(".")+1:]
                        if tmp == "":
                            tmp = str(record[col])
                        else:
                            tmp = tmp + separator + str(record[col])
                    values.append(tmp)
            return values
        except Exception as e:
            print("common.sqlalchemy_db 667 except: " + str(e) + " Error on line {}".format(sys.exc_info()[-1].tb_lineno))
            self.msg = self.msg + str(e) + "\n"


    def list_of_dict_to_2d_list(self, dictionary_list, column_names):
        """

        :param dictionary_list:
        :param column_names:
        :return:
        """
        results = []
        for record in dictionary_list:
            row = []
            for column in column_names:
                row.append(record[column])
            results.append(row)

        return results

    def view_results_in_table(self, table_name, column_names, header_names, join_tables=None, filter_columns=None, filter_values=None, equal=False):
        """
        Displays the records in a table view.
        :param join_tables:list
        :param column_names: list
        :param filter_columns: list
        :param filter_values: list
        :param equal: True/False
        :return: # of records found

        """
        try:
            if join_tables is not None:
                records = self.join_view_filter(table_name, join_tables, column_names, filter_columns, filter_values, equal)
            else:
                records = self.view(table_name, column_names, filter_columns, filter_values, equal)

            results = []
            if records is not None:
                for record in records:
                    inner_list = []
                    for column in column_names:
                        inner_list.append(print_text.insert_newlines(str(record[column])))
                    results.append(inner_list)

            if records is not None and len(records) > 0:
                print_text.console_table_view(table_name, header_names, results)
                return len(records)
            else:
                msg = "No " + table_name + " entries in the repository.  Insert one first!"
                print_text.print_msg("\t" + msg)
                self.msg = self.msg + msg + "\n"
            return 0
        except Exception as e:
            print("common.sqlalchemy_db 577 except: " + str(e) + " Error on line {}".format(sys.exc_info()[-1].tb_lineno))
            self.msg = self.msg + str(e) + "\n"

    def selection(self, table_name, column_names, header_names, action, join_tables=None, filter_column=None, filter_value=None, equal=True):
        """
        Allows user to select row from displayed current contents.
        :param action:
        :param join_tables:
        :param filter_column:
        :param filter_value:
        :param equal:
        :return:
        """
        if filter_column is not None and not isinstance(filter_column, list):
            filter_column = [filter_column]
        if filter_value is not None and not isinstance(filter_value, list):
            filter_value = [filter_value]

        selection = ''
        records = self.view_results_in_table(table_name, column_names, header_names, join_tables, filter_column, filter_value, equal)
        if records > 0:
            while True:
                try:
                    selection = int(input("Please enter the Row # of the " + table_name + " to " + action + ": "))
                except:
                    selection = None
                if isinstance(selection, int):
                    return int(selection)
                else:
                    print_text.print_error("\tYour selection was not a valid Row #.  Please try again.")
                records = self.view_results_in_table(table_name, column_names, header_names, join_tables, filter_column, filter_value, equal)
            return -1


    def select_to_edit_or_delete(self, table_name, column_names, header_names, action, join_tables=None, filter_column=None, filter_value=None, equal=True):
        """
        Display table view of data to allow for selection.
        :param action:
        :param join_tables:
        :param filter_column:
        :param filter_value:
        :param equal:
        :return:
        """

        row_to_update = self.selection(table_name, column_names, header_names, action, join_tables, filter_column, filter_value, equal)
        selected_record = self.edit(table_name, row_to_update)

        return selected_record, row_to_update

