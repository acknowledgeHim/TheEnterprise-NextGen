import sys
from datetime import datetime
from flask_files import common_flask
from common import common, sqlalchemy_model
from setup import current_location
from enterprise_user_conf import OUTPUT_PATH

def validate_input(table_name, inputs, request):
    """ Validates the input based on the regex for that field. """
    required_fields = sqlalchemy_model.retrieve_required_fields(table_name)
    try:
        # Validate input
        field_values = {}
        for input in inputs:
            post_data = request.form.get(input[1])
            value = post_data.strip()
            if "_date" in input[1]:
                if value == "":
                    value = None
                else:
                    value = datetime.strptime(value, '%Y-%m-%d')

            if common.regex_exist_in_entry(value, input[2]) == "" and input[1] in required_fields:
                return None

            if value == "Y":
                value = True
            elif value == "N":
                value = False

            field_values[input[1]] = value
        return field_values

    except Exception as e:
        print("flask-files/insert_views.py except: " + str(e) + " Error on line {}".format(sys.exc_info()[-1].tb_lineno))#, file=sys.stderr)

    return None


def insert(session, inputs, request, table_name, column_names, header_names):
    """ Actually does the inserting. """
    try:
        field_values = validate_input(table_name, inputs, request)

        selected_engagement = session.get('selected_engagement')

        repo_file = common_flask.grab_repo_file(session.get('engagement_path'), selected_engagement)

        if table_name == "Engagement":
            created_tables = sqlalchemy_model.initialize(repo_file)
            common.assign_permissions(repo_file)

        db_object = common_flask.create_db_object(session.get('engagement_path'), selected_engagement,
                                                  session.get('key'), session.get('username'))

        if not isinstance(db_object, str):
            if field_values is not None:
                success, hashval = db_object.add(table_name, field_values)
                # add() returns (True, hashval) on success or (error message, None) on failure -
                # it never raises for a DB-level failure, it just swallows the exception
                # internally (see common/sqlalchemy_db.py). Not checking this meant a failed
                # Engagement insert (this is the table_name=="Engagement" call path -
                # insert_engagement() in this same file) still reported success and handed back
                # a db_object as if the Engagement row existed - it didn't, and every later
                # Scope add crashed on "'NoneType' object is not iterable" trying to read
                # Engagement.external_only for a row that was never created.
                if success is not True:
                    return "Failed inserting " + table_name + ", error: " + str(success), None
                return "Successfully inserted " + table_name + ".", db_object
            else:
                return "Failed.  Nice try, but your posted data to insert was not valid. <br>Dang it Jim, I'm a Doctor not your pentest-validation-monitoring babysitter!", None
        else:
            return "Failed.  Not sure what happened here but problems connecting to the repo.  Try again?", None
    except Exception as e:
        print("flask-files/insert_views.py except: " + str(e) + " Error on line {}".format(sys.exc_info()[-1].tb_lineno))

        return "Failed.  Error: " + str(e), None


def insert_engagement(session, request):
    """ setups of information to be inserted. """
    try:
        from setup.engagement import MANUAL_FIELDS, MORE_MANUAL_FIELDS, COLUMN_NAMES, HEADER_NAMES
        inputs = [["Client Number", "client_number", r'^(?:[\d\-]+)$'],
                  ["Client Name", "client_name", r'^(?:[a-zA-Z_ \-0-9]+)$'],
                  ["Engagement Number", "engagement_number", r'^(?:[a-zA-Z_\-0-9]+)$']] \
                 + MANUAL_FIELDS + MORE_MANUAL_FIELDS

        path = OUTPUT_PATH

        selected_engagement = request.form.get('client_number').strip() + "__" + request.form.get('client_name').replace(" ", "_").strip() + "/"
        path = path + selected_engagement
        new_path_created = common.create_path(path)

        if new_path_created:
            selected_engagement = selected_engagement + request.form.get('engagement_number').strip() + "/"
            path = OUTPUT_PATH + selected_engagement
            new_path_created = common.create_path(path)
            session['engagement_path'] = path

            # Setup necessary session vars
            if new_path_created:
                selected_engagement = selected_engagement.rstrip("/")
                session['selected_engagement'] = selected_engagement
                session['selected_engagement_number'] = selected_engagement[selected_engagement.rfind("/")+1:]
            else:
                return "Failed. Not sure what happened here!"

            if not new_path_created:
                return "Failed. Could not create the necessary folder structure.  Please check your permissions to " + session.get('engagement_path') + "."

        session['engagement_path'] = path

        result, db_object = insert(session, inputs, request, "Engagement", COLUMN_NAMES, HEADER_NAMES)

        if db_object is not None and not isinstance(db_object, str):
            version_added = db_object.add("Information", {'version': '1.0'})

            # Add default 'main' location
            success, hashval = db_object.add("Location", {'name': 'main'})
            # Now assign current location as default 'main' location
            session['current_location'] = '1'
            session['current_location_name'] = 'main'
            current_location_dict = {"current_location": '1', 'modified_by': db_object.current_tester}
            db_object.add("CurrentLocation", current_location_dict) #.update

        return result

    except Exception as e:
        print("flask-files/insert_views.py except: " + str(e) + " Error on line {}".format(sys.exc_info()[-1].tb_lineno), file=sys.stderr)

        return "Failed.  Error: " + str(e)