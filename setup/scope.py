import sys
import os
from common import print_text, common
from common import encryption, network
from common.sqlalchemy_model import retrieve_hash_fields
from common.manual import Entry
from common.entry_db_middle_man import MiddleMan
from setup.engagement_scope import ScopeEntry
from common.selection import Selection


DB_TABLE_NAME = "Scope"
MANUAL_FIELDS = [["Entry", "entry", '']]#, ["Permission to test, Y", "permission", r'^(?:Y|N)$']]
UPDATE_MANUAL_FIELDS = (["Open IP", "open_ip", ''], ["Open Port", "open_port", r'[\d]+'],
                                    ["Permission to test, Y|N", "permission", r'^(?:Y|N)$'])

HEADER_NAMES = [['Row #', 'Location', 'Original Entry', 'Entry', 'Permission', 'Type', 'Open IP', 'Open Port', 'Information', 'Additional', 'Modified By', 'Modified Date']]
COLUMN_NAMES = ['id', 'name', 'original_entry', 'entry', 'permission', 'type', 'open_ip','open_port', 'information', 'additional', 'modified_by', 'modified_date']
JOIN_TABLES = ["Location.name"]

class Scope(MiddleMan):
    """
    Add, update or remove Scope entries. For all engagements there
	should be at least one Scope entry.

	Scope can be: ip, website, domain, person, or device

	Arguments:
	    only_public -- bool if True then only Public, External IPs allowed.
    """
    def __init__(self, db_object, full_client_engagement_path):
        MiddleMan.__init__(self, db_object, full_client_engagement_path, DB_TABLE_NAME, MANUAL_FIELDS, COLUMN_NAMES, HEADER_NAMES)
        self.only_public = True
        self.db_object = db_object
        return

    def __enter__(self):
        return self

    def __exit__(self, type, value, traceback):
        return self

    def add(self):
        """
        Add entry to SqlCipher DB
        Overrides db.Interaction.add
        Returns number of entries added or 0 if failed.
        """
        try:
            list_of_ips_to_remove = None

            testing_location = self.db_object.grab_current_location()

            locations = self.db_object.dictionary_list("Location", "name")
            count_numbers = self.db_object.dictionary_list("Location", "id")

            if len(locations) > 0:
                number_rows_added = 0
                with Entry(self.DB_TABLE_NAME, self.MANUAL_FIELDS) as me:
                    field_values = me.user_input_fields(input_text='Please enter the')

                if testing_location == "all_locations":
                    if len(locations) == 1:
                        location_id = count_numbers[0]
                    else:
                        with Selection('Select the Location of this entry', locations, None) as selection:
                            location_id = selection.select_option(count_numbers)
                else:
                    location_id = testing_location

                field_values['entry'] = field_values['entry'].lower()
                field_values['location_id'] = location_id

                return add_scope(self.db_object, field_values)

            else:
                print_text.print_error("\tPlease add a location first!")
                number_rows_added = 0
            return number_rows_added
        except Exception as e:
            print_text.print_error("\tFailed to add Scope entry to database except: " + str(e) + " Error on line {}".format(sys.exc_info()[-1].tb_lineno))

    def join_view(self):
        """ Overwrite join_view in entry_db_middleman.py """
        return MiddleMan.join_view(self, JOIN_TABLES)

    def join_view_filter(self):
        """ Overwrite join_view in entry_db_middleman.py """
        return MiddleMan.join_view_filter(self, JOIN_TABLES)

    def update(self):
        """
        Override MiddleMan.update
        Must also add client_name, client_number, id keys to field_values dict.
        """
        try:
            selected_record, selected_record_num = self.db_object.select_to_edit_or_delete(DB_TABLE_NAME, COLUMN_NAMES,
                                                                               HEADER_NAMES, "modify", JOIN_TABLES)

            with Entry(DB_TABLE_NAME, UPDATE_MANUAL_FIELDS) as me:
                field_values = me.user_input_fields(selected_record, input_text='Please enter the')

            # verify that open IP is actually within this scope entries range
            if field_values['open_ip'].strip() != "" and selected_record['type'] == "IP":
                if not network.check_in_network(selected_record['entry'], field_values['open_ip']):
                    #field_values['open_ip'] = selected_record['open_ip']
                    print_text.print_error("\tThe Open IP, " + field_values['open_ip'] + ", is not within this Scope's entry's network, " + \
                                           selected_record['entry'] + ".  Open IP/Port is used for blacklist checking "
                                           "so entering an IP in a different network than the scope entry makes no "
                                           "sense. Allowing but make sure you want this!")

            testing_location = self.db_object.grab_current_location()

            location_id = selected_record["location_id"]
            locations = self.db_object.dictionary_list("Location", "name")
            count_numbers = self.db_object.dictionary_list("Location", "id")

            if testing_location == "all_locations":
                if len(locations) == 1:
                    location_id = count_numbers[0]
                else:
                    with Selection('Select the Location of this entry', locations, None) as selection:
                        location_id = selection.select_option(count_numbers)
            else:
                location_id = testing_location

            field_values['id'] = selected_record['id']
            field_values['location_id'] = location_id
            field_values['entry'] = selected_record['entry']
            field_values['permission'] = selected_record['permission']

            self.db_object.update("Scope", field_values)

            # Create scope_ips.txt, scope_domains.txt, scope_websites.txt files
            base_file_path = self.db_object.sqlite_file
            if ".out" in base_file_path:
                base_file_path = base_file_path[:base_file_path.rfind("/") + 1] + "hosts/"
            base_file_path = base_file_path.rstrip(" ").rstrip("'").lstrip("'")
            if not os.path.isdir(base_file_path):
                common.makedirs(base_file_path)
            ip_file_name = base_file_path + "/scope_ips.txt"
            scope_ips = self.db_object.view("Scope", None, ["type"], ["IP"])
            with open(ip_file_name, "w") as scope_file:
                for entry in scope_ips:
                    scope_file.write(entry["entry"] + "\n")
            domain_file_name = base_file_path + "/scope_domains.txt"
            scope_domains = self.db_object.view("Scope", None, ["type"], ["DOMAIN"])
            with open(domain_file_name, "w") as scope_file:
                for entry in scope_domains:
                    scope_file.write(entry["entry"] + "\n")
            website_file_name = base_file_path + "/scope_websites.txt"
            scope_websites = self.db_object.view("Scope", None, ["type"], ["DOMAIN"])
            with open(website_file_name, "w") as scope_file:
                for entry in scope_websites:
                    scope_file.write(entry["entry"] + "\n")

        except Exception as e:
            print("setup scope 182 except: " + str(e) + " Error on line {}".format(sys.exc_info()[-1].tb_lineno))
        return

    def delete(self):
        """ Overwrite delete in entry_db_middleman.py. """
        return MiddleMan.delete(self, JOIN_TABLES)


def add_scope(db_object, field_values, allow_unknown=True):
    """ Does actual adding of Scope entry (removing duplicates, checking if already in repo - even if is a subset of another entry), etc."""
    try:
        list_of_ips_to_remove = None
        locations = db_object.dictionary_list("Location", "name")

        if len(locations) > 0:
            number_rows_added = 0
            location_id = field_values['location_id']
            field_values['entry'] = field_values['entry'].lower()
            if "original_entry" not in field_values or field_values['original_entry'] == "":
                field_values['original_entry'] = field_values['entry']

            insert_many = False  # only IP ranges entered will set this to True if multiple standardized ranges entered
            try:
                # view() returns None both on a real query error and on a genuinely empty
                # result (see its own fallthrough `return None`), and there should always be
                # exactly one Engagement row per engagement - but if this engagement's Engagement
                # row is missing (e.g. from insert_views.py's insert() not checking whether that
                # insert actually succeeded when the engagement was first created), the old
                # `for eoi in external_or_internal_dictionary:` here raised a bare
                # "'NoneType' object is not iterable" and add_scope() never got past this point
                # for *any* Scope entry, IP or not. Defaults to "both" (not externally
                # restricted) when it can't be determined - permissive, so a data gap here
                # doesn't also block adding scope.
                external_or_internal_dictionary = db_object.view("Engagement", ["external_only"])
                external_only = False
                if external_or_internal_dictionary is not None:
                    for eoi in external_or_internal_dictionary:
                        external_only = eoi['external_only']
                if external_only:
                    external_or_internal = "external"
                else:
                    external_or_internal = "both"

                with ScopeEntry(external_or_internal, field_values) as scopeentry:
                    type = scopeentry.initialize()  # Finds the entry type
                    if type == "UNKNOWN" and not allow_unknown:
                        return
                    elif type == "UNKNOWN":
                        TYPE_MANUAL_FIELDS = (["Type", "type", r'^(?:DOMAIN|IP|AD_DOMAIN)$'],)
                        with Entry("Scope", TYPE_MANUAL_FIELDS) as me:
                            type_field_values = me.user_input_fields(input_text='Please enter the')
                        type = type_field_values['type']

                    elif type.lower() == "ip":
                        queryset = db_object.view("Scope", ["entry"], ["type", "location_id"],
                                                               ["IP", location_id], True)
                        current_scope_ips_in_db = []
                        if queryset is not None:
                            for record in queryset:
                                current_scope_ips_in_db.append(record["entry"])

                        field_values, insert_many, list_of_ips_to_remove = scopeentry.add_ip(current_scope_ips_in_db, location_id)

                    elif type.lower() == "website":
                        # Current Websites in DB
                        queryset = db_object.view("Scope", ["entry"], ["type"], ["WEBSITE"], True)
                        current_websites_in_db = []
                        if queryset is not None:
                            for record in queryset:
                                current_websites_in_db.append(record["entry"])
                        field_values = scopeentry.add_website(current_websites_in_db, location_id)

                        # Check if website ip is within current scope ip, if so add website as engagementdevice not scope entry
                        if 'open_ip' in field_values and field_values['open_ip'] is not None and network.valid_ip(field_values['open_ip']):
                            # Grab all current scope IPs
                            website = field_values['entry']
                            website_domain = common.format_website(website)
                            website_ip = field_values['open_ip']
                            scope_ips = db_object.scope_ips()
                            scope_id = None
                            scope_entry = None
                            last_slash = website.rfind("/")

                            # Add website to scope
                            number_rows_added = db_object.add("Scope", field_values)

                            if last_slash > 7 and len(website.rstrip("/")) > last_slash:
                                # Add the website to scope if very specific URL (ex. http://example.co/MyCoolApp)
                                pass
                            else:
                                for scope in scope_ips:
                                    if network.check_in_network(scope['entry'], website_ip):
                                        field_values = field_values['entry'] + " website is already part of " + \
                                                       scope['entry'] + " so not inserting into scope but inserting " \
                                                       "website into Engagement Device."
                                        scope_id = scope['id']
                                        scope_entry = scope['entry']
                                        break

                                if scope_id is not None:
                                    fvalues = {'scope_id': scope_id, 'target_name': website_domain, 'target_ip': website_ip,
                                                                       'source': 'manual scope entry'}
                                    fvalues = encryption.get_hash_string({'target_name': website_domain, 'scope_id': scope_id}, fvalues)
                                    db_object.add("EngagementDevice", fvalues)
                                    print_text.print_msg(website + " was added as a Engagement Device b/c its IP is already within the scope of " + str(scope_entry) + "!")

                    elif type.lower() == "domain":
                        # Current Domains in DB
                        queryset = db_object.view("Scope", ["entry"], ["type"], ["DOMAIN"], True)
                        current_domains_in_db = []
                        if queryset is not None:
                            for record in queryset:
                                current_domains_in_db.append(record["entry"])
                        field_values = scopeentry.add_domain(current_domains_in_db, location_id)
                    else:  # nothing special to insert for remaining items as probably all forensics related
                        field_values['type'] = type

                    # fails break out of here
                    if field_values is None:
                        return "Failed."
                    elif isinstance(field_values, str):  # means it is an error message
                        return field_values

                scope_hash_fields = retrieve_hash_fields("Scope")
                print("265 setup/scope field_values: " + str(field_values))
                print("266 setup/scope type: " + str(type))
                if isinstance(field_values, dict):
                    if 'type' not in field_values:
                        field_values['type'] = type
                    field_values['location_id'] = location_id
                    field_values = encryption.get_hash_string(scope_hash_fields, field_values)
                elif isinstance(field_values, list):
                    new_field_values = []
                    for fval in field_values:
                        if 'type' not in fval: # Make sure type is specified
                            fval['type'] = type
                        fval['location_id'] = location_id
                        fval = encryption.get_hash_string(scope_hash_fields, fval)
                        new_field_values.append(fval)
                    field_values = new_field_values

                if isinstance(field_values, str):
                    print_text.print_error("\t" + field_values)
                elif len(field_values) > 0:
                    # Insert new scope entry
                    if not insert_many:
                        number_rows_added = db_object.add("Scope", field_values)
                    else:
                        number_rows_added = db_object.add_multiple(DB_TABLE_NAME, field_values)

                if isinstance(list_of_ips_to_remove, list):
                    # Now have to go through Scope entries to remove, by first determining new Scope entry to update associated foreign keys to if possible
                    # 1st get all scope entries so can find each superset
                    super_scope_entries = []
                    super_scope_ids = []
                    scopes = db_object.view("Scope", None, ["location_id", "type"], [location_id, "IP"], True)
                    for scope in scopes:
                        super_scope_entries.append(scope['entry'])
                        super_scope_ids.append(scope['id'])

                    for ip in list_of_ips_to_remove:
                        # 2nd for each scope id to remove find new scope id that is its superset, has to be one for it to make this list
                        super_scope_id = None
                        for count, scope in enumerate(super_scope_entries):
                            if scope != ip:
                                if network.check_in_network(scope, ip):
                                    super_scope_id = super_scope_ids[count]
                                    break

                        # 3rd find all scope_ids that wil be removed
                        scopes = db_object.view("Scope", None, ["entry", "location_id"], [ip, location_id], True)
                        for scope in scopes:
                            # 4rd update all foreign keys to now point to superset scope_id (newly inserted one)
                            #interaction.find_foreign_keys_to_update("Scope", {"scope": super_scope_id}, "Scope", "scope", scope['id'])
                            db_object.update_all_tables_that_have_specified_foreign_key("scope",
                                                                    {"scope_id": super_scope_id}, ["scope_id"], [scope['id']], True)

                        # 5th remove all the subset scope ids that should be removed
                        success = db_object.delete_where("Scope", ["entry", "location_id"], [ip, location_id], True)

                # Create scope_ips.txt, scope_domains.txt, scope_websites.txt files
                base_file_path = db_object.sqlite_file
                if ".out" in base_file_path:
                    base_file_path = base_file_path[:base_file_path.rfind("/") + 1] + "hosts/"
                base_file_path = base_file_path.rstrip(" ").rstrip("'").lstrip("'")
                if not os.path.isdir(base_file_path):
                    common.create_path(base_file_path)
                ip_file_name = base_file_path + "/scope_ips.txt"
                scope_ips = db_object.view("Scope", None, ["type"], ["IP"])
                if scope_ips is not None:
                    with open(ip_file_name, "w") as scope_file:
                        for entry in scope_ips:
                            scope_file.write(entry["entry"] + "\n")
                domain_file_name = base_file_path + "/scope_domains.txt"
                scope_domains = db_object.view("Scope", None, ["type"], ["DOMAIN"])
                if scope_domains is not None:
                    with open(domain_file_name, "w") as scope_file:
                        for entry in scope_domains:
                            scope_file.write(entry["entry"] + "\n")
                website_file_name = base_file_path + "/scope_websites.txt"
                scope_websites = db_object.view("Scope", None, ["type"], ["DOMAIN"])
                if scope_websites is not None:
                    with open(website_file_name, "w") as scope_file:
                        for entry in scope_websites:
                            scope_file.write(entry["entry"] + "\n")

            except Exception as e:
                # insert_entry() (flask_files/form_views.py) routes a string return straight
                # back to the browser as the failure reason - dropping str(e) here and only
                # print_text.print_error'ing it meant the user only ever saw the generic
                # "Failed to add Scope entry to database.", while the actual cause sat in a
                # server log they can't see.
                msg = "Failed to add Scope entry to database, error: " + str(e) + " Error on line {}".format(sys.exc_info()[-1].tb_lineno)
                print_text.print_error("\t" + msg)
                return msg
        else:
            print_text.print_error("\tPlease add a location first!")
            number_rows_added = 0
        return number_rows_added
    except Exception as e:
        # Same as the inner except above - this is the outer catch-all for the whole function
        # (a bug outside the ScopeEntry block, e.g. in db_object.dictionary_list("Location", ...)
        # right at the top), and previously had no return at all here, falling through to an
        # implicit `return None` that insert_entry() reports as the unhelpful "error: None".
        msg = "Failed to add Scope entry, error: " + str(e) + " Error on line {}".format(sys.exc_info()[-1].tb_lineno)
        print_text.print_error("\t" + msg)
        return msg