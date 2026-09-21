import sys
from common import common
from common import print_text
from common import sqlalchemy_model
from common.directory_list import DirList
from common.selection import Selection
from common.manual import Entry
from setup.engagement import Engagement
from common.database_object import OurCoolDBObject

class ClientEngagement():
    """
    Used to select/create a Client/Engagement.

    Attributes:
        path -- the root output_path, where all client folders are found
        tester -- current *nix user
        only_owner -- True/False: True display only client/engagements that tester created
        newer_than_months -- int: number of months since created to display current client/engagements
        encrypt_key -- the encryption key used to protect the SqlCipher database
    """

    def __init__(self, path, tester, only_owner, newer_than_months, encrypt_key):
        self.encrypt_key = encrypt_key
        self.path = path
        self.tester = tester
        self.only_owner = only_owner
        self.newer_than_months = newer_than_months
        self.sqlite_extension = ".out"
        return

    def __enter__(self):
        return self

    def __exit__(self, type, value, traceback):
        #print sys.exc_info()
        return self

    def grab_client_engagement_list(self, first_record="", search_text_if_more_folders_than=None, depth=1):
        """ Creates the list of Client/Engagements (based off enterprise_user_conf.py OUTPUT_PATH). """
        with DirList(self.path, self.tester) as dir_list:
            sub_folder_list = dir_list.find_folders(depth)

            if self.only_owner is not None and self.only_owner:
                sub_folder_list = dir_list.dir_filter_by_owner(sub_folder_list)
            if isinstance(self.newer_than_months, int) and self.newer_than_months > 0:
                sub_folder_list = dir_list.dir_filter_by_date(sub_folder_list, self.newer_than_months)
            sub_folder_list = dir_list.formatted_folders(sub_folder_list)

        if search_text_if_more_folders_than is not None and len(sub_folder_list) > search_text_if_more_folders_than :
            tmp_sub_folder_list = []
            while True:
                search_text = input("More than " + str(search_text_if_more_folders_than)+ " current"
                                " client/engagements found, so please enter a search string to filter the"
                                " client/engagements that are displayed to choose from: ")
                matched_search_text = False
                for sfl in sub_folder_list:
                    if search_text.lower() in sfl.lower():
                        tmp_sub_folder_list.append(sfl)
                        matched_search_text = True
                if matched_search_text:
                    sub_folder_list = tmp_sub_folder_list
                else:
                    print_text.print_error("\tYour search string did not match any current client/engagements so"
                                           " all client/engagements will print out matching your profile.")
                break

        dir_list_selection = []
        if first_record != "":
            dir_list_selection.append(first_record)
        for sub_folder in sub_folder_list:
            dir_list_selection.append(sub_folder)

        return dir_list_selection

    def create_list(self, title, first_record, depth):
        """
        Sets up the Folder List (of current client/engagement folders).
        Allows filtering by user input if more than 30 client/engagements found.
        Sets up Selection list based off of the Folder List.
        Return the select client/engagement and the selection list.

        Attributes:
            search_text_if_more_folders_than -- filter by user input if there are more client/engagements than this number
            title -- display text for client/engagement list
            first_record -- display_text for first record (used for Creating New)
            depth -- the depth that the folders should grab results for
        """
        search_text_if_more_folders_than = 20

        dir_list_selection = self.grab_client_engagement_list(first_record, search_text_if_more_folders_than, depth)

        with Selection(title, dir_list_selection) as client_engagement_selection:
            selected_client_engagement = client_engagement_selection.select_option()

        return (selected_client_engagement, dir_list_selection)

    def new_client(self):
        """
        Gets user-inputted client_number + client_name to create folder.
        The folder structure is as follows:
            client_number__client_name/engagement_number/client_number.db
            ex: 013-028375__CLA/013-02837-S0SAIE/013-028375.db
        Returns the full_client_engagement_path
        """
        CLIENT_UNIQUE = [["Client Number", "client_number", r'^(?:[\d\-]+)$'],
                            ["Client Name", "client_name", r'^(?:[a-zA-Z_ \-0-9]+)$'],
                            ["Engagement Number", "engagement_number", r'^(?:[a-zA-Z_\-0-9]+)$']]
        field_values = {}
        with Entry("Engagement", CLIENT_UNIQUE) as me:
            field_values = me.user_input_fields(input_text='Please enter the')

        if "client_name" in field_values and "client_number" in field_values:
            self.path = self.path + field_values['client_number'] + "__" + field_values['client_name'].replace(" ","_") + "/"
            new_path_created = common.create_path(self.path)
            if new_path_created:
                self.path = self.path + field_values['engagement_number'] + "/"
                new_path_created = common.create_path(self.path)
                if not new_path_created:
                    return '', field_values
            else:
                return '', field_values
        sqlite_path = self.path + field_values['client_number'] + self.sqlite_extension

        return sqlite_path, field_values

    def new_engagement(self, client_folder):
        """
        Creates new engagement for selected client.
        Pulls client_number and client_name from client_folder.
        Creates new engagement folder based on the engagement_number.
        Sets full client/engagement path as self.path.
        Returns the sqlite_file and a dictionary, field_values, containing client_number and client_name.

        Atrributes:
            client_folder -- the client folder selected (consists of client_number and client_name)
        """

        client_info = client_folder.split("__")
        field_values = {}
        field_values['client_number'] = client_info[0]
        field_values['client_name'] = client_info[1]
        with DirList(self.path + client_folder, self.tester) as dir_list:
            sub_folder_list = dir_list.find_folders(1)

        CLIENT_UNIQUE = [["Engagement Number", "engagement_number", r'^(?:[a-zA-Z_\-0-9]+)$']]
        engagement_field_values = {}
        with Entry("Engagement", CLIENT_UNIQUE) as me:
            engagement_field_values = me.user_input_fields(input_text='Please enter the')
        engagement_folder = engagement_field_values['engagement_number']
        field_values['engagement_number'] = engagement_folder
        self.path = self.path + "/" + client_folder + "/" + engagement_folder +"/"
        if engagement_folder in sub_folder_list:
            return '', field_values
        new_path_created = common.create_path(self.path)
        if not new_path_created:
            return '', field_values
        sqlite_file = self.path + client_info[0] + self.sqlite_extension
        return sqlite_file, field_values

    def client(self):
        """
        Select current client to add new engagement for or add new client.
        Returns full_client_engagement_path and db_object
        """
        selected_client, client_folder_list = self.create_list("Select Client", "Create New Client", 1)
        if selected_client == 1:
            return self.new_client()
        else:
            return self.new_engagement(client_folder_list[selected_client-1])


    def which_client_engagement(self, selected_client_engagement=None, client_engagement_folder_list=None):
        """
        Sets up initial client/engagement selection or create menu.
        Opens SqlCipher database from sqlite_file.
        Creates SqlCipher table for database if newly created client/engagement.
        Returns full_client_engagement_path and SqlCipher db_object
        """
        if selected_client_engagement is None or client_engagement_folder_list is None:
            selected_client_engagement, client_engagement_folder_list = self.create_list("Select Client / Engagement", "Create New Client/Engagement", 2)

        if selected_client_engagement == 1:
            sqlite_file, field_values_passed = self.client()
        else:
            field_values_passed = None
            client_number = client_engagement_folder_list[selected_client_engagement-1]
            client_number = client_number[:client_number.rfind("__")]
            self.path = self.path + client_engagement_folder_list[selected_client_engagement-1] +"/"
            sqlite_file = self.path + client_number + self.sqlite_extension

        db_object = None
        if sqlite_file != "":
            db_object = OurCoolDBObject(sqlite_file)
            if field_values_passed is not None:
                failed_client_engagement_text = "\tFailed.  Adding client/engagement to newly created Repository failed!"

                created_tables = sqlalchemy_model.initialize(sqlite_file)

                if created_tables:
                    # change permissions of sqlite file
                    common.assign_permissions(sqlite_file)

                    with Engagement(db_object, self.path) as client_engage:
                        number_records_added = client_engage.add(field_values_passed)
                        if number_records_added > 0:
                            print_text.print_msg("Successfully setup new client/engagement.")
                        else:
                            print_text.print_error(failed_client_engagement_text)
                            sys.exit()
                else:
                    print_text.print_error(failed_client_engagement_text)
                    sys.exit()
            return self.path, db_object
        return '', None
