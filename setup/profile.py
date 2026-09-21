import os
from common import print_text
from common import common
from common.manual import Entry
from enterprise_user_conf import EMAIL_ADDRESS

def is_admin():
    """Checks enterprise.profile to see if ADMIN:True is set, if so then returns True"""
    profile_file = os.path.expanduser('~') + '/.enterprise.profile'
    if os.path.isfile(profile_file):
        with open(profile_file, 'r') as pat_profile:
            profile_text = pat_profile.read()

        if "ADMIN:True" in profile_text or "ADMIN: True" in profile_text:
            return True
    return False

def grab_profile():
    """
    Grab profile values from ~/.enterprise_profile.
    Returns bool Owner and int Newer_than.
    """
    email_address = ""
    owner = False
    newer_than = 12
    auto_view_flask_user = ""
    profile_file = os.path.expanduser('~') + '/.enterprise.profile'
    if os.path.isfile(profile_file):
        with open(profile_file, 'r') as pat_profile:
            profile = pat_profile.read()
        try:
            if "OWNER:" in profile:
                owner = profile[profile.find("OWNER:")+6:]
                owner = owner[:owner.find("\n")].strip()
                owner = common.regex_exist_in_entry(owner, r'^(?:True|False)$')
                if owner == "True":
                    owner = True
                elif owner == "False":
                    owner = False
            if "NEWER_THAN:" in profile:
                newer_than = profile[profile.find("NEWER_THAN:")+11:]
                newer_than = newer_than[:newer_than.find("\n")].strip()
                newer_than = common.regex_exist_in_entry(newer_than, r'^(?:[\d]{1,2})$')
            if "EMAIL_ADDRESS:" in profile:
                email_address = profile[profile.find("EMAIL_ADDRESS:") + 14:]
                email_address = email_address[:email_address.find("\n")].strip()
                email_address = common.regex_exist_in_entry(email_address, r'^[0-9a-zA-Z.-_]+[@]+[0-9a-zA-Z.-_]+$')
            if "AUTO_VIEW_FLASK_USERS" in profile:
                auto_view_flask_user = profile['AUTO_VIEW_FLASK_USERS']
                if auto_view_flask_user == "True":
                    auto_view_flask_user = True
                else:
                    auto_view_flask_user = False
        except Exception as e:
            print_text.print_error("\tProblem grabbing profile.")
    else:
        print_text.print_error("\tProfile does not exists.")
    return {'only_owner':owner, 'newer_than':newer_than, 'email': email_address, 'auto_view_flask_user': auto_view_flask_user}

class MyProfile():
    """
    My Profile checker, creater, updater.
    """
    def __init__(self, check_for_profile):
        """
        Initializes My Profile.

        Arguments:
            check_for_profile -- bool True to check for profile, False to not check for profile
            MANUAL_FIELDS -- fields user will be asked to manually input
            create_profile -- keeps track if profile needs to be created
            profile_file -- the profile name and path where it is saved (users home folder)
            owner -- keeps track of current set owner value which is used to determine if list is dependant on the owner of the list item
            newer_than -- keeps track of date range, in months, that acceptable list items will be displayed
        """
        self.MANUAL_FIELDS = [["Only view folders you are owner of, Y|N", "owner_only", r'^(?:Y|y|N|n)$'],
                ["Only view folders newer than X months", "only_newer_than", r'^(?:[\d]{1,2})$'],
                ["Your email address, email notifications will be sent as if from this address", "email_address", r'^[0-9a-zA-Z.-_]+[@]+[0-9a-zA-Z.-_]+$'],
                ["View Flask Users at Login (before selecting engagement), Y|N", "auto_view_flask_user", r'^(?:Y|y|N|n)$']]
        self.create_profile = False
        self.profile_file = os.path.expanduser('~') + '/.enterprise.profile'
        self.owner = ""
        self.newer_than = ""
        self.email_address = ""
        self.auto_view_flask_user = ""
        corrupted_profile_text = "\tLooks like your profile is corrupted as it could not load the values properly."
        if check_for_profile:
            profile_dictionary = grab_profile()
            self.owner = profile_dictionary['only_owner']
            self.newer_than = profile_dictionary['newer_than']
            self.email_address = profile_dictionary['email']
            self.auto_view_flask_user = profile_dictionary['auto_view_flask_user']

            if self.owner == "" or self.newer_than == "" or self.email_address == "":
                self.recreate_profile()
            else:
                print_text.print_msg("Your profile found at ~/.enterprise.profile.  Using setting store within it,"
                     " including default Client/Engagement views which are currently set to:\n\tOnly view client/engagements"
                     " you created: " + str(self.owner) + "\n\tOnly view client/engagements created with the last: " +
                     str(self.newer_than) + " months.\n\tAnd your email is: " + str(self.email_address))

                RECREATE_PROFILE_FIELDS = [["Do you want to modify your profile settings or load them, Y (to modify) or N (to load them)", "profile", r'^(?:Y|N)$']]
                field_values = {}
                with Entry('profile', RECREATE_PROFILE_FIELDS) as me:
                    field_values = me.user_input_fields()
                if "profile" in field_values:
                    if field_values["profile"]:
                        self.recreate_profile()

    def __enter__(self):
        return self

    def __exit__(self, type, value, traceback):
        return self

    def recreate_profile(self):
        """Remove current profile and create a new one."""
        self.create_profile = True
        if os.path.isfile(self.profile_file):
            os.remove(self.profile_file)
        self.newer_than = ""
        self.profile_questions()

    def create_profile_file(self):
        """
        Create the profile file.
        Returns bool True if successful, False if not successful.
        """
        try:
            with open(self.profile_file, 'a') as profile:
                profile.write("OWNER:"+str(self.owner) + "\n")
                profile.write("NEWER_THAN:"+str(self.newer_than) + "\n")
                profile.write("EMAIL_ADDRESS:" + str(self.email_address) + "\n")
                profile.write("AUTO_VIEW_FLASK_USERS:" + str(self.auto_view_flask_user) + "\n")
            return True
        except Exception as e:
            return False

    def initialize(self):
        """
        Initializes profile file creation and sets self.create_profile so profile will be or not created.
        """
        PROFILE_FIELDS = [["Do you want to create an enterprise profile, Y or N", "profile", r'^(?:Y|N)$']]
        print_text.print_msg("You currently do not have a profile.")
        field_values = {}
        with Entry('profile', PROFILE_FIELDS) as me:
            field_values = me.user_input_fields()
        if "profile" in field_values:
            if field_values['profile'].upper() == "Y":
                self.create_profile = True

    def profile_questions(self):
        """
        Sets up profile questions for user to type using self.MANUAL_FIELDS as the questions and regex check.

        Returns the self.owner (True/False) and self.newer_than (int representing the number of months)
        """
        if self.owner == "" or self.newer_than == "":
            if self.create_profile == True:
                owner = False
                newer_than = 6
                email_address = EMAIL_ADDRESS
                field_values = {}
                with Entry('profile', self.MANUAL_FIELDS) as me:
                    field_values = me.user_input_fields()
                assert isinstance(field_values, dict)

                if "owner_only" in field_values:
                    self.owner = field_values["owner_only"]

                if "only_newer_than" in field_values:
                    try:
                        self.newer_than = int(field_values["only_newer_than"])
                    except:
                        self.newer_than = 12

                if "email_address" in field_values:
                    self.email_address = field_values['email_address']

                if "auto_view_flask_user" in field_values:
                    self.auto_view_flask_user = field_values['auto_view_flask_user']

                successful = self.create_profile_file()
                if not successful:
                    print_text.print_error("\tFailed to create your profile. :(")
        return {"only_owner": self.owner, "newer_than": self.newer_than, "profile_email": self.email_address, "auto_view_flask_user": self.auto_view_flask_user}
