import sys
import getpass
from datetime import datetime
from common import print_text
from common import common
from common import sqlalchemy_model


class Entry():
    """
    Will bool True if manual entry is valid and False if not.
    """

    def __init__(self, name, manual_fields, required_fields=None):
        self.name = name
        self.manual_fields = manual_fields
        self.required_fields = required_fields
        return

    def __enter__(self):
        return self

    def __exit__(self, type, value, traceback):
        #print_text.print_error(sys.exc_info())
        return self

    def is_valid_null_check(self, manual_entry, can_be_null):
        """
        Used to verify if entry is allowed to be Null, if not then checks if it is Null
        :return: bool True if valid, False if not valid
        """
        if not can_be_null:
            if manual_entry.strip() == "":
                return False
        return True

    def user_input_fields(self, update=None, input_text=None):
        """
        Used to allow user input for fields (insert and update).
        Splits up each manual field into the display text, field name, nullable value, and regex check.
        Creates display text for manual user entry, appending current value of field entry if updatting.
        Checks if user entered blank entry and if allowed to be blank.
        Checks if user input matches regex check.
        Returns dictionary of fieldname:value.

        Attributes:
            update -- dictionary of current field values if applicable
            input_text -- used to help specify text to display for user input
        """

        try:
            field_values = {}
            for field in self.manual_fields:
                field_text = field[0]
                field_name = field[1]

                if self.required_fields is None and self.name is not None:
                    not_null_fields = sqlalchemy_model.retrieve_required_fields(self.name)
                    if not_null_fields is None:
                        not_null_fields = []
                elif self.required_fields is None and self.name is None:
                    not_null_fields = []
                elif self.required_fields is not None:
                    not_null_fields = self.required_fields
                else:
                    not_null_fields = []

                field_can_be_null = True
                if field_name in not_null_fields:
                    field_can_be_null = False
                regex = field[2]
                if input_text == None:
                    full_field_text = field_text
                else:
                    full_field_text = input_text + " " + field_text

                while True:
                    current_value = ''
                    if update is not None:
                        if field_name in update:
                            if update[field_name] != "":
                                update_value = update[field_name]
                                if update_value == True:
                                    update_value = "Y"
                                    update[field_name] = update_value
                                elif update_value == False:
                                    update_value = "N"
                                    update[field_name] = update_value
                                current_value = " or leave blank to keep the existing value, " + str(update_value)

                    # User input
                    if "password" in field_name or "passwd" in field_name:
                        print_text.print_bold("Enter password for " + field_name)
                        manual_entry = getpass.getpass()
                    else:
                        manual_entry = input(full_field_text + current_value + ': ')

                    if update is not None and manual_entry.strip() == "":
                        if field_name in update:
                            manual_entry = update[field_name]

                    if manual_entry is None:
                        manual_entry = ""

                    # make sure not to regex check if no regex check should be performed
                    if regex is not None and regex != "" and regex != r'':
                        manual_entry = common.regex_exist_in_entry(manual_entry, regex, False)

                    null_check_valid = self.is_valid_null_check(manual_entry, field_can_be_null)

                    valid_entry = False
                    if null_check_valid:
                        valid_entry = True
                    if valid_entry:
                        break
                    else:
                        field_null_string = ""
                        if not field_can_be_null:
                            field_null_string = "Field cannot be null."
                        print_text.print_error("\tYour entry is not valid.  Please try again. Regex match against, " +
                                               str(regex) + " failed. " + field_null_string)

                if manual_entry is not None:
                    manual_entry = manual_entry.strip()
                if manual_entry.upper() == "N":
                    manual_entry = False
                elif manual_entry.upper() == "Y":
                    manual_entry = True
                elif manual_entry == "":
                    manual_entry = None

                if "_date" in field_name:
                    if manual_entry is not None and manual_entry != "":
                        manual_entry = datetime.strptime(manual_entry, "%Y-%m-%d").date()
                    else:
                        manual_entry = None

                field_values[field_name] = manual_entry

            # any update fields that where not entered are set to current field value
            if update is not None:
                for key,value in update.items():
                    if key not in field_values:
                        field_values[key] = value

            return field_values
        except Exception as e:
            print("common manual 134 except: " + str(e) + " Error on line {}".format(sys.exc_info()[-1].tb_lineno))
