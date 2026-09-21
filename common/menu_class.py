import sys
import importlib
from common import print_text, common
from common.selection import Selection
from common.navigation_menu import NAVIGATION


class Menu(Selection):
    def __init__(self, db_object, title, menu_items, full_client_engagement_path, quit):
        """
        Used to create Menu Objects which extend the Selection Class.

        Attributes:
            db_object -- sqlcipher object used for saving results
            current_menu -- Current Menu path (ex. recon for Recon Menu, setup for Setup Menu, etc)
            menu_items -- Dictionary of Menu Options obtained from current enterprise_conf.py file
            quit -- bool True or False
        """

        self.db_object = db_object
        self.menu_items = menu_items
        self.full_client_engagement_path = full_client_engagement_path
        selection_items = self.selection_list(menu_items)
        Selection.__init__(self, title + " Menu", selection_items, quit)
        return

    def __enter__(self):
        return self

    def __exit__(self, type, value, traceback):
        return self

    def __setup_queryset_count(self, table_name):
        """
        Queries tables and returns columns desired for records.
        Returns queryset.

        Argurments:
            columns_to_return -- List of column names desired to return.
            filter_column -- the column in the table to match against.
            filter_value -- the value to match against.
        """
        return self.db_object.count_records(table_name)

    def setup_completion_check(self):
        """
        Returns True is setup finished (contacts, scope, etc)
        """
        try:
            #client_contact_check = self.__setup_queryset_count("ClientContact")
            #corp_contact_check = self.__setup_queryset_count("CorpContact")
            if self.navigation[0][0] != "WebApp User":
                location_check = self.__setup_queryset_count("Location")
                scope_check = self.__setup_queryset_count("Scope")
                if location_check > 0 and scope_check > 0: #client_contact_check > 0 and corp_contact_check
                    return True
                return False
            else:
                return True
        except Exception as e:
            print("menu_class Exception: " + str(e) + " Error on line {}".format(sys.exc_info()[-1].tb_lineno))

    def selection_list(self, menu_items):
        selection_items = []
        for menu_item in menu_items:
            selection_items.append(menu_item[0])
        return selection_items


    def select_option(self):
        """
        Gets user selection to determine class to import
        Overrides Menu.selection_option
        Imports module and class selected or return to previous menu
        """
        while True:
            if not self.options():
                break

    def options(self):
        try:
            ERROR_TEXT = "\tInvalid option selected.  Please try again!"
            QUOTE_TEXT = "\tI was way off!  I knew it started with an S, though. - Lloyd from Dumb N Dumber"

            #If not setup then force into Setup
            if "WebApp User Menu" in self.title:
                self.navigation = setup_navigation([0,8,8])

            path = ''
            if "WebApp User Menu" not in self.title:
                if not self.setup_completion_check() and self.navigation[0][0] == "Setup":
                    self.navigation = setup_navigation([0,0])
                    self.menu_items = self.navigation
                    Selection.title = "Setup"
                    Selection.set_selection_items(self, self.selection_list(self.navigation))

                current_location = self.db_object.grab_column_from_single_record("CurrentLocation", ['modified_by'], [common.get_tester()], 'current_location')
                if current_location == "all_locations":
                    location = ' - Testing Location: All Locations'
                else:
                    location = ' - Testing Location: ' + str(self.db_object.grab_column_from_single_record("Location", ["id"], [int(current_location)], "name"))
                path = "Path: " + self.full_client_engagement_path + location

            self.display_menu(path)
            input_valid = False
            try:
                user_input = int(input('Selection: ').rstrip())
                if isinstance(user_input, int):
                    input_valid = self.validate_input(int(user_input) - 1)

                if input_valid:
                    name = self.menu_items[int(user_input)-1][0]
                    module_to_load = self.menu_items[int(user_input) - 1][1]
                    class_to_import = self.menu_items[int(user_input) - 1][2]

                    path_to_module = self.full_client_engagement_path
                    if "EmailEvent" in class_to_import:
                        path_to_module = "setup/"
                    method_to_call = ""

                    yaml_config = None
                    if "." in class_to_import:
                        method_to_call = class_to_import[class_to_import.rfind(".")+1:]
                        class_to_import = class_to_import[:class_to_import.rfind(".")]

                        if ":" in method_to_call:
                            yaml_config = method_to_call[method_to_call.find(":") + 1:]
                            method_to_call = method_to_call[:method_to_call.find(":")]

                    if module_to_load is not None:
                        try:
                            SubClass = getattr(importlib.import_module(module_to_load), class_to_import)
                            if yaml_config is not None:
                                instance = SubClass(self.db_object, path_to_module, yaml_config)
                            else:
                                instance = SubClass(self.db_object, path_to_module)

                            if method_to_call != "":
                                method = getattr(instance, method_to_call)
                                method()
                        except Exception as e:
                            print_text.print_error("142 menu_class module_to_load: " + str(module_to_load) + " except: " + str(e) + " Error on line {}".format(sys.exc_info()[-1].tb_lineno))

                    else:
                        current_place_holders = list(class_to_import)
                        current_place_holders.append(int(user_input) - 1)

                        with MenuClass(self.db_object, name, current_place_holders, self.full_client_engagement_path, False) as create_menu:
                            create_menu.select_option()
                elif user_input == 99 or user_input == 1337:
                    return False
                else:
                    print_text.print_error(ERROR_TEXT)
                    print_text.print_quote(QUOTE_TEXT)

            except Exception as e:
                #print("menu_class Exception: " + str(e) + " Error on line {}".format(sys.exc_info()[-1].tb_lineno))
                print_text.print_error(ERROR_TEXT)
                print_text.print_quote(QUOTE_TEXT)
            return True
        except Exception as e:
            print("menu_class Exception: " + str(e) + " Error on line {}".format(sys.exc_info()[-1].tb_lineno))


class MenuClass(Menu):
    def __init__(self, db_object, title, place_holders, full_client_engagement_path, quit):
        """
        Used to create Main Menu Objects which extend the Menu Class.
        This is only used for the Main Menu as it is modified depending if the setup
        is completed or not for the selected engagement.

        Attributes:
            db_object -- sqlcipher object used for saving results
            current_menu -- Current Menu path (ex. recon for Recon Menu, setup for Setup Menu, etc)
            menu_items -- Dictionary of Menu Options obtained from current enterprise_conf.py file
            quit -- bool True or False
        """
        try:
            self.db_object = db_object
            self.full_client_engagement_path = full_client_engagement_path

            self.navigation = setup_navigation(place_holders)

            Menu.__init__(self, db_object, title, self.navigation, full_client_engagement_path, quit)
        except Exception as e:
            print("menu_class Exception: " + str(e) + " Error on line {}".format(sys.exc_info()[-1].tb_lineno))
        return

    def __enter__(self):
        return self

    def __exit__(self, type, value, traceback):
        return self

    def select_option(self):
        """
        Overrides select_options from Menu class.
        Gets user selection to determine class to import
        Overrides Menu.selection_option
        Imports module and class selected or return to previous menu
        """
        try:
            while True:
                if "WebApp User Menu" not in self.title:
                    if not Menu.setup_completion_check(self) and self.navigation[0][0] == "Setup":
                        print_text.print_msg("You still need to finish setting up the Engagement before using The Enterprise."
                                         "\nYou must have at least 1 - Location, and Scope Entry.")

                        with MenuClass(self.db_object, "Setup", [0,0], self.full_client_engagement_path, False) as create_menu:
                            create_menu.select_option()
                    else:
                        Selection.set_selection_items(self, Menu.selection_list(self, self.navigation))
                else:
                    Selection.set_selection_items(self, Menu.selection_list(self, self.navigation))

                if not self.options():
                    break
        except Exception as e:
            print("menu_class Exception: " + str(e) + " Error on line {}".format(sys.exc_info()[-1].tb_lineno))


def setup_navigation(place_holders):
    try:
        navigation = []
        menu_items = NAVIGATION
        for count, placeholder in enumerate(place_holders):
            if count + 1 < len(place_holders):
                menu_items = menu_items[int(placeholder)][1]

        last_index = len(place_holders) - 1
        for count, item in enumerate(menu_items):
            new_placeholders = list(place_holders)
            current_placeholder = count
            new_placeholders[last_index] = current_placeholder
            if not isinstance(item[1], list):
                navigation.append([item[0], item[2][0], item[2][1]])
            else:
                navigation.append([item[0], None, new_placeholders])
    except Exception as e:
        print("menu_class Exception: " + str(e) + " Error on line {}".format(sys.exc_info()[-1].tb_lineno))

    return navigation