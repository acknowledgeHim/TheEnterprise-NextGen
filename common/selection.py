import sys
import importlib
from common import print_text

class Selection():
    def __init__(self, title, selection_items, quit=None):
        """
        Used to create Selection Objects

        Attributes:
            title -- Current Menu path (ex. recon for Recon Menu, setup for Setup Menu, etc)
            selection_items -- Dictionary of Menu / Selection Options
            quit -- bool True or False or None
        """
        self.selection_items = selection_items
        self.quit = quit

        self.return_value = 99
        self.return_text = "Return to Previous Menu"
        if self.quit:
            self.return_value = 1337
            self.return_text = "Quit"

        self.title = title

    def __enter__(self):
        return self

    def __exit__(self, type, value, traceback):
        return self

    def set_selection_items(self, new_selection_items):
        self.selection_items = new_selection_items

    def display_menu(self, additional_header=None, count_numbers=None):
        """Prints out the menu items to screen"""
        try:
            if additional_header is not None:
                print_text.print_break(self.title + " - " + additional_header)
            else:
                print_text.print_break(self.title)
            print_text.print_menu("\nSelect from the following options:")

            if len(self.selection_items) > 50:
                # Display in table form
                results = []
                i = 1
                column = 0
                tmp_results = []
                for selection_item in self.selection_items:
                    num = str(i)
                    if count_numbers is not None:
                        num = str(count_numbers[i - 1])
                    tmp_results.append(num + "  " + selection_item)
                    if column == 9:
                        results.append(tmp_results)
                        column = 0
                        tmp_results = []
                    else:
                        column += 1
                    i = i + 1
                if len(tmp_results) > 0:
                    results.append(tmp_results)
                print_text.console_table_view(self.title, None, results)
            else:
                i = 1
                for selection_item in self.selection_items:
                    num = str(i)
                    if count_numbers is not None:
                        num = str(count_numbers[i-1])
                    print_text.print_menu_item("\t" + num + ".\t" + selection_item)
                    i = i + 1
            if self.quit is not None:
                print_text.print_menu_item("\t" + str(self.return_value) + ".\t" + self.return_text)
        except Exception as e:
            print("Selection except: "+ str(e) + " Error on line {}".format(sys.exc_info()[-1].tb_lineno))

    def validate_input(self, input):
        """
        Used to make sure the selected option is valid Menu Option
        Returns bool, True if valid and False if not valid

        Attributes:
            input -- (int) user selection from current menu
        """
        if (input < len(self.selection_items) and input >= 0) or input == self.return_value:
            return True
        return False

    def select_option(self, count_numbers=None):
        """
        Gets user selection to determine class to import
        Imports module and class selected or return to previous menu
        """
        try:
            ERROR_TEXT  = "\tInvalid option selected.  Please try again!"
            QUOTE_TEXT = "\tI was way off!  I knew it started with an S, though. - Lloyd from Dumb N Dumber"
            while True:
                self.display_menu(count_numbers=count_numbers)
                input_valid = False
                try:
                    user_input = int(input('Selection: '))
                    if isinstance(user_input, int):
                        if count_numbers is None:
                            input_valid = self.validate_input(int(user_input) - 1)
                        elif int(user_input) in count_numbers:
                            input_valid = True
                        else:
                            input_valid = False
                    if input_valid:
                        return user_input
                    else:
                        print_text.print_error(ERROR_TEXT)
                        print_text.print_quote(QUOTE_TEXT)
                except Exception as e:
                    print_text.print_error("except: " + str(e) + " Error on line {}".format(sys.exc_info()[-1].tb_lineno))
                    print_text.print_error(ERROR_TEXT)
                    print_text.print_quote(QUOTE_TEXT)
                    print_text.print_warning("\tIf any of you lack wisdom, let him ask of God, that giveth to all men liberally, and upbraideth not; and it shall be given him. - James 1:5")

        except Exception as e:
            print("Selection except: "+ str(e) + " Error on line {}".format(sys.exc_info()[-1].tb_lineno))
