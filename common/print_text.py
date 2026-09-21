from terminaltables import SingleTable
from colorclass import Color
from textwrap import TextWrapper


# from tabulate import tabulate

# used to print out terminal colors
class bcolors:
    HEADER = '\033[95m'
    OKBLUE = '\033[94m'
    OKGREEN = '\033[92m'
    WARNING = '\033[93m'  # yellow
    OKPURPLE = '\033[95m'
    OKCYAN = '\033[96m'
    ORANGE = '\033[208m'
    FAIL = '\033[91m'  # red
    ENDC = '\033[0m'  # clear
    BOLD = '\033[1m'
    UNDERLINE = '\033[4m'
    ITALIC = '\033[3m'
    STRIKETHROUGH = '\033[9m'
    FLASHING = '\033[6m'


def print_underline(line):
    print(bcolors.UNDERLINE + str(line) + bcolors.ENDC)


def print_italic(line):
    print(bcolors.ITALIC + str(line) + bcolors.ENDC)


def print_result_begin(line):
    print(bcolors.OKGREEN + str(line))


def print_result(line):
    print(bcolors.OKGREEN + str(line) + bcolors.ENDC)


def print_msg(line):
    print(bcolors.OKBLUE + str(line) + bcolors.ENDC)


def print_bold(line):
    print(bcolors.BOLD + str(line) + bcolors.ENDC)


def print_quote(line):
    print(bcolors.OKCYAN + str(line) + bcolors.ENDC)

def print_warning(line):
    print(bcolors.WARNING + str(line) + bcolors.ENDC)

def print_error(line):
    print(bcolors.FAIL + str(line) + bcolors.ENDC)


def print_close(line):
    print(line + bcolors.ENDC)


def print_menu(line):
    print_underline(line)


def print_menu_item(line):
    print(line)
    # printitalic(line)   #italic not work in scanner


def print_break(line):
    print('\n' + '#' * 100)
    print('#\t' + line)
    print('#' * 100)

def insert_newlines(text):
    """
    Inserts new lines in text that is longer than 35 characters and
    does so every 35 characters and returns the result.
    Arguments:
        text -- the string to check for length if need to add newlines
    """
    tw = TextWrapper()
    tw.width = 25
    return "\n".join(tw.wrap(text))

def console_table_view(title, header, results):
    """
    Prints out table view of data passed to it.
    Returns True is successful, False if not.

    Arguments:
        title -- the title of the table
        header -- the first row of the table (column headers) - 2D list
        results -- the rows of the table with the data - 2D list
    """
    try:
        if header is not None and len(header) > 0:
            table_data = header + results
        else:
            table_data = results
        table = SingleTable(table_data)
        table.title = " " + title + " "
        table.inner_row_border = True
        print(table.table)
        return True
    except Exception as e:
        return False
