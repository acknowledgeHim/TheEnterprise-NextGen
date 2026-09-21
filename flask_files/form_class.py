import logging

from flask_wtf.csrf import generate_csrf
from markupsafe import escape

logger = logging.getLogger(__name__)


class FormSetup():
    def __init__(self, form_name, action_url):
        """ Creates form. """
        csrf_field = '<input type="hidden" name="csrf_token" value="' + generate_csrf() + '">'
        self.html_form = '<form name="' + str(escape(form_name)) + '" action="' + str(escape(action_url)) + '" method=post enctype="multipart/form-data">' + csrf_field + '<table>'

    def __enter__(self):
        return self


    def __exit__(self, type, value, traceback):
        return self


    def create_form(self, inputs, css_class="", dropdown_fields=[]):
        """

        :param self:
        :param inputs: Multi-dimensional list - [[label, name, regex]]; example: [['Client #', client_number, r'[a-zA-Z0-9]']]
        :return:
        """
        try:
            for input in inputs:
                self.html_form = self.html_form + "<tr><td class='input_label " + css_class + "'>" + input[0] + ": </td>"

                value = ""
                names = None
                if len(input) > 3:
                    value = input[3]
                if len(input) == 5 and input[4] is not None:
                    names = input[4].split(",")

                name = input[1]
                regex = input[2]
                if isinstance(regex, list):
                    regex_string = regex
                else:
                    regex_string = str(regex)
                    if "r'" in regex_string:
                        regex_string = regex_string.replace("r'", "")
                    regex_string = regex_string.rstrip("'")
                    if "-" in regex_string:
                        regex_string = regex_string.replace("-", "\\-")
                    if "[\d" in regex_string:
                        regex_string = regex_string.replace("[\d", "[\\\\d")
                    if "[\w" in regex_string:
                        regex_string = regex_string.replace("[\w", "[\\\\w")

                if name == "comment" or "msg" in name or name == "description" or "output" in name \
                        or name == "accounts" or name == "programs" or name == "services" or "info" in name:
                    self.html_form = self.html_form + self.text_area(name, regex_string, value)
                elif "password" in name:
                    self.html_form = self.html_form + self.password_field(name, regex_string, value)
                elif "|" in str(regex_string) or "_id" in name or isinstance(regex, list) or name in dropdown_fields:
                    self.html_form = self.html_form + self.dropdown(name, regex_string, value, names)
                else:
                    self.html_form = self.html_form + self.text_box(name, regex_string, value)

                self.html_form = self.html_form + "</tr>"

            return self.html_form + "<tr><td></td><td><input type=Submit value=Submit></td></tr></table></form>"
        except Exception as e:
            logger.exception("create_form failed: %s", e)


    def text_area(self, name, regex, value):
        if value is None:
            value = ""
        return "<td><textarea name='" + name + "' cols=50 rows=4 onBlur='validate_input(this, \""+regex+"\");'>" + str(escape(value)) + "</textarea>"

    def dropdown(self, name, regex, value, names):
        try:
            if isinstance(regex, list):
                options = regex
            else:
                option = regex[regex.find("(")+1:]
                option = option[:option.find(")")]
                if "?:" in option:
                    option = option.replace("?:", "").replace("'", "")
                if "(" in option:
                    option = option.replace("(", "")
                if "^" in option:
                    option = option.replace("^", "")
                options = option.split("|")

            select_box = "<td><select name='" + name + "'>"
            for count, option in enumerate(options):
                checked = ""
                option = option.replace("'", "")
                name = option
                if option == "Y":
                    name = "Yes"
                    if value:
                        checked = " selected "
                elif option == "N":
                    name = "No"
                    if not value:
                        checked = " selected "
                elif str(value) == str(option):
                    checked = " selected "
                elif names is not None and value == str(names[count]):
                    checked = " selected"

                if names is not None:
                    name = str(names[count])

                select_box = select_box + "<option value='" + str(escape(option)) + "' " + checked + ">" + str(escape(name)) + "</option>"

            return select_box + "</select>"
        except Exception as e:
            logger.exception("dropdown failed: %s", e)


    def text_box(self, name, regex, value):
        if value is None:
            value = ""
        return "<td><input type=text name='" + name + "' size=75 id='" + name + "' value='" + str(escape(value)) + "' onBlur='validate_input(this, \""+regex+"\");'>"

    def password_field(self, name, regex, value):
        if value is None:
            value = ""
        return "<td><input type=password name='" + name + "' size=75 id='" + name + "' value='" + str(
            escape(value)) + "' onBlur='validate_input(this, \"" + regex + "\");'>"
