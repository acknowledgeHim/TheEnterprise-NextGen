import sys
import re
import xlsxwriter

class ExcelReport():
    def __init__(self, file_name):
        try:
            # used for converting numerical column # to Excel referenced
            self.alphabet = ['A', 'B', 'C', 'D', 'E', 'F', 'G', 'H', 'I', 'J', 'K', 'L', 'M', 'N', 'O', 'P', 'Q', 'R', 'S',
                             'T', 'U', 'V', 'W', 'X', 'Y', 'Z']

            # Used to keep track of Series data for charts
            self.start_column = 0
            self.start_row = 0
            self.workbook = xlsxwriter.Workbook(file_name, {'remove_timezone': True})

            self.worksheets_created_name = []   # list of add_worksheet names (tab name)
            self.worksheets_created = []    # list of add_worksheet objects

            # Formatting
            self.bold = {'bold': True}
            self.nonbold = {'bold': False}

            self.italic = {'italic': True}
            self.nonitalic = {'italic': False}

            self.bgcolor_red = {'bg_color': 'red'}

            self.red_font = {'font_color': 'red'}
            self.black_font = {'font_color': 'black'}
            self.green_font = {'font_color': 'green'}
            self.orange_font = {'font_color': 'orange'}
            self.yellow_font = {'font_color': 'yellow'}
            self.blue_font = {'font_color': 'blue'}

            self.font_timesnewroman = {'font_name': 'Times New Roman'}
            self.font_couriernew = {'font_name': 'Courier New'}
            self.font_calibri = {'font_name': 'Calibri'}

            self.single_underline = {'underline': 1}
            self.double_underline = {'underline': 2}

            self.number_format = {'num_format': '#,##0'}
            self.number_format_decimal = {'num_format': '#,##0.00'}

            self.halign_center = {'align': 'center'}
            self.halign_right = {'align': 'right'}
            self.halign_justify = {'align': 'justify'}

            self.valign_top = {'valign': 'top'}
            self.valign_center = {'valign': 'vcenter'}
            self.valign_bottom = {'valign': 'bottom'}

            self.text_wrap = {'text_wrap': True}
            self.notext_wrap = {'text_wrap': False}

            self.font_size_extralarge = {'font_size': 25}
            self.font_size_large = {'font_size': 16}
            self.font_size_small = {'font_size': 8}

            self.font_h1 = {'font_size': 24}
            self.font_h2 = {'font_size': 22}
            self.font_h3 = {'font_size': 18}
            self.font_h4 = {'font_size': 16}

            self.shrink_to_fit = {'shrink': True}

            # pre-determined formatting
            self.title_format = self.workbook.add_format({'font_size': 24, 'text_wrap': False})
            self.header_format = self.workbook.add_format(
                {'font_size': 16, 'align': 'center', 'bg_color': "4C4C4C", 'font_color': "white", 'text_wrap': True,
                 'right': 1, 'border_color': "a6a6a6"})
            self.text_block = self.workbook.add_format({'valign': 'top', 'text_wrap': True})
        except Exception as e:
            print("ExcelReport 61 except: " + str(e) + " Error on line {}".format(sys.exc_info()[-1].tb_lineno))

    def __enter__(self):
        return self

    def __exit__(self, type, value, traceback):
        # Hide ChartData worksheet
        if "ChartData" in self.worksheets_created_name:
            chart_worksheet = self.worksheets_created[self.worksheets_created_name.index("ChartData")]
            chart_worksheet.hide()
        self.workbook.close()
        return self

    def summary(self):
        """
        Create summary add_worksheet w/ charts.
        :return:
        """
        pass

    def convert_to_excel_range(self, start_column):
        """
        Convert column number to Excel column specification.
        :param start_column:
        :return:
        """
        try:
            decimal_notation_of_column_place = int(start_column) / 26
            if decimal_notation_of_column_place <= 1:
                alphabet_location = ((decimal_notation_of_column_place - int(decimal_notation_of_column_place)) * 26)
                column = self.alphabet[int(alphabet_location)]
            elif decimal_notation_of_column_place > (26 * 26 + 26) and decimal_notation_of_column_place < (26 * 26 * 26 + 26):
                # Means to AAA to ZZZ (shouldn't have to worry about higher than that!)
                pass
            elif decimal_notation_of_column_place > 1:
                # Right most column location
                alphabet_location = ((decimal_notation_of_column_place - int(decimal_notation_of_column_place)) * 26)
                column = self.alphabet[int(alphabet_location)]

                no_decimal_of_column_place = int(str(decimal_notation_of_column_place)[:str(decimal_notation_of_column_place).find(".")])
                alphabet_location = no_decimal_of_column_place
                # Must minus 1 from left most as it is 1 too high
                column = self.alphabet[int(alphabet_location)-1] + column
        except Exception as e:
            print("ExcelReport 106 except: " + str(e) + " Error on line {}".format(sys.exc_info()[-1].tb_lineno))

        return column

    def add_worksheet(self, tab_name, column_widths=None, orientation='portrait'):
        """
        Create a worksheet
        :param tab_name: name of the tab
        :param column_widths: list of width of columns starting at column 'A'; must be list of integers
        :param orientation: landscape or portrait
        :return: the created worksheet
        """
        try:
            if "new tab" in tab_name.lower():
                tab_name = "Data"
            re_no_invalid_characters = re.compile(r"[\[\]:*?/\\]")
            if tab_name not in self.worksheets_created_name:
                if re_no_invalid_characters.search(tab_name):
                    tab_name = re.sub('\W+','', tab_name )
                worksheet = self.workbook.add_worksheet(tab_name)
                if orientation != 'portrait':
                    worksheet.set_landscape()
                else:
                    worksheet.set_portrait()

                worksheet.center_horizontally()

                self.worksheets_created.append(worksheet)
                self.worksheets_created_name.append(tab_name)

                if column_widths is not None:
                    for count, cw in enumerate(column_widths):
                        worksheet.set_column(count, count, int(cw))
            else:
                 worksheet = self.worksheets_created[self.worksheets_created_name.index(tab_name)]
            return worksheet
        except Exception as e:
            print("ExcelReport 136 except: " + str(e) + " Error on line {}".format(sys.exc_info()[-1].tb_lineno))

    def row_data(self, worksheet, cell_position, data):
        """ Write data in a row starting at cell position, ie. B3. """
        try:
            worksheet.write_row(cell_position, data)
        except Exception as e:
            print("ExcelReport 161 except: " + str(e) + " Error on line {}".format(sys.exc_info()[-1].tb_lineno))

    def autofilter(self, worksheet, filter_range):
        """ Create dropdown filter lists for items in the filter range. """
        worksheet.autofilter(filter_range)

    def set_row(self, worksheet, row, height):
        """ Set height of a row. """
        worksheet.set_row(row, height)

    def merge_range(self, worksheet, cell_range, data, cell_format):
        """ Merge cells. """
        worksheet.merge_range(cell_range, data, cell_format)

    def title(self, worksheet, row_number, title_string, starting_column=0):
        """
        Format a tab title
        :param worksheet:
        :param row_number: zero indexed (so 1st row is 0)
        :param title_string: list of header values
        :param starting_column: default is column 0 (Column A)
        :return:
        """
        try:
            title = {}
            title.update(self.single_underline)
            title.update(self.font_size_large)
            title.update(self.bold)
            title.update(self.black_font)
            format = self.workbook.add_format(title)
            worksheet.set_row(int(row_number), 40, format)
            worksheet.write(row_number, starting_column, title_string)
        except Exception as e:
            print("ExcelReport 144 except: " + str(e) + " Error on line {}".format(sys.exc_info()[-1].tb_lineno))

        return worksheet

    def header(self, worksheet, row_number, header_content, starting_column=0):
        """
        Format a header
        :param worksheet:
        :param row_number: zero indexed (so 1st row is 0)
        :param header_content: list of header values
        :param starting_column: default is column 0 (Column A)
        :return: add_worksheet w/ formatted header
        """
        try:
            worksheet.set_row(int(row_number), 20, self.header_format)

            for column_head in header_content:
                worksheet.write(row_number, starting_column, column_head)
                starting_column += 1

        except Exception as e:
            print("ExcelReport 169 except: " + str(e) + " Error on line {}".format(sys.exc_info()[-1].tb_lineno))

        return worksheet

    # NOT USED
    def format_row(self, worksheet, start_row, end_row, format):
        """
        Format a row or range of rows.
        :param worksheet: add_worksheet to apply this to
        :param start_row: int - starting row # (rows start w/ # 0)
        :param end_row: int - ending row #
        :param format: workbook.add_format(...)
        :return: add_worksheet formatted
        """
        return worksheet.set_row(int(start_row), int(end_row), format)

    def format_column(self, worksheet, column_range, column_width, format):
        """
        Format a column (or range of columns)
        :param worksheet: add_worksheet to apply this to
        :param column_range: string, ex. 'A:D'
        :param column_width: int - width to make the column(s)
        :param format: workbook.add_format(...)
        :return: add_worksheet formatted
        """
        return worksheet.set_column(column_range, int(column_width), format)

    def insert_textbox(self, worksheet, row, text, options):
        """
        Insert a textbox (always starting at Column A (0))
        :param row:
        :param text:
        :return:
        """
        worksheet.insert_textbox('A'+ str(row+1), text, options)

    def cell(self, worksheet, row, col, content, format=None):
        """
        Add content to cell
        :param row: row number (0 = 1st Row)
        :param col: column number (0 = 1st Column - A)
        :param content: data to put in the cell (can be a list
        :return add_worksheet w/ added cell data
        """
        try:
            if format is not None:
                worksheet.write(int(row), int(col), content, format)
            else:
                worksheet.write(int(row), int(col), content)
        except Exception as e:
            print("ExcelReport 234 except: " + str(e) + " Error on line {}".format(sys.exc_info()[-1].tb_lineno))

        return worksheet

    def cell2(self, worksheet, cell, content, format=None):
        """
        Add content to cell
        :param cell: cell (ie A3)
        :param content: data to put in the cell (can be a list
        :return add_worksheet w/ added cell data
        """
        if format is not None:
            worksheet.write(cell, content, format)
        else:
            worksheet.write(cell, content)
        return worksheet

    def chart(self, chart_name, chart_type, data, chart_size={'width': 400, 'height': 225}, additional=None):
        """
        Create chart
        :param chart_name: name of the chart
        :param chart_type: chart type (pie, bar, line, plot, etc)
        :param data: values represented in the chart; list or 2d list
            if chart_type requires values & categories then must be 2d list where list[0] is category & list[1] is value
        :return: chart (needs placed in a worksheet)
        """
        try:
            if "ChartData" not in self.worksheets_created_name:
                chart_worksheet = self.add_worksheet("ChartData")
            else:
                chart_worksheet = self.worksheets_created[self.worksheets_created_name.index("ChartData")]

            if chart_type == 'pie':
                chart = self.pie_chart(chart_worksheet, chart_name, data, chart_size)
            elif chart_type == 'column':
                chart = self.column_chart(chart_worksheet, chart_name, data, chart_size, additional)
            elif chart_type == 'line':
                chart = self.line_chart(chart_worksheet, chart_name, data, chart_size, additional)
        except Exception as e:
            print("ExcelReport 198 except: " + str(e) + " Error on line {}".format(sys.exc_info()[-1].tb_lineno))

        return chart

    def insert_chart(self, start_col, start_row, chart, worksheet):
        """
        Insert chart into worksheet.
        :param start_col: starting col where to insert chart
        :param start_row: starting row where to insert chart
        :param chart: chart to insert
        :param worksheet: worksheet to insert chart onto
        :return:
        """
        try:
            worksheet.insert_chart(start_row, start_col, chart)
        except Exception as e:
            print("ExcelReport 214 except: " + str(e) + " Error on line {}".format(sys.exc_info()[-1].tb_lineno))

    def pie_chart(self, chart_worksheet, chart_name, data, chart_size):
        """

        :param data: must be 2D list where list[0] is list of categories and list[1] is list of values
            if list[2] then is list of color
        :return:
        """
        try:
            color = {}
            points = []
            if len(data) == 3:
                for curr_color in data[2]:
                    points.append({'fill': {'color': curr_color}})
                color = {'points': points}

            start_row = self.start_row
            start_column = self.start_column

            pie_chart = self.workbook.add_chart({'type': 'pie'})
            categories = data[0]
            values = data[1]
            row = int(start_row)
            for count, category in enumerate(categories):
                chart_worksheet = self.cell(chart_worksheet, row, int(start_column), category)
                chart_worksheet = self.cell(chart_worksheet, row, int(start_column)+1, values[count])
                row += 1

            # reset next starting point for next chart series data
            self.start_column = start_column
            self.start_row = row + 2

            # Convert column/row to Excel column/row to get series range
            begin_column = self.convert_to_excel_range(start_column)
            end_column = self.convert_to_excel_range(start_column + 1)

            value_range = '=ChartData!$' + end_column + '$' + str(start_row + 1) + ':$' + end_column + '$' + str(row)
            category_range = '=ChartData!$' + begin_column + '$' + str(start_row+1) + ':$' + begin_column + '$' + str(row)
            series_dict = {'name': chart_name, 'gap': 25, 'values': value_range, 'categories': category_range,
                           'data_labels': {'percentage': True}}

            full_series_dict = {**series_dict, **color}
            pie_chart.add_series(full_series_dict)
            pie_chart.set_chartarea({'fill': {'color': 'white'}, 'border': {'color': 'black'}})
            pie_chart.set_size(chart_size)
        except Exception as e:
            print("ExcelReport 325 except: " + str(e) + " Error on line {}".format(sys.exc_info()[-1].tb_lineno))

        return pie_chart

    def column_chart(self, chart_worksheet, chart_name, data, chart_size, additional):
        """
        Create Column (or bar) chart.
        :param data: must be 2D list where
            inner_list[0] is list of categories
            inner_list[1] is list of series name,
            inner_list[2] is 2D list of values,
            inner_list[3] is list of colors
                                                                               high         medium          low         high    medium     low
        Example: [['pc1', 'pc2', 'pc3', 'pc4'],['high', 'medium', 'low'], [[23, 57, 13, 49],[37, 16,2 29, 35],[19, 11, 23, 34]], ['red', 'orange', 'yellow']]
                                                                           pc1 pc2 pc3 pc4   pc1 pc2 pc3 pc4   pc1 pc2 pc3 pc4
        :return: bar chart
        """
        # http://xlsxwriter.readthedocs.io/working_with_charts.html?highlight=set_chartarea
        # chart_worksheet = self.write_column(chart_worksheet, )

        try:
            start_row = self.start_row
            start_column = self.start_column

            # Convert column/row to Excel column/row to get series range
            neutralizer = 1
            if len(data[2][0]) > 26:
                neutralizer = 0
            begin_column = self.convert_to_excel_range(start_column)
            end_column = self.convert_to_excel_range(start_column + len(data[2][0]) - neutralizer) # -1 b/c zero index

            # Category Range
            chart_worksheet.write_row(begin_column + str(start_row), data[0])
            category_range = '=ChartData!$' + begin_column + '$' + str(start_row) + ':$' + end_column + '$' + str(start_row)
            start_row += 1

            if additional is None:
                columnchart = self.workbook.add_chart({'type': 'column'})
            elif 'subtype' in additional:
                columnchart = self.workbook.add_chart({'type': 'column', 'subtype': additional['subtype']})
            for count, series_data in enumerate(data[2]):
                cell_position = begin_column + str(start_row)
                chart_worksheet.write_row(cell_position, series_data)
                value_range = '=ChartData!$' + begin_column + '$' + str(start_row) + ':$' + end_column + '$' + str(start_row)
                series_dictionary = {'name': data[1][count], 'values': value_range, 'gap': 150,
                                        'data_labels': {'value': True}, 'categories': category_range}
                if len(data) > 3:
                    if len(data[3]) > count:
                        series_dictionary['fill'] = {'color': data[3][count]}

                columnchart.add_series(series_dictionary)
                start_row += 1

            columnchart.set_title({'name': chart_name})
            columnchart.set_chartarea({'fill': {'color': 'white'}, 'border': {'color': 'black'}})
            columnchart.set_size(chart_size)
            if additional is not None:
                if 'y_axis' in additional:
                    columnchart.set_y_axis({'name': additional['y_axis']})
                if 'x_axis' in additional:
                    columnchart.set_x_axis({'name': additional['x_axis']})

            # Increment self.start_row ready for next chart data
            self.start_row += 2

            return columnchart
        except Exception as e:
            print("ExcelReport 423 except: " + str(e) + " Error on line {}".format(sys.exc_info()[-1].tb_lineno))


    def line_chart(self, chart_worksheet, chart_name, data, chart_size, additional):
        """
        Create Line chart.
        :param data: must be 2D list where
            inner_list[0] is list of categories
            inner_list[1] is list of series name,
            inner_list[2] is 2D list of values,
            inner_list[3] is list of colors
                                                                                                  client          region_ave       overall_ave        client region_ave overall_ave
        Example: [['2014', '2015', '2016', '2017'],['client', 'region_ave', 'overall_ave'], [[23, 57, 13, 49],  [37, 16, 29, 35],  [19, 11, 23, 34]], ['red', 'orange', 'yellow']]
                                                                                           2014 2015 2016 2017 2014 2015 2016 2017 2014 2015 2016 2017
        :return: bar chart
        """
        # http://xlsxwriter.readthedocs.io/working_with_charts.html?highlight=set_chartarea
        # chart_worksheet = self.write_column(chart_worksheet, )

        try:
            start_row = self.start_row
            start_column = self.start_column

            # Convert column/row to Excel column/row to get series range
            begin_column = self.convert_to_excel_range(start_column)
            end_column = self.convert_to_excel_range(start_column + len(data[2][0]) - 1)  # -1 b/c zero index

            # Category Range
            chart_worksheet.write_row(begin_column + str(start_row), data[0])
            category_range = '=ChartData!$' + begin_column + '$' + str(start_row) + ':$' + end_column + '$' + str(start_row)
            start_row += 1

            linechart = self.workbook.add_chart({'type': 'line'})

            for count, series_data in enumerate(data[2]):
                cell_position = begin_column + str(start_row)
                chart_worksheet.write_row(cell_position, series_data)
                value_range = '=ChartData!$' + begin_column + '$' + str(start_row) + ':$' + end_column + '$' + str(
                    start_row)
                series_dictionary = {'name': data[1][count], 'values': value_range, 'gap': 150,
                                     'data_labels': {'value': True}, 'categories': category_range}
                if len(data) > 3:
                    if len(data[3]) > count:
                        series_dictionary['fill'] = {'color': data[3][count]}

                linechart.add_series(series_dictionary)
                start_row += 1

            linechart.set_title({'name': chart_name})
            linechart.set_chartarea({'fill': {'color': 'white'}, 'border': {'color': 'black'}})
            linechart.set_size(chart_size)
            if additional is not None:
                if 'y_axis' in additional:
                    linechart.set_y_axis({'name': additional['y_axis']})
                if 'x_axis' in additional:
                    linechart.set_x_axis({'name': additional['x_axis']})

            # Increment self.start_row ready for next chart data
            self.start_row +=  2

            return linechart
        except Exception as e:
            print("ExcelReport 479 except: " + str(e) + " Error on line {}".format(sys.exc_info()[-1].tb_lineno))



