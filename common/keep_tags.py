import re
from bs4 import BeautifulSoup

def clean_text(text):
    if text is not None and isinstance(text, str):
        text = text.strip().strip("\n")
        return strip_unwanted_chars(strip_html_tags(text))
    return text

def strip_unwanted_chars(value):
    return value.replace("'", "").replace('"', '')

def strip_html_tags(value):
    if value is not None:
        soup = BeautifulSoup(value, 'lxml')
        return soup.get_text()
    print("13 common/keep_tags value: " + str(value))
    return value

def escape_ansi(line):
    ansi_escape = re.compile(r'(\x9B|\x1B\[)[0-?]*[ -/]*[@-~]')
    return ansi_escape.sub('', line)
