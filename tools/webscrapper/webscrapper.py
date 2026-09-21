import re
from selenium import webdriver
from time import sleep

class WebScrapper():

    def __init__(self):
        self.driver = webdriver.PhantomJS(service_args=['--ignore-ssl-errors=true', '--ssl-protocol=any'])
        self.driver.set_window_size(1120, 550)

        # Keep track of pages already visited
        self.already_visited = []
        self.visit_queue = []

    def __enter__(self):
        pass

    def __exit__(self, exc_type, exc_val, exc_tb):
        self.driver.quit()

    def get_base_url(self, url):
        tmp = url[url.find("://") + 3:]
        base_url = tmp
        if "?" in tmp:
            base_url = tmp[:tmp.find("?")]
        return base_url

    def get_page(self, url, use_base_url=True, regex_search=None, only_these_html_tag_elements=None):
        """

        :param url:
        :param only_these_html_tag_elements: list of html tag name elements: ex - [a.href, div, div.id, etc...]
        :param regex_search: dictionary of regex patterns to search for and return matches
        :return:
        """
        base_url = url
        if use_base_url:
            base_url = self.get_base_url(url)

        if base_url not in self.already_visited:
            self.already_visited.append(base_url)
            self.driver.get(url)

            # Allow the page to 'fully load'
            sleep(10)

            tag_items = []
            regex_matches = {}
            if only_these_html_tag_elements is not None:
                for html_tag_element in only_these_html_tag_elements:
                    html_tag = html_tag_element
                    element_attribute = html_tag
                    if "." in html_tag_element:
                        part = html_tag_element.split(".")
                        html_tag = part[0]
                        element_attribute = part[1]
                    for element in self.driver.find_element_by_tag_name(html_tag): #ex. 'a' for links
                        if element_attribute != html_tag:
                            tag_items.append(element.get_attribute(element_attribute))
                        else:
                            tag_items.append(element)

            if regex_search is not None:
                for name, regex in regex_search.items():
                    matches = re.findall(regex, self.driver.page_source)
                    regex_matches[name] = matches
            else:
                tag_items.append(self.driver.page_source)

            return tag_items, regex_matches


    def follow_links(self, url, regex_to_match):
        self.visit_queue.append(url)

        regex_matches = {'email':r'[\w\-][\w\-\.]+@[\w\-][\w\-\.]+[a-zA-Z]{1,4}'}

        for url_in_queue in self.visit_queue:
            url_in_queue.pop(0)
            links, regex_matches = self.get_page(url_in_queue, True, ["a.href"])
            for link in links:
                base_link = self.get_base_url(url)
                if base_link not in self.already_visited and base_link not in self.visit_queue:
                    self.visit_queue.append(url)

