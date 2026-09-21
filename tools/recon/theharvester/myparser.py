import string
import re
import sys
import print_text
from bs4 import BeautifulSoup

class parser:

    def __init__(self, results, word):
        self.results = results
        self.word = word
        self.temp = []

    def genericClean(self):
        try:
            self.results = re.sub('<em>', '', self.results)
            self.results = re.sub('<b>', '', self.results)
            self.results = re.sub('</b>', '', self.results)
            self.results = re.sub('</em>', '', self.results)
            self.results = re.sub('%2f', ' ', self.results)
            self.results = re.sub('%3a', ' ', self.results)
            self.results = re.sub('<strong>', '', self.results)
            self.results = re.sub('</strong>', '', self.results)
            self.results = re.sub('<wbr>','',self.results)
            self.results = re.sub('</wbr>','',self.results)


            for e in ('>', ':', '=', '<', '/', '\\', ';', '&', '%3A', '%3D', '%3C'):
                self.results = self.results.replace(e, ' ')
        except Exception as e:
            print_text.print_error("myparser except: " + str(e) + " Error on line {}".format(sys.exc_info()[-1].tb_lineno))

    def urlClean(self):
        self.results = re.sub('<em>', '', self.results)
        self.results = re.sub('</em>', '', self.results)
        self.results = re.sub('%2f', ' ', self.results)
        self.results = re.sub('%3a', ' ', self.results)

        for e in ('<', '>', ':', '=', ';', '&', '%3A', '%3D', '%3C'):
            self.results = string.replace(self.results, e, ' ')

    def emails(self):
        self.genericClean()
        regex = '[\w\-][\w\-\.]+@[a-zA-Z0-9.-]*' + self.word
        reg_emails = re.compile(regex)#'[a-zA-Z0-9.\-_+#~!$&\',;=:]+' + '@' + '[a-zA-Z0-9.-]*' + self.word
        # Local part is required, charset is flexible
        # https://tools.ietf.org/html/rfc6531 (removed * and () as they provide FP mostly )

        self.temp = reg_emails.findall(self.results)
        emails = self.unique()

        return emails

    def names(self):
        #regex = "\\b([A-Z]{1}[a-z]{1,30}[- ]{0,1}|[A-Z]{1}[- \']{1}[A-Z]{0,1}[a-z]{1,30}[- ]{0,1}|[a-z]{1,2}[ -\']{1}[A-Z]{1}[a-z]{1,30}){2,5}" #+ self.word
        #reg_names = re.compile(regex)

        #self.temp = reg_names.findall(self.results)
        #names = self.unique()

        import nltk
        from nameparser.parser import HumanName
        from nltk.corpus import wordnet

        tokens = nltk.tokenize.word_tokenize(self.results)
        pos = nltk.pos_tag(tokens)
        sentt = nltk.ne_chunk(pos, binary=False)

        person = []
        person_list = []
        name = ""
        for subtree in sentt.subtrees(filter=lambda t: t.label() == 'PERSON'):
            for leaf in subtree.leaves():
                person.append(leaf[0])
            if len(person) > 1:  # avoid grabbing lone surnames
                for part in person:
                    name += part + ' '
                if name[:-1] not in person_list:
                    person_list.append(name[:-1])
                name = ''
            person = []

        return person_list

    def fileurls(self, file_type):
        try:
            urls = []
            #reg_urls = re.compile('<a href="(.*?)"')
            #self.temp = reg_urls.findall(self.results)
            soup = BeautifulSoup(self.results, 'html.parser')
            links = soup.find_all('a', href=True)
            for link in links:
                if link is not None:
                    href = link.get('href')
                    href = href.lower()
                    if "." + file_type.lower() in href and "webcache.google" not in href and ("http://" in href or "https://" in href):
                        self.temp.append(href)

            allurls = self.unique()

            for x in allurls:
                x = x.lower()
                if x is None:
                    pass
                elif file_type.lower() in x:
                    if "url=http" in x:
                        x = x[x.find("url=http") + 4:]
                    if "." + file_type.lower() in x:
                        x = x[:x.find("."+file_type.lower())+len(file_type)+1]
                        urls.append(x)
        except Exception as e:
            print_text.print_error("\tmyparser - theharvester - except: " + str(e) + " Error on line {}".format(sys.exc_info()[-1].tb_lineno))
        return urls

    def people_googleplus(self):
        self.results = re.sub('</b>', '', self.results)
        self.results = re.sub('<b>', '', self.results)
        reg_people = re.compile('>[a-zA-Z0-9._ ]* - Google\+')
        #reg_people = re.compile('">[a-zA-Z0-9._ -]* profiles | LinkedIn')
        self.temp = reg_people.findall(self.results)
        resul = []
        for x in self.temp:
            y = x.replace(' | LinkedIn', '')
            y = y.replace(' profiles ', '')
            y = y.replace('LinkedIn', '')
            y = y.replace('"', '')
            y = y.replace('>', '')
            if y != " ":
                resul.append(y)
        return resul



    def people_twitter(self):
        reg_people = re.compile('(@[a-zA-Z0-9._ -]*)')
        #reg_people = re.compile('">[a-zA-Z0-9._ -]* profiles | LinkedIn')
        self.temp = reg_people.findall(self.results)
        users = self.unique()
        resul = []
        for x in users:
            y = x.replace(' | LinkedIn', '')
            y = y.replace(' profiles ', '')
            y = y.replace('LinkedIn', '')
            y = y.replace('"', '')
            y = y.replace('>', '')
            if y != " ":
                resul.append(y)
        return resul

    def people_linkedin(self):
        reg_people = re.compile('">[a-zA-Z0-9._ -]* \| LinkedIn')
        #reg_people = re.compile('">[a-zA-Z0-9._ -]* profiles | LinkedIn')
        self.temp = reg_people.findall(self.results)
        resul = []
        for x in self.temp:
            y = x.replace(' | LinkedIn', '')
            y = y.replace(' profiles ', '')
            y = y.replace('LinkedIn', '')
            y = y.replace('"', '')
            y = y.replace('>', '')
            if y != " ":
                resul.append(y)
        return resul

    def profiles(self):
        reg_people = re.compile('">[a-zA-Z0-9._ -]* - <em>Google Profile</em>')
        self.temp = reg_people.findall(self.results)
        resul = []
        for x in self.temp:
            y = x.replace(' <em>Google Profile</em>', '')
            y = y.replace('-', '')
            y = y.replace('">', '')
            if y != " ":
                resul.append(y)
        return resul

    def people_jigsaw(self):
        res = []
        #reg_people = re.compile("'tblrow' title='[a-zA-Z0-9.-]*'><span class='nowrap'/>")
        reg_people = re.compile("href=javascript:showContact\('[0-9]*'\)>[a-zA-Z0-9., ]*</a></span>")
        self.temp = reg_people.findall(self.results)
        for x in self.temp:
            a = x.split('>')[1].replace("</a", "")
            res.append(a)
        return res

    def hostnames(self):
        self.genericClean()
        reg_hosts = re.compile('[a-zA-Z0-9.-]*\.' + self.word)
        self.temp = reg_hosts.findall(self.results)
        hostnames = self.unique()
        return hostnames

    def set(self):
        reg_sets = re.compile('>[a-zA-Z0-9]*</a></font>')
        self.temp = reg_sets.findall(self.results)
        sets = []
        for x in self.temp:
            y = x.replace('>', '')
            y = y.replace('</a</font', '')
            sets.append(y)
        return sets

    def hostnames_all(self):
        reg_hosts = re.compile('<cite>(.*?)</cite>')
        temp = reg_hosts.findall(self.results)
        for x in temp:
            if x.count(':'):
                res = x.split(':')[1].split('/')[2]
            else:
                res = x.split("/")[0]
            self.temp.append(res)
        hostnames = self.unique()
        return hostnames

    def unique(self):
        self.new = []
        for x in self.temp:
            if x not in self.new:
                self.new.append(x)
        return self.new
