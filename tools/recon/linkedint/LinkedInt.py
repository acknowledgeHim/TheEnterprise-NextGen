# LinkedInt
# Scrapes LinkedIn without using LinkedIn API
# Original scraper by @DisK0nn3cT (https://github.com/DisK0nn3cT/linkedin-gatherer)
# Modified by @vysecurity
# - Additions:
# --- UI Updates
# --- Constrain to company filters
# --- Addition of Hunter for e-mail prediction
# Modified by HUBER - Oct 8, 2017 for use with TheEnterprise (python3, xml output, etc)


#!/usr/bin/python

import sys
import re
import time
import requests
import subprocess
import json
import argparse
#import cookiejar
from http import cookiejar
import os
import urllib
import math
import string
from bs4 import BeautifulSoup
from thready import threaded
from xml.sax.saxutils import escape
import print_text

""" Setup Argument Parameters """
parser = argparse.ArgumentParser(description='Discovery LinkedIn')
parser.add_argument('-s', '--keywords', type=str, help='Keywords to search')
parser.add_argument('-o', '--outfile', type=str, help='Output file (do not include extentions)')
parser.add_argument('-u', '--username', type=str, help='Username')
parser.add_argument('-p', '--password', type=str, help='Password')
parser.add_argument('-f', '--prefix', type=str, help='Email Format')
parser.add_argument('-c', '--filtercompany', type=str, help='Filter By Company (Y|N)')
parser.add_argument('-i', '--company_id', type=str, help="Company ID")
parser.add_argument('-d', '--domain', type=str, help="Email Domain (ie. @yourdomain.com)")
args = parser.parse_args()

api_key = "" # Hunter API key
username = args.username  	# enter username here
password = args.password	# enter password here
if "'" in password:
    password = password.replace("'", "")
prefix = args.prefix
keywords = args.keywords
if "ZZZZZ" in keywords:
    keywords = "'" + keywords.replace("ZZZZZ", " ") + "'"
filter_company = args.filtercompany
company_id = args.company_id
domain = args.domain
outfile = args.outfile


def login():
    try:
        cookie_filename = "/tmp/cookies.txt"
        real_cookiejar = cookiejar.MozillaCookieJar(cookie_filename)
        opener = urllib.request.build_opener(urllib.request.HTTPRedirectHandler(), urllib.request.HTTPHandler(debuglevel=0),
                                             urllib.request.HTTPSHandler(debuglevel=0),
                                             urllib.request.HTTPCookieProcessor(real_cookiejar))
        page = loadPage(opener, "https://www.linkedin.com/")
        parse = BeautifulSoup(page, "html.parser")
        print("68 linkedint parse: " + str(parse))
        csrf = parse.find(id="loginCsrfParam-login")['value']

        login_data = urllib.parse.urlencode({'session_key': username, 'session_password': password, 'loginCsrfParam': csrf})
        page = loadPage(opener,"https://www.linkedin.com/uas/login-submit", login_data)

        parse = BeautifulSoup(page, "html.parser")
        cookie = ""
        try:
            cookie = real_cookiejar._cookies['.www.linkedin.com']['/']['li_at'].value
        except Exception as e:
            print("linkedint 76 except: " + str(e) + " Error on line {}".format(sys.exc_info()[-1].tb_lineno))
            error = "LinkedInt tool error: Probably used the wrong username and/or password for the LinkedIn account."
            print_text.print_error("\t " + error)
            sys.exit(0)

        real_cookiejar.save()
        os.remove(cookie_filename)
        return cookie
    except Exception as e:
        print("linkedint 86 except: " + str(e) + " Error on line {}".format(sys.exc_info()[-1].tb_lineno))

def loadPage(client, url, data=None):
    try:
        response = client.open(url)
    except:
        print_text.print_error("[!] Cannot load main LinkedIn page")
    try:
        if data is not None:
            response = client.open(url, data.encode('utf-8'))
        else:
            response = client.open(url)
        return response.read().decode('utf-8')
    except Exception as e:
        print("linkedint.py 100 except: " + str(e) + " Error on line {}".format(sys.exc_info()[-1].tb_lineno))
        sys.exit(0)

def get_search():
    try:
        body = ""
        csv = []
        xml = []
        css = """<style>
        #employees {
            font-family: "Trebuchet MS", Arial, Helvetica, sans-serif;
            border-collapse: collapse;
            width: 100%;
        }

        #employees td, #employees th {
            border: 1px solid #ddd;
            padding: 8px;
        }

        #employees tr:nth-child(even){background-color: #f2f2f2;}

        #employees tr:hover {background-color: #ddd;}

        #employees th {
            padding-top: 12px;
            padding-bottom: 12px;
            text-align: left;
            background-color: #4CAF50;
            color: white;
        }
        </style>

        """

        header = """<center><table id=\"employees\">
                 <tr>
                 <th>Photo</th>
                 <th>Name</th>
                 <th>Possible Email:</th>
                 <th>Job</th>
                 <th>Location</th>
                 </tr>
                 """

        # Do we want to automatically get the company ID?
        if bCompany:
            if bAuto:
                # Automatic
                # Grab from the URL
                companyID = 0
                url = "https://www.linkedin.com/voyager/api/typeahead/hits?q=blended&query=%s" % search
                headers = {'Csrf-Token':'ajax:0397788525211216808', 'X-RestLi-Protocol-Version':'2.0.0'}
                cookies['JSESSIONID'] = 'ajax:0397788525211216808'
                r = requests.get(url, cookies=cookies, headers=headers)
                content = json.loads(r.text)
                print("157 linkedint content: " + str(content))
                firstID = 0
                for i in range(0,len(content['elements'])):
                    try:
                        companyID = content['elements'][i]['hitInfo']['com.linkedin.voyager.typeahead.TypeaheadCompany']['id']
                        if firstID == 0:
                            firstID = companyID
                        print_text.print_error("[Notice] Found company ID: %s" % companyID)
                    except:
                        continue
                companyID = firstID
                if companyID == 0:
                    print_text.print_error("[WARNING] No valid company ID found in auto, please restart and find your own")
            else:
                # Don't auto, use the specified ID
                companyID = bSpecific

            print_text.print_msg("[*] Using company ID: %s" % companyID)

        # Fetch the initial page to get results/page counts
        if bCompany == False:
            url = "https://www.linkedin.com/voyager/api/search/cluster?count=40&guides=List()&keywords=%s&origin=OTHER&q=guided&start=0" % search
        else:
            url = "https://www.linkedin.com/voyager/api/search/cluster?count=40&guides=List(v->PEOPLE,facetCurrentCompany->%s)&origin=OTHER&q=guided&start=0" % (companyID)

        print_text.print_msg(url)

        headers = {'Csrf-Token':'ajax:0397788525211216808', 'X-RestLi-Protocol-Version':'2.0.0'}
        cookies['JSESSIONID'] = 'ajax:0397788525211216808'

        r = requests.get(url, cookies=cookies, headers=headers)
        content = json.loads(r.text)
        data_total = content['elements'][0]['total']

        # Calculate pages off final results at 40 results/page
        pages = int(data_total / 40)

        if pages == 0:
            pages = 1

        if data_total % 40 == 0:
            # Because we count 0... Subtract a page if there are no left over results on the last page
            pages = pages - 1

        if pages == 0:
            print_text.print_error("[!] Try to use quotes in the search name")
            sys.exit(0)

        print_text.print_msg("[*] %i Results Found" % data_total)
        if data_total > 1000:
            pages = 25
            print_text.print_msg("[*] LinkedIn only allows 1000 results. Refine keywords to capture all data")
        print_text.print_msg("[*] Fetching %i Pages" % pages)

        for p in range(pages):
            try:
                r = requests.get(url, cookies=cookies, headers=headers)
                content = r.text    #.encode('UTF-8')
                content = json.loads(content)
                print_text.print_msg("[*] Fetching page %i with %i results" % ((p),len(content['elements'][0]['elements'])))
                for c in content['elements'][0]['elements']:
                    try:
                        if 'com.linkedin.voyager.search.SearchProfile' in c['hitInfo'] and c['hitInfo']['com.linkedin.voyager.search.SearchProfile']['headless'] == False:
                            try:
                                data_industry = c['hitInfo']['com.linkedin.voyager.search.SearchProfile']['industry']
                            except:
                                data_industry = ""
                            data_firstname = c['hitInfo']['com.linkedin.voyager.search.SearchProfile']['miniProfile']['firstName']
                            data_lastname = c['hitInfo']['com.linkedin.voyager.search.SearchProfile']['miniProfile']['lastName']
                            data_slug = "https://www.linkedin.com/in/%s" % c['hitInfo']['com.linkedin.voyager.search.SearchProfile']['miniProfile']['publicIdentifier']
                            data_occupation = c['hitInfo']['com.linkedin.voyager.search.SearchProfile']['miniProfile']['occupation']
                            data_location = c['hitInfo']['com.linkedin.voyager.search.SearchProfile']['location']
                            try:
                                data_picture = "https://media.licdn.com/mpr/mpr/shrinknp_400_400%s" % c['hitInfo']['com.linkedin.voyager.search.SearchProfile']['miniProfile']['picture']['com.linkedin.voyager.common.MediaProcessorImage']['id']
                            except:
                                print_text.print_error("[*] No picture found for %s %s, %s" % (data_firstname, data_lastname, data_occupation))
                                data_picture = ""

                            # incase the last name is multi part, we will split it down

                            parts = data_lastname.split()

                            name = data_firstname + " " + data_lastname
                            fname = ""
                            mname = ""
                            lname = ""

                            if len(parts) == 1:
                                fname = data_firstname
                                mname = '?'
                                lname = parts[0]
                            elif len(parts) == 2:
                                fname = data_firstname
                                mname = parts[0]
                                lname = parts[1]
                            elif len(parts) >= 3:
                                fname = data_firstname
                                lname = parts[0]
                            else:
                                fname = data_firstname
                                lname = '?'

                            fname = re.sub('[^A-Za-z]+', '', fname)
                            mname = re.sub('[^A-Za-z]+', '', mname)
                            lname = re.sub('[^A-Za-z]+', '', lname)

                            if len(fname) == 0 or len(lname) == 0:
                                # invalid user, let's move on, this person has a weird name
                                continue

                            if prefix == 'full':
                                user = '{}{}{}'.format(fname, mname, lname)
                            if prefix == 'firstlast':
                                user = '{}{}'.format(fname, lname)
                            if prefix == 'firstmlast':
                                user = '{}{}{}'.format(fname, mname[0], lname)
                            if prefix == 'flast':
                                user = '{}{}'.format(fname[0], lname)
                            if prefix == 'first.last':
                                user = '{}.{}'.format(fname, lname)
                            if prefix == 'fmlast':
                                user = '{}{}{}'.format(fname[0], mname[0], lname)
                            if prefix == 'lastfirst':
                                user = '{}{}'.format(lname, fname)

                            email = '{}@{}'.format(user, suffix)

                            body += "<tr>" \
                                "<td><a href=\"%s\"><img src=\"%s\" width=200 height=200></a></td>" \
                                "<td><a href=\"%s\">%s</a></td>" \
                                "<td>%s</td>" \
                                "<td>%s</td>" \
                                "<td>%s</td>" \
                                "<a>" % (data_slug, data_picture, data_slug, name, email, data_occupation, data_location)

                            csv.append('"%s","%s","%s","%s","%s", "%s"' % (data_firstname, data_lastname, name.encode('utf-8'), email, data_occupation, data_location.replace(",",";")))
                            xml.append("<record><name>" + name + "</name><email>" + email + "</email><occupation>" + escape(data_occupation) + "</occupation><location>" + escape(data_location) + "</location></record>")
                        else:
                            print_text.print_error("[!] Headless profile found. Skipping")
                    except Exception as e:
                        print_text.print_error("LinkedInt.py except: " + str(e) + " Error on line {}".format(sys.exc_info()[-1].tb_lineno))
            except Exception as e:
                print_text.print_error("LinkedInt.py except: " + str(e) + " Error on line {}".format(sys.exc_info()[-1].tb_lineno))

        foot = "</table></center>"
        f = open('{}.html'.format(outfile), 'w')
        f.write(css)
        f.write(header)
        f.write(body)
        f.write(foot)
        f.close()

        f = open('{}.csv'.format(outfile), 'w')
        f.writelines('\n'.join(csv))
        f.close()

        # xml version
        with open(outfile + ".xml", "w") as of:
            of.write('<?xml version="1.0" encoding="UTF-8"?><LinkedInt>')
            of.write('\n'.join(xml))
            of.write('</LinkedInt>')
    except Exception as e:
        print_text.print_error("LinkedInt.py except: " + str(e) + " Error on line {}".format(sys.exc_info()[-1].tb_lineno))

def banner():
        with open(os.path.dirname(os.path.realpath(__file__)) + '/banner.txt', 'r') as f:
            data = f.read()

            print_text.print_msg("\033[1;31m%s\033[0;0m" % data)
            print_text.print_msg("\033[1;34mProviding you with Linkedin Intelligence")
            print_text.print_msg("\033[1;32mAuthor: Vincent Yiu (@vysec, @vysecurity)\033[0;0m")
            print_text.print_msg("\033[1;32mOriginal version by @DisK0nn3cT\033[0;0m")
            print_text.print_msg("\033[1;32mModified for TheEnterprise by HUBER\033[0;0m")

def authenticate():
    try:
        a = login()
        print_text.print_msg(a)
        session = a
        if len(session) == 0:
            sys.exit("[!] Unable to login to LinkedIn.com")
        print_text.print_msg("[*] Obtained new session: %s" % session)
        cookies = dict(li_at=session)
    except Exception as e:
        sys.exit("[!] Could not authenticate to linkedin. %s" % str(e))
    return cookies

if __name__ == '__main__':
    banner()
    # Prompt user for data variables
    search = keywords #args.keywords if args.keywords!=None else raw_input("[*] Enter search Keywords (use quotes for more percise results)\n")

    bCompany = filter_company #raw_input("[*] Filter by Company? (Y/N): \n")

    if bCompany == "True":
        bCompany = True
    else:
        bCompany = False

    bAuto = True
    bSpecific = 0
    suffix = domain

    # URL Encode for the querystring
    search = urllib.parse.quote_plus(search)
    cookies = authenticate()

    # Initialize Scraping
    get_search()

    print_text.print_msg("[+] Complete")