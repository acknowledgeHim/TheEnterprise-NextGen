#!/usr/bin/env python

import string
import sys
import os
import json
from socket import *
import re
import getopt
import print_text

try:
    import requests
except:
    print_text.print_error("Request library not found, please install it before proceeding\n")
    sys.exit()

from discovery import *
from lib import htmlExport
from lib import hostchecker

print_text.print_msg("\n*******************************************************************")
print_text.print_msg("*                                                                 *")
print_text.print_msg("* | |_| |__   ___    /\  /\__ _ _ ____   _____  ___| |_ ___ _ __  *")
print_text.print_msg("* | __| '_ \ / _ \  / /_/ / _` | '__\ \ / / _ \/ __| __/ _ \ '__| *")
print_text.print_msg("* | |_| | | |  __/ / __  / (_| | |   \ V /  __/\__ \ ||  __/ |    *")
print_text.print_msg("*  \__|_| |_|\___| \/ /_/ \__,_|_|    \_/ \___||___/\__\___|_|    *")
print_text.print_msg("*                                                                 *")
print_text.print_msg("* TheHarvester Ver. 2.7                                           *")
print_text.print_msg("* Coded by Christian Martorella                                   *")
print_text.print_msg("* Edge-Security Research                                          *")
print_text.print_msg("* cmartorella@edge-security.com                                   *")
print_text.print_msg("*                                                                 *")
print_text.print_msg("* Modified by: khuber@issgs.net on March 14, 2017                 *")
print_text.print_msg("*\t Update: Python3, color printing, additional functionality ... *")
print_text.print_msg("*******************************************************************\n\n")


def usage():

    comm = os.path.basename(sys.argv[0])

    if os.path.dirname(sys.argv[0]) == os.getcwd():
        comm = "./" + comm

    print_text.print_msg("Usage: theharvester options \n")
    print_text.print_msg("       -d: Domain to search or company name")
    print_text.print_msg("""       -b: data source: baidu, bing, bingapi, dogpile,google, googleCSE,
                        googleplus, google-profiles, google-files, linkedin, pgp, twitter, vhost,
                        yahoo, all\n""")
    print_text.print_msg("       -s: Start in result number X (default: 0)")
    print_text.print_msg("       -v: Verify host name via dns resolution and search for virtual hosts")
    print_text.print_msg("       -f: Save the results into an HTML and XML file (both)")
    print_text.print_msg("       -n: Perform a DNS reverse query on all ranges discovered")
    print_text.print_msg("       -c: Perform a DNS brute force for the domain name")
    print_text.print_msg("       -t: Perform a DNS TLD expansion discovery")
    print_text.print_msg("       -e: Use this DNS server")
    print_text.print_msg("       -l: Limit the number of results to work with(bing goes from 50 to 50 results,")
    print_text.print_msg("            google 100 to 100, and pgp doesn't use this option)")
    print_text.print_msg("       -h: use SHODAN database to query discovered hosts")
    print_text.print_msg("\nExamples:")
    print_text.print_msg("        " + comm + " -d microsoft.com -l 500 -b google -h myresults.html")
    print_text.print_msg("        " + comm + " -d microsoft.com -b pgp")
    print_text.print_msg("        " + comm + " -d microsoft -l 200 -b linkedin")
    print_text.print_msg("        " + comm + " -d apple.com -b googleCSE -l 500 -s 300\n")


def start(argv):
    if len(sys.argv) < 4:
        usage()
        sys.exit()
    try:
        opts, args = getopt.getopt(argv, "a:l:d:b:s:vf:nhcte:")
    except getopt.GetoptError:
        usage()
        sys.exit()
    try:
        start = 0
        host_ip = []
        filename = ""
        bingapi = "yes"
        dnslookup = False
        dnsbrute = False
        dnstld = False
        shodan = False
        vhost = []
        virtual = False
        limit = 100
        dnsserver = ""
        additional_word_to_search = None
        site_search = False

        for opt, arg in opts:
            if opt == '-l':
                limit = int(arg)
            elif opt == '-a':
                additional = arg.split("____")
                additional_word_to_search = additional[0].replace("ZZZZZ", " ")
                site_search = False
                if additional[1] == "True":
                    site_search = True
                elif isinstance(additional[1], str) and len(additional[1]) > 1:
                    site_search = additional[1]
            elif opt == '-d':
                word = arg
            elif opt == '-s':
                start = int(arg)
            elif opt == '-v':
                virtual = "basic"
            elif opt == '-f':
                filename = arg
            elif opt == '-n':
                dnslookup = True
            elif opt == '-c':
                dnsbrute = True
            elif opt == '-h':
                shodan = True
            elif opt == '-e':
                dnsserver = arg
            elif opt == '-t':
                dnstld = True
            elif opt == '-b':
                engine = arg
                if engine not in ("baidu", "bing", "bingapi","dogpile", "google", "googleCSE", "googleplus", "google-profiles", "google-files", "linkedin", "pgp", "twitter", "vhost", "yahoo", "all"):
                    usage()
                    print_text.print_msg("Invalid search engine, try with: baidu, bing, bingapi, dogpile, google, googleCSE, googleplus, google-profiles, google-files, linkedin, pgp, twitter, vhost, yahoo, all")
                    sys.exit()
                else:
                    pass
    except Exception as e:
        print_text.print_error("tool theharvester except: " + str(e) + " Error on line {}".format(sys.exc_info()[-1].tb_lineno))

    try:
        all_emails = []
        all_hosts = []
        all_people = []
        all_files = []
        full = []
        vhost = []
        shodanres = []

        if engine == "google":
            print_text.print_msg("[-] Searching in Google:")
            search = googlesearch.search_google(word, limit, start, additional_word_to_search, site_search)
            search.process()
            all_emails = search.get_emails()
            all_hosts = search.get_hostnames()
            all_people = search.get_names()

        if engine == "googleCSE":
            print_text.print_msg("[-] Searching in Google Custom Search:")
            search = googleCSE.search_googleCSE(word, limit, start, additional_word_to_search, site_search)
            search.process()
            search.store_results()
            all_emails = search.get_emails()
            all_hosts = search.get_hostnames()
            #all_people = search.get_names()

        elif engine == "bing" or engine == "bingapi":
            print_text.print_msg("[-] Searching in Bing:")
            search = bingsearch.search_bing(word, limit, start)
            if engine == "bingapi":
                bingapi = "yes"
            else:
                bingapi = "no"
            search.process(bingapi)
            all_emails = search.get_emails()
            all_hosts = search.get_hostnames()
            #all_people = search.get_names()

        elif engine == "dogpile":
            print_text.print_msg("[-] Searching in Dogpilesearch..")
            search = dogpilesearch.search_dogpile(word, limit)
            search.process()
            all_emails = search.get_emails()
            #all_people = search.get_hostnames()

        elif engine == "pgp":
            print_text.print_msg("[-] Searching in PGP key server..")
            search = pgpsearch.search_pgp(word)
            search.process()
            all_emails = search.get_emails()
            all_hosts = search.get_hostnames()
            #all_people = search.get_names()

        elif engine == "yahoo":
            print_text.print_msg("[-] Searching in Yahoo..")
            search = yahoosearch.search_yahoo(word, limit)
            search.process()
            all_emails = search.get_emails()
            all_hosts = search.get_hostnames()
            #all_people = search.get_names()

        elif engine == "ask":
            print_text.print_msg("[-] Searching in Ask..")
            search = asksearch.search_ask(word, limit)
            search.process()
            all_emails = search.get_emails()
            all_hosts = search.get_hostnames()
            #all_people = search.get_names()

        elif engine == "baidu":
            print_text.print_msg("[-] Searching in Baidu..")
            search = baidusearch.search_baidu(word, limit)
            search.process()
            all_emails = search.get_emails()
            all_hosts = search.get_hostnames()
            #all_people = search.get_names()

        elif engine == "googleplus":
            print_text.print_msg("[-] Searching in Google+ ..")
            search = googleplussearch.search_googleplus(word, limit)
            search.process()
            all_people = search.get_people()
            print_text.print_msg("Users from Google+:")
            print_text.print_msg("====================")
            for user in all_people:
                print_text.print_msg(user)

        elif engine == "twitter":
            print_text.print_msg("[-] Searching in Twitter ..")
            search = twittersearch.search_twitter(word, limit)
            search.process()
            all_people = search.get_people()
            print_text.print_msg("Users from Twitter:")
            print_text.print_msg("====================")
            for user in all_people:
                print_text.print_msg(user)

        elif engine == "linkedin":
            try:
                print_text.print_msg("[-] Searching in Linkedin..")
                search = linkedinsearch.search_linkedin(word, limit)
                search.process()
                all_people = search.get_people()
                print_text.print_msg("Users from Linkedin:")
                print_text.print_msg("====================")
                for user in all_people:
                    print_text.print_msg(user)
            except Exception as e:
                print_text.print_error("tool theharvester except: " + str(e) + " Error on line {}".format(sys.exc_info()[-1].tb_lineno))

        elif engine == "google-profiles":
            print_text.print_msg("[-] Searching in Google profiles..")
            search = googlesearch.search_google(word, limit, start, additional_word_to_search, site_search)
            search.process_profiles()
            all_people = search.get_profiles()
            print_text.print_msg("Users from Google profiles:")
            print_text.print_msg("---------------------------")
            for users in all_people:
                print_text.print_msg(users)

        elif engine == "google-files":
            file_type = word[word.find(":") + 1:]
            print_text.print_msg("[-] Searching in google for files..")
            search = googlesearch.search_google(word, limit, start, additional_word_to_search, site_search)
            search.process_files()
            all_files = search.get_files(file_type)
            all_emails = search.get_emails()
            print_text.print_msg("Files from google:")
            print_text.print_msg("---------------------------")
            for f in all_files:
                print_text.print_msg(f)

        elif engine == "all":
            print_text.print_msg("Full harvest..")
            virtual = "basic"
            print_text.print_msg("[-] Searching in Google..")
            search = googlesearch.search_google(word, limit, start, additional_word_to_search, site_search)
            search.process()
            emails = search.get_emails()
            hosts = search.get_hostnames()
            names = search.get_names()
            all_emails.extend(emails)
            all_hosts.extend(hosts)
            all_people.extend(names)
            print_text.print_msg("[-] Searching in PGP Key server..")
            search = pgpsearch.search_pgp(word)
            search.process()
            emails = search.get_emails()
            hosts = search.get_hostnames()
            names = search.get_names()
            all_hosts.extend(hosts)
            all_emails.extend(emails)
            all_people.extend(names)
            print_text.print_msg("[-] Searching in Bing..")
            bingapi = "no"
            search = bingsearch.search_bing(word, limit, start)
            search.process(bingapi)
            emails = search.get_emails()
            hosts = search.get_hostnames()
            names = search.get_names()
            all_hosts.extend(hosts)
            all_emails.extend(emails)
            all_people.extend(names)
            print_text.print_msg("[-] Searching in Exalead..")
            search = exaleadsearch.search_exalead(word, limit, start)
            search.process()
            emails = search.get_emails()
            hosts = search.get_hostnames()
            all_hosts.extend(hosts)
            all_emails.extend(emails)

            #Clean up email list, sort and uniq
            all_emails=sorted(set(all_emails))
        #Results############################################################
        print_text.print_msg("\n\n[+] Emails found:")
        print_text.print_msg("------------------")
        if all_emails == []:
            print_text.print_msg("No emails found")
        else:
            print_text.print_msg("\n".join(all_emails))

        print_text.print_msg("\n[+] Hosts found in search engines:")
        print_text.print_msg("------------------------------------")
        if all_hosts == []:
            print_text.print_msg("No hosts found")
        else:
            all_hosts=sorted(set(all_hosts))
            print_text.print_msg("[-] Resolving hostnames IPs... ")
            full_host = hostchecker.Checker(all_hosts)
            full = full_host.check()
            for host in full:
                ip = host.split(':')[0]
                print_text.print_msg(host)
                if host_ip.count(ip.lower()):
                    pass
                else:
                    host_ip.append(ip.lower())

        print_text.print_msg("\n\n[+] Files found:")
        print_text.print_msg("------------------")
        if all_files == []:
            print_text.print_msg("No files found")
        else:
            print_text.print_msg("\n".join(all_files))

        print_text.print_msg("\n\n[+] Names found:")
        print_text.print_msg("------------------")
        if all_people == []:
            print_text.print_msg("No Names found")
        else:
            print_text.print_msg("\n".join(all_people))

        #DNS reverse lookup#################################################
        dnsrev = []
        if dnslookup == True:
            print_text.print_msg("\n[+] Starting active queries:")
            analyzed_ranges = []
            for x in full:
                ip = x.split(":")[0]
                range = ip.split(".")
                range[3] = "0/24"
                range = string.join(range, '.')
                if not analyzed_ranges.count(range):
                    print_text.print_msg("[-]Performing reverse lookup in :" + range)
                    a = dnssearch.dns_reverse(range, True)
                    a.list()
                    res = a.process()
                    analyzed_ranges.append(range)
                else:
                    continue
                for x in res:
                    if x.count(word):
                        dnsrev.append(x)
                        if x not in full:
                            full.append(x)
            print_text.print_msg("Hosts found after reverse lookup:")
            print_text.print_msg("---------------------------------")
            for xh in dnsrev:
                print_text.print_msg(xh)
        #DNS Brute force####################################################
        dnsres = []
        if dnsbrute == True:
            print_text.print_msg("\n[-] Starting DNS brute force:")
            a = dnssearch.dns_force(word, dnsserver, verbose=True)
            res = a.process()
            print_text.print_msg("\n[+] Hosts found after DNS brute force:\n")
            for y in res:
                print_text.print_msg(y)
                dnsres.append(y)
                if y not in full:
                    full.append(y)
        #DNS TLD expansion###################################################
        dnstldres = []
        if dnstld == True:
            print_text.print_msg("[-] Starting DNS TLD expansion:")
            a = dnssearch.dns_tld(word, dnsserver, verbose=True)
            res = a.process()
            print_text.print_msg("\n[+] Hosts found after DNS TLD expansion:")
            print_text.print_msg("==========================================")
            for y in res:
                print_text.print_msg(y)
                dnstldres.append(y)
                if y not in full:
                    full.append(y)

        #Virtual hosts search###############################################
        if virtual == "basic":
            print_text.print_msg("[+] Virtual hosts:")
            print_text.print_msg("==================")
            for l in host_ip:
                search = bingsearch.search_bing(l, limit, start)
                search.process_vhost()
                res = search.get_allhostnames()
                for x in res:
                    x = re.sub(r'[[\<\/?]*[\w]*>]*','',x)
                    x = re.sub('<','',x)
                    x = re.sub('>','',x)
                    print_text.print_msg(l + "\t" + x)
                    vhost.append(l + ":" + x)
                    full.append(l + ":" + x)
            vhost=sorted(set(vhost))
        else:
            pass
        shodanres = []
        shodanvisited = []
        if shodan == True:
            print_text.print_msg("[+] Shodan Database search:")
            for x in full:
                print_text.print_msg(x)
                try:
                    ip = x.split(":")[0]
                    if not shodanvisited.count(ip):
                        print_text.print_msg("\tSearching for: " + x)
                        a = shodansearch.search_shodan(ip)
                        shodanvisited.append(ip)
                        results = a.run()
                        for res in results:
                            shodanres.append(
                                x + "SAPO" + str(res['banner']) + "SAPO" + str(res['port']))
                except:
                    pass
            print_text.print_msg("[+] Shodan results:")
            print_text.print_msg("===================")
            for x in shodanres:
                print_text.print_msg(x.split("SAPO")[0] + ":" + x.split("SAPO")[1])
        else:
            pass

        ###################################################################
        # Here i need to add explosion mode.
        # Tengo que sacar los TLD para hacer esto.
        recursion = None
        if recursion:
            start = 0
            for word in vhost:
                search = googlesearch.search_google(word, limit, start)
                search.process()
                emails = search.get_emails()
                hosts = search.get_hostnames()
                print_text.print_msg(emails)
                print_text.print_msg(hosts)
        else:
            pass

        #Reporting#######################################################
        if filename != "":
            try:
                print_text.print_msg("[+] Saving files...")
                html = htmlExport.htmlExport(
                    all_emails,
                    all_people,
                    full,
                    vhost,
                    dnsres,
                    dnsrev,
                    filename,
                    word,
                    shodanres,
                    dnstldres)
                save = html.writehtml()
            except Exception as e:
                print_text.print_error("theharvester except: " + str(e) + " Error on line {}".format(sys.exc_info()[-1].tb_lineno))
                print_text.print_error("Error creating the file")
            try:
                if ".xml" not in filename:
                    filename = filename.split(".")[0] + ".xml"

                file = open(filename, 'w')
                file.write('<?xml version="1.0" encoding="UTF-8"?><theHarvester>')
                for x in all_emails:
                    file.write('<email>' + x + '</email>')
                for x in all_people:
                    file.write('<person>' + x + '</person>')

                for x in full:
                    x = x.split(":")
                    if len(x) == 2:
                        file.write('<host>' + '<ip>' + x[0] + '</ip><hostname>' + x[1]  + '</hostname>' + '</host>')
                    else:
                        file.write('<host>' + x + '</host>')
                for x in vhost:
                    x = x.split(":")
                    if len(x) == 2:
                        file.write('<vhost>' + '<ip>' + x[0] + '</ip><hostname>' + x[1]  + '</hostname>' + '</vhost>')
                    else:
                        file.write('<vhost>' + x + '</vhost>')

                for x in all_people:
                    file.write('<person>' + x + '</person>')

                for x in all_files:
                    file.write('<file>' + x + '</file>')

                if shodanres != []:
                    shodanalysis = []
                    for x in shodanres:
                        res = x.split("SAPO")
                        # print_text.print_msg(" res[0] " + res[0] # ip/host)
                        # print_text.print_msg(" res[1] " + res[1] # banner/info)
                        # print_text.print_msg(" res[2] " + res[2] # port)
                        file.write('<shodan>')
                        #page.h3(res[0])
                        file.write('<host>' + res[0] + '</host>')
                        #page.a("Port :" + res[2])
                        file.write('<port>' + res[2] + '</port>')
                        #page.pre(res[1])
                        file.write('<banner><!--' + res[1] + '--></banner>')


                        reg_server = re.compile('Server:.*')
                        temp = reg_server.findall(res[1])
                        if temp != []:
                            shodanalysis.append(res[0] + ":" + temp[0])

                        file.write('</shodan>')
                    if shodanalysis != []:
                        shodanalysis=sorted(set(shodanalysis))
                        file.write('<servers>')
                        for x in shodanalysis:
                            #page.pre(x)
                            file.write('<server>' + x + '</server>')
                        file.write('</servers>')


                file.write('</theHarvester>')
                file.flush()
                file.close()
                print_text.print_msg("Files saved!")
            except Exception as e:
                print_text.print_error("Error saving XML file: " + str(e))
            sys.exit()
    except Exception as e:
        print_text.print_error("tool theharvester except: " + str(e) + " Error on line {}".format(sys.exc_info()[-1].tb_lineno))

if __name__ == "__main__":
    try:
        start(sys.argv[1:])
    except KeyboardInterrupt:
        print_text.print_error("Search interrupted by user..")
    except:
        sys.exit()
