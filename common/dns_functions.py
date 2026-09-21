import sys
try:
   # import pythonwhois
    import whois
except:
    pass
import time
import pygeoip
import dns.resolver
from ipwhois import IPWhois
from common import print_text, network

def domain_information(domain, check_if_no_valid_ip=True):
    """ Builds domain information given whois / dns data. """
    try:
        information = ""
        description = ""
        organization = ""
        nameservers = []

        domain_ip, additional = grab_dns_record(domain, True)

        if check_if_no_valid_ip or domain_ip != "":
            information, registrar, domain_valid_date_range, nameservers = grab_whois_domain(domain)

            if registrar != "":
                description = "Registrar: " + registrar + ";"
            if domain_valid_date_range != "":
                description = description + "Valid Domain Date Range: " + domain_valid_date_range

            if ";" in information:
                organization = information[:information.find(";")]
                information = information[information.find("; ") + 2:]
            if information != "":
                information = information + "; " + additional
            else:
                information = additional
    except Exception as e:
        print_text.print_error("dns_functions 30 except: " +  str(e) +  " Error on line {}".format(sys.exc_info()[-1].tb_lineno))

    return domain_ip, information, description, organization, nameservers

def grab_whois_domain(domain):
    """Query whois by domain and return selected whois values"""
    registrar = ""
    nameservers = []
    information = ''
    domain_valid_date_range = ""

    try:
        #whois_domain = pythonwhois.get_whois(domain)
        #print("53 dns functions whois_domain: " + str(whois_domain))
        whois_domain = whois.whois(domain)
    except Exception as e:
        print_text.print_error("\tThe domain, " + domain + ", does not appear to be a valid, registered domain, except: " + str(e))
        return information, registrar, domain_valid_date_range, nameservers

    try:
        information = ""
        if "emails" in whois_domain:
            emails = whois_domain['emails']
            information = "Emails: " + ", ".join(emails)

        if "name" in whois_domain:
            information += " Organization: " + whois_domain['name']

        information = information.replace("\n", "; ").strip()

        if "registrar" in whois_domain:
            registrar = whois_domain['registrar']
            registrar = '; '.join(str(item) for item in registrar)

        if "expiration_date" in whois_domain and "creation_date" in whois_domain:
            domain_valid_date_range = str(whois_domain['creation_date'].strftime("%Y-%m-%d")) + " - " + str(whois_domain['expiration_date'].strftime("%Y-%m-%d"))

        if "nameservers" in whois_domain:
            nameservers = whois_domain['nameservers']

    except Exception as e:
        print_text.print_error("dns_functions except: " +  str(e) +  " Error on line {}".format(sys.exc_info()[-1].tb_lineno))

    return information.replace("\n"," "), registrar.replace("\n"," "), domain_valid_date_range.replace("\n"," "), nameservers


def find_dns_records(domain):
    """ Get A record DNS entries. """
    try:
        answer = dns.resolver.query(domain, "A")
        for data in answer:
            return data.address
    except:
        return ""

def grab_dns_record(domain, public_only=True):
    try:
        domain_ip = find_dns_records(domain)
        if isinstance(domain_ip, str) and domain_ip != "":
            domain_ip.encode("utf-8")
        if domain_ip != "" and network.valid_ip(domain_ip) and not network.private_ip(domain_ip) and public_only:
            additional = "DNS A Record: " + domain_ip + "; " + grab_whois_ip(domain_ip)
            sep = ""
            if additional != "":
                sep = "; "
            if domain_ip is not None:
                geoip = get_geo_data(domain_ip)
                if 'countrycode' in geoip:
                    city = ""
                    if 'city' in geoip and geoip['city'] != None:
                        city = geoip['city'] + ", "
                    regioncode = ""
                    if 'regioncode' in geoip and geoip['regioncode'] != None:
                        regioncode = geoip['regioncode']
                    countrycode = ""
                    if 'countrycode' in geoip and geoip['countrycode'] != None:
                        countrycode = geoip['countrycode']
                    additional = additional + sep + "IP Geo Location: " + city + regioncode + " " + countrycode
        else:
            #print_text.print_error("\tThe domain entered, " + domain + ", does not have a valid IP address it resolves to, so this might be an unused domain!")
            additional = "Domain has no associated IP."
            domain_ip = ""
    except Exception as e:
        print_text.print_error("dns_functions 105 except: " + str(e) + " Error on line {}".format(sys.exc_info()[-1].tb_lineno))
        domain_ip = ""
        additional = ""
    return domain_ip, additional


def grab_whois_ip(ip):
    """
    Does whois search and puts results in information(str).
    If get connection reset by peer then sleep for 90 sec and try again.
    Returns str(information).

    Arguments:
        ip -- single IP address used to find Whois and Geolocation information
    """
    whois_info = []
    information = ''
    text_divider = "; "
    try:
        ipwhoisobj = IPWhois(ip)
        whois_info = ipwhoisobj.lookup_whois(get_referral=True)
    except Exception as e:
        #print("dns_functions 174 except: " + str(e) + " Error on line {}".format(sys.exc_info()[-1].tb_lineno))
        if "connection reset by peer" in str(e).lower():
            time.sleep(90)
        try:
            ipwhoisobj = IPWhois(ip)
            whois_info = ipwhoisobj.lookup_whois(get_referral=True)
        except Exception as e:
            print_text.print_error("\tWhois lookup failed for " + ip + ".")#, except: " + str(e) + " Error on line {}".format(sys.exc_info()[-1].tb_lineno))
    try:
        if len(whois_info) > 0:
            if 'nets' in whois_info:
                networks = whois_info['nets']
                if 'name' in whois_info['nets'][0] and 'cidr' in whois_info['nets'][0]:
                    isp = "ISP: " + whois_info['nets'][0]['name'] + " for IP range " + whois_info['nets'][0]['cidr']
                    if isp not in information:
                        sep = ''
                        if information != "":
                            sep = text_divider
                        information = information + sep + isp
                sep = ''
                for network in networks:
                    if 'description' in network:
                        if information != '':
                            sep = text_divider
                        if network is not None and 'description' in network and information is not None and network['description'] not in information:  # avoid having redudant descriptions added
                            information = network['description'] + sep + information
            if 'referral' in whois_info:
                referral = whois_info['referral']
                if referral is not None and 'description' in referral:
                    if referral['description'].strip() != "" and referral['description'] not in information:
                        sep = ''
                        if information != "":
                            sep = text_divider
                        information = referral['description'] + sep + information
                if referral is not None and 'name' in referral:
                    if referral['name'].strip() != "" and referral['name'] not in information:
                        sep = ''
                        if information != "":
                            sep = text_divider
                        information = referral['name'] + sep + information
    except Exception as e:
        print("dns_functions 215 except: " + str(e) + " Error on line {}".format(sys.exc_info()[-1].tb_lineno))
    return information.replace("\n", "; ").replace("\t", "")

def get_geo_data(ip):
    """
    Grab Geolocation of IP.
    Return Dictionary of result.
    """
    rawdata = pygeoip.GeoIP('common/GeoLiteCity.dat')
    data = rawdata.record_by_name(ip)
    if "country_name" in data and 'country_code3' in data and 'region_code' in data and 'metro_code' in data and \
        'city' in data and 'postal_code' in data and 'latitude' in data and 'longitude' in data:
        return {
            "ip": ip,
            "countryname": data['country_name'],
            "countrycode": data['country_code3'],
            "regioncode": data['region_code'],
            "regionname": data['metro_code'],
            "city": data['city'],
            "zipcode": data['postal_code'],
            "latitude": data['latitude'],
            "longitude": data['longitude']
        }
    return {'ip': ip}

def get_formated_geo_data(ip):
    geoip = get_geo_data(ip)
    if 'countrycode' in geoip:
        city = ""
        if 'city' in geoip and geoip['city'] != None:
            city = geoip['city'] + ", "
        regioncode = ""
        if 'regioncode' in geoip and geoip['regioncode'] != None:
            regioncode = geoip['regioncode']
        countrycode = ""
        if 'countrycode' in geoip and geoip['countrycode'] != None:
            countrycode = geoip['countrycode']

        return "IP Geo Location: " + city + regioncode + " " + countrycode
    return ""

