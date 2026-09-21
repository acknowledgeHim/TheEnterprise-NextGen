import sys
import re
import ipaddress
import netaddr
import netifaces
import socket
from common import print_text
from common import common

def check_port(good_ip, good_port):
    s = socket.socket()
    host = good_ip
    port = good_port
    s.connect((host, port))
    try:
        s.recv(1024)
        s.close()
        return True
    except Exception as e:
        print_text.print_error("network except: " +  str(e) +  " Error on line {}".format(sys.exc_info()[-1].tb_lineno))
        s.close()
        return False

def nc_verify(ip, port, ip_type="tcp"):
    """
    Uses Netcat to check if IP/Port is open.
    Returns bool, True if open, False if appears closed.
    """
    try:
        if ip_type == "tcp":
            command = "nc -v "
        else:
            command = "nc -vu "
        command = str(command + ip + " " + port)
        errorode, stdout, stderr, timeout = common.ipc_shell_timeout(command, 1)

        if "succeeded" in stdout.lower() or "open" in stdout.lower() or "connected to " in stdout.lower():
            return True
        elif "succeeded" in stderr.lower() or "open" in stderr.lower() or "connected to " in stderr.lower():
            return True
    except Exception as e:
        if "'utf-8' codec can't decode byte" in str(e):
            return True
        print("common/network.py 39 except: " + str(e) + " Error on line {}".format(sys.exc_info()[-1].tb_lineno))

    return False

def is_private(ip):
    return ipaddress.ip_address(ip).is_private

def grab_single_ip_from_network(network):
    tmp_single_ip = network
    if "/" in network:
        tmp_single_ip = network[:network.find("/")]
    return tmp_single_ip

def valid_ip(address):
    """
    Checks for valid IPv4 or IPv6 Address
    Makes sure the IP address given is a valid IPv4 address. If it isn't, it
    will then make a similar check if it is a valid IPv6 address. The
    checks are done in separate functions.

    :param address (str): String to check if valid IPv4 or IPv6 Address
    :return: A bool, true if it is a valid IPv4 or IPv6 address.
    """

    validip = is_valid_ipv4_address(address)
    if not validip:
        validip = is_valid_ipv6_address(address)
    return validip


def is_valid_ipv4_address(address):
    """
    Checks for valid IPv4 Address
    Verifies if the string is a valid IPv4 address.

    :param address (str): String to check if valid IPv4 Address
    :return: A bool, true if it is a valid IPv4 address.
    """
    try:
        socket.inet_pton(socket.AF_INET, address)
    except AttributeError:  # no inet_pton here, sorry
        try:
            socket.inet_aton(address)
        except socket.error:
            return False
        return address.count('.') == 3
    except socket.error:  # not a valid address
        return False
    return True


def is_valid_ipv6_address(address):
    """
    Checks for valid IPv6 Address
    Verifies if the string is a valid IPv6 address.

    :param address (str): String to check if valid IPv6 Address
    :return: A bool, true if it is a valid IPv6 address.
    """

    try:
        socket.inet_pton(socket.AF_INET6, address)
    except socket.error:  # not a valid address
        return False
    return True


def convert_ip_range_to_cidr(startip, endip):
    """
    Converts IP Range to a Network in CIDR notation
    Takes in an IP range and converts it to a network in CIDR notation.

    :param startip (str): First IP address in the range
    :param endip (str): Last IP address in the IP range
    :return: Network in CIDR notation as a string
    """

    startip = startip.replace(" ", "")
    endip = endip.replace(" ", "")
    if "." not in endip:
        endip = startip[:startip.rfind(".") + 1] + endip

    list1 = netaddr.iprange_to_cidrs(startip, endip)
    num = 0
    str_range = ""
    for l in list1:
        str_range = str_range + str(list1[num]) + "\n"
        num += 1
    return str_range

def network_range(range):
    try:
        tmp_ent = range[:range.find("-")]
        ipaddress.ip_network(tmp_ent, strict=False)
        ip_ent = convert_ip_range_to_cidr(range[:range.find("-")].strip(),
                              range[range.find("-") + 1:].strip()).split("\n")
    except:
        ip_ent = []
        print_text.print_error("\tFailed converting ip to CIDR notation!")
    return ip_ent

def valid_cidr(entry, tmp, cidr):
    """
    Validates that CIDR notation entered.

    :param entry: full IP entry to check if valid.
    :param tmp: IP entry with CIDR stripped off.
    :param cidr: CIDR stripped off of IP entry.
    :return: CIDR entry list
    """
    try:
        if isinstance(cidr, int):
            ipaddress.ip_network(tmp, strict=False)
            if valid_ip(tmp):
                return [entry]
    except:
        print_text.print_error("\tFailed to validate CIDR IP.")
    return []

def valid_single_ip(ip):
    """
    Grabs single IP (not in CIDR notation),
    makes sure it is a valid IP,
    and makes it into CIDR notation.

    :param ip: the single IP addresses to check
    :return: list with single IP in it
    """
    try:
        ipaddress.ip_network(ip, strict=False)
        ip_type = 'v4'
        if is_valid_ipv6_address(ip):
            ip_type = 'v6'
        if "/" not in ip and ip_type == 'v4':
            ip = ip + "/32"
        elif "/" not in ip and ip_type == 'v6':
            ip = ip + "/128"
        if valid_ip(ip[:ip.find("/")]):
            return [ip]
    except:
        print_text.print_error("\tFailed to validate single IP entered!")
    return []

def convert_entry_to_cidrs(entry):
    """
    Converts entry to CIDR notated IP range(s).
    Removes whitespace. Then checks for comma in entry.
    If comma, then breaks up entry by comma and attempts to create CIDR entries for each portion.

    :param entry: IP entry to convert to CIDR (can be 10.0.0.1-6, 10.0.0.5,10.0.0.6, 10.0.0.3/29)
    :return: CIDR formatted IP range(s)
    """

    entry = entry.replace(' ', '')

    ip_ent = []
    if "," in entry:
        ip_ents = entry.split(',')
        for ient in ip_ents:
            if "-" in ient:
                ip_ent = ip_ent + network_range(ient)
            elif "/" in ient:
                ip_ent = ip_ent + valid_cidr(ient, ient[:ient.find("/")], int(ient[ient.find("/") + 1:]))
            else:
                ip_ent = ip_ent + valid_single_ip(ient)
    elif "-" in entry:
        ip_ent = network_range(entry)
    elif "/" in entry:
        ip_ent = valid_cidr(entry[:entry.find("/")], int(entry[entry.find("/") + 1:]))
    else:
        ip_ent = valid_single_ip(entry)

    ip_ent = filter(None, ip_ent)
    return ip_ent

def networks_overlap(cidr0, cidr1):
    """
    Compares 2 network ranges to see if they overlap.
    Checks is 1st range's 1st IP is <= 2nd's range's last IP and the 2nd ranges 1st IP is <= 1st ranges last IP
    if so then cidr0 is within cidr1.
    :param cidr0: larger range?
    :param cidr1: smaller range?
    :return:  True if cidr1 is subset of cidr0 or False if not
    """
    return cidr0.first <= cidr1.first and cidr0.last >= cidr1.last
    #return cidr0.first <= cidr1.last and cidr1.first <= cidr0.last

def find_networks_ip_is_in(ip, networks):
    """
    Finds all networks that IP is within (irrespective of location)
    :param ip:
    :param networks:
    :return:
    """
    try:
        if "/" not in ip:
            ip = ip + "/32"
        in_network = []
        rows = []
        for count, network in enumerate(networks):
            if network is not None:
                if "/" not in network:
                    network = network + '/32'

                if check_in_network(network, ip):
                    in_network.append(network)
                    rows.append(count)

        return in_network, rows
    except Exception as e:
        print_text.print_error("\tnetwork failed, except: " + str(e) + \
                               " Error on line {}".format(sys.exc_info()[-1].tb_lineno))

def check_in_network(current_network, new_network):
    """Checks if an IP is inside a Network

    Checks if a specific IP address exists inside an IP subnet.
    example: 192.168.1.50 exists inside 192.168.1.0/24

    Returns true if the new_network DOES exist inside the current_network, false if it does NOT, and returns the network_to_check.

    Arguments:
        current_network -- (str): IP Network in CIDR notation
        new_network -- (str): IP address to check
    """
    already_included = False
    try:
        if "/32" in current_network and "/32" in new_network:
            if current_network == new_network:
                already_included = True
            else:
                already_included = False
        elif networks_overlap(netaddr.IPNetwork(current_network), netaddr.IPNetwork(new_network)):
            already_included = True
        elif networks_overlap(netaddr.IPNetwork(new_network), netaddr.IPNetwork(current_network)):
            already_included = current_network
    except Exception as e:
        print_text.print_error("\tEncountered a problem checking if " + new_network + " is already included, except: " + str(e) + " Error on line {}".format(sys.exc_info()[-1].tb_lineno))
    return already_included

def return_source_ip(request) :
    """Returns source IP of visitor"""
    return request.META['HTTP_X_REAL_IP']

def local_user(ip):
    """Returns True if the IP is private (either IPv4 or IPv6)"""
    return ipaddress.ip_address(ip).is_private

def private_ip(ip):
    """Returns True if the IP is private (either IPv4 or IPv6)"""
    return ipaddress.ip_address(ip).is_private

def return_all_ips_from_network_cidr(network_as_cidr, return_full_range=False):
    """ Return all IPs in network when give Network w/ CIDR notation. """
    ips = []
    net = ipaddress.ip_network(network_as_cidr, strict=False)
    for a in net.hosts():
        ips.append(a)
    if return_full_range:
        ips.insert(0, net.network_address)
        ips.insert(len(ips), net.broadcast_address)
    return ips

def return_range_of_ips_from_cidr(network_as_cidr, return_full_range=False):
    """ Return range of IPs from CIDR notation. """
    if "/32" not in network_as_cidr:
        all_ips = return_all_ips_from_network_cidr(network_as_cidr, return_full_range)
        return str(all_ips[0]) + "-" + str(all_ips[-1])
    else:
        return network_as_cidr[:network_as_cidr.find("/32")]

def return_port(url):
    """
    Returns just the port from a URL
    Takes in a web URL and returns the port number based on the info given.

    :param url (str): URL of website to retrieve port
    :return  The port number in string format.

    Example:
        https://google.com would return port 443
        http://example.com:8080 would return port 8080
    """
    port = 80
    tmp_url = url.replace("http://","").replace("https://","")
    if ":" in tmp_url:
        port = tmp_url[tmp_url.find(":")+1:]
        if "/" in port :
            port = port[:port.find("/")]
    elif "https://" in url :
        port = "443"
    return port

def grab_interfaces():
    """ Grab computer interfaces, except Loopback interfaces. """
    interfaces = netifaces.interfaces()
    interface_string = ""
    sep = ""
    for interface in interfaces:
        if interface_string != "":
            sep = "|"
        if not interface.startswith('lo'):
            interface_string = interface_string + sep + interface
    interface_regex = re.compile(interface_string)

    ip_addresses = list(map(lambda i: netifaces.ifaddresses(i), netifaces.interfaces()))
    ip_address_string = ""
    sep = ""
    for ip in ip_addresses:
        if ip_address_string != "":
            sep = "|"
        try:
            if not ip[2][0]['addr'].startswith('127.'):
                ip_address_string = ip_address_string + sep + ip[2][0]['addr']
        except:
            pass
    ip_address_regex = re.compile(ip_address_string)

    return interface_string, interface_regex, ip_address_string, ip_address_regex

def grab_default_gateway():
    gws = netifaces.gateways()
    gws['default'][netifaces.AF_INET]
    return gws[0]


def get_full_hostname_of_local_computer():
    """ Return your computer's fully qualified domain name. """
    return socket.getfqdn()


def grab_ip_from_dns_name(dns_name):
    try:
        return socket.gethostbyname(dns_name)
    except Exception as e:
        print("376 common/network error: " + str(e))
        return ""




