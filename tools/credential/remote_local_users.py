# pip install wmi-client-wrapper

import argparse
import wmi_client_wrapper as wmi

ap = argparse.ArgumentParser()
# Add arguments
ap.add_argument("-u", "--username", required=True, help="Username")
ap.add_argument("-p", "--password", required=True, help="Password")
ap.add_argument("-r", "--remotecomputer", required=True, help="Remote Computer IP / Hostname")
args = vars(ap.parse_args())


def main():
    wmic = wmi.WmiClientWrapper(username=args['username'], password=args['password'], host=args['remotecomputer'], )
    output = wmic.query("SELECT * FROM WIN32_UserAccount")
    print(output)

if __name__ == "__main__":
    main()