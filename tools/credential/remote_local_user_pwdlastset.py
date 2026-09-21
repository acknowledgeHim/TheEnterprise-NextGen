# sudo apt-get install winexe

import subprocess
import argparse

ap = argparse.ArgumentParser()
# Add arguments
ap.add_argument("-u", "--username", required=True, help="Username")
ap.add_argument("-p", "--password", required=True, help="Password")
ap.add_argument("-r", "--remotecomputer", required=True, help="Remote Computer IP / Hostname")
args = vars(ap.parse_args())


def main():
    wmic = subprocess.Popen(['winexe', '-u', args['username'], 'password=' + args['password'], 'host=' + args['remotecomputer']])
if __name__ == "__main__":
    main()