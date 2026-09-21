#https://null-byte.wonderhowto.com/how-to/download-all-pdfs-webpage-with-python-script-0163031/
import os
import sys
from urllib.parse import urljoin

import requests

try:
    from bs4 import BeautifulSoup
except ImportError:
    print("[*] Please download and install Beautiful Soup first!")
    sys.exit(0)


def download_file(url, download_path):
    """

    :param url:
    :param download_path: where to save the downloaded files
    :return:
    """
    allowed_file_types = ['.pdf', '.doc', '.docx', '.xls', '.xlsx', '.ppt', '.pptx', '.pst']
    url = input("[+] Enter the url: ")

    try:
        # to make it look legit for the url
        headers = {"User-Agent": "Mozilla/5.0 (Windows NT 6.3; WOW64; rv:38.0) Gecko/20100101 Firefox/38.0"}

        i = 0

        html = requests.get(url, headers=headers)
        soup = BeautifulSoup(html.text, "html.parser")  # to parse the website

        for tag in soup.findAll('a', href=True):  # find <a> tags with href in it so you know it is for urls
            # so that if it doesn't contain the full url it can the url itself to it for the download
            tag['href'] = urljoin(url, tag['href'])

            # this is pretty easy we are getting the extension (splitext) from the last name of the full url(basename)
            # the spiltext splits it into the filename and the extension so the [1] is for the second part(the extension)
            if os.path.splitext(os.path.basename(tag['href']))[1] in allowed_file_types:
                current = requests.get(tag['href'], headers=headers)
                print("\n[*] Downloading: %s" % (os.path.basename(tag['href'])))

                f = open(os.path.join(download_path, os.path.basename(tag['href'])), "wb")
                f.write(current.content)
                f.close()
                i += 1

        print("\n[*] Downloaded %d files" % (i + 1))
        input("[+] Press any key to exit...")

    except requests.exceptions.RequestException as e:
        print("[*] Could not get information from server!!")
        sys.exit(2)

    except Exception:
        print("I don't know the problem but sorry!!")
        sys.exit(3)
