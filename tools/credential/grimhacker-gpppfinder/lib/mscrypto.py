'''
.       .1111...          | Title: mscrypto.py
    .10000000000011.   .. | Author: Oliver Morton (Sec-1 Ltd)
 .00              000...  | Email: oliverm-tools@sec-1.com
1                  01..   | Description:
                    ..    | Implements encryption and decryption using
                   ..     | the AES key published by Microsoft.
GrimHacker        ..      |
                 ..       |
grimhacker.com  ..        |
@grimhacker    ..         |
----------------------------------------------------------------------------
GPPPFinder - Group Policy Preference Password Finder
    Copyright (C) 2015  Oliver Morton (Sec-1 Ltd)

    This program is free software; you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation; either version 2 of the License, or
    (at your option) any later version.

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License along
    with this program; if not, write to the Free Software Foundation, Inc.,
    51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
'''

from __future__ import print_function
import logging

from Crypto.Cipher import AES
from base64 import b64decode
from base64 import b64encode


class MSCrypto(object):
    """Decrypt cpassword to password.
    adapted from:
    http://www.leonteale.co.uk/decrypting-windows-2008-gpp-user-passwords-using-gpprefdecrypt-py/ (http://pastebin.com/TE3fvhEh)
    http://carnal0wnage.attackresearch.com/2012/10/group-policy-preferences-and-getting.html"""
    def __init__(self):
        """Initialise Decryptor."""
        self.log = logging.getLogger(__name__)

        self._iv = '\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0'
        #  16 bytes of 0 this is the old default from pycrypto that was removed
        #  (see https://bugs.launchpad.net/pycrypto/+bug/1018283 and https://github.com/dlitz/pycrypto/commit/411f60f58cea79f7e93476ba0c069b80a2a4c1a0)

        # From MSDN: http://msdn.microsoft.com/en-us/library/2c15cbf0-f086-4c74-8b70-1f2fa45dd4be%28v=PROT.13%29#endNote2
        key = ""  # this is here purely so that the next two lines align => increased readability.
        key = key + "4e 99 06 e8  fc b6 6c c9  fa f4 93 10  62 0f fe e8"
        key = key + "f4 96 e8 06  cc 05 79 90  20 9b 09 a4  33 b6 6c 1b"
        self._key = key.replace(" ", "").replace("\n", "").decode('hex')

    @property
    def iv(self):
        """Return the iv"""
        return self._iv

    @property
    def key(self):
        """Return the key"""
        return self._key

    def encrypt(self, plaintext):
        """Encrypt plaintext. Return ciphertext."""
        warning = "\n    WARNING: THIS IS NOT SECURE ENCRYPTION BECAUSE THE KEY IS PUBLICALLY KNOWN.\n        DO NOT USE FOR ANYTHING! EVER!\n"
        def _encrypt_plaintext(plaintext):
            """Pad and encrypt plaintext."""
            # plaintext comes in as utf-8, but need it to be utf-16, so convert it.
            self.log.debug("plaintext (hex): " + plaintext)
            utf8decoded_plaintext = unicode(plaintext, "utf-8")
            self.log.debug("utf8decoded_plaintext (hex): " + utf8decoded_plaintext)
            utf16encoded_plaintext = utf8decoded_plaintext.encode("utf-16le")  # needs le because Microsoft apparently (http://stackoverflow.com/questions/20212487/utf-8-convert-to-utf-16) otherwise a BOM is prepended (fffe)
            self.log.debug("utf16encoded_plaintext (hex): " + utf16encoded_plaintext)

            # pad plaintext to blocksize
            block_size = 16  # block size for cbc
            padding_length = block_size - len(utf16encoded_plaintext) % block_size  # calculate length of padding required.
            padding_char = chr(padding_length)  # get character to pad with
            padding = padding_char * padding_length  # getting padding
            padded_plaintext = utf16encoded_plaintext + padding  # pad plaintext
            self.log.debug("padded_plaintext (hex):" + padded_plaintext.encode('hex'))
            return AES.new(self.key, AES.MODE_CBC, self.iv).encrypt(padded_plaintext)  # encrypt padded plaintext and return

        def _encode_ciphertext(ciphertext):
            """Base64 encode ciphertext and strip padding."""
            encoded_ciphertext = b64encode(ciphertext)  # base64 encode ciphertext
            return encoded_ciphertext.strip("=")  # remove "=" padding from end of encoded ciphertext and return

        # encrypt() logic
        self.log.debug("Padding and encrypting plaintext...")

        try:
            ciphertext = _encrypt_plaintext(plaintext)
        except Exception as e:
            raise Exception("Failed to encrypt plaintext. {0}".format(e))
        else:
            self.log.debug("encoding and stripping padding...")
            try:
                encoded_ciphertext = _encode_ciphertext(ciphertext)
            except Exception as e:
                raise Exception("Failed to encode ciphertext. {0}".format(e))
            else:
                return warning, encoded_ciphertext

    def decrypt(self, encoded_ciphertext):
        """Decrypt cpassword and return plain text password."""
        def _decode_cpassword(encoded_cpassword):
            """Pad and base64 decode cpassword."""
            self.log.debug("padding and decoding cpassword...")
            try:
                encoded_cpassword += "=" * (((4 - len(encoded_cpassword)) % 4) % 4)  # Add padding to the base64 string so that it is the correct length for decoding
            except Exception as e:
                raise Exception("Error padding encoded cpassword. {0}".format(e))
            else:
                try:
                    decoded_cpassword = b64decode(encoded_cpassword)  # Base64 Decode
                except Exception as e:
                    raise Exception("Error base64 decoding cpassword. {0}".format(e))
                else:
                    return decoded_cpassword

        def _decrypt(ciphertext):
            """Decrypt ciphertext. Return plaintext."""
            self.log.debug("decrypting decoded cpassword...")
            try:
                decryption = AES.new(self.key, AES.MODE_CBC, self.iv).decrypt(ciphertext)  # Decrypt the password
                self.log.debug("decryption (hex): " + decryption.encode('hex'))
            except Exception as e:
                raise Exception("Error decrypting ciphertext. {0}".format(e))
            else:
                try:
                    plaintext = decryption[:-ord(decryption[-1])].decode('utf16')  # convert to readable format
                except Exception as e:
                    raise Exception("Errror converting decryption to readable form. {0}".format(e))
                else:
                    return plaintext

        # decrypt() logic
        try:
            decoded_cpassword = _decode_cpassword(encoded_ciphertext)
        except Exception as e:
            raise Exception("Failed to decode cpassword. {0}".format(e))
        else:
            try:
                plaintext = _decrypt(decoded_cpassword)
            except Exception as e:
                raise Exception("Failed to decrypt ciphertext. {0}".format(e))
            else:
                return plaintext


if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser(description="MSCrypto encryption/decryption of cpassword.")
    mutex = parser.add_mutually_exclusive_group()
    mutex.add_argument("-e", "--encrypt", help="String to encrypt.")
    mutex.add_argument("-d", "--decrypt", help="Decrypt cpassword.")
    args = parser.parse_args()

    crypto = MSCrypto()
    if args.encrypt:
        warning, encrypted = crypto.encrypt(args.encrypt)
        print(warning)
        print(encrypted)
    elif args.decrypt:
        print(crypto.decrypt(args.decrypt))
    else:
        print("Specify string to encrypt or cpassword to decrypt.")
        parser.print_usage()
