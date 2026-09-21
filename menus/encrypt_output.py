import os
import sys
import subprocess
from common import print_text

class EncryptOutput():
    """
    View, add or remove Logs. Adding/removing only for testing purposes.
    """
    def __init__(self, db_object, full_client_engagement_path):
        self.full_client_engagement_path = full_client_engagement_path
        self.file_name = self.full_client_engagement_path.rstrip("/")
        self.client_name_formated = self.file_name[:self.file_name.rfind("/")]
        self.client_name_formated = self.client_name_formated[self.client_name_formated.rfind("/")+1:]

        self.file_name = self.client_name_formated + "__" + self.file_name[self.file_name.rfind("/")+1:] + ".zip"
        return

    def __enter__(self):
        return self

    def __exit__(self, type, value, traceback):
        return self

    def all(self, encrypt_key=None):
        try:
            # check if already there, if so remove the old
            if os.path.isfile(self.full_client_engagement_path + "/" + self.file_name):
                os.remove(self.full_client_engagement_path + "/" + self.file_name)

            if encrypt_key is None:
                while True:
                    encrypt_key = input("Please enter the password to 7z encrypt everything: ")
                    confirm_encrypt_key = input("Please retype the password: ")

                    if len(encrypt_key.strip()) > 0 and encrypt_key == confirm_encrypt_key:
                        break
                    else:
                        print_text.print_error("\tPlease try again, your passwords did not match.")

            # THIS IS WHERE WE ZIP-ENCRYPT the files
            #call = ['7z', 'u', '-p' + encrypt_key, '-y', self.full_client_engagement_path + "/" + self.file_name, self.full_client_engagement_path + "/*"]
            ##call = ['zip', '-r', self.full_client_engagement_path + self.file_name, self.full_client_engagement_path + "*"]
            #subprocess.check_output(call)
            import shutil
            shutil.make_archive(self.full_client_engagement_path + self.file_name, 'zip', self.full_client_engagement_path + "*")

            print_text.print_msg("The Engagement has now been 7zip encrypted with the password you just selected and is "
                                 "located at: " + self.full_client_engagement_path + ".  To decrypt using the password you"
                                 " setup do: '7z x <filename>' and you will be prompted for the password.")

            return self.full_client_engagement_path
        except Exception as e:
            print_text.print_error("menus/encrypt_output.py except: " + str(e) + " Error on line {}".format(sys.exc_info()[-1].tb_lineno))



