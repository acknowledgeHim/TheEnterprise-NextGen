from enterprise_conf import BING_API_KEY, GOOGLE_CSE_API_KEY, SHODAN_API_KEY, GITHUB_ACCESS_TOKEN, BUILTWITH_API, \
    CENSYSIO_ID, CENSYSIO_SECRET, FACEBOOK_ACCESS_TOKEN, FLICKR_API, GOOGLE_API, GOOGLE_CSE_CX, HASHES_API, \
    IPINFODB_API, JIGSAW_API, JIGSAW_PASSWORD, JIGSAW_USERNAME, LINKEDIN_API, LINKEDIN_SECRET, PWNDEDLIST_API, \
    PWNDEDLIST_IV, PWNDELIST_SECRET, SPYONWEB_ACCESS_TOKEN, TWITTER_CONSUMER_KEY, TWITTER_CONSUMER_SECRET, \
    TWITTER_ACCESS_TOKEN, TWITTER_ACCESS_TOKEN_SECRET, ZOOMEYEUSER, ZOOMEYPASS, CLEARBIT_API, EMAILHUNTER, JSONWHOIS, \
    INSTAGRAM_TOKEN, INSTAGRAM_CLIENT_ID, INSTAGRAM_CLIENT_SECRET, FULLCONTACT_API, MAILBOXLAYER_API, \
    VIRUSTOTAL_PUBLIC_API, GITHUB_TRAVIS_KEY

def copy_keys():
    # Make sure enterprise_config API KEYS are copied to tools/recon/theharvester/API_KEYS (so theHarvester can use them)
    with open("tools/recon/theharvester/API_KEYS.py", "w") as api_keys:
        api_keys.write("BING_API_KEY='" + BING_API_KEY + "'\n")
        api_keys.write("GOOGLE_CSE_API_KEY='" + GOOGLE_CSE_API_KEY + "'\n")
        api_keys.write("SHODAN_API_KEY='" + SHODAN_API_KEY + "'\n")

    # Make sure enterprise_config API KEYS are copied to /pentest/datasploit/config.py
    new_file = ""
    with open("/pentest/datasploit/config.py", "r") as conf:
        for line in conf.readlines():
            if 'shodan_api' in line:
                line = 'shodan_api="' + SHODAN_API_KEY + '"\n'
            elif 'bing_api' in line:
                line = 'bing_api="' + BING_API_KEY + '"\n'
            elif 'github_access_token' in line:
                line = 'github_access_token="' + GITHUB_ACCESS_TOKEN + '"\n'
            elif 'builtwith_api' in line:
                line = 'builtwith_api="' + BUILTWITH_API + '"\n'
            elif 'censysio_id' in line:
                line = 'censysio_id="' + CENSYSIO_ID + '"\n'
            elif 'censysio_secret' in line:
                line = 'censysio_secret="' + CENSYSIO_SECRET + '"\n'
            elif 'facebook_access_token' in line:
                line = 'facebook_access_token="' + FACEBOOK_ACCESS_TOKEN + '"\n'
            elif 'flickr_api' in line:
                line = 'flickr_api="' + FLICKR_API + '"\n'
            elif 'google_api' in line:
                line = 'google_api="' + GOOGLE_API + '"\n'
            elif 'google_cse_key' in line:
                line = 'google_cse_key="' + GOOGLE_CSE_API_KEY + '"\n'
            elif 'google_cse_cx' in line:
                line = 'google_cse_cx="' + GOOGLE_CSE_CX + '"\n'
            elif 'hashes_api' in line:
                line = 'hashes_api="' + HASHES_API + '"\n'
            elif 'ipinfodb_api' in line:
                line = 'ipinfodb_api="' + IPINFODB_API + '"\n'
            elif 'jigsaw_api' in line:
                line = 'jigsaw_api="' + JIGSAW_API + '"\n'
            elif 'jigsaw_password' in line:
                line = 'jigsaw_password="' + JIGSAW_PASSWORD + '"\n'
            elif 'jigsaw_username' in line:
                line = 'jigsaw_username="' + JIGSAW_USERNAME + '"\n'
            elif 'linkedin_api' in line:
                line = 'linkedin_api="' + LINKEDIN_API + '"\n'
            elif 'linkedin_secret' in line:
                line = 'linkedin_secret="' + LINKEDIN_SECRET + '"\n'
            elif 'pwnedlist_api' in line:
                line = 'pwnedlist_api="' + PWNDEDLIST_API + '"\n'
            elif 'pwnedlist_iv' in line:
                line = 'pwnedlist_iv="' + PWNDEDLIST_IV + '"\n'
            elif 'pwnedlist_secret' in line:
                line = 'pwnedlist_secret="' + PWNDELIST_SECRET + '"\n'
            elif 'spyonweb_access_token' in line:
                line = 'spyonweb_access_token="' + SPYONWEB_ACCESS_TOKEN + '"\n'
            elif 'twitter_consumer_key' in line:
                line = 'twitter_consumer_key="' + TWITTER_CONSUMER_KEY + '"\n'
            elif 'twitter_consumer_secret' in line:
                line = 'twitter_consumer_secret="' + TWITTER_CONSUMER_SECRET + '"\n'
            elif 'twitter_access_token' in line:
                line = 'twitter_access_token="' + TWITTER_ACCESS_TOKEN + '"\n'
            elif 'twiter_access_token_secret' in line:
                line = 'twiter_access_token_secret="' + TWITTER_ACCESS_TOKEN_SECRET + '"\n'
            elif 'zoomeyeuser' in line:
                line = 'zoomeyeuser="' + ZOOMEYEUSER + '"\n'
            elif 'zoomeyepass' in line:
                line = 'zoomeyepass="' + ZOOMEYPASS + '"\n'
            elif 'clearbit_apikey' in line:
                line = 'clearbit_apikey="' + CLEARBIT_API + '"\n'
            elif 'emailhunter' in line:
                line = 'emailhunter="' + EMAILHUNTER + '"\n'
            elif 'jsonwhois' in line:
                line = 'jsonwhois="' + JSONWHOIS + '"\n'
            elif 'instagram_token' in line:
                line = 'instagram_token="' + INSTAGRAM_TOKEN + '"\n'
            elif 'instagram_client_id' in line:
                line = 'instagram_client_id="' + INSTAGRAM_CLIENT_ID + '"\n'
            elif 'instagram_client_secret' in line:
                line = 'instagram_client_secret="' + INSTAGRAM_CLIENT_SECRET + '"\n'
            elif 'fullcontact_api' in line:
                line = 'fullcontact_api="' + FULLCONTACT_API + '"\n'
            elif 'mailboxlayer_api' in line:
                line = 'mailboxlayer_api="' + MAILBOXLAYER_API + '"\n'
            elif 'virustotal_public_api' in line:
                line = 'virustotal_public_api="' + VIRUSTOTAL_PUBLIC_API + '"\n'
            elif 'github_travis_key' in line:
                line = 'github_travis_key="' + GITHUB_TRAVIS_KEY + '"\n'
            else:
                line = line + "\n"

        with open("/pentest/datasploit/config.py", "w") as conf:
            conf.write(line)