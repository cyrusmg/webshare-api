#!/usr/bin/env python
"""
Webshare downloader plugin
"""

import requests
import hashlib
import re
import urllib.request
import os.path
import shutil
import argparse
from passlib.hash import md5_crypt
from xml.etree import ElementTree

class WebshareAPI:
    def __init__(self):
        self._base_url = "https://webshare.cz/api/"
        self._token = ""

    def login(self, user_name, password):
        """Logs {{user_name}} in Webshare API"""
        salt = self.get_salt(user_name)
        headers = {'Content-Type': 'application/x-www-form-urlencoded; charset=UTF-8'}
        url = self._base_url + 'login/'
        password, digest = self.hash_password(user_name, password, salt)
        data = {
                'username_or_email' : user_name,
                'password' : password,
                'digest' : digest,
                'keep_logged_in' : 1
                }
        response = requests.post(url, data=data, headers=headers)
        assert(response.status_code == 200)
        root = ElementTree.fromstring(response.content)
        assert root.find('status').text == 'OK', 'Return code was not OK, debug info: status: {}, code: {}, message: {}'.format(
                    root.find('status').text,
                    root.find('code').text,
                    root.find('message').text)

        self._token = root.find('token').text

    def download_file(self, url, dest_path):
        """Downloads file in {{url}} to {{dest_path}}"""
        file_id = self.get_file_id(url)
        download_url = self.get_download_link(file_id)

        with urllib.request.urlopen(download_url) as response:
            assert response.status == 200
            assert response.getheader('content-disposition'), "Expected 'content-disposition' header in response"
            file_name = response.getheader('content-disposition')[21:]
            file_path = os.path.join(dest_path, file_name)
            with open(file_path, 'wb') as out_file:
                shutil.copyfileobj(response, out_file)

    def hash_password(self, user_name, password, salt):
        """Creates password hash used by Webshare API"""
        password = hashlib.sha1(md5_crypt.encrypt(password, salt=salt).encode('utf-8')).hexdigest()
        digest = hashlib.md5((user_name + ':Webshare:' + password).encode('utf-8')).hexdigest()
        return password, digest

    def get_salt(self, user_name):
        """Retrieves salt for password hash from webshare.cz"""
        headers = {'Content-Type': 'application/x-www-form-urlencoded; charset=UTF-8'}
        url = self._base_url + 'salt/'
        data = {'username_or_email' : user_name}
        response = requests.post(url, data=data, headers=headers)
        assert(response.status_code == 200)
        root = ElementTree.fromstring(response.content)
        assert root.find('status').text == 'OK', 'Return code was not OK, debug info: status: {}, code: {}, message: {}'.format(
                    root.find('status').text, 
                    root.find('code').text, 
                    root.find('message').text)

        return root.find('salt').text

    def get_file_id(self, url):
        """Return file_id for given webshare URL"""
        # Example URL: https://webshare.cz/#/file/7e31cQ7l44/txt-txt?nojs=true
        regex = r'https?://(?:www\.)?webshare\.cz/(?:#/)?file/(?P<ID>\w+)'
        match = re.match(regex, url)
        assert match, "Invalid URL: {}".format(url)

        return match.groupdict()['ID']

    def get_download_link(self, file_id):
        headers = {'Content-Type': 'application/x-www-form-urlencoded; charset=UTF-8'}
        url = self._base_url + 'file_link/'
        data = {'ident' : file_id, 'wst' : self._token}
        response = requests.post(url, data=data, headers=headers)
        assert response.status_code == 200
        root = ElementTree.fromstring(response.content)
        assert root.find('status').text == 'OK', 'Return code was not OK, debug info: status: {}, code: {}, message: {}'.format(
                    root.find('status').text, 
                    root.find('code').text, 
                    root.find('message').text)

        return root.find('link').text

if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument('-u', '--user-name', type=str, help='your webshare username (REQUIRED)', required=True)
    parser.add_argument('-p', '--password', type=str, help='your webshare password (REQUIRED)', required=True)
    parser.add_argument('link', metavar='link', type=str, help='file link to be downloaded')
    parser.add_argument('-d', '--dest', type=str, default='.', help='destination folder (default is current folder)')
    params = parser.parse_args()

    webshare = WebshareAPI()
    webshare.login(params.user_name, params.password)
    webshare.download_file(params.link, params.dest)

