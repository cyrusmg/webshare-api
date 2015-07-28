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
import logging, argparse
from passlib.hash import md5_crypt
from xml.etree import ElementTree

BASE_URL = "https://webshare.cz/api/"

def get_logger():
    return logging.getLogger(__name__)

def get_hashed_password(user_name, password, salt):
    password = hashlib.sha1(md5_crypt.encrypt(password, salt=salt).encode('utf-8')).hexdigest()
    digest = hashlib.md5((user_name + ':Webshare:' + password).encode('utf-8')).hexdigest()
    return password, digest

def get_salt(user_name):
    """Retrieves salt for password hash from webshare.cz"""
    headers = {'Content-Type': 'application/x-www-form-urlencoded; charset=UTF-8'}
    url = BASE_URL + 'salt/'
    data = {'username_or_email' : user_name}
    response = requests.post(url, data=data, headers=headers)
    assert(response.status_code == 200)
    root = ElementTree.fromstring(response.content)
    assert root.find('status').text == 'OK', 'Return code was not OK, debug info: status: {}, code: {}, message: {}'.format(
                root.find('status').text, 
                root.find('code').text, 
                root.find('message').text)

    return root.find('salt').text

def do_login(user_name, password, salt):
    """Logs in webshare.cz and returns login token"""
    headers = {'Content-Type': 'application/x-www-form-urlencoded; charset=UTF-8'}
    url = BASE_URL + 'login/'
    password, digest = get_hashed_password(user_name, password, salt)
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

    return root.find('token').text

def parse_file_id(url):
    """Return file_id for given webshare URL"""
    # Example URL: https://webshare.cz/#/file/7e31cQ7l44/txt-txt?nojs=true
    regex = r'https?://(?:www\.)?webshare\.cz/(?:#/)?file/(?P<ID>\w+)'
    match = re.match(regex, url)
    assert match, "Invalid URL: {}".format(url)

    return match.groupdict()['ID']

def get_download_link(file_id, token):
    headers = {'Content-Type': 'application/x-www-form-urlencoded; charset=UTF-8'}
    url = BASE_URL + 'file_link/'
    data = {'ident' : file_id, 'wst' : token}
    response = requests.post(url, data=data, headers=headers)
    assert response.status_code == 200
    root = ElementTree.fromstring(response.content)
    assert root.find('status').text == 'OK', 'Return code was not OK, debug info: status: {}, code: {}, message: {}'.format(
                root.find('status').text, 
                root.find('code').text, 
                root.find('message').text)

    return root.find('link').text

def download_file(url, dest_path):
    with urllib.request.urlopen(url) as response:
        assert response.status == 200
        assert response.getheader('content-disposition'), "Expected 'content-disposition' header in response"
        file_name = response.getheader('content-disposition')[21:]
        file_path = os.path.join(dest_path, file_name)
        with open(file_path, 'wb') as out_file:
            shutil.copyfileobj(response, out_file)

def download(token, url, dest_path):
    file_id = parse_file_id(url)
    download_url = get_download_link(file_id, token)
    download_file(download_url, dest_path)

def download_urls(urls, dest_path, user_name, password):
    assert(os.path.exists(dest_path))
    salt = get_salt(user_name)
    token = do_login(user_name, password, salt)
    for url in urls:
        get_logger().info("Downloading URL: {}".format(url))
        download(token, url, dest_path)
        get_logger().info("Downloaded")
    get_logger().info("Finished")

if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument('-u', '--user-name', type=str, help='your webshare username (REQUIRED)', required=True)
    parser.add_argument('-p', '--password', type=str, help='your webshare password (REQUIRED)', required=True)
    parser.add_argument('links', metavar='link', type=str, nargs='+', help='file link to be downloaded')
    parser.add_argument('-d', '--dest', type=str, default='.', help='destination folder (default is current folder)')
    params = parser.parse_args()
    logging.basicConfig(level=logging.INFO)
    get_logger().info("Destionation folder: {}".format(params.dest))
    download_urls(params.links, params.dest, params.user_name, params.password)

