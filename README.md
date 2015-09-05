### About
Simple webshare.cz API interface for downloading files. For basic usage use `login` and `download_file` methods.

Defined interface:
```python
class WebshareAPI:
    def login(self, user_name, password):
        """Logs {user_name} in Webshare API"""

    def download_file(self, url, dest_path):
        """Downloads file in {url} to {dest_path}"""

    def hash_password(self, user_name, password, salt):
        """Creates password hash used by Webshare API"""

    def get_salt(self, user_name):
        """Retrieves salt for password hash from webshare.cz"""

    def get_file_id(self, url):
        """Return file_id for given webshare URL"""

    def get_download_link(self, file_id):
        """Query actual download link from {file_id}"""
```

### To get pip plugin:

```sh
$ virtualenv venv
$ source venv/bin/activate
$ pip install .
```
