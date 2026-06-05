import logging

from htpclient.config import Config
from htpclient.session import Session


class JsonRequest:

    def __init__(self, data):
        self.data = data
        self.config = Config()
        self.session = Session().s

    def execute(self, ignore_certificate: bool = False):
        try:
            logging.debug(self.data)
            if ignore_certificate is None:
                ignore_certificate = bool(self.config.get_value('ignore-cert'))
            verify = not ignore_certificate
            if verify:
                ca_cert = self.config.get_value('ca-cert')
                if ca_cert:
                    verify = ca_cert
            r = self.session.post(
                self.config.get_value('url'),
                json=self.data,
                timeout=30,
                verify=verify,
                allow_redirects=True)
            if r.status_code != 200:
                logging.error("Status code from server: " + str(r.status_code))
                return None
            logging.debug(r.content)
            try:
                return r.json()
            except ValueError:
                logging.error("Server response is not JSON. Ensure URL points to the Hashtopolis API endpoint (for example /api/server.php).")
                return None
        except Exception as e:
            logging.error("Error occurred: %s", e)
            return None
