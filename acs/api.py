import base64
import ssl
import logging
from rest import *

logger = logging.getLogger(__name__)


class ACSClient(AppClient):
    def __init__(self, *args, **kwargs):
        self.AUTH_HTTP_STATUS = 200
        self.AUTH_REQ_HDR_FIELD = 'Set-Cookie'
        self.AUTH_HDR_FIELD = 'Cookie'
        self.AUTH_URL = '/Rest/Common/AcsVersion'
        super(ACSClient, self).__init__(*args, **kwargs)

    def login(self, *args, **kwargs):
        base64str = base64.b64encode('{}:{}'.format(self.username, self.password))
        self.hdrs_auth["Authorization"] = "Basic {}".format(base64str)
        self.login_data = None
        self.login_method = 'GET'
        super(ACSClient, self).login(*args, **kwargs)

    def logout(self):
        self.cookie = ''
        self.LOGOUT_URL = ''

    def _req(self, *args, **kwargs):
        method = kwargs['method']
        if method not in ['GET', 'POST', 'PUT', 'DELETE']:
            raise RestClientError("HTTP method {} is not supported".format(method))

        super(ACSClient, self)._req(*args, **kwargs)


class ACSError(Exception):
    pass


class ACSRestClient(Rest3Client, ACSClient, RestXMLHandler):
    """
    Method Resolution Order:
    ACSRestClient
    Rest3Client
    ACSClient
    AppClient
    RestXMLHandler
    RestDataHandler
    object
    """
    pass


class ACS(ACSRestClient):
    def __init__(self, url=None, username=None, password=None):
        """
        Initialize ACS object with URL. `username` and `password`
        parameters are optional. If omitted, `login` method can be used.

        :param url: URL of the ACS server
        :param username: ACS username
        :param password: ACS password
        """
        super(ACS, self).__init__(url=url, username=username, password=password)

    def getNetworkDeviceById(self, dev_id):
        dev_url = self.url + '/Rest/NetworkDevice/Device' + '/id/' + dev_id
        logger.info("getNetworkDeviceById {}".format(dev_id))
        XML_resp = self._req(dev_url)

    def getNetworkDeviceByName(self, dev_name):
        dev_url = self.url + '/Rest/NetworkDevice/Device' + '/name/' + dev_name
        logger.info("getNetworkDeviceByName {}".format(dev_name))
        XML_resp = self._req(dev_url)
        logger.debug("Network Device")

    def createNetworkDeviceByXML(self, dev_xml):
        dev_url = self.url + '/Rest/NetworkDevice/Device'
        XML_resp = self._req(dev_url, method='POST', data=dev_xml)
        logger.debug("Network Device")

    def updateNetworkDeviceByXML(self, dev_xml):
        dev_url = self.url + '/Rest/NetworkDevice/Device'
        XML_resp = self._req(dev_url, method='PUT', data=dev_xml)
        logger.debug("Network Device")

    def deleteNetworkDevice(self, dev_id):
        dev_url = self.url + '/Rest/NetworkDevice/Device' + '/id/' + dev_id
        XML_resp = self._req(dev_url, method='DELETE')
        logger.debug("Network Device")
