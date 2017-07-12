import urllib2
import requests
import logging
import json
from lxml import etree
from collections import OrderedDict

__author__ = "Chetankumar Phulpagare"
__copyright__ = "Copyright 2017, Cisco"
__credits__ = ["Chetankumar Phulpagare"]
__email__ = "cphulpag@cisco.com"

logger = logging.getLogger(__name__)


class RestClientError(Exception):
    pass


class RestDataHandler(object):
    def __init__(self, *args, **kwargs):
        self.hdrs_auth = {}
        self.hdrs_req = {}

    def handle_response(self, resp):
        """Child must override"""
        pass


class RestJSONHandler(RestDataHandler):
    def __init__(self, *args, **kwargs):
        super(RestJSONHandler, self).__init__(*args, **kwargs)

    def login(self, *args, **kwargs):
        self.hdrs_auth["Content-Type"] = "application/json"

    def handle_response(self, resp):
        json_resp = json.loads(resp).copy()
        # if method in ['PUT', 'POST']:
        #     # DEFECT: POST/PUT response does NOT have description in it!!
        #     json_resp['description'] = data['description']
        logger.debug("JSON Response")
        logger.debug(json.dumps(json_resp, sort_keys=True, indent=4, separators=(',', ': ')))
        return json_resp

    def prepare_data(self, data):
        req_data = None
        if data == 'LOGOUT':
            req_data = ''
        elif data:  # input data is a dictionary
            req_data = json.dumps(data)
        return req_data

    def _req(self, *args, **kwargs):
        self.hdrs_req['Content-Type'] = 'application/json'
        self.hdrs_req['Accept'] = 'application/json'

    def _handle_http_err(self, err):
        logging.error(
            "HTTP error code {} received from server.".format(err.code))
        try:
            json_err = json.loads(err.read())
            if json_err:
                logging.error(
                    json.dumps(json_err, sort_keys=True,
                               indent=4, separators=(',', ': ')))
        except ValueError:
            pass


class RestXMLHandler(RestDataHandler):
    def __init__(self, *args, **kwargs):
        super(RestXMLHandler, self).__init__(*args, **kwargs)

    def login(self, *args, **kwargs):
        self.hdrs_auth["Content-Type"] = "application/xml"
        if self.login_data is not None:
            req_type = kwargs.get('req_type')
            etree_data = self._dict2xml(req_type, self.login_data)
            self.login_data = etree.tostring(etree_data)
            logging.debug(self.login_data)

    def logout(self, *args, **kwargs):
        self.hdrs_auth["Content-Type"] = "application/xml"

    def handle_response(self, resp):
        XML_resp = etree.fromstring(resp)
        logger.debug("XML Response")
        logger.debug(etree.tostring(XML_resp, pretty_print=True))
        return XML_resp

    def prepare_data(self, *args, **kwargs):
        data = kwargs.get('data')
        req_data = None
        if data == 'LOGOUT':
            req_data = ''
        elif data is not None:
            req_type = kwargs.get('req_type')
            etree_data = self._dict2xml(req_type, data)
            logger.debug("data: {}".format(etree.tostring(etree_data, pretty_print=True)))
            req_data = etree.tostring(etree_data)
        return req_data

    def _req(self, *args, **kwargs):
        if kwargs.get('http_accept') is None:
            self.hdrs_req['Accept'] = 'application/xml'
        else:  # This is required for ISE
            self.hdrs_req['Accept'] = kwargs.get('http_accept')

        if kwargs.get('http_content') is None:
            self.hdrs_req['Content-Type'] = 'application/xml'
        else:  # This is required for ISE
            self.hdrs_req['Content-Type'] = kwargs.get('http_content')

    def _handle_http_err(self, err):
        logging.error(
            "HTTP error code {} received from server.".format(err.code))

    def _add_elem(self, xml_data, key, value):
        elem = etree.Element(key)
        xml_data.append(elem)
        if isinstance(value, OrderedDict):  # value is object
            # Recursion
            self._add_elems(elem, value)
        else:  # value is string
            elem.text = value

    def _add_elems(self, xml_data, input_dict):
        for key, value in input_dict.items():
            if value is not None:
                if isinstance(value, list):  # value is array
                    for v_item in value:
                        self._add_elem(xml_data, key, v_item)
                else:  # value is string or object
                    self._add_elem(xml_data, key, value)

    def _dict2xml(self, root_tag, input_dict, **kwargs):
        if not isinstance(input_dict, OrderedDict):
            raise RestClientError("Expecting OrderedDict type for input_dict!")
        nsmap = {}
        if kwargs.get('nsmap') is not None:  # Required for ISE
            nsmap = kwargs.get('nsmap')
        xml_data = etree.Element(root_tag, nsmap=nsmap)
        if kwargs.get('name') is not None:  # Required for ISE
            xml_data.attrib['name'] = kwargs.get('name')
        if kwargs.get('descr') is not None:  # Required for ISE
            xml_data.attrib['description'] = kwargs.get('descr')
        self._add_elems(xml_data, input_dict)
        return xml_data


class AppClient(object):
    AUTH_URL = 'App/Must/Override'
    LOGOUT_URL = 'App/Must/Override'
    AUTH_HTTP_STATUS = 200
    AUTH_REQ_HDR_FIELD = 'App-Must-Override'
    AUTH_HDR_FIELD = 'App-Must-Override'

    def __init__(self, *args, **kwargs):
        self.hdrs_auth = {}
        self.hdrs_req = {}
        super(AppClient, self).__init__(*args, **kwargs)

    def _req(self, *args, **kwargs):
        self.hdrs_req[self.AUTH_HDR_FIELD] = self.token
        super(AppClient, self)._req(*args, **kwargs)


class Rest3Client(AppClient, RestDataHandler):
    def __init__(self, url=None, username=None, password=None):
        """
        Initialize REST API object with URL. `username` and `password`
        parameters are optional. If omitted, `login` method can be used.

        :param url: URL of the REST API server
        :param username: Login username for REST API server
        :param password: Login password for REST API server
        """
        if url is None:
            logger.fatal("REST API Server URL needs to be specified")
            exit(1)

        self.url = url     # Server URL
        self.token = None  # Authentication token
        self.username = username
        self.password = password
        self.session = requests.Session()
        super(Rest3Client, self).__init__()
        if self.username and self.password:
            self.login()

    def login(self):
        """
        The login method authenticates a REST client attempting to
        access the services provided by the REST server. This method
        must be called prior to any other method called on other
        services.
        """
        self.login_data = ""
        super(Rest3Client, self).login()
        url_token = self.url + self.AUTH_URL
        # req = urllib2.Request(url_token, self.login_data, headers=self.hdrs_auth)
        # f = None
        try:
            # f = urllib2.urlopen(req)  # can raise URLError
            print(url_token)
            resp = self.session.post(url_token, data=self.login_data, headers=self.hdrs_auth, verify=False)
            # status_code = f.getcode()
            if resp.status_code != self.AUTH_HTTP_STATUS:
                logger.fatal("Error code {} in the HTTP request".format(resp.status_code))
                exit(1)
            self.token = resp.headers.get(self.AUTH_REQ_HDR_FIELD, default=None)
            logging.info("{}: Login Successful!".format(self.url))
            logging.debug("REST API Server Auth token: {}".format(self.token))
        except requests.exceptions.HTTPError as err:
            self._handle_http_err(err)
            raise RestClientError("Login to REST API Server Failed!!")

    def logout(self):
        """
        The logout method notifies the FMC server that a previously
        authenticated FMC client is no longer requiring session access
        to the server.
        """
        self.logout_data = 'LOGOUT'
        super(Rest3Client, self).logout()
        if self.LOGOUT_URL:
            url = self.url + self.LOGOUT_URL
            self._req(url, method='POST', data=self.logout_data)
        logging.info("{}: Logout Successful!".format(self.url))

    def _req(self, url, method='GET', data=None, **kwargs):
        """
        RestClient Internal function. Submit request towards RSET API server,
        checks return status and parses return content.

        :param path: Path to append to URI
        :param method: REST API method, can be any of
            'GET','POST','PUT','DELETE'
        :param data: JSON request content
        :return: JSON response from FMC server as dict()
        """
        if url is None:
            raise RestClientError("REST URL needs to be specified")

        super(Rest3Client, self)._req(method=method, data=data, **kwargs)
        req_data = self.prepare_data(data=data, **kwargs)

        if method in ['GET', 'DELETE'] and data is not None:
            raise RestClientError("HTTP 'GET' or 'DELETE' can only accept data=None")

        logger.debug('{} data: {}'.format(method, req_data))

        obj_resp = ''  # len(json_resp) = 0 if HTTP request fails
        r = None
        try:
            logger.debug("Requesting {} for {}".format(method, url))
            req = requests.Request(method, url, data=req_data, headers=self.hdrs_req)
            prep_req = self.session.prepare_request(req)
            r = self.session.send(prep_req, verify=False)
            if r.status_code not in [200, 201, 202, 204]:
                # 200-OK, 201-Created, 202-Accepted, 204-No Content
                logger.error(
                    "Error code {} in the HTTP request".format(r.status_code))
                if r.text is not None:
                    logging.debug("Error message:\n{}".format(r.text))
                return obj_resp
            resp = r.text  # logout method returns nothing
            if len(resp):
                # print(resp)
                obj_resp = self.handle_response(resp)
        except requests.exceptions.HTTPError, err:
            self._handle_http_err(err)
        return obj_resp

    def __enter__(self):
        return self

    def __exit__(self, errtype, errvalue, errtb):
        if errtype == RestClientError:
            logging.fatal(errvalue)
        else:
            self.logout()

    def handle_response(self, resp):
        obj = super(Rest3Client, self).handle_response(resp)
        return obj


class RestClient(AppClient, RestDataHandler):
    def __init__(self, url=None, username=None, password=None):
        """
        Initialize REST API object with URL. `username` and `password`
        parameters are optional. If omitted, `login` method can be used.

        :param url: URL of the REST API server
        :param username: Login username for REST API server
        :param password: Login password for REST API server
        """
        if url is None:
            logger.fatal("REST API Server URL needs to be specified")
            exit(1)

        self.url = url     # Server URL
        self.token = None  # Authentication token
        self.username = username
        self.password = password
        super(RestClient, self).__init__()
        if self.username and self.password:
            self.login()

    def login(self):
        """
        The login method authenticates a REST client attempting to
        access the services provided by the REST server. This method
        must be called prior to any other method called on other
        services.
        """
        self.login_data = ""
        super(RestClient, self).login()
        url_token = self.url + self.AUTH_URL
        req = urllib2.Request(url_token, self.login_data, headers=self.hdrs_auth)
        f = None
        try:
            f = urllib2.urlopen(req)  # can raise URLError
            status_code = f.getcode()
            if status_code != self.AUTH_HTTP_STATUS:
                logger.fatal("Error code {} in the HTTP request".format(status_code))
                exit(1)
            self.token = f.info().getheader(self.AUTH_REQ_HDR_FIELD)
            logging.info("{}: Login Successful!".format(self.url))
            logging.debug("REST API Server Auth token: {}".format(self.token))
        except urllib2.HTTPError, err:
            self._handle_http_err(err)
            raise RestClientError("Login to REST API Server Failed!!")
        finally:
            if f:
                f.close()

    def logout(self):
        """
        The logout method notifies the FMC server that a previously
        authenticated FMC client is no longer requiring session access
        to the server.
        """
        self.logout_data = 'LOGOUT'
        super(RestClient, self).logout()
        if self.LOGOUT_URL:
            url = self.url + self.LOGOUT_URL
            self._req(url, method='POST', data=self.logout_data)
        logging.info("{}: Logout Successful!".format(self.url))

    def _req(self, url, method='GET', data=None, **kwargs):
        """
        RestClient Internal function. Submit request towards RSET API server,
        checks return status and parses return content.

        :param path: Path to append to URI
        :param method: REST API method, can be any of
            'GET','POST','PUT','DELETE'
        :param data: JSON request content
        :return: JSON response from FMC server as dict()
        """
        if url is None:
            raise RestClientError("REST URL needs to be specified")

        super(RestClient, self)._req(method=method, data=data, **kwargs)
        req_data = self.prepare_data(data=data, **kwargs)

        if method in ['GET', 'DELETE'] and data is not None:
            raise RestClientError("HTTP 'GET' or 'DELETE' can only accept data=None")

        logger.debug('{} data: {}'.format(method, req_data))
        req = urllib2.Request(url, req_data, headers=self.hdrs_req)  # Create Request
        if method in ['PUT', 'DELETE']:
            # urllib2 supports only GET and POST by default
            req.get_method = lambda: method

        obj_resp = ''  # len(json_resp) = 0 if HTTP request fails
        f = None
        try:
            logger.debug("Requesting {} for {}".format(method, url))
            f = urllib2.urlopen(req)
            status_code = f.getcode()
            if status_code not in [200, 201, 202, 204]:
                # 200-OK, 201-Created, 202-Accepted, 204-No Content
                logger.error(
                    "Error code {} in the HTTP request".format(status_code))
                return obj_resp
            resp = f.read()  # logout method returns nothing
            if len(resp):
                obj_resp = self.handle_response(resp)
        except urllib2.HTTPError, err:
            self._handle_http_err(err)
        finally:
            if f:
                f.close()
            return obj_resp

    def __enter__(self):
        return self

    def __exit__(self, errtype, errvalue, errtb):
        if errtype == RestClientError:
            logging.fatal(errvalue)
        else:
            self.logout()
