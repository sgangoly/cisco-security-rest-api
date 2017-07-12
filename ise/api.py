import base64
import ssl
import logging
from collections import OrderedDict
from rest import *

logger = logging.getLogger(__name__)
# Ignore SSL certificate check for all API URLs
ssl._create_default_https_context = ssl._create_unverified_context


class ISEClient(AppClient):
    def __init__(self, *args, **kwargs):
        self.AUTH_HTTP_STATUS = 200
        self.AUTH_REQ_HDR_FIELD = 'Set-Cookie'
        self.AUTH_HDR_FIELD = 'Cookie'
        self.AUTH_URL = '/ers/sdk/'
        super(ISEClient, self).__init__(*args, **kwargs)

    def login(self, *args, **kwargs):
        base64str = base64.b64encode('{}:{}'.format(self.username, self.password))
        self.hdrs_auth["Authorization"] = "Basic {}".format(base64str)
        self.login_data = None
        super(ISEClient, self).login(*args, **kwargs)

    def logout(self):
        self.cookie = ''
        self.LOGOUT_URL = ''

    def _req(self, *args, **kwargs):
        method = kwargs['method']
        if method not in ['GET', 'POST', 'PUT', 'DELETE']:
            raise RestClientError("HTTP method {} is not supported".format(method))

        super(ISEClient, self)._req(*args, **kwargs)
        

class ISEError(Exception):
    pass


class ISERestClient(RestClient, ISEClient, RestXMLHandler):
    """
    Method Resolution Order:
    ISERestClient
    RestClient
    ISEClient
    AppClient
    RestXMLHandler
    RestDataHandler
    object
    """
    pass


class ISE(ISERestClient):
    def __init__(self, url=None, username=None, password=None):
        """
        Initialize ISE object with URL. `username` and `password` 
        parameters are optional. If omitted, `login` method can be used.
        
        :param url: URL of the ISE server
        :param username: ISE username
        :param password: ISE password
        """
        super(ISE, self).__init__(url=url, username=username, password=password)

    def getAllEndpoints(self, filter=''):
        dev_url = self.url + '/ers/config/endpoint' + filter
        XML_resp = self._req(dev_url, http_accept='application/vnd.com.cisco.ise.identity.endpoint.1.1+xml')
        logger.info("getAll Network Endpoint")
        for rsrc in XML_resp.iter('resource'):
            logger.info(rsrc.attrib['id'] + ' --> ' + rsrc.attrib['name'])
        return XML_resp

    def getEndpointByName(self, mac_addr):
        mac_filter = '?filter=mac.EQ.' + mac_addr
        mac_search = self.getAllEndpoints(filter=mac_filter)
        mac_id = ''
        if len(mac_search[0]):
            mac_id = mac_search[0][0].get('id')
        return mac_id
    
    def getEndpointById(self, endpt_id):
        dev_url = self.url + '/ers/config/endpoint/' + endpt_id
        XML_resp = self._req(dev_url, http_accept='application/vnd.com.cisco.ise.identity.endpoint.1.1+xml')
        logger.info("Get Network Endpoint {}".format(endpt_id))
        return XML_resp
    
    def updateEndpointById(self, endpt_id, xml_data):
        dev_url = self.url + '/ers/config/endpoint/' + endpt_id
        XML_resp = self._req(
            dev_url, method='PUT', data=xml_data, 
            http_accept='application/vnd.com.cisco.ise.identity.endpoint.1.1+xml',
            http_content='application/vnd.com.cisco.ise.identity.endpoint.1.1+xml; charset=utf-8')
        logger.info("Update Network Endpoint {}".format(endpt_id))
        return XML_resp
    
    def createEndpoint(self, endpt_mac, descr, group_id):
        endpt_dict = OrderedDict([
                ('customAttributes',OrderedDict([
                    ('customAttributes',None)
                    ])),
                ('groupId', group_id),
                ('identityStore', None),
                ('identityStoreId', None),
                ('mac', endpt_mac),
                ('portalUser', None),
                ('profileId', None),
                ('staticGroupAssignment', 'true'),
                ('staticProfileAssignment', 'false')
                ])

        xml_data = self._dict2xml('{identity.ers.ise.cisco.com}endpoint', endpt_mac, descr, endpt_dict)
        dev_url = self.url + '/ers/config/endpoint'
        XML_resp = self._req(
            dev_url, method='POST', data=xml_data, 
            http_accept='application/vnd.com.cisco.ise.identity.endpoint.1.1+xml',
            http_content='application/vnd.com.cisco.ise.identity.endpoint.1.1+xml; charset=utf-8')
        logger.info("Created Network Endpoint")
        return XML_resp
    
    def getAllEndpointIdGroups(self, filter=''):
        dev_url = self.url + '/ers/config/endpointgroup' + filter
        XML_resp = self._req(dev_url, http_accept='application/vnd.com.cisco.ise.identity.endpointgroup.1.0+xml')
        print("The response is ", XML_resp)
        logger.info("All Endpoint ID Groups")
        for rsrc in XML_resp.iter('resource'):
            logger.info(rsrc.attrib['name'] + ': ' + rsrc.attrib['description'] + ' --> ' + rsrc.attrib['id'])
        return XML_resp
    
    def getEndpointIdGroupById(self, group_id):
        dev_url = self.url + '/ers/config/endpointgroup/' + group_id
        XML_resp = self._req(dev_url, http_accept='application/vnd.com.cisco.ise.identity.endpointgroup.1.0+xml')
        logger.info("Get Endpoint ID Group {}".format(group_id))
        return XML_resp
    
    def getEndpointIdGroupByName(self, group_name):
        group_filter = '?filter=name.EQ.' + group_name
        group_search = self.getAllEndpointIdGroups(filter=group_filter)
        group_id = ''
        for child in group_search[0]:
            group_id = child.get('id')
        return group_id
