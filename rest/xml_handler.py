import re
from lxml import etree
from collections import OrderedDict
import logging
from rest import RestDataHandler, RestClientError

logger = logging.getLogger(__name__)


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
        # etree does not like unicode strings with encoding definition in it
        # etree_resp = resp.replace(r''' encoding="utf-8"''', '')
        etree_resp = re.sub(r""" encoding=["|'][u|U][t|T][f|F]-8["|']""", '', resp)
        logger.debug(etree_resp)
        XML_resp = etree.fromstring(etree_resp)
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
            "HTTP error {} received from server.".format(err))

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


