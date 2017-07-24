import pyxb
import csmxsd
from lxml import etree
import logging
from rest import RestDataHandler, RestClientError
from collections import OrderedDict

logger = logging.getLogger(__name__)


class RestPyxbHandler(RestDataHandler):
    def __init__(self, *args, **kwargs):
        super(RestPyxbHandler, self).__init__(*args, **kwargs)

    def login(self, *args, **kwargs):
        self.hdrs_auth["Content-Type"] = "application/xml"
        self.login_data = csmxsd.loginRequest(**self.login_data).toxml()

    def logout(self, *args, **kwargs):
        self.hdrs_auth["Content-Type"] = "application/xml"

    def toprettyxml(self, pyxb_obj):
        etree_data = etree.fromstring(pyxb_obj.toxml())
        return etree.tostring(etree_data, pretty_print=True)

    def handle_response(self, resp):
        pyxb_resp = csmxsd.CreateFromDocument(resp)
        logger.debug(u"XML Response\n{}".format(self.toprettyxml(pyxb_resp)))
        return pyxb_resp

    def _add_elems(self, csmxsd_obj, input_dict):
        # logger.debug("{} {}".format(csmxsd_obj, input_dict))
        for key, value in input_dict.items():
            if value is not None:
                if isinstance(value, list):  # value is array
                    plural_obj = getattr(csmxsd_obj, key)
                    # logger.debug("plural {} {} {}".format(plural_obj, key, value))
                    for v_item in value:
                        if isinstance(v_item, OrderedDict):  # value is object
                            pyxb_obj = pyxb.BIND()
                            plural_obj.append(pyxb_obj)
                            self._add_elems(plural_obj[-1], v_item)  # Recursion
                        else:  # value is string
                            plural_obj.append(v_item)
                else:  # value is string or object
                    if isinstance(value, OrderedDict):  # value is object
                        setattr(csmxsd_obj, key, pyxb.BIND())
                        pyxb_obj = getattr(csmxsd_obj, key)
                        self._add_elems(pyxb_obj, value)  # Recursion
                    else:  # value is string
                        setattr(csmxsd_obj, key, value)

    def _dict2pyxb(self, req_type, input_dict, **kwargs):
        if not isinstance(input_dict, OrderedDict):
            raise RestClientError("Expecting OrderedDict type for input_dict!")
        csmxsd_class = csmxsd.__dict__[req_type]
        csmxsd_obj = csmxsd_class()
        # xml_data = etree.Element(root_tag, nsmap=nsmap)
        self._add_elems(csmxsd_obj, input_dict)
        return csmxsd_obj

    def prepare_data(self, *args, **kwargs):
        data = kwargs.get('data')
        req_data = None
        if data == 'LOGOUT':
            req_data = ''
        elif data is not None:
            req_type = kwargs.get('req_type')[5:]
            req_obj = self._dict2pyxb(req_type, data)
            req_data = req_obj.toxml()
            # logger.debug("data: {}".format(req_data))
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

    def write_file(self, pyxb_obj, filename):
        f = open(filename, 'wb')
        f.write(self.toprettyxml(pyxb_obj))
        f.close()

    def append_file(self, pyxb_obj, filename):
        f = open(filename, 'a')
        f.write(self.toprettyxml(pyxb_obj))
        f.close()


