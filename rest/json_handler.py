import json
import logging
from rest import RestDataHandler, RestClientError

logger = logging.getLogger(__name__)


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
        # err.code worked for urllib2
        logging.error(
            "HTTP error {} received from server.".format(err))
        try:
            # json_err = json.loads(err.read())err.response.text  # This worked for urllib2
            json_err = json.loads(err.response.text)
            if json_err:
                logging.error(
                    json.dumps(json_err, sort_keys=True, indent=4, separators=(',', ': ')))
        except ValueError:
            pass


