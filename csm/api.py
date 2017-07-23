import base64
import ssl
import re
import logging
from collections import OrderedDict
from rest import *
import pyxb
import csmxsd
from lxml import etree
from netaddr import *

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


class CsmClient(AppClient):
    def __init__(self, *args, **kwargs):
        self.AUTH_HTTP_STATUS = 200
        self.AUTH_REQ_HDR_FIELD = 'set-cookie'
        self.AUTH_HDR_FIELD = 'cookie'
        self.AUTH_URL = '/nbi/login'
        self.post_data = OrderedDict([
            ('protVersion', '1.0'),
            ('reqId', '123')
        ])
        super(CsmClient, self).__init__(*args, **kwargs)

    def login(self, *args, **kwargs):
        base64str = base64.b64encode('{}:{}'.format(self.username, self.password))
        self.hdrs_auth["Authorization"] = "Basic {}".format(base64str)
        login_dict = self.post_data.copy()
        login_dict.update(OrderedDict([
                ('username', self.username),
                ('password', self.password),
                ('heartbeatRequested', 'false')
                ]))
        self.login_data = login_dict
        self.login_method = 'POST'
        kwargs['req_type'] = '{csm}loginRequest'
        super(CsmClient, self).login(*args, **kwargs)

    def logout(self):
        self.LOGOUT_URL = '/nbi/logout'
        self.logout_data = self.post_data.copy()

    def prepare_data(self, *args, **kwargs):
        if kwargs.get('req_type') is None:
            kwargs['req_type'] = 'logoutRequest'
        req_type = '{csm}' + kwargs.get('req_type')
        kwargs['req_type'] = req_type
        req_data = super(CsmClient, self).prepare_data(*args, **kwargs)
        return req_data

    def _req(self, *args, **kwargs):
        method = kwargs['method']
        if method != 'POST':
            raise RestClientError("HTTP method {} is not supported".format(method))

        super(CsmClient, self)._req(*args, **kwargs)
        

class CSMError(Exception):
    pass


class CSMRestClient(Rest3Client, CsmClient, RestPyxbHandler):
    """
    Method Resolution Order:
    ISERestClient
    Rest3Client
    CsmClient
    AppClient
    RestXMLHandler
    RestDataHandler
    object
    """
    pass


class CSM(CSMRestClient):
    POLICY_TYPES = ['DeviceAccessRuleUnifiedFirewallPolicy',
                    'DeviceAccessRuleFirewallPolicy',
                    'DeviceStaticRoutingFirewallPolicy',
                    'FirewallACLSettingsPolicy']
    def __init__(self, url=None, username=None, password=None):
        """
        Initialize ISE object with URL. `username` and `password` 
        parameters are optional. If omitted, `login` method can be used.
        
        :param url: URL of the ISE server
        :param username: ISE username
        :param password: ISE password
        """
        super(CSM, self).__init__(url=url, username=username, password=password)
        self.obj_tables = {}
        self.obj_tables['network'] = {}
        self.obj_tables['service'] = {}
        self.ordered_tables = {}
        self.ordered_tables['network'] = OrderedDict()  # This makes sure child objects appear before parent
        self.ordered_tables['service'] = OrderedDict()  # This makes sure child objects appear before parent

    def _valid_gid(self, gid):
        GID_PATTERN = r'[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}'
        if re.search(GID_PATTERN, gid) is not None:
            return True
        else:
            return False

    def _csm_req(self, url, req_type, req_dict=None):
        data_dict = self.post_data.copy()
        if req_dict is not None:
            data_dict.update(req_dict)
        logger.debug(data_dict)
        response = self._req(url, method="POST", data=data_dict, req_type=req_type)
        return response

    def ping(self):
        url = self.url + '/nbi/ping'
        logger.debug(url)
        self._csm_req(url, 'pingRequest')

    def getServiceInfo(self):
        url = self.url + '/nbi/configservice/GetServiceInfo'
        logger.debug(url)
        self._csm_req(url, 'getServiceInfoRequest')

    def getGroupList(self):
        url = self.url + '/nbi/configservice/getGroupList'
        req_dict = OrderedDict([('includeEmptyGroups', 'false')])
        self._csm_req(url, 'groupListRequest', req_dict)

    def getDeviceListByType(self, device_type):
        """GET DEVICE LIST BY TYPE

        The GetDeviceListByCapability method returns the list of devices
        matching one or more categories or all devices if the wild card
        argument is chosen.
        device_type can be any of following:
        'firewall': To return all ASA, PIX and FWSM devices.
        'ids': To return all IPS Devices
        'router': To return routers
        'switch': To return switches
        '*' = Wildcard for all device types
        """
        if device_type not in ['firewall', 'ids', 'router', 'switch']:
            raise CSMError("Invalid device type {}. Must be 'firewall', 'ids', 'router', 'switch'".format(device_type))

        url = self.url + '/nbi/configservice/getDeviceListByType'
        req_dict = OrderedDict([('deviceCapability', [device_type])])
        device_list_obj = self._csm_req(url, 'deviceListByCapabilityRequest', req_dict)
        return device_list_obj

    @property
    def firewall_list(self):
        device_list_resp = self.getDeviceListByType('firewall')
        for device in device_list_resp.deviceId:
            yield device.deviceName, device.ipv4Address

    def getDeviceListByGroup(self, device_group_path):
        """GET DEVICE LIST BY GROUP

        The GetDeviceListByGroup method returns the list of devices contained
        within a particular group or all devices if the wildcard argument is
        chosen. 'device_group_path' must be a list of strings for full group
        path. For example if device details for group includes a path such as
        "/VmsVirtualRoot/San Jose/Building 13" (obtained from the response of
        getGroupList API), then 'device_group_path' should be
        ['VmsVirtualRoot', 'San Jose', 'Building 13']
        The "VmsVirtualRoot" is a virtual "root node" for all groups
        '*' = Wildcard for all device groups
        """
        url = self.url + '/nbi/configservice/getDeviceListByGroup'
        logging.debug(url)
        path_list = device_group_path.split('/')[1:]
        req_dict = OrderedDict([('deviceGroupPath', OrderedDict([('pathItem', path_list)]))])
        self._csm_req(url, 'deviceListByGroupRequest', req_dict)

    def execDeviceReadOnlyCLICmds(self, device_name, cmdline, timeout='180'):
        """ISSUE READ ONLY COMMANDS ON DEVICE

        :param device_name: Display name of the device configured in CSM
        :param cmdline: Read-only command that will be issued on the device.
        It must be a `show` command.
        """
        cmd_args = cmdline.split(' ')
        read_cmd = cmd_args[0]  # Must match '[sS][hH][oO][wW]'
        cmd_args = ' '.join(cmd_args[1:])
        url = self.url + '/nbi/utilservice/execDeviceReadOnlyCLICmds'
        req_dict = OrderedDict([
                ('deviceReadOnlyCLICmd', OrderedDict([
                        ('deviceName', device_name),
                        ('cmd', 'show'),
                        ('argument', cmd_args),
                        ('execTimeout', timeout)
                    ])
                 )
            ])
        resp_obj = self._csm_req(url, 'execDeviceReadOnlyCLICmdsRequest', req_dict)
        return resp_obj

    def exec_fw_cmd(self, cmdline):
        for fw_name, fw_ip in self.firewall_list:
            if fw_ip is not None:
                resp = self.execDeviceReadOnlyCLICmds(fw_name, cmdline)
                if resp.deviceCmdResult.result == 'ok':
                    cmd_output = resp.deviceCmdResult.resultContent
                    logger.info("\n{}# {}\n{}".format(fw_name, cmdline, cmd_output))
                else:
                    logger.error(self.toprettyxml(resp))

    def getDeviceConfigByGID(self, device_gid):
        """GET DEVICE CONFIG BY GID

        The GetDeviceConfigByGID method returns a specific device object and
        its associated configuration based on the device id passed into the
        method.
        """
        if not self._valid_gid(device_gid):
            raise CSMError("Device GID {} is not valid.", device_gid)

        url = self.url + '/nbi/configservice/getDeviceConfigByGID'
        req_dict = OrderedDict([
                ('gid', device_gid)
            ])
        self._csm_req(url, 'deviceConfigByGIDRequest', req_dict)

    def getDeviceConfigByName(self, device_name):
        """GET DEVICE CONFIG BY NAME

        The GetDeviceConfigByName method returns a specific device object and
        its associated configuration based on the device id passed into the
        method.
        """
        url = self.url + '/nbi/configservice/getDeviceConfigByName'
        req_dict = OrderedDict([('name', device_name)])
        self._csm_req(url, 'deviceConfigByNameRequest', req_dict)

    def getPolicyListByDeviceGID(self, device_gid):
        """GET POLICY LIST BY GID

        The GetPolicyListByDeviceGID method returns the list of policy names
        and their types, for a particular device GID.
        """
        if not self._valid_gid(device_gid):
          raise CSMError("Device GID {} is not valid.", device_gid)

        url = self.url + '/nbi/configservice/getPolicyListByDeviceGID'
        req_dict = OrderedDict([('gid', device_gid)])
        self._csm_req(url, 'policyListByDeviceGIDRequest', req_dict)

    def getPolicyConfigById(self, device_gid, policy_type):
        """GET POLICY CONFIGURATION BY DEVICE GID

        The GetPolicyConfigByDeviceGID method returns a specific policy and its
        associated policy objects based on the device id and policy type passed
        into the method.
        """
        if not self._valid_gid(device_gid):
            raise CSMError("Device GID {} is not valid.", device_gid)
        if policy_type not in self.POLICY_TYPES:
            raise CSMError("Policy type {} is invalid.", policy_type)

        url = self.url + '/nbi/configservice/getPolicyConfigById'
        req_dict = OrderedDict([
                ('gid', device_gid),
                ('policyType', policy_type)
            ])
        self._csm_req(url, 'policyConfigByDeviceGIDRequest', req_dict)

    def getObjectsByName(self, obj_type, obj_names):
        if obj_type not in ['network', 'service']:
            raise CSMError('Object type {} is invalid!'.format(obj_type))
        if not isinstance(obj_names, list):
            raise CSMError('obj_names must be a list!')

        url = self.url + '/nbi/configservice/getPolicyObject'
        req_dict = OrderedDict([(obj_type + 'PolicyObject', [])])
        for obj_name in obj_names:
            req_dict[obj_type + 'PolicyObject'].append(OrderedDict([('name', obj_name)]))
        self._csm_req(url, 'getPolicyObjectRequest', req_dict)

    def getObjectsByGid(self, obj_type, obj_gids):
        if obj_type not in ['network', 'service']:
            raise CSMError('Object type {} is invalid!'.format(obj_type))
        if not isinstance(obj_gids, list):
            raise CSMError('obj_gids must be a list!')

        url = self.url + '/nbi/configservice/getPolicyObject'
        req_dict = OrderedDict([(obj_type + 'PolicyObject', [])])
        for obj_gid in obj_gids:
            if not self._valid_gid(obj_gid):
                raise CSMError("Object GID {} is not valid.", net_obj_gid)
            req_dict[obj_type + 'PolicyObject'].append(OrderedDict([('gid', obj_gid)]))
        self._csm_req(url, 'getPolicyObjectRequest', req_dict)

    def getObjectByName(self, obj_type, obj_name):
        """Deprecated"""
        self.getObjectsByName(obj_type, [obj_name])

    def getObjectByGID(self, obj_type, obj_gid):
        """Deprecated"""
        self.getObjectsByGid(obj_type, [obj_gid])

    def getNetworkObjectByName(self, net_obj_name):
        """Deprecated"""
        self.getObjectsByName('network', [net_obj_name])

    def getNetworkObjectByGID(self, net_obj_gid):
        """Deprecated"""
        self.getObjectsByGid('network', [net_obj_gid])

    def getSharedPolicyListByType(self, policy_type):
        """GET POLICY CONFIG BY NAME

        The GetPolicyConfigByName method returns a specific policy object and
        its associated configuration based on the shared policy name passed
        into the method
        Example policy_type: DeviceAccessRuleUnifiedFirewallPolicy
        """
        if policy_type not in self.POLICY_TYPES:
            raise CSMError("Policy type {} is invalid.", policy_type)

        url = self.url + '/nbi/configservice/getSharedPolicyListByType'
        req_dict = OrderedDict([('policyType', policy_type)])
        policy_list = self._csm_req(url, 'policyNamesByTypeRequest', req_dict)
        return policy_list

    def getPolicyConfigByName(self, policy_name, policy_type):
        """GET POLICY CONFIG BY NAME

        The GetPolicyConfigByName method returns a specific policy object and
        its associated configuration based on the shared policy name passed
        into the method
        Example policy_type: DeviceAccessRuleUnifiedFirewallPolicy
        """
        if policy_type not in self.POLICY_TYPES:
            raise CSMError("Policy type {} is invalid.", policy_type)

        url = self.url + '/nbi/configservice/getPolicyConfigByName'
        req_dict = OrderedDict([
                ('name', policy_name),
                ('policyType', policy_type),
                ('startIndex', 0)
            ])
        policy_obj = self._csm_req(url, 'policyConfigByNameRequest', req_dict)
        self.ping()  # Ping in case connection is lost
        self.update_tables(policy_obj)
        yield policy_obj
        if policy_obj.endIndex is not None:
            while policy_obj.totalCount > policy_obj.endIndex:
                # print(policy_obj.endIndex, policy_obj.totalCount)
                req_dict = OrderedDict([
                    ('name', policy_name),
                    ('policyType', policy_type),
                    ('startIndex', policy_obj.endIndex),
                ])
                policy_obj = self._csm_req(url, 'policyConfigByNameRequest', req_dict)
                self.ping()
                self.update_tables(policy_obj)
                yield policy_obj

    def update_tables(self, policy_obj):
        """
        Update object tables for network and service policy objects. Table contains mapping of GID to its name.

        :param policy_obj:
        :return:
        """
        net_objs = self.obj_tables['network']
        srv_objs = self.obj_tables['service']
        for net_obj in policy_obj.policyObject.networkPolicyObject:
            # print(net_obj.gid, net_obj.type, net_obj.name, net_obj.comment)
            if net_objs.get(net_obj.gid) is None:
                # self.getObjectsByGid('network', [net_obj_gid])
                net_objs[net_obj.gid] = net_obj
        for srv_obj in policy_obj.policyObject.servicePolicyObject:
            # print(srv_obj.gid, srv_obj.type, srv_obj.name, srv_obj.comment)
            if srv_objs.get(srv_obj.gid) is None:
                srv_objs[srv_obj.gid] = srv_obj

    def order_tables(self, obj_type):
        """
        Build ordered tables using child first order. XML response from CSM does NOT use child first order for network
        groups.

        :param obj_type: Object type, 'network' or 'service'
        """
        if obj_type not in ['network', 'service']:
            logging.error('Object type {} not supported'.format(obj_type))
        for gid, obj in self.obj_tables[obj_type].items():
            self.add_child_first(obj, obj_type)

    def add_child_first(self, obj, obj_type):
        net_objs = self.obj_tables[obj_type]
        if obj.refGIDs is not None:
            for child_gid in obj.refGIDs.gid:
                if self.ordered_tables[obj_type].get(child_gid) is None:
                    self.add_child_first(net_objs[child_gid])  # recursion for multi-level nesting

        if self.ordered_tables[obj_type].get(obj.gid) is None:
            self.ordered_tables[obj_type][obj.gid] = obj

    def print_rules(self, policy_obj):
        net_objs = self.obj_tables['network']
        srv_objs = self.obj_tables['service']
        for rule in policy_obj.policy.deviceAccessRuleUnifiedFirewallPolicy:
            for src_gid in rule.sources.networkObjectGIDs.gid:
                for dst_gid in rule.destinations.networkObjectGIDs.gid:
                    for srv_gid in rule.services.serviceObjectGIDs.gid:
                        s = u"{} {} {} {} {} {}".format(
                            rule.orderId,
                            rule.policyName,
                            rule.sectionName,
                            net_objs[src_gid].name,
                            net_objs[dst_gid].name,
                            srv_objs[srv_gid].name)
                        logging.info(s)

    def fmc_nw_objects(self, fmc):
        """
        Convert CSM network policy objects into dictionary objects for FMC network object creation.

        :param fmc: Firepower Management Center 6.1 API Object
        :return:
        """
        # Assume that object table is already updated and all are network object-groups
        net_objs = self.ordered_tables['network']
        for gid, net_obj in net_objs.items():  # child first order
            nwog_dict = {"name": net_obj.name,
                         "description": net_obj.comment.strip('\n'),
                         "overridable": True,
                         "type": "NetworkGroup"}  # Create everything as Network Group

            if net_obj.ipData is not None:
                for subnet_cidr in net_obj.ipData:  # Works for network policy objects having ipData
                    if nwog_dict.get("literals") is None:
                        nwog_dict["literals"] = []

                    ip_nw = IPNetwork(subnet_cidr)
                    if ip_nw.netmask == IPAddress('255.255.255.255'):  # subnet_cidr is Host
                        d = {"type": "Host",
                             "value": subnet_cidr.split('/')[0]}
                        nwog_dict["literals"].append(d)
                    else:  # subnet_cidr is a Network
                        d = {"type": "Network",
                             "value": str(ip_nw)}
                        nwog_dict["literals"].append(d)

            if net_obj.refGIDs is not None:
                for child_gid in net_obj.refGIDs.gid:  # Works for network policy objects having ipData
                    if nwog_dict.get("objects") is None:
                        nwog_dict["objects"] = []

                    child_name = net_objs[child_gid].name                                 # CSM GID --> OG Name
                    child_fmc_id = fmc.obj_tables['networkgroups'].names.get(child_name)  # OG Name --> FMC OID
                    d = {"id": child_fmc_id,
                         "name": child_name,
                         "type": "NetworkGroup",
                         "overridable": True}
                    nwog_dict["objects"].append(d)

            yield nwog_dict  # this must be child first order
