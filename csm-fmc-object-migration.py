import sys
import logging
import csm  # Cisco Security Manager (CSM) 4.12 API
import fmc  # Firepower Management Center (FMC) 6.1 API

logger = logging.getLogger(__name__)


def migrate_network_objects(csm_obj, fmc_obj, action='CREATE'):
    """
    Read network policy objects used in firewall rules from CSM and create them in FMC.

    :param csm_obj: CSM class object
    :param fmc_obj: FMC class
    :param action: Create objects or delete objects
    """
    policy_type = 'DeviceAccessRuleUnifiedFirewallPolicy'
    policy_list = csm_obj.getSharedPolicyListByType(policy_type)
    for po in policy_list.policy:
        # if not (po.policyName.startswith('.') or po.policyName.endswith('QUARANTINE')):
        #     print(po.policyName)
        if 'BC-OOB' in po.policyName:
            for policy_obj in csm_obj.getPolicyConfigByName(po.policyName, policy_type):
                # csm_obj.write_file(policy_obj, 'bc-oob.xml')
                csm_obj.print_rules(policy_obj)

            csm_obj.order_tables(obj_type='network')  # Child first order

            if action is 'CREATE':
                for nwog_data in csm_obj.fmc_nw_objects(fmc_obj):
                    print(nwog_data)
                    logging.info("Creating Network Group Object {}".format(nwog_data['name']))
                    obj_nw_group = fmc.FPObject(fmc_obj, type='networkgroups', data=nwog_data)
            elif action is 'DELETE':  # This helps in testing the script multiple times
                net_objs = csm_obj.ordered_tables['network']
                fmc_names_dict = fmc_obj.obj_tables['networkgroups'].names
                for gid, net_obj in net_objs.items()[::-1]:  # Delete with parents first order
                    nwog_name = net_obj.name
                    if nwog_name in fmc_names_dict.keys():
                        obj_nw_group = fmc.FPObject(fmc_obj, type='networkgroups', name=nwog_name)
                        logging.info("Deleting Network Group Object {}".format(nwog_name))
                        obj_nw_group.delete()
                    else:
                        print "Object Group {} NOT Found".format(nwog_name)


def main():
    logging.basicConfig(
        stream=sys.stdout,
        # filename='csm_policy_output.log',
        level=logging.INFO,  # INFO, INFO, WARNING, ERROR, CRITICAL
        format='[%(asctime)s-%(levelname)s]: %(message)s',
        datefmt='%m/%d/%Y %I:%M:%S %p',
        encoding="UTF-8")

    # Get server, username and password from CLI
    csm_user = 'username'
    if len(sys.argv) > 1:
        csm_user = sys.argv[1]
    csm_pswd = 'password'
    if len(sys.argv) > 2:
        csm_pswd = sys.argv[2]
    csm_url = 'https://csm.example.com'
    if len(sys.argv) > 3:
        csm_url = sys.argv[3]

    fmc_user = 'username'
    if len(sys.argv) > 4:
        fmc_user = sys.argv[4]
    fmc_pswd = 'password'
    if len(sys.argv) > 5:
        fmc_pswd = sys.argv[5]
    fmc_url = 'https://fmc.example.com'
    if len(sys.argv) > 6:
        fmc_url = sys.argv[6]

    with csm.CSM(csm_url, csm_user, csm_pswd) as lab_csm:
        lab_csm.getServiceInfo()  # Validate communication with CSM
        with fmc.FMC(fmc_url, fmc_user, fmc_pswd) as lab_fmc:
            for obj_type in lab_fmc.NETWORK_OBJECT_TYPES:
                # ['hosts', 'networks', 'ranges', 'networkgroups']
                lab_fmc.obj_tables[obj_type].build()

            migrate_network_objects(lab_csm, lab_fmc, action='CREATE')

    return    

# Standard boilerplate to call main() function.
if __name__ == "__main__":
    main()
