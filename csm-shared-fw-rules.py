import sys
import logging
import csm

logger = logging.getLogger(__name__)

def get_all_access_rules(csm_obj):
    policy_type = 'DeviceAccessRuleUnifiedFirewallPolicy'
    policy_list = csm_obj.getSharedPolicyListByType(policy_type)
    for po in policy_list.policy:
        if not (po.policyName.startswith('.') or po.policyName.endswith('QUARANTINE')):
            print(po.policyName)
            if 'TEST' in po.policyName:
                for policy_obj in csm_obj.getPolicyConfigByName(po.policyName, policy_type):
                    csm_obj.print_rules(policy_obj)

def main():
    logging.basicConfig(
        stream=sys.stdout,
        # filename='csm_policy_output.log',
        level=logging.INFO,  # INFO, INFO, WARNING, ERROR, CRITICAL
        format='[%(asctime)s-%(levelname)s]: %(message)s',
        datefmt='%m/%d/%Y %I:%M:%S %p',
        encoding="UTF-8")

    # Get server, username and password from CLI
    username = 'username'
    if len(sys.argv) > 1:
        username = sys.argv[1]
    password = 'password'
    if len(sys.argv) > 2:
        password = sys.argv[2]
    server_url = 'https://csm.example.com'
    if len(sys.argv) > 3:
        server_url = sys.argv[3]

    with csm.CSM(server_url, username, password) as lab_csm:
        lab_csm.getServiceInfo()
        get_all_access_rules(lab_csm)

    return    

# Standard boilerplate to call main() function.
if __name__ == "__main__":
    main()
