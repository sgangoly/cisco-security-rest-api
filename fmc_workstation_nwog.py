import fmc  # Firepower Management Center (FMC) 6.1 API
import sys
import logging
import csv
# from collections import OrderedDict

logger = logging.getLogger(__name__)

def main():
    """
    Create network objects in FMC as per information in CSV file.
    """
    logging.basicConfig(
        # filename='/path/to/python-fmc/output.txt',
        stream=sys.stdout,
        level=logging.DEBUG,  # DEBUG, INFO, WARNING, ERROR, CRITICAL
        # format="[%(levelname)8s]:  %(message)s",
        format='[%(asctime)s-%(levelname)s]: %(message)s',
        datefmt='%m/%d/%Y %I:%M:%S %p')

    # Get server, username and password from CLI
    username = 'username'
    if len(sys.argv) > 1:
        username = sys.argv[1]
    password = 'password'
    if len(sys.argv) > 2:
        password = sys.argv[2]
    server_url = 'https://fmc.example.com'
    if len(sys.argv) > 3:
        server_url = sys.argv[3]

    # Read CSV file and create JSON data to be POST'd to FMC
    # "subnet_cidr", "subnet_nwog"
    # "192.168.10.0/23", "TEST.NETWORK-GROUP_1"
    # "192.168.0.0/23", "TEST.NETWORK-GROUP_1"
    # "10.10.10.0/28", "TEST.NETWORK-GROUP_2"
    # "10.48.0.0/20", "TEST.NETWORK-GROUP_3"
    # "192.168.64.0/20", "TEST.NETWORK-GROUP_1"

    nwog_dicts = {}
    with open('workstation_subnets.csv') as csvfile:
        reader = csv.DictReader(csvfile)
        for row in reader:
            subnet_nwog = row['subnet_nwog']
            # If we have not seen this key before, create a new dictionary for it
            if subnet_nwog not in nwog_dicts.keys():
                nwog_dicts[subnet_nwog] = {"name": subnet_nwog,
                                            "overridable": True,
                                            "type": "NetworkGroup",
                                            "literals": []}

            d = {"type": "Network", "value": row['subnet_cidr']}
            nwog_dicts[subnet_nwog]["literals"].append(d)

    action = 'DELETE'  # or 'DELETE'
    with fmc.FMC(url=server_url, username=username, password=password) as lab_fmc:
        # Build the object names dictionary for the FMC
        # This is required for data validation before making changes in FMC.
        for obj_type in lab_fmc.NETWORK_OBJECT_TYPES:
            # ['hosts', 'networks', 'ranges', 'networkgroups']
            lab_fmc.obj_tables[obj_type].build()

        for nwog_name, nwog_data in nwog_dicts.items():
            if action is 'CREATE':
                logging.info("Creating object-group {}".format(nwog_name))
                obj_nw_group = fmc.FPObject(lab_fmc, type='networkgroups', data=nwog_data)
            elif action is 'DELETE':  # This helps in testing the script multiple times
                if nwog_name in lab_fmc.obj_tables['networkgroups'].names.keys():
                    obj_nw_group = fmc.FPObject(lab_fmc, type='networkgroups', name=nwog_name)
                    logging.info("Deleting object-group {}".format(nwog_name))
                    obj_nw_group.delete()
                else:
                    print "Object Group {} NOT Found".format(nwog_name)

    # End of with block
    print("Done running...")
    return

# Standard boilerplate to call main() function.
if __name__ == "__main__":
    main()
