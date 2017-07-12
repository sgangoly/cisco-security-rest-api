import fmc # Firepower Management Center (FMC) 6.1 API
import sys
import logging
import csv
# from collections import OrderedDict

logger = logging.getLogger(__name__)

def main():

    logging.basicConfig(
        # filename='/path/to/python-fmc/output.txt',
        stream=sys.stdout,
        level=logging.INFO,  # DEBUG, INFO, WARNING, ERROR, CRITICAL
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

    with fmc.FMC(url=server_url, username=username, password=password) as lab_fmc:
        # Build the object names dictionary for the FMC
        for obj_type in lab_fmc.NETWORK_OBJECT_TYPES:
            # ['hosts', 'networks', 'ranges', 'networkgroups']
            lab_fmc.obj_tables[obj_type].build()

        for key, item in nwog_dicts.items():
            # Create Objects
            logging.info("Creating object-group {}".format(key))
            obj_nw_group = fmc.FPObject(lab_fmc, type='networkgroups', data=item)
            # # Delete Objects
            # if key in lab_fmc.obj_tables['networkgroups'].names.keys():
            #     obj_nw_group = fmc.FPObject(lab_fmc, type='networkgroups', name=key)
            #     logging.info("Deleting object-group {}".format(key))
            #     obj_nw_group.delete()
            # else:
            #     print "Object Group {} NOT Found".format(key)

    # End of with block
    print "Done running..."
    return

# Standard boilerplate to call main() function.
if __name__ == "__main__":
    main()
