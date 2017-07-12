import fmc
import sys
import logging

logger = logging.getLogger(__name__)

def main():

    logging.basicConfig(
        # filename='/path/to/python-fmc/output.txt',
        stream=sys.stderr, 
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
    server_from = 'https://fmc1.example.com'
    if len(sys.argv) > 3:
        server_from = sys.argv[3]
    server_to = 'https://fmc2.example.com'
    if len(sys.argv) > 4:
        server_to = sys.argv[4]

    obj_types = [
        'hosts', 'networks', 'ranges',  # Network
        'networkgroups',                # Network
        'vlantags', 'vlangrouptags',    # VLAN Tag
        'urls', 'urlgroups',            # URL
        'protocolportobjects',          # Service
        # 'icmpv4objects',              # DEFECT: ICMPv4Objects is not working
        'icmpv6objects',                # Service
        'portobjectgroups',             # Service
        ]

    # Port DEFECT: ICMPv4Objects is not working
    # There is incomplete JSON response when individual IPMPv4Object is requested via GET
    # There is incomplete JSON response when all IPMPv4Objects are requested via GET with 'expanded=true'

    with fmc.FMC(url=server_from, username=username, password=password) as fmc_old:
        with fmc.FMC(url=server_to, username=username, password=password) as fmc_new:
            for obj_type in obj_types:
                # Build the names dictionary for new FMC
                fmc_old.obj_tables[obj_type].build()  # child first order
                fmc_new.obj_tables[obj_type].build()  # child first order
                names_dict = fmc_old.obj_tables[obj_type].names
                # Migrate objects from old FMC VM to new FMC VM
                for obj_name, obj_id in names_dict.items():
                    print "{}: old_id {}".format(obj_name, obj_id)
                    obj_old = fmc.FPObject(fmc_old, type=obj_type, oid=obj_id)
                    obj_new = fmc.FPObject(fmc_new, obj=obj_old)
                    print "{}: new_id {}".format(obj_new.name, obj_new.id)

    print "Done running..."
    
# Standard boilerplate to call main() function.
if __name__ == "__main__":
    main()
