import fmc # Firepower Management Center (FMC) 6.1 API
import sys
from collections import OrderedDict
import logging

logger = logging.getLogger(__name__)

def main():
    """
    Use this script for testing object API.
    """
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

    with fmc.FMC(url=server_url, username=username, password=password) as lab_fmc:
        # Build the object names dictionary for the FMC
        for obj_type in lab_fmc.NETWORK_OBJECT_TYPES:
            # ['hosts', 'networks', 'ranges', 'networkgroups']
            lab_fmc.obj_tables[obj_type].build()

        for obj in lab_fmc.obj_tables['networkgroups']:  # Current list of objects in FMC
            print(obj.name)

        test_host = {
            "description": "Testing Python API | Chetan",
            "name": "TEST.HOST.OBJECT",
            "overridable": True,
            "type": "Host",
            "value": "8.8.8.8"
            }
        
        test_range = {
            "description": "Testing Python API | Chetan",
            "name": "TEST.RANGE.OBJECT",
            "overridable": True,
            "type": "Range",
            "value": "8.8.8.8-8.8.8.10"
            }
        
        test_nw = {
            "description": "Testing Python API | Chetan",
            "name": "TEST.NETWORK.OBJECT",
            "overridable": True,
            "type": "Network",
            "value": "8.8.8.0/24"
            }
        
        test_ch_group = OrderedDict([
            ("description", "Testing Python API | Chetan"),
            ("name", "TEST.CHGROUP.OBJECT"),
            ("overridable", True),
            ("type", "NetworkGroup"),
            ("literals", [OrderedDict([
                    ("type", "Network"),
                    ("value", "8.8.8.0/24")
                    ])]
                )
            ])

        test_nw_group = {
            "description": "Testing Python API | Chetan",
            "name": "TEST.GROUP.OBJECT",
            "overridable": True,
            "type": "NetworkGroup"
            }
    
        # Create Objects
        logging.info("CREATING OBJECTS")
        obj_host = fmc.FPObject(lab_fmc, data=test_host)
        obj_range = fmc.FPObject(lab_fmc, data=test_range)
        obj_nw = fmc.FPObject(lab_fmc, data=test_nw)
        obj_ch_group = fmc.FPObject(lab_fmc, data=test_ch_group)
        # Create Group object with no children and overridable = True
        obj_nw_group = fmc.FPObject(lab_fmc, data=test_nw_group)

        logging.info('Child method: Add child object to Parent')
        obj_ch_group.add_to_parent('TEST.GROUP.OBJECT')

        logging.info('Child method: Add child object to Parent')
        obj_host.add_to_parent('TEST.GROUP.OBJECT')
    
        logging.info('Parent method: Add multiple children objects to Parent')
        obj_nw_group.add_children('TEST.RANGE.OBJECT', 'TEST.NETWORK.OBJECT')
    
        logging.info('Rename Object')
        obj_range.rename('TEST.RENAME.OBJECT')
    
        logging.info('Child method: Remove child object from Parent')
        obj_nw.remove_from_parent('TEST.GROUP.OBJECT')
    
        logging.info('Parent method: Remove child object')
        obj_nw_group.remove_child('TEST.RENAME.OBJECT')
    
        logging.info('Test script clean up')
        obj_nw.delete()
        obj_nw_group.delete()
        obj_range.delete()
        obj_host.delete()
        obj_ch_group.delete()
    # End of with block

    print("Done running...")
    return


# Standard boilerplate to call main() function.
if __name__ == "__main__":
    main()
