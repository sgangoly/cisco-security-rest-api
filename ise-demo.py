import ise
import sys
import logging

logger = logging.getLogger(__name__)

def main():
    logging.basicConfig(
        stream=sys.stdout,  # filename='/full/path/to/file',
        level=logging.DEBUG, # DEBUG, INFO, WARNING, ERROR, CRITICAL
        format='[%(asctime)s-%(levelname)s]: %(message)s',
        datefmt='%m/%d/%Y %I:%M:%S %p')

    # Get server, username and password from CLI
    username = 'username'
    if len(sys.argv) > 1:
        username = sys.argv[1]
    password = 'password'
    if len(sys.argv) > 2:
        password = sys.argv[2]
    server_url = 'https://ise.example.com:9060'
    if len(sys.argv) > 3:
        server_url = sys.argv[3]

    with ise.ISE(server_url, username, password) as lab_ise:
        lab_ise.getAllEndpoints()  # filter='?filter=mac.EQ.11:11:11:11:11:12'
        lab_ise.getAllEndpoints(filter='?filter=groupId.EQ.a4a97d40-b4cb-11e5-8ffd-005056903ad0')
        lab_ise.getEndpointById('719854a0-e26d-11e6-b433-005056926a52')
        lab_ise.getAllEndpointIdGroups(filter='?filter=name.EQ.TEST-GROUP')
        lab_ise.getEndpointIdGroupById('a4a97d40-b4cb-11e5-8ffd-005056903ad0')

    return    

# Standard boilerplate to call main() function.
if __name__ == "__main__":
    main()
