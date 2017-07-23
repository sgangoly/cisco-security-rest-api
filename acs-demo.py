import acs  # Cisco Secure Access Control Server (ACS) 5.8
import sys
import logging

logger = logging.getLogger(__name__)

def main():
    """
    Demo script for ACS REST API.
    """
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
    server_url = 'https://acs.example.com'
    if len(sys.argv) > 3:
        server_url = sys.argv[3]

    lab_acs = acs.ACS(server_url, username, password)
    lab_acs.getNetworkDeviceById('1750')
    lab_acs.getNetworkDeviceByName('TEST-WLC')

    return    

# Standard boilerplate to call main() function.
if __name__ == "__main__":
    main()
