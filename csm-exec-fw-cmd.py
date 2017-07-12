import sys
import logging
import csm

logger = logging.getLogger(__name__)

def main():
    logging.basicConfig(
        stream=sys.stdout,
        # filename='csm_output.log',
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
        lab_csm.exec_fw_cmd('show clock')

    return    

# Standard boilerplate to call main() function.
if __name__ == "__main__":
    main()

