import fmc  # Firepower Management Center (FMC) 6.1 API
import sys
import logging

logger = logging.getLogger(__name__)


def main():
    """
    Use this script to delete all network and service objects that are not defaults.
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

    DEFAULT_OBJECTS = {}
    DEFAULT_OBJECTS['ranges'] = []
    DEFAULT_OBJECTS['hosts'] = ['any-ipv6']
    DEFAULT_OBJECTS['networkgroups'] = ['IPv4-Private-All-RFC1918']
    DEFAULT_OBJECTS['networks'] = [
        "any",
        "any-ipv4",
        "IPv4-Benchmark-Tests",
        "IPv4-Link-Local",
        "IPv4-Multicast",
        "IPv4-Private-10.0.0.0-8",
        "IPv4-Private-172.16.0.0-12",
        "IPv4-Private-192.168.0.0-16",
        "IPv6-IPv4-Mapped",
        "IPv6-Link-Local",
        "IPv6-Private-Unique-Local-Addresses",
        "IPv6-to-IPv4-Relay-Anycast"
    ]
    DEFAULT_OBJECTS['portobjectgroups'] = []
    DEFAULT_OBJECTS['protocolportobjects'] = [
        'AOL', 'Bittorrent', 'DNS_over_TCP', 'DNS_over_UDP',
        'FTP', 'HTTP', 'HTTPS', 'IMAP', 'LDAP',
        'NFSD-TCP', 'NFSD-UDP', 'NTP-TCP', 'NTP-UDP',
        'POP-2', 'POP-3', 'RADIUS', 'RIP', 'SIP',
        'SMTP', 'SMTPS', 'SNMP', 'SSH', 'SYSLOG',
        'TCP_high_ports', 'TELNET', 'TFTP',
        'Yahoo_Messenger_Messages',
        'YahooMessenger_Voice_Chat_TCP',
        'YahooMessenger_Voice_Chat_UDP'
    ]
    DEFAULT_OBJECTS['icmpv4objects'] = []
    DEFAULT_OBJECTS['icmpv6objects'] = []

    with fmc.FMC(url=server_url, username=username, password=password) as lab_fmc:
        # Build the object names dictionary for the FMC
        for obj_type in [
                'networkgroups', 'hosts', 'networks', 'ranges',
                'portobjectgroups', 'protocolportobjects', 'icmpv6objects'
        ]:  # Groups first order
            lab_fmc.obj_tables[obj_type].build()  # List of objects with child first order
            names_dict = lab_fmc.obj_tables[obj_type].names
            for obj_name, obj_id in names_dict.items()[::-1]:  # Delete with parents first order
                if obj_name in DEFAULT_OBJECTS[obj_type]:
                    continue
                else:
                    # obj_id = names_dict[obj_name]
                    fp_obj = fmc.FPObject(lab_fmc, type=obj_type, oid=obj_id)
                    fp_obj.delete()
    # End of with block
    print("Done running...")
    return


# Standard boilerplate to call main() function.
if __name__ == "__main__":
    main()
