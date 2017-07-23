# Cisco Security REST API

This is a collection of modules that interact with REST API available in Cisco Security applications:
* Cisco Identity Services Engine (ISE) 2.1
* Cisco Security Manager (CSM) 4.12
* Cisco Firepower Management Center (FMC) 6.1
* Cisco Secure Access Control Server (ACS) 5.8

## Example Scripts:
* `acs-demo.py`: Demo script for ACS REST API
* `csm-exec-fw-cmd.py`: Send read-only commands to all firewalls managed by CSM.
* `csm-fmc-object-migration.py`: Read network policy objects used in firewall rules from CSM and create them in FMC.
* `csm-shared-fw-rules.py`: Read shared firewall access rules policies from CSM.
* `fmc_delete_networkgroups.py`: Delete all non-default network objects from FMC. This is useful for API testing.
* `fmc_migrate_objects.py`: Migrate policy objects from one FMC to another. This is useful when FMC needs to be re-imaged.
* `fmc_test_objects-networks.py`: Test FMC Object Manager API
* `fmc_workstation_nwog.py`: Create network objects in FMC as per information in CSV file.
* `ise-demo.py`: Demo script for ISE REST API

## Requires
* Python 2.7.x
* requests
* lxml (required for ISE and ACS)
* pyxb (required for CSM)
* netaddr (Used in CSM to FMC network object migration)

