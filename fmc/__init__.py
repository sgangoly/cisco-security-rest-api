"""Python module for interacting with Cisco Firepower Management Center (FMC).

Firepower Management Center API
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
This module is based on FMC 6.1 REST API specification.
"""

from .api import FMC
from .api import FPObject
from .api import FPObjectTable
from .api import FPPolicyTable
from .api import FPDeviceTable

__author__ = "Chetankumar Phulpagare"
__copyright__ = "Copyright 2017, Cisco"
__credits__ = ["Chetankumar Phulpagare"]
__email__ = "cphulpag@cisco.com"
