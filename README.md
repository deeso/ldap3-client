# ldap3-client


The LDAP client is a Python3 library that provides programatic access to LDAP services.  In general, this  
library uses `ldap3` to connect to the enterprise LDAP service.  The library enables LDAP look ups and
user authentication.


the web site endpoints to make requests.  Parameters are submitted as form data, query parameters, or 
multipart forms, which is dicated based on observed manual interactions.  The results returned by the library can be the
HTML or a JSON result derived by parsing the HTML.

## Setup and Installation

Currently, this code runs on Ubuntu Linux 18.04 and requires Python 3.6+.

### Cloning and using the utilities
```bash

# install dependencies
sudo apt-get install -y python3-venv git

# disable SSL verification, generally insecure
git config --global http.sslVerify false

# setting up runtime environment
python3 -m venv ldap3_client

git clone https://github.com/deeso/ldap3-client
source bin/activate
pip3 install ipython
cd ldap3-client
python3 setup.py install

```

### Installation with no utilities
```bash

# install dependencies
sudo apt-get install -y python3-venv git

# disable SSL verification, generally insecure
git config --global http.sslVerify false

# setting up runtime environment
python3 -m venv ldap3_client
cd ldap3_client/bin

pip3 install git+https://github.com/deeso/ldap3-client

```

## Configuration

There are two sample configurations included in the project directory:
  * `ldap-client-config.toml`: example config for the client
  
  
### Configuration stanzas, keys, and values

#### Configuring server components `ldap-client` (a.k.a. `HOST_BLOCK`)
* `ldap_host`: host to contact for LDAP, default: 'ldap.example.com'
* `ldap_port`: port to contact for LDAP, default:  636
* `bind_user`: user to authenticate as e.g. `'CN=deeso,OU=Employees,OU=Example Users,DC=example,DC=com'`
* `bind_password`: password to use for authentication
* `default_search_base`: default base search for LDAP queries `'dc=example,dc=com'`
* `base_dn`: base distinguished name for queries `'OU=Employees,OU=Example Users,DC=example,DC=com'`
* `validate_ssl`: validate SSL (requires certs in the path to validated by Python) default `false`


## Using the Library

There is one demonstrative script included in this repo.  These utilities include:
1. ``ldap_query.py``: a script that can be used to query email, username, and employee ID from the CLI attributes 
returned can also be specified

Here are some other examples.

* Checking if user is part of a group
```python
from ldap3_client.config import Config
from ldap3_client.ldap import LdapClient
from ldap3_client.consts import *

# note the config needs valid service or user creds to perform lookups
config = 'ldap-client-config.toml'
Config.parse_config(config)

groups = [
        "CN=Group1,OU=Standard,OU=Example Groups,DC=example,DC=com",
        "CN=Group2,OU=Standard,OU=Example Groups,DC=example,DC=com",
        "CN=Group3,OU=Standard,OU=Example Groups,DC=example,DC=com",
    ]

if LdapClient.from_config().user_in_groups('deeso', groups):
    print("Of course i get to hang with cool kids!")
    
results = LdapClient.from_config().users_in_groups(['deeso', 'adam'], groups)
print (results)

```

* Authenticate user
```python
from ldap3_client.config import Config
from ldap3_client.ldap import LdapClient
from ldap3_client.consts import *
from getpass import getpass

# note the config needs valid service or user creds to perform lookups
config = 'ldap-client-config.toml'
Config.parse_config(config)

if not LdapClient.from_config().authenticate('deeso', 'changeme!'):
    print ("weak sauce passwords not welcome")

password = getpass()

if not LdapClient.from_config().authenticate('deeso', password):
    print ("oops bad password")
else:
    print ("Successful authentication")

```



## Background and assumptions

### Code Structure

The library uses the following conventions:
* All LDAP activities happen in `ldap.py`
