from ldap3_client.config import Config
from ldap3_client.ldap import LdapClient
from ldap3_client.consts import *

import json
from getpass import getpass
import argparse
import sys


CMD_DESC = 'query ldap server via interface.'
parser = argparse.ArgumentParser(description=CMD_DESC)
parser.add_argument('-config', type=str, default=None,
                    help='config file containing client information')

parser.add_argument('-employeeID', type=str, default=None,
                    help='employee ID to query')

parser.add_argument('-username', type=str, default=None,
                    help='username to query')

parser.add_argument('-email', type=str, default=None,
                    help='email to query')

parser.add_argument('-attrs', nargs='+', default=['manager', 'mail', 'displayName', 'employeeID'],
                    help='attributes to query')

parser.add_argument('-auth_user', type=str, default=None,
                    help='username to authenticate')

parser.add_argument('-auth_password', type=str, default=None,
                    help='password to authenticate with')


if __name__ == '__main__':
    args = parser.parse_args()

    attrs = args.attrs

    if args.config is None:
        print ('config file is required')
        sys.exit(1)

    if args.employeeID is None and \
        args.username is None and \
        args.email is None and \
        args.auth_user is None:
        print ('provide one of the following parameters: emmployeeID, username, email, auth_user')
        sys.exit(1)

    Config.parse_config(args.config)

    if args.auth_user is not None:
        password = args.auth_password
        if password is None:
            password = getpass("Enter the password to authenticate the users: ")

        result = LdapClient.from_config().authenticate(args.auth_user, password)
        if result:
            print ("Authentication success: %s"%args.auth_user)
        else:
            print("Authentication failed: %s" % args.auth_user)

        sys.exit(0)

    results = {}
    if args.employeeID is not None:
        results = LdapClient.from_config().search_employeeid(args.employeeID, attributes=attrs)
    elif args.username is not None:
        results = LdapClient.from_config().search_user(args.username, attributes=attrs)
    elif args.email is not None:
        results = LdapClient.from_config().search_email(args.email, attributes=attrs)
    print(json.dumps(results, indent=4, sort_keys=True))


