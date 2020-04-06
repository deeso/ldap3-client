from threading import Thread
from datetime import datetime, timedelta
from .config import Config
from .consts import *
from .cache import CacheSystem, CacheEntry
from ldap3 import Server, Connection, Tls
import ssl
import json


PERSISTENT_CONNECTION = None
PERSISTENT_CACHE = CacheSystem()

THREADS = []


class LdapPersistentConnection(object):

    MINUTES_REBIND_TIMEOUT = 10

    def __init__(self, ldap_host, ldap_port, bind_user, bind_password, validate_ssl):
        self.ldap_host = ldap_host
        self.ldap_port = ldap_port
        self.bind_user = bind_user
        self.bind_password = bind_password
        self.validate_ssl = validate_ssl
        self.conn = None
        self.created = datetime.utcnow()
        self.expired = datetime.utcnow() + timedelta(minutes=self.MINUTES_REBIND_TIMEOUT)
        self.rebind()

    def get_server(self):
        tls = Tls(validate=ssl.CERT_OPTIONAL)
        if not self.validate_ssl:
            tls = Tls(validate=ssl.CERT_NONE)
        return Server(self.ldap_host, port=self.ldap_port, use_ssl=True, tls=tls)

    def get_conn(self):
        return self.conn

    def create_connection(self):
        bind_user = self.bind_user
        bind_password = self.bind_password
        bind_anon = False
        if bind_password is None or bind_user is None:
            bind_anon = True
        server = self.get_server()
        if bind_anon:
            return Connection(server, auto_bind=True)
        return Connection(server, auto_bind=True, user=bind_user, password=bind_password)

    def rebind(self):
        global PERSISTENT_CONNECTION
        if self.conn is None:
            self.conn = self.create_connection()
            self.expired = datetime.utcnow() + timedelta(minutes=self.MINUTES_REBIND_TIMEOUT)
            PERSISTENT_CONNECTION = self
        elif self.is_expired():
            self.conn = self.create_connection()
            self.expired = datetime.utcnow() + timedelta(minutes=self.MINUTES_REBIND_TIMEOUT)

        return self.conn

    def is_expired(self):
        now = datetime.utcnow()
        return self.expired < now

    @classmethod
    def get_connection(cls):
        global PERSISTENT_CONNECTION
        if PERSISTENT_CONNECTION is not None and PERSISTENT_CONNECTION.is_expired():
            PERSISTENT_CONNECTION.rebind()
        elif PERSISTENT_CONNECTION is not None:
            return PERSISTENT_CONNECTION.get_conn()
        return None

    @classmethod
    def build_persistent_connection(cls, ldap_host, ldap_port, bind_user, bind_password,
                                    validate_ssl, set_connection=True):
        global PERSISTENT_CONNECTION
        lpc = LdapPersistentConnection(ldap_host, ldap_port, bind_user, bind_password, validate_ssl)
        if set_connection:
            PERSISTENT_CONNECTION = lpc
            return PERSISTENT_CONNECTION.get_conn()
        return lpc.get_conn()

    @classmethod
    def build_persistent_connection_from_client(cls, ldc, set_connection=True):
        global PERSISTENT_CONNECTION
        return cls.build_persistent_connection(ldc.get_ldap_host(),
                                               ldc.get_ldap_port(),
                                               ldc.get_bind_user(),
                                               ldc.get_bind_password(),
                                               ldc.get_validate_ssl(),
                                               set_connection=set_connection)


class LdapClient(object):
    MINUTES_EXPIRATION_POLICY = 10
    NAME = LDAP_CLIENT_BLOCK
    DEFAULT_VALUES = {
        LDAP_HOST: '127.0.0.1',
        LDAP_PORT: 636,
        BIND_USER: None,
        BIND_PASSWORD: None,
        DEFAULT_SEARCH_BASE: None,
        BASE_DN: None,
        VALIDATE_SSL: False,
    }

    def __init__(self, **kwargs):
        self.auto_bind = False
        for k, v in self.DEFAULT_VALUES.items():
            if k not in kwargs:
                setattr(self, k, v)
            else:
                setattr(self, k, kwargs.get(k))

        self.search_base = self.default_search_base


    def get_bind_user(self):
        return getattr(self, BIND_USER)

    def get_bind_password(self):
        return getattr(self, BIND_PASSWORD)

    def get_ldap_host(self):
        return getattr(self, LDAP_HOST)

    def get_ldap_port(self):
        return getattr(self, LDAP_PORT)

    def get_validate_ssl(self):
        return getattr(self, VALIDATE_SSL, False)

    def get_server(self):
        tls = Tls(validate=ssl.CERT_OPTIONAL)
        if not self.validate_ssl:
            tls = Tls(validate=ssl.CERT_NONE)
        return Server(self.ldap_host, port=self.ldap_port, use_ssl=True, tls=tls)

    def get_connection(self, bind_user=None, bind_password=None):
        global THREADS
        THREADS = [i for i in THREADS if i.is_alive()]
        if bind_user is None and bind_password is None:
            connection = LdapPersistentConnection.get_connection()
            if connection is None:
                connection = LdapPersistentConnection.build_persistent_connection_from_client(self)
            if connection is not None:
                return connection

        bind_user = self.bind_user if bind_user is None else bind_user
        bind_password = self.bind_password if bind_password is None else bind_password
        bind_anon = False
        if bind_password is None or bind_user is None:
            bind_anon = True
        server = self.get_server()
        if bind_anon:
            return Connection(server, auto_bind=True)
        return Connection(server, auto_bind=True, user=bind_user, password=bind_password)

    def search(self, search_filter, search_base=None, attributes=[], connection=None):
        search_base = self.search_base if search_base is None else search_base
        connection = self.get_connection() if connection is None else connection
        jd = []
        if connection.search(search_base, search_filter=search_filter, attributes=attributes):
            jd = json.loads(connection.response_to_json()).get('entries', [])
        return jd

    def authenticate(self, username, password, base_dn=None):
        bdn = self.base_dn if base_dn is None else base_dn
        bind_user = "CN={}".format(username)
        if bdn is not None:
            bind_user = bind_user + ',' + bdn

        try:
            connection = self.get_connection(bind_user, password)
            post_auth_populate = Thread(target=perform_post_authentication, args=(username, self, connection))
            post_auth_populate.start()
            THREADS.append(post_auth_populate)
            return True
        except:
            return False

    def check_cache(self, username, attributes):
        if PERSISTENT_CACHE.has_username_attributes(username, attributes):
            return PERSISTENT_CACHE.get_username(username).get_fields(attributes)
        return None

    @classmethod
    def build_or_search_filter(cls, parameters):
        q = ['({})'.format(v) for v in parameters]
        return '(|{})'.format(''.join(q))

    def user_manager(self, username):
        return self.users_manager([username,])[0]

    def users_manager(self, userlist):
        results = {k: [] for k in userlist}
        username_entries = self.search_users(userlist, attributes=SUBJECT_ATTRIBUTES)
        for username, entries in username_entries.items():
            for entry in entries:
                if username is None:
                    continue
                if results[username]:
                    continue
                manager = set(entry.get(ATTRIBUTES, {}).get(MANAGER, ''))
                if len(manager) == '':
                    continue
                m = manager.split('CN=')[1].split(',')[0]
                results[username].append(m)
        return results

    def user_in_groups(self, username, group_list=[]):
        return self.users_in_groups([username, ], group_list)[username]

    def users_in_groups(self, userlist, group_list=[]):
        results = {k: False for k in userlist}
        if len(group_list) == 0:
            return results

        _group_list = set(group_list)

        username_entries = self.search_users(userlist, attributes='memberOf')
        for username, entries in username_entries.items():
            for entry in entries:
                if results[username]:
                    continue
                groups = set(entry.get('attributes', {}).get('memberOf', []))
                yes = len(groups & _group_list) > 0
                if yes:
                    results[username] = True
        return results

    def search_attr(self, item, attr, attributes=[]):
        return self.search_attrs([item], attr, attributes=attributes)

    def search_attrs(self, itemlist, attr, attributes=[]):
        results = {k: [] for k in itemlist}
        if isinstance(attributes, str):
            attributes = [attributes, attr]
        elif isinstance(attributes, list):
            attributes.append(attr)

        users_to_attr = {d: '{}={}'.format(attr, d) for d in itemlist}
        search_filter = self.build_or_search_filter(users_to_attr.values())
        entries = self.search(search_filter, self.search_base, attributes=attributes)
        if len(entries) == 0:
            return results

        for entry in entries:
            k = entry.get('attributes', {}).get(attr, None)
            if k is None:
                continue
            results[k].append(entry)
        return results

    def search_employeeid(self, employeeid, attributes=SUBJECT_ATTRIBUTES):
        return self.search_employeeids([employeeid,], attributes).get(employeeid, [])

    def search_employeeids(self, employeeidlist, attributes=SUBJECT_ATTRIBUTES):
        return self.search_attrs(employeeidlist, 'employeeID', attributes)

    def search_email(self, email, attributes='*'):
        return self.search_emails([email,], attributes).get(email, [])

    def search_emails(self, emaillist, attributes=SUBJECT_ATTRIBUTES):
        return self.search_attrs(emaillist, 'mail', attributes)

    def search_username(self, username, attributes=SUBJECT_ATTRIBUTES, connection=None, ignore_cache=False):
        return self.search_user(username,
                                attributes=attributes,
                                connection=connection,
                                ignore_cache=ignore_cache).get(username, [])

    def search_user(self, username, attributes=SUBJECT_ATTRIBUTES, connection=None, ignore_cache=False):
        if not ignore_cache:
            result = self.check_cache(username, attributes)
            if result is not None:
                return {username:[result]}

        search_filter = self.build_or_search_filter(['CN={}'.format(username)])
        entries = self.search(search_filter, self.search_base, attributes=attributes, connection=connection)
        attributes = None
        dn =  None
        for entry in entries:
            dn = entry['dn']
            if dn.lower().find(self.search_base) == -1:
                continue
            attributes = entry[ATTRIBUTES]
            break

        if attributes is not None:
            fields = {ATTRIBUTES:attributes, 'dn':dn}
            ce = CacheEntry(username, fields=fields, mail=attributes.get(MAIL))
            PERSISTENT_CACHE.add_entry(ce)
            return {username:[fields]}
        return {username:[]}

    def search_users(self, userlist, attributes=SUBJECT_ATTRIBUTES, connection=None, ignore_cache=False):
        results = {}
        for username in userlist:
            result = self.search_username(username, attributes, connection=connection, ignore_cache=ignore_cache)
            if len(result) == 0:
                continue
            results[username] = result
            # results.update(result)
        return results

    @classmethod
    def from_config(cls):
        cfg = Config.get_value(cls.NAME)
        kwargs = {}
        for k, v in cls.DEFAULT_VALUES.items():
            if k not in cfg:
                kwargs[k] = v
            else:
                kwargs[k] = cfg.get(k)
        return cls(**kwargs)

def perform_post_authentication(username, ldap_client: LdapClient, connection):
    global THREADS
    results = ldap_client.search_username(username, SUBJECT_ATTRIBUTES, connection=connection)
    attributes = results[0].get(ATTRIBUTES, {})
    mgr = attributes.get(MANAGER, 'CN=,')
    if isinstance(mgr, str):
        mgr_username = mgr.split('CN=', )[1].split(',')[0]
        results = ldap_client.search_username(mgr_username, SUBJECT_ATTRIBUTES, connection=connection)
    elif isinstance(mgr, list):
        for _mgr in mgr:
            mgr_username = _mgr.split('CN=', )[1].split(',')[0]
            results = ldap_client.search_username(mgr_username, SUBJECT_ATTRIBUTES, connection=connection)
    connection.unbind()
