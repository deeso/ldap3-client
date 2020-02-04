

AUTH_SERVICE = 'auth-service'
LDAP_CLIENT_BLOCK = 'ldap-client'

VALIDATE_SSL = 'validate_ssl'
LDAP_HOST = 'ldap_host'
LDAP_PORT = 'ldap_port'

LISTENING_HOST = 'listening_host'
LISTENING_PORT = 'listening_port'

BIND_USER = 'bind_user'
BIND_PASSWORD = 'bind_password'

# DEFAULT_DISTINGUISHED_NAME = 'default_dn'
BASE_DN = 'base_dn'
DEFAULT_SEARCH_BASE = 'default_search_base'
USE_MONGO = 'use_mongo'
AUTHENTICATE_ALL_REQUESTS = 'authenticate_all_requests'

LDAP_CLIENT_CONFIGS = [
    LDAP_HOST,
    LDAP_PORT,
    BIND_USER,
    BIND_PASSWORD,
    DEFAULT_SEARCH_BASE,
    VALIDATE_SSL,
    BASE_DN,
]

ADMIN_BLOCK = 'admin'
ADMIN_TOKENS = 'tokens'
ADMIN_USERS = 'users'
ADMIN_GROUPS = 'groups'

ADMIN_USERS_CONFIGS = [
    ADMIN_TOKENS,
    ADMIN_USERS,
    ADMIN_GROUPS
]

ACCESS_CONTROL_BLOCK = 'access-control'

MANAGED_BY = 'managed_by'
ACCESS_CONTROL_USERS = 'users'
ACCESS_CONTROL_TOKENS = 'tokens'
ACCESS_CONTROL_GROUPS = 'groups'

ACCESS_CONTROL_CONFIGS = [
    MANAGED_BY,
    ACCESS_CONTROL_USERS,
    ACCESS_CONTROL_TOKENS,
    ACCESS_CONTROL_GROUPS,
]

ALLOWED_TOKENS_BLOCK = 'allowed-tokens'
TOKEN_NAME = 'token_name'
TOKEN_VALUE = 'token_value'
TOKEN_DESCRIPTION = 'token_description'
TOKEN_USERNAME = 'token_username'
TOKEN_ACCOUNT_TYPE = 'token_account_type'
TOKEN_EMAIL = 'token_email'

ALLOWED_TOKENS = 'allowed_tokens'
TOKEN_CONFIGS = [
    TOKEN_NAME,
    TOKEN_VALUE,
    TOKEN_DESCRIPTION,
    TOKEN_USERNAME,
    TOKEN_ACCOUNT_TYPE,
    TOKEN_EMAIL
]

MONGO_SERVICE_BLOCK = 'mongo-service'
MONGO_HOST = 'mongo_host'
MONGO_PORT = 'mongo_port'
MONGO_DB = 'mongo_db'
MONGO_USERNAME = 'mongo_username'
MONGO_PASSWORD = 'mongo_password'

ACCESS_CONTROL = 'access_control'
ACCESS_CONTROL_COLLECTION = 'access_control_collection'
MANAGED_BY = 'managed_by_collection'
ACCESS_CONTROL_USERS = 'access_control_users'
ACCESS_CONTROL_GROUPS = 'access_control_groups'
ACCESS_CONTROL_TOKENS = 'access_control_tokens'

ADMINS = 'admins'
ADMIN_COLLECTION = 'admin_collection'
ADMIN_USERS = 'admin_users'
ADMIN_GROUPS = 'admin_groups'
ADMIN_TOKENS = 'admin_tokens'

ALLOWED_TOKENS_COLLECTION = 'allowed_tokens_collection'


MONGO_CONFIGS = [
    MONGO_HOST,
    MONGO_PORT,
    MONGO_DB,
    MONGO_PASSWORD,
    MONGO_USERNAME,
    ACCESS_CONTROL_COLLECTION,
    MANAGED_BY,
    ACCESS_CONTROL_USERS,
    ACCESS_CONTROL_GROUPS,
    ACCESS_CONTROL_TOKENS,
    ADMIN_COLLECTION,
    ADMIN_USERS,
    ADMIN_GROUPS,
    ADMIN_TOKENS,
    ALLOWED_TOKENS_COLLECTION,
]

# LDAP SEARCH
RAW_QUERY = 'raw_query'
SEARCH_BASE = 'search_base'
ATTRIBUTES = 'attributes'
MANAGER_ATTRIBUTES = 'manager_attributes'
SEARCH_FILTER = 'search_filter'

# AUTHENTICATE
USERNAME = 'username'
PASSWORD = 'password'

# LDAP AUTH FMT
mail_search_filter = '(mail={username}@{domain})'
username = '(cn={username})'
title = '(title={title})'

# requests
URL = 'url'
HOST = 'host'
PORT = 'port'
PROTO = 'proto'
URI = 'uri'
USE_DIGEST = 'use_digest'
HEADERS = 'headers'
COOKIES = 'cookies'
PROXIES = 'proxies'
CERT = 'cert'
TIMEOUT = 'timeout'
VERIFY = 'verify'
SUCCESS = 'success'
ERROR = 'error'
DEBUG = 'debug'
METHOD = 'method'
JSON_DATA = 'json_data'
PARAMS = 'params'
FILES = 'files'
DATA = 'data'
STREAM = 'stream'
DEFAULT_PORT = 443
DEFAULT_PROTO = 'https'
DEFAULT_HOST = '127.0.0.1'
FIREFOX_BINARY = 'firefox_binary'
DEFAULT_FF_BINARY = '/usr/bin/firefox'
OTHER_BLOCK = 'other'
OTHER_CONFIGS = [FIREFOX_BINARY,]
SCHEME = 'scheme'
NETLOC = 'netloc'
PATH = 'path'
QQUERY = 'query'
URL_JOIN_KEYS = [SCHEME, NETLOC, PATH, QQUERY]

TIME_FMT = '%m/%d/%Y:%H:%M:%S'
EXPIRED = 'expired'
CREATED = 'created'

USERNAME = 'username'
DISPLAY_NAME = 'displayName'
MANAGER = 'manager'
NAME = 'name'
MAIL = 'mail'
TITLE = 'title'
MEMBER_OF = 'memberOf'

SUBJECT_ATTRIBUTES = [DISPLAY_NAME, TITLE, NAME, MAIL, MANAGER, MEMBER_OF]
