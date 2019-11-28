from .consts import *
import toml


class Config(object):

    CONFIG = {}

    @classmethod
    def check_raise(cls, block_name, key, value):
        if value is None:
            raise Exception("'%s':'%s' requires a value"%(block_name, key))

    @classmethod
    def parse_config(cls, config_file):
        try:
            toml_data = toml.load(open(config_file))
            cls.parse_ldap_service(toml_data)
        except:
            raise

    @classmethod
    def parse_ldap_service(cls, toml_data):
        block = toml_data.get(LDAP_CLIENT_BLOCK)
        block = {} if block is None else block
        if len(block) == 0:
            return

        cfg = {}
        for k in LDAP_CLIENT_CONFIGS:
            cls.check_raise(LDAP_CLIENT_BLOCK, k, block.get(k))
            cfg[k] = block.get(k)

        cls.CONFIG[LDAP_CLIENT_BLOCK] = cfg

    @classmethod
    def get(cls):
        return cls.CONFIG

    @classmethod
    def set_value(cls, key, value):
        cls.CONFIG[key] = value

    @classmethod
    def get_value(cls, key):
        return cls.CONFIG.get(key, None)

    @classmethod
    def set_username(cls, value):
        cls.set_value(BIND_USER, value)

    @classmethod
    def set_password(cls, value):
        cls.set_value(BIND_PASSWORD, value)
