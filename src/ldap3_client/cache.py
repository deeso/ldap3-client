from datetime import datetime, timedelta
from .consts import *

class CacheEntry(object):

    MINUTES_EXPIRATION_POLICY = 60

    def __init__(self, username, fields: dict, mail=None, authenticated=False):
        self.username = username
        self.mail = mail
        self.attributes = {k:v for k,v in fields.get(ATTRIBUTES,{}).items()}
        self.fields = fields
        self.authenticated = authenticated
        self.created = datetime.utcnow()
        self.expired = datetime.utcnow() + timedelta(minutes=self.MINUTES_EXPIRATION_POLICY)

    def is_expired(self):
        return self.expired < datetime.utcnow()

    def is_authenticated(self):
        return self.authenticated

    def touch(self):
        self.expired = datetime.utcnow() + timedelta(minutes=self.MINUTES_EXPIRATION_POLICY)

    def reauthenticated(self):
        self.authenticated = True
        self.touch()

    def still_valid(self):
        now = datetime.utcnow()
        return now < self.expired

    def update_fields(self, attributes: dict):
        for k in attributes:
            self.attributes[k] = attributes[k]

    def get_attributes(self, attributes_list: list = None):
        if len(attributes_list) > 0:
            attributes = {k:None for k in attributes_list}
            attributes.update(self.attributes)
            return attributes
        return {k:v for k,v in self.attributes.items()}

    def get_fields(self, attributes_list: list = None):
        fields = {k: v for k, v in self.fields.items()}
        if attributes_list is not None and len(attributes_list) > 0:
            fields[ATTRIBUTES] = {k:None for k in attributes_list}
            fields[ATTRIBUTES].update(self.attributes)
        else:
            fields[ATTRIBUTES] = {k: v for k, v in self.attributes.items()}
        return fields

    def has_attributes(self, attribute_list):
        if len(attribute_list) == 0:
            return True
        return all([i in self.attributes for i in attribute_list])

    def serialize(self):
        return {
            USERNAME: self.username,
            ATTRIBUTES: self.attributes,
            CREATED: self.created.strftime(TIME_FMT),
            EXPIRED: self.expired.strftime(TIME_FMT),
        }

CACHE_SYSTEM = None

class CacheSystem(object):
    MINUTES_EXPIRATION_POLICY = 60

    @classmethod
    def update_user_expiration_policy(cls, days=None, minutes=None):
        _minutes = 0
        updated = False
        if days is not None and isinstance(days, int) and days > 0:
            _minutes += days * (24 * 60)
            updated = True
        if minutes is not None and isinstance(minutes, int) and minutes >= 0:
            _minutes += minutes
            updated = True

        if updated:
            cls.MINUTES_EXPIRATION_POLICY = _minutes
            return True
        return False

    def __init__(self):
        self.entries = {}
        self.mail_to_entry = {}
        self.bound_ldap = None

    def get_username_from_email(self, email):
        if email in self.mail_to_entry:
            return self.mail_to_entry[email]
        return None

    def flush_cache(self):
        self.entries = {}
        self.mail_to_entry = {}

    def is_username_expired(self, username):
        if not self.has_username(username):
            return True
        return self.get_username(username).is_expired()

    def has_username_attributes(self, username, attributes_list):
        if username in self.mail_to_entry:
            username = self.mail_to_entry[username]

        if self.is_username_expired(username):
            return False
        return self.get_username(username).has_attributes(attributes_list)

    def add_entry(self, cached_entry: CacheEntry):
        username = cached_entry.username
        mail = cached_entry.mail

        if mail is not None:
            self.mail_to_entry[mail] = username

        if username not in self.entries:
            self.entries[username] = cached_entry
        else:
            ce = self.entries[username]
            ce.update_fields(cached_entry.attributes)
            if cached_entry.authenticated:
                ce.authenticated = True
            ce.touch()

    def has_username(self, username):
        return username in self.entries

    def has_email(self, email):
        return email in self.mail_to_entry

    def get_username(self, username) -> CacheEntry:
        # TODO check if expired
        if username in self.entries:
            return self.entries[username]
        return None

    def get_email(self, email) -> CacheEntry:
        if email in self.mail_to_entry:
            username = self.mail_to_entry[email]
            return self.get_username(username)
        return None


    @classmethod
    def get_system(cls, expiration_days=None, expiration_minutes=None):
        cls.update_user_expiration_policy()