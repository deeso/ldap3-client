
#!/usr/bin/env python
from setuptools import setup, find_packages
import os


data_files = [(d, [os.path.join(d, f) for f in files])
              for d, folders, files in os.walk(os.path.join('src', 'config'))]


setup(name='ldap3-client',
      version='1.0',
      description='simple ldap client for interacting with LDAP service',
      author='Adam Pridgen',
      author_email='adam.pridgen@cisco.com',
      install_requires=['ldap3', 'toml'],
      packages=find_packages('src'),
      package_dir={'': 'src'},
)
