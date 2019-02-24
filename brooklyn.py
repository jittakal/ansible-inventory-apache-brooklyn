#!/usr/bin/env python
# -*- coding: UTF-8 -*-
'''
Apache Brooklyn Ansible External Inventory Script
'''
# Copyright 2016-2017 by Jitendra Takalkar - All Rights Reserved.

import codecs
import logging
import os
import sys
import six
from ansible.module_utils.urls import open_url
from ansible.module_utils.urls import SSLValidationError
from ansible.module_utils._text import to_text

try:
    from urllib.error import HTTPError
except ImportError:
    from urllib2 import HTTPError

try:
    from ConfigParser import NoSectionError
    from ConfigParser import SafeConfigParser as ConfigParser
except ImportError:
    from configparser import NoSectionError
    from configparser import ConfigParser

try:
    import json
    from json import JSONDecodeError
except ImportError:
    import simplejson as json

"""
Apache Brooklyn external inventory script
==================================

Generates inventory that Ansible can understand by making API requests to Apache Brooklyn.

The default configuration file is named 'brooklyn.ini' and is located alongside this script. You can
choose any other file by setting the BROOKLYN_INI_PATH environment variable.

If param 'application_id' is left blank in 'brooklyn.ini', the inventory includes all the instances
in application where the requesting user belongs. Otherwise, only instances from the given project
are included, provided the requesting user belongs to it.

The following variables are established for every host. They can be retrieved from the hostvars
dictionary.
 - app_name: str
 - app_description: str
 - app_status: str
 - app_tags: list(str)
 - app_internal_ips: list(str)
 - app_external_ips: list(str)
 - app_created_at
 - app_updated_at
 - ansible_ssh_host

Instances are grouped by the following categories:
 - tag:
   A group is created for each tag. E.g. groups 'tag_foo' and 'tag_bar' are created if there exist
   instances with tags 'foo' and/or 'bar'.
 - application:
   A group is created for each application. E.g. group 'application_test' is created if an
   applicationproject named 'test' exist.
 - status:
   A group is created for each instance state. E.g. groups 'status_RUNNING' and 'status_PENDING'
   are created if there are instances in running and pending state.

Examples:
  Execute uname on all instances in application 'test'
  $ ansible -i brooklyn.py application_test -m shell -a "/bin/uname -a"

  Install nginx on all debian web servers tagged with 'www'
  $ ansible -i brooklyn.py tag_www -m apt -a "name=nginx state=present"

  Run site.yml playbook on web servers
  $ ansible-playbook -i brooklyn.py site.yml -l tag_www

  $ export ANSIBLE_HOST_KEY_CHECKING=False
  $ dos2unix brooklyn.py
  $ ansible -i brooklyn.py all -m apt -a "name=nginx state=present" --become --become-user=root
 
Support:
  This script is tested on Python 2.7 and 3.5. It may work on other versions though.

Author: Jitendra Takalkar <jitendra.takalkar@atos.net>
Version: 0.1
"""

# logging configuration
LOGGING_FORMAT = '[%(asctime)s] p%(process)s {%(pathname)s:%(lineno)d} %(levelname)s - %(message)s'
# /logging configuration

# global variables
LOGGER = None
DEFAULT_REQUEST_HEADER = dict(
    Accept="application/json",
    ContentType="application/json"
)
# /global variables

# global functions
def configure_logger(name='brooklyn', level=logging.DEBUG, file_handler_level=logging.ERROR):
    '''
    configure module logger and returns logger
    '''
    logger = logging.getLogger(name)
    logger.setLevel(level)

    # create file handler which logs even debug messages
    file_handler = logging.FileHandler('brooklyn-inventory.log')
    file_handler.setLevel(file_handler_level)

    # create formatter and add it to the handlers
    formatter = logging.Formatter(LOGGING_FORMAT, '%m-%d %H:%M:%S')
    file_handler.setFormatter(formatter)
    # add the handlers to logger
    logger.addHandler(file_handler)
    return logger

def read_http_json_response(response=None):
    '''
    Read HTTP response
    '''
    LOGGER.debug('Inside read_http_json_response()')
    reader = codecs.getreader("utf-8")
    #Fixme: handle json load error
    try:
        return (json.load(reader(response)), None)
    except JSONDecodeError as err:
        LOGGER.error(err)
        error = Error("500", "Internal error while reading json response")
        return (None, error)

def read_http_text_response(response=None):
    '''
    Read HTTP response
    '''
    LOGGER.debug('Inside read_http_json_response()')
    data_bytes = response.read()
    return (to_text(data_bytes), None)
# /global functions

class Error:
    " Generic Error class "

    def __init__(self, code=None, message=None):
        '''
        Default constructor
        '''
        self.code = code
        self.message = message
        LOGGER.error(self)
        return

    def get_code(self):
        '''
        return error code
        '''
        return self.code

    def get_message(self):
        '''
        return error message
        '''
        return self.message

    def __str__(self):
        '''
        return formatted error message
        '''
        return "Error # {0}: {1}".format(self.code, self.message)

    def __repr__(self):
        '''
        return formatted error message
        '''
        return self.__str__()

class BrooklynServer:
    """ Apache Brooklyn Brooklyn Server Class """

    def __init__(self, base_url, api_key, secret_key, use_private_ip='False'):
        '''
        Default constructor
        '''
        if base_url is not None:
            self.url = base_url.rstrip("/")
        self.api_key = api_key
        self.secret_key = secret_key
        if use_private_ip == 'True' or use_private_ip == 'true':
            self.use_private_ip = True
        else:
            self.use_private_ip = False
        return

    def open_server_url(self, uri, data=None, headers=None, method="GET", use_proxy=True,
                        force=False, last_mod_time=None, timeout=10, validate_certs=True,
                        http_agent=None, force_basic_auth=True, follow_redirects='urllib2'):
        '''
        open server url wraps ansible open url method
        '''
        LOGGER.debug("Inside open_server_url")
        if headers is None:
            headers = DEFAULT_REQUEST_HEADER

        url = self.url + uri
        try:
            response = open_url(url, data, headers, method, use_proxy, force, last_mod_time,
                                timeout, validate_certs, self.api_key, self.secret_key,
                                http_agent, force_basic_auth, follow_redirects)
            return (response, None)
        except HTTPError as err:
            LOGGER.error(err)
            error = Error(err.getcode(), err.msg)
            return (None, error)
        except TimeoutError as err:
            LOGGER.error(err)
            error = Error(500, "Connection timed out")
            return (None, error)
        except SSLValidationError as err:
            LOGGER.error(err)
            error = Error(500, err)
            return (None, error)

    def is_server_running(self):
        '''
        This method return True if server is up and running
        '''
        up_uri = "/v1/server/up"
        response, err = self.open_server_url(uri=up_uri, headers=DEFAULT_REQUEST_HEADER,
                                             method="GET")

        if err is not None:
            LOGGER.error(err)
            return (False, err)

        status, err = read_http_json_response(response)        
        return (status, err)

    def get_applications(self):
        '''
        Get all applications
        '''
        applications_uri = "/v1/applications?typeRegex=.*"
        response, err = self.open_server_url(applications_uri)
        if err is not None:
            LOGGER.error(err)
            return(None, err)

        applications, err = read_http_json_response(response)
        return (applications, err)

    def get_application_descendants(self, application_id):
        '''
        Fetch entity info for all (or filtered) descendants
        '''
        app_desc_uri = "/v1/applications/{0}/entities/{0}/descendants"\
                       .format(application_id)
        response, err = self.open_server_url(app_desc_uri)

        if err is not None:
            return(None, err)

        descendants, err = read_http_json_response(response)
        return (descendants, err)

    def get_application_locations(self, application_id):
        '''
        Fetch application locations
        '''
        provisiong_location_uri = "/v1/applications/{0}/entities/{0}/descendants/sensor/{1}" \
                                  .format(application_id, "softwareservice.provisioningLocation")

        response, err = self.open_server_url(provisiong_location_uri)
        application_locations = list()
        if err is not None:
            return (application_locations, err)

        app_descendants_locations, err = read_http_json_response(response)

        for entity_id in app_descendants_locations:
            application_locations.append(entity_id)

        return (application_locations, None)

    def get_entity_ip_address(self, application_id, entity_id):
        '''
        Wrapper method to get IP address based on config parameter
        '''
        if self.use_private_ip:
            host_ip_address, err = self.get_entity_host_subnet_address(application_id, entity_id)
        else:
            host_ip_address, err = self.get_entity_host_address(application_id, entity_id)

        return host_ip_address, err

    def get_entity_host_address(self, application_id, entity_id):
        '''
        Get application entity details
        '''
        header = dict(
            Accept="text/plain"
        )
        host_address_uri = "/v1/applications/{0}/entities/{1}/sensors/host.address?raw=false"\
                           .format(application_id, entity_id)

        response, err = self.open_server_url(host_address_uri, headers=header)
        if err is not None:
            return ("", err)

        host_address, err = read_http_text_response(response)
        if err is not None:
            return ("", err)

        return (host_address, None)

    def get_entity_host_subnet_address(self, application_id, entity_id):
        '''
        Get application entity details
        '''
        header = dict(
            Accept="text/plain"
        )
        host_subnet_address_uri = "/v1/applications/{0}/entities/{1}/sensors/host.subnet.address?raw=false"\
                           .format(application_id, entity_id)

        response, err = self.open_server_url(host_subnet_address_uri, headers=header)
        if err is not None:
            return ("", err)

        host_subnet_address, err = read_http_text_response(response)
        if err is not None:
            return ("", err)

        return (host_subnet_address, None)

    def get_entity_host_name(self, application_id, entity_id):
        '''
        Get application entity details
        '''
        header = dict(
            Accept="text/plain"
        )
        host_name_uri = "/v1/applications/{0}/entities/{1}/sensors/host.name?raw=false"\
                           .format(application_id, entity_id)

        response, err = self.open_server_url(host_name_uri, headers=header)
        if err is not None:
            return ("", err)

        host_name, err = read_http_text_response(response)
        if err is not None:
            return ("", err)

        return (host_name, None)

    def get_entity_local_host_name(self, application_id, entity_id):
        '''
        Get application entity brooklyn local host name if exists.
        '''
        header = dict(
            Accept="text/plain"
        )
        host_name_uri = "/v1/applications/{0}/entities/{1}/sensors/brooklyn.host.name?raw=false"\
                           .format(application_id, entity_id)

        response, err = self.open_server_url(host_name_uri, headers=header)
        if err is not None:
            return ("", err)

        host_name, err = read_http_text_response(response)
        if err is not None:
            return ("", err)

        return (host_name, None)

    def get_entity_tags(self, application_id, entity_id):
        '''
        Get application entity details
        '''
        if application_id == entity_id:
            return (list(), None)

        entity_tags_uri = "/v1/applications/{0}/entities/{1}/tags"\
                           .format(application_id, entity_id)

        response, err = self.open_server_url(entity_tags_uri)
        if err is not None:
            return ("", err)

        entity_tags, err = read_http_json_response(response)
        if err is not None:
            return ("", err)

        tags = list()
        for tag in entity_tags:
            if six.PY2 and isinstance(tag, basestring):
                tags.append(tag)
            if six.PY3 and isinstance(tag, str):
                tags.append(tag)
                
        return (tags, None)

    def get_host_conn_details(self, application_id, entity_id):
        '''
        Get Entity host connection details
            protocol   - ssh / winrm
            username   - login user
            host       - IP Address / Hostname
            port       - Connection Port
            password   - <optional>
        '''
        ssh_address, err = self.get_host_ssh_address(application_id, entity_id)
        host_ip_address, _ = self.get_entity_ip_address(application_id, entity_id)
        local_host_name, _ = self.get_entity_local_host_name(application_id, entity_id)

        if self.use_private_ip:
            host_subnet_address = host_ip_address
        else:
            host_subnet_address, _ = self.get_entity_host_subnet_address(application_id, entity_id)

        if ssh_address is None and err is not None:
            winrm_address, err = self.get_host_winrm_address(application_id, entity_id)
            if winrm_address is not None and err is None:
                winrm_host_creds, _ = self.get_winrm_host_creds(application_id, entity_id)
                winrm_address['ipaddress'] = host_ip_address
                winrm_address['password'] = winrm_host_creds
                winrm_address['localhostname'] = local_host_name
                winrm_address['hostsubnetaddress'] = host_subnet_address
                return (winrm_address, None)
            else:
                return (None, Error(500, "Unknow host type"))
        else:
            ssh_address['ipaddress'] = host_ip_address
            ssh_address['localhostname'] = local_host_name
            ssh_address['hostsubnetaddress'] = host_subnet_address
            ssh_host_user, ssh_host_password, err = self.get_ssh_host_creds(application_id, entity_id)
            if err is None and ssh_host_user is not None:
                ssh_address['user'] = ssh_host_user
            if err is None and ssh_host_password is not None:
                ssh_address['password'] = ssh_host_password
            return (ssh_address, None)

        return (None, Error(500, "Unknow host type"))

    def get_host_ssh_address(self, application_id, entity_id):
        '''
        Get Entity host connection details
            protocol   - ssh
            username   - login user
            host       - IP Address / Hostname
            port       - Connection Port
            password   - <optional>
        '''
        header = dict(
            Accept="text/plain"
        )
        host_ssh_address_uri = "/v1/applications/{0}/entities/{1}/sensors/"\
                               "host.sshAddress?raw=false"\
                               .format(application_id, entity_id)
        response, err = self.open_server_url(host_ssh_address_uri, headers=header)
        if err is not None:
            return (None, err)

        if response.getcode() == 200:
            host_ssh_address, err = read_http_text_response(response)
            if err is not None:
                return (None, err)

            if six.PY3:
                tokens = str.split(host_ssh_address, "@")
            else:
                tokens = host_ssh_address.split("@")

            host_ssh_address_tokens = list()
            for token in tokens:
                if six.PY3:
                    subtokens = str.split(token, ":")
                else:
                    subtokens = token.split(":")
                for subtoken in subtokens:
                    host_ssh_address_tokens.append(subtoken.strip())

            if len(host_ssh_address_tokens) == 3:
                ssh_address = dict()
                ssh_address['protocol'] = 'ssh'
                ssh_address['user'] = host_ssh_address_tokens[0]
                ssh_address['host'] = host_ssh_address_tokens[1]
                ssh_address['port'] = host_ssh_address_tokens[2]
                return (ssh_address, None)
            else:
                return(None, Error(500, "host.sshAddress sensor information format is unknown"))
        else:
            return (None, Error(response.getcode(), "host.sshAddress "\
                                                    "sensor information does not exists"))

    def get_host_winrm_address(self, application_id, entity_id):
        '''
        Get Entity host connection details
            protocol   - winrm
            username   - login user
            host       - IP Address / Hostname
            port       - Connection Port
            password   - <optional>
        '''
        header = dict(
            Accept="text/plain"
        )
        host_winrm_address_uri = "/v1/applications/{0}/entities/{1}/sensors/"\
                                 "host.winrmAddress?raw=false"\
                                 .format(application_id, entity_id)
        response, err = self.open_server_url(host_winrm_address_uri, headers=header)
        if err is not None:
            return (None, err)

        if response.getcode() == 200:
            host_winrm_address, err = read_http_text_response(response)
            if err is not None:
                return (None, err)

            if six.PY3:
                tokens = str.split(host_winrm_address, "@")
            else:
                tokens = host_winrm_address.split("@")

            host_winrm_address_tokens = list()
            for token in tokens:
                if six.PY3:
                    subtokens = str.split(token, ":")
                else:
                    subtokens = token.split(":")
                for subtoken in subtokens:
                    host_winrm_address_tokens.append(subtoken.strip())

            if len(host_winrm_address_tokens) == 3:
                winrm_address = dict()
                winrm_address['protocol'] = 'winrm'
                winrm_address['user'] = host_winrm_address_tokens[0]
                winrm_address['host'] = host_winrm_address_tokens[1]
                winrm_address['port'] = host_winrm_address_tokens[2]
                return (winrm_address, None)
            else:
                return(None, Error(500, "host.winrmAddress sensor information format is unknown"))
        else:
            return (None, Error(response.getcode(), "host.winrmAddress "\
                                                    "sensor information does not exists"))

    def get_winrm_host_creds(self, application_id, entity_id):
        '''
        Get windows host credentials
        '''
        header = dict(
            Accept="text/plain"
        )
        host_winrm_pass_uri = "/v1/applications/{0}/entities/{1}/sensors/"\
                              "windows.password?raw=false"\
                              .format(application_id, entity_id)
        response, err = self.open_server_url(host_winrm_pass_uri, headers=header)
        if err is not None:
            return ("", err)

        if response.getcode() == 200:
            windows_password, err = read_http_text_response(response)
            if err is None:
                return (windows_password, err)

        return ("", Error(response.getcode(), "windows.password "\
                                              "sensor information does not exists."))


    def get_ssh_host_creds(self, application_id, entity_id):
        '''
        Get host of type ssh credentials.
        '''
        header = dict(
            Accept="text/plain"
        )
        ssh_host_creds_uri = "/v1/applications/{0}/entities/{1}/sensors/"\
                         "createuser.vm.user.credentials?raw=false"\
                         .format(application_id, entity_id)

        response, err = self.open_server_url(ssh_host_creds_uri, headers=header)
        if err is not None:
            return (None, None, err)

        if response.getcode() != 200:
            return (None, None, Error(response.getcode(), "SSH Host credential is not exists"))

        host_credentials, err = read_http_text_response(response)
        if err is not None:
            return (None, None, err)

        if six.PY3:
            tokens = str.split(host_credentials, "@")
        else:
            tokens = host_credentials.split("@")

        credentials = list()
        for token in tokens:
            if six.PY3:
                subtokens = str.split(token, ":")
            else:
                subtokens = token.split(":")
            for subtoken in subtokens:
                credentials.append(subtoken.strip())

        if len(credentials) == 4:
            return (credentials[0], credentials[1], None)

        return (None, None, Error(500, "Password does not exists"))

class BrooklynInventory:
    "Apache Brooklyn External Inventory Script"

    def __init__(self):
        self.server = self._configure_from_file()
        self.inventory = self.get_inventory()
        return

    def _configure_from_file(self):
        """Initialize from .ini file.abs

        Configuration file is assumed to be named 'brooklyn.ini' and to be located on the same
        directory than this file, unless the environment variable BROOKLYN_INI_PATH says otherwise.
        """
        brooklyn_ini_default_path = \
            os.path.join(os.path.dirname(os.path.realpath(__file__)), 'brooklyn.ini')
        brooklyn_ini_path = os.environ.get('BROOKLYN_INI_PATH', brooklyn_ini_default_path)

        config = ConfigParser(defaults={
            'server_url': '',
            'api_key': '',
            'secret_key': '',
            'use_private_ip':''
        })

        try:
            config.read(brooklyn_ini_path)
            server_url = config.get('brooklyn', 'server_url')
            api_key = config.get('brooklyn', 'api_key')
            secret_key = config.get('brooklyn', 'secret_key')
            use_private_ip = config.get('brooklyn', 'use_private_ip')
        except NoSectionError:
            print('Please provide correct brooklyn ini file')
            sys.exit(1)

        if not server_url or server_url == '' or str.isspace(server_url):
            print('You must provide brooklyn server url [server_url]')
            sys.exit(1)

        if not api_key or api_key == '' or str.isspace(api_key):
            print('You must provide brooklyn server api key [api_key]')
            sys.exit(1)

        if not secret_key or secret_key == '' or str.isspace(secret_key):
            print('You must provide brooklyn server secret key [secret_key]')
            sys.exit(1)

        server = BrooklynServer(server_url, api_key, secret_key, use_private_ip)

        if not server.is_server_running():
            print('Server is not up and running')
            sys.exit(1)

        return server

    def get_inventory(self):
        """
        Get brooklyn applications inventory.
        """
        applications, err = self.server.get_applications()

        if err is not None:
            LOGGER.error(err)
            sys.exit(1)

        groups = dict()
        meta = dict()
        meta['hostvars'] = dict()
        app_entity_tags = []

        for application in applications:
            if application['status'] == 'STARTING' or application['status'] == 'STOPPING' or application['status'] == 'ON_FIRE':
                continue
            application_id = application['id']
            entity_ids, err = self.server.get_application_locations(application_id)
            if err is None and len(entity_ids) > 0:
                hosts_set = set()
                ssh_hosts_set = set()
                winrm_hosts_set = set()

                # Group by application_id
                for entity_id in entity_ids:
                    host_details, err = self.server.get_host_conn_details(application_id, entity_id)
                    if err is None and host_details is not None:
                        hosts_set.add(host_details['ipaddress'])
                        node = dict()
                        node["ansible_user"] = host_details['user']
                        node["ansible_host"] = host_details['ipaddress']
                        node["ansible_port"] = host_details['port']
                        node["brooklyn_hostname"] = host_details['host']
                        node["brooklyn_local_hostname"] = host_details['localhostname']
                        node["brooklyn_host_subnet_address"] = host_details["hostsubnetaddress"]
                        if host_details['protocol'] == 'ssh':
                            ssh_hosts_set.add(host_details['ipaddress'])
                            node["ansible_ssh_pass"] = host_details.get('password','')
                        elif host_details['protocol'] == 'winrm':
                            winrm_hosts_set.add(host_details['ipaddress'])
                            node["ansible_password"] = host_details.get('password','')
                            node["ansible_connection"] = 'winrm'
                            node["ansible_winrm_server_cert_validation"] = 'ignore'
                        meta['hostvars'][host_details['ipaddress']] = node
                if len(hosts_set) > 0:
                    key = "app_" + application_id
                    groups[key] = list(hosts_set)
                if len(ssh_hosts_set) > 0 and len(winrm_hosts_set) > 0:
                    key = "app_" + application_id + '_ssh'
                    groups[key] = list(ssh_hosts_set)
                if len(winrm_hosts_set) > 0 and len(ssh_hosts_set) > 0:
                    key = "app_" + application_id + '_winrm'
                    groups[key] = list(winrm_hosts_set)

                # Group by tags
                descendant_entities, err = self.server.get_application_descendants(application_id)
                for descendant_entity in descendant_entities:
                    entity_id = descendant_entity["id"]
                    entity_tags, err = self.server.get_entity_tags(application_id, entity_id)
                    if err is None and len(entity_tags) > 0:
                        entity_host_ip_address, err = self.server.get_entity_ip_address(application_id, entity_id)
                        if err is None:
                            app_entity_tags.append((application_id, entity_id, entity_tags,
                                                    entity_host_ip_address))


        # process application entity tags if exists
        if len(app_entity_tags) > 0:
            env = os.getenv('ENV')
            for app_entity in app_entity_tags:
                tags = app_entity[2]                
                
                if env is None:
                    envtagexists = False
                    for tag in app_entity[2]:
                        if tag is not None and tag.startswith('env_'):
                            envtagexists = True
                            break
                    
                    if envtagexists is False:
                        for tag in app_entity[2]:
                            key = "tag_" + tag
                            hosts = groups.get(key, list())
                            if hosts.__contains__(app_entity[3]) is False and app_entity[3] is not "" and key is not "":
                                hosts.append(app_entity[3])
                                groups[key] = hosts
                else:
                    env_tag = "env_" + env
                    if tags.__contains__(env_tag):
                        for tag in app_entity[2]:
                            key = "tag_" + tag                            
                            hosts = groups.get(key, list())
                            # tag_group_key = env_tag + ":children"
                            # group_tags = groups.get(tag_group_key, list())
                            if hosts.__contains__(app_entity[3]) is False and app_entity[3] is not "" and key is not "":
                                hosts.append(app_entity[3])
                                groups[key] = hosts
                            # if group_tags.__contains__(key) is False and tag is not "" and key is not "" and tag != env_tag:
                            #    group_tags.append(key)
                            #    groups[tag_group_key] = group_tags

        groups['_meta'] = meta
        return groups

# Configure logger
LOGGER = configure_logger('brooklyn')

# Run the script
BROOKLYN = BrooklynInventory()
print(json.dumps(BROOKLYN.inventory))
