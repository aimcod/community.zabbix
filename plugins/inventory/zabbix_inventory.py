#
# Copyright: (c), Ansible Project
#
# (c) 2013, Greg Buehler
# (c) 2018, Filippo Ferrazini
# (c) 2021, Timothy Test
# Modified from ServiceNow Inventory Plugin and Zabbix inventory Script
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function
__metaclass__ = type

from ansible.plugins.inventory import BaseInventoryPlugin, Constructable, Cacheable, to_safe_group_name
import os
import atexit
import json
from ansible.module_utils.urls import Request
from ansible.module_utils.six.moves.urllib.error import URLError, HTTPError
from ansible.module_utils.compat.version import LooseVersion
from ansible.errors import AnsibleParserError


class InventoryModule(BaseInventoryPlugin, Constructable, Cacheable):

    NAME = 'community.zabbix.zabbix_inventory'

    def __init__(self):
        super().__init__()
        self.auth = ''
        self.zabbix_verion = ''

    def api_request(self, method, params=None):
        # set proxy information if required
        proxy = self.get_option('proxy')
        os.environ['http_proxy'] = proxy
        os.environ['HTTP_PROXY'] = proxy
        os.environ['https_proxy'] = proxy
        os.environ['HTTPS_PROXY'] = proxy

        server_url = self.get_option('server_url')
        validate_certs = self.get_option('validate_certs')
        timeout = self.get_option('timeout')

        headers = {'Content-Type': 'application/json-rpc'}
        payload = {
            'jsonrpc': '2.0',
            'method': method,
            'id': '1'
        }
        if params is None:
            payload['params'] = {}
        else:
            payload['params'] = params

        if self.auth != '':
            if (LooseVersion(self.zabbix_version) >= LooseVersion('6.4')):
                headers['Authorization'] = 'Bearer ' + self.auth
            else:
                payload['auth'] = self.auth

        api_url = server_url + '/api_jsonrpc.php'
        req = Request(
            headers=headers,
            timeout=timeout,
            validate_certs=validate_certs
        )
        try:
            self.display.vvv("Sending request to {0}".format(api_url))
            response = req.post(api_url, data=json.dumps(payload))
        except ValueError:
            raise AnsibleParserError("something went wrong with JSON loading")
        except (URLError, HTTPError) as error:
            raise AnsibleParserError(error)

        return response

    def get_version(self):
        response = self.api_request(
            'apiinfo.version'
        )
        res = json.load(response)
        self.zabbix_version = res['result']

    def logout_zabbix(self):
        self.api_request(
            'user.logout',
            []
        )

    def login_zabbix(self):
        auth_token = self.get_option('auth_token')
        if auth_token:
            self.auth = auth_token
            return

        atexit.register(self.logout_zabbix)

        login_user = self.get_option('login_user')
        login_password = self.get_option('login_password')
        response = self.api_request(
            'user.login',
            {
                "username": login_user,
                "password": login_password
            }
        )
        res = json.load(response)
        self.auth = res["result"]

    def verify_file(self, path):
        valid = False
        if super(InventoryModule, self).verify_file(path):
            if path.endswith(('zabbix_inventory.yaml', 'zabbix_inventory.yml')):
                valid = True
            else:
                self.display.vvv(
                    'Skipping due to inventory source not ending in "zabbix_inventory.yaml" nor "zabbix_inventory.yml"')
        return valid

#    def parse(self, inventory, loader, path, cache=True):  # Plugin interface (2)
    def parse(self, inventory, loader, path):  # Plugin interface (2)
        super(InventoryModule, self).parse(inventory, loader, path)

#        self._read_config_data(path)
#        self.cache_key = self.get_cache_key(path)

 #       self.use_cache = self.get_option('cache') and cache
#        self.update_cache = self.get_option('cache') and not cache

        self.get_version()
        self.login_zabbix()
        zapi_query = self.get_option('host_zapi_query')
        response = self.api_request(
            'host.get',
            zapi_query
        )
        res = json.load(response)
        content = res['result']

        strict = self.get_option('strict')

        for record in content:
            # add host to inventory
            host_name = self.inventory.add_host(record['host'])
            # set variables for host
            for k in record.keys():
                self.inventory.set_variable(host_name, 'zbx_%s' % k, record[k])

            # added for compose vars and keyed groups
            self._set_composite_vars(
                self.get_option('compose'),
                self.inventory.get_host(host_name).get_vars(), host_name, strict)

            self._add_host_to_composed_groups(self.get_option('groups'), dict(), host_name, strict)
            self._add_host_to_keyed_groups(self.get_option('keyed_groups'), dict(), host_name, strict)

        # organize inventory by zabbix groups
        if self.get_option('add_zabbix_groups'):
            content = self.host.get({'selectGroups': ['name']})
            for record in content:
                host_name = record['host']
                if len(record['groups']) >= 1:
                    for group in record['groups']:
                        group_name = to_safe_group_name(group['name'])
                        self.inventory.add_group(group_name)
                        self.inventory.add_child(group_name, host_name)
