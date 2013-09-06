# vim: tabstop=4 shiftwidth=4 softtabstop=4

# Copyright 2013 OpenStack Foundation.
# All Rights Reserved.
#
#    Licensed under the Apache License, Version 2.0 (the "License"); you may
#    not use this file except in compliance with the License. You may obtain
#    a copy of the License at
#
#         http://www.apache.org/licenses/LICENSE-2.0
#
#    Unless required by applicable law or agreed to in writing, software
#    distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
#    WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
#    License for the specific language governing permissions and limitations
#    under the License.

import os

import neutron.plugins.nicira.api_client.client_eventlet as client
from neutron.plugins.nicira import extensions
import neutron.plugins.nicira.NeutronPlugin as plugin
import neutron.plugins.nicira.NvpApiClient as nvpapi
from neutron.plugins.nicira.vshield import vcns

nvp_plugin = plugin.NvpPluginV2
api_helper = nvpapi.NVPApiHelper
nvp_client = client.NvpApiClientEventlet
vcns_class = vcns.Vcns

STUBS_PATH = os.path.join(os.path.dirname(__file__), 'etc')
NVPEXT_PATH = os.path.dirname(extensions.__file__)
NVPAPI_NAME = '%s.%s' % (api_helper.__module__, api_helper.__name__)
PLUGIN_NAME = '%s.%s' % (nvp_plugin.__module__, nvp_plugin.__name__)
CLIENT_NAME = '%s.%s' % (nvp_client.__module__, nvp_client.__name__)
VCNS_NAME = '%s.%s' % (vcns_class.__module__, vcns_class.__name__)


def get_fake_conf(filename):
    return os.path.join(STUBS_PATH, filename)
