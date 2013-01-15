# vim: tabstop=4 shiftwidth=4 softtabstop=4

# Copyright 2012 OpenStack LLC.
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

from quantum.db import api as qdbapi
from quantum.db import l3_db
from quantum.db import model_base
from quantum.plugins.common import constants as service_constants


# A fake l3 service plugin class for plugins that delegate
# away L3 routing functionality
class FakeL3ServicePlugin(l3_db.L3_NAT_db_mixin):
    supported_extension_aliases = ["router"]

    def __init__(self):
        qdbapi.register_models(base=model_base.BASEV2)

    def get_plugin_type(self):
        return service_constants.L3_ROUTER_NAT

    def get_plugin_description(self):
        return "Fake L3 Router Service Plugin for testing"
