# Copyright 2011 Cisco Systems, Inc.
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
#
# @author Sumit Naiksatam
#

import logging

from webob import exc

from quantum.api import api_common as common
from quantum.api.l3 import l3faults
from quantum.api.l3.views import targets as targets_view
from quantum.common.l3 import l3exceptions as exception

LOG = logging.getLogger('quantum.api.targets')


def create_resource(plugin, version):
    controller_dict = {
                        '1.1': [ControllerV11(plugin),
                                ControllerV11._serialization_metadata,
                                common.XML_NS_V11]}
    return common.create_resource(version, controller_dict)


class Controller(common.QuantumController):
    """ Targets API controller for Quantum API """

    _route_ops_param_list = [{}]

    def __init__(self, plugin):
        self._resource_name = 'target'
        super(Controller, self).__init__(plugin)

    def _items(self, request, tenant_id, routetable_id):
        """ Returns a list of targets """
        targets = self._plugin.get_all_targets(tenant_id, routetable_id)
        builder = targets_view.get_view_builder(request, self.version)
        result = [builder.build(target)['target']
                  for target in targets]
        return dict(targets=result)

    def get_all_targets(self, request, tenant_id, routetable_id):
        """ Returns a list of targets for this tenant """
        return self._items(request, tenant_id, routetable_id)


class ControllerV11(Controller):
    """Target resources controller for Quantum v1.1 API
    """

    _serialization_metadata = {
        "application/xml": {
            "attributes": {
                "route": ["tag", "description"]},
            "plurals": {"targets": "target"}},
    }

    def __init__(self, plugin):
        self.version = "1.1"
        super(ControllerV11, self).__init__(plugin)
