# vim: tabstop=4 shiftwidth=4 softtabstop=4

# Copyright 2013 OpenStack LLC.
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

import sqlalchemy as sa
from sqlalchemy.orm import exc
from sqlalchemy.sql import expression as expr

from quantum.api.v2 import attributes
from quantum.common import constants as l3_constants
from quantum.common import exceptions as q_exc
from quantum.db import db_base_plugin_v2
from quantum.db import model_base
from quantum.db import models_v2
from quantum.extensions import ext_net
from quantum import policy


DEVICE_OWNER_ROUTER_GW = l3_constants.DEVICE_OWNER_ROUTER_GW


class ExternalNetwork(model_base.BASEV2):
    network_id = sa.Column(sa.String(36),
                           sa.ForeignKey('networks.id', ondelete="CASCADE"),
                           primary_key=True)


class Ext_net_db_mixin(object):
    """Mixin class to add external network methods to db_plugin_base_v2"""

    def _network_model_hook(self, context, original_model, query):
        query = query.outerjoin(ExternalNetwork,
                                (original_model.id ==
                                 ExternalNetwork.network_id))
        return query

    def _network_filter_hook(self, context, original_model, conditions):
        if conditions is not None and not hasattr(conditions, '__iter__'):
            conditions = (conditions, )
            # Apply the external network filter only in non-admin context
        if not context.is_admin and hasattr(original_model, 'tenant_id'):
            conditions = expr.or_(ExternalNetwork.network_id != expr.null(),
                                  *conditions)
        return conditions

    # TODO(salvatore-orlando): Perform this operation without explicitly
    # referring to db_base_plugin_v2, as plugins that do not extend from it
    # might exist in the future
    db_base_plugin_v2.QuantumDbPluginV2.register_model_query_hook(
        models_v2.Network,
        "external_net",
        _network_model_hook,
        _network_filter_hook)

    def _check_l3_view_auth(self, context, network):
        return policy.check(context,
                            "extension:router:view",
                            network)

    def _enforce_l3_set_auth(self, context, network):
        return policy.enforce(context,
                              "extension:router:set",
                              network)

    def _network_is_external(self, context, net_id):
        try:
            context.session.query(ExternalNetwork).filter_by(
                network_id=net_id).one()
            return True
        except exc.NoResultFound:
            return False

    def _extend_network_dict_l3(self, context, network):
        if self._check_l3_view_auth(context, network):
            network[ext_net.EXTERNAL] = self._network_is_external(
                context, network['id'])

    def _process_l3_create(self, context, net_data, net_id):
        external = net_data.get(ext_net.EXTERNAL)
        external_set = attributes.is_attr_set(external)

        if not external_set:
            return

        self._enforce_l3_set_auth(context, net_data)

        if external:
            # expects to be called within a plugin's session
            context.session.add(ExternalNetwork(network_id=net_id))

    def _process_l3_update(self, context, net_data, net_id):
        new_value = net_data.get(ext_net.EXTERNAL)
        if not attributes.is_attr_set(new_value):
            return

        self._enforce_l3_set_auth(context, net_data)
        existing_value = self._network_is_external(context, net_id)

        if existing_value == new_value:
            return

        if new_value:
            context.session.add(ExternalNetwork(network_id=net_id))
        else:
            # must make sure we do not have any external gateway ports
            # (and thus, possible floating IPs) on this network before
            # allow it to be update to external=False
            port = context.session.query(models_v2.Port).filter_by(
                device_owner=DEVICE_OWNER_ROUTER_GW,
                network_id=net_id).first()
            if port:
                raise ext_net.ExternalNetworkInUse(net_id=net_id)

            context.session.query(ExternalNetwork).filter_by(
                network_id=net_id).delete()

    def _filter_nets_l3(self, context, nets, filters):
        vals = filters and filters.get(ext_net.EXTERNAL, [])
        if not vals:
            return nets

        ext_nets = set([en['network_id'] for en in
                        context.session.query(ExternalNetwork).all()])
        if vals[0]:
            return [n for n in nets if n['id'] in ext_nets]
        else:
            return [n for n in nets if n['id'] not in ext_nets]

    def get_external_network_id(self, context):
        nets = self.get_networks(context, {ext_net.EXTERNAL: [True]})
        if len(nets) > 1:
            raise q_exc.TooManyExternalNetworks()
        else:
            return nets[0]['id'] if nets else None
