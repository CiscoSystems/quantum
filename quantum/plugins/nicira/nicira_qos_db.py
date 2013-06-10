# vim: tabstop=4 shiftwidth=4 softtabstop=4
#
# Copyright 2013 Nicira Networks, Inc.  All rights reserved.
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
# @author: Aaron Rosen, Nicira, Inc

import sqlalchemy as sa
from sqlalchemy.orm import exc

from quantum.api.v2 import attributes as attr
from quantum.db import model_base
from quantum.db import models_v2
from quantum.openstack.common import uuidutils
from quantum.plugins.nicira.extensions import nvp_qos as ext_qos
from quantum.plugins.nicira import nvplib


class QoSQueue(model_base.BASEV2, models_v2.HasId, models_v2.HasTenant):
    name = sa.Column(sa.String(255))
    default = sa.Column(sa.Boolean, default=False)
    min = sa.Column(sa.Integer, nullable=False)
    max = sa.Column(sa.Integer, nullable=True)
    qos_marking = sa.Column(sa.Enum('untrusted', 'trusted',
                                    name='qosqueues_qos_marking'))
    dscp = sa.Column(sa.Integer)


class PortQueueMapping(model_base.BASEV2):
    port_id = sa.Column(sa.String(36),
                        sa.ForeignKey("ports.id", ondelete="CASCADE"),
                        primary_key=True)

    queue_id = sa.Column(sa.String(36), sa.ForeignKey("qosqueues.id"),
                         primary_key=True)


class NetworkQueueMapping(model_base.BASEV2):
    network_id = sa.Column(sa.String(36),
                           sa.ForeignKey("networks.id", ondelete="CASCADE"),
                           primary_key=True)

    queue_id = sa.Column(sa.String(36), sa.ForeignKey("qosqueues.id",
                                                      ondelete="CASCADE"))


class NVPQoSDbMixin(ext_qos.QueuePluginBase):
    """Mixin class to add queues."""

    def create_qos_queue(self, context, qos_queue):
        q = qos_queue['qos_queue']
        with context.session.begin(subtransactions=True):
            qos_queue = QoSQueue(id=q.get('id', uuidutils.generate_uuid()),
                                 name=q.get('name'),
                                 tenant_id=q['tenant_id'],
                                 default=q.get('default'),
                                 min=q.get('min'),
                                 max=q.get('max'),
                                 qos_marking=q.get('qos_marking'),
                                 dscp=q.get('dscp'))
            context.session.add(qos_queue)
        return self._make_qos_queue_dict(qos_queue)

    def get_qos_queue(self, context, id, fields=None):
        return self._make_qos_queue_dict(
            self._get_qos_queue(context, id), fields)

    def _get_qos_queue(self, context, id):
        try:
            return self._get_by_id(context, QoSQueue, id)
        except exc.NoResultFound:
            raise ext_qos.QueueNotFound(id=id)

    def get_qos_queues(self, context, filters=None, fields=None):
        return self._get_collection(context, QoSQueue,
                                    self._make_qos_queue_dict,
                                    filters=filters, fields=fields)

    def delete_qos_queue(self, context, id):
        qos_queue = self._get_qos_queue(context, id)
        with context.session.begin(subtransactions=True):
            context.session.delete(qos_queue)

    def _process_port_queue_mapping(self, context, p):
        if not p.get(ext_qos.QUEUE):
            return
        with context.session.begin(subtransactions=True):
            db = PortQueueMapping(port_id=p['id'],
                                  queue_id=p.get(ext_qos.QUEUE))
            context.session.add(db)

    def _get_port_queue_bindings(self, context, filters=None, fields=None):
        return self._get_collection(context, PortQueueMapping,
                                    self._make_port_queue_binding_dict,
                                    filters=filters, fields=fields)

    def _delete_port_queue_mapping(self, context, port_id):
        query = self._model_query(context, PortQueueMapping)
        try:
            binding = query.filter(PortQueueMapping.port_id == port_id).one()
        except exc.NoResultFound:
            # return since this can happen if we are updating a port that
            # did not already have a queue on it. There is no need to check
            # if there is one before deleting if we return here.
            return
        with context.session.begin(subtransactions=True):
            context.session.delete(binding)

    def _process_network_queue_mapping(self, context, network):
        if not network.get(ext_qos.QUEUE):
            return
        with context.session.begin(subtransactions=True):
            db = NetworkQueueMapping(network_id=network['id'],
                                     queue_id=network.get(ext_qos.QUEUE))
            context.session.add(db)

    def _get_network_queue_bindings(self, context, filters=None, fields=None):
        return self._get_collection(context, NetworkQueueMapping,
                                    self._make_network_queue_binding_dict,
                                    filters=filters, fields=fields)

    def _delete_network_queue_mapping(self, context, network_id):
        query = self._model_query(context, NetworkQueueMapping)
        with context.session.begin(subtransactions=True):
            binding = query.filter_by(network_id=network_id).first()
            if binding:
                context.session.delete(binding)

    def _extend_port_qos_queue(self, context, port):
        filters = {'port_id': [port['id']]}
        fields = ['queue_id']
        port[ext_qos.QUEUE] = None
        queue_id = self._get_port_queue_bindings(
            context, filters, fields)
        if queue_id:
            port[ext_qos.QUEUE] = queue_id[0]['queue_id']
        return port

    def _extend_network_qos_queue(self, context, network):
        filters = {'network_id': [network['id']]}
        fields = ['queue_id']
        network[ext_qos.QUEUE] = None
        queue_id = self._get_network_queue_bindings(
            context, filters, fields)
        if queue_id:
            network[ext_qos.QUEUE] = queue_id[0]['queue_id']
        return network

    def _make_qos_queue_dict(self, queue, fields=None):
        res = {'id': queue['id'],
               'name': queue.get('name'),
               'default': queue.get('default'),
               'tenant_id': queue['tenant_id'],
               'min': queue.get('min'),
               'max': queue.get('max'),
               'qos_marking': queue.get('qos_marking'),
               'dscp': queue.get('dscp')}
        return self._fields(res, fields)

    def _make_port_queue_binding_dict(self, queue, fields=None):
        res = {'port_id': queue['port_id'],
               'queue_id': queue['queue_id']}
        return self._fields(res, fields)

    def _make_network_queue_binding_dict(self, queue, fields=None):
        res = {'network_id': queue['network_id'],
               'queue_id': queue['queue_id']}
        return self._fields(res, fields)

    def _check_for_queue_and_create(self, context, port):
        """Check for queue and create.

        This function determines if a port should be associated with a
        queue. It works by first querying NetworkQueueMapping to determine
        if the network is associated with a queue. If so, then it queries
        NetworkQueueMapping for all the networks that are associated with
        this queue. Next, it queries against all the ports on these networks
        with the port device_id. Finally it queries PortQueueMapping. If that
        query returns a queue_id that is returned. Otherwise a queue is
        created that is the size of the queue associated with the network and
        that queue_id is returned.

        If the network is not associated with a queue we then query to see
        if there is a default queue in the system. If so, a copy of that is
        created and the queue_id is returned.

        Otherwise None is returned. None is also returned if the port does not
        have a device_id or if the device_owner is network:
        """

        queue_to_create = None
        # If there is no device_id don't create a queue. The queue will be
        # created on update port when the device_id is present. Also don't
        # apply QoS to network ports.
        if (not port.get('device_id') or
            port['device_owner'].startswith('network:')):
            return

        # Check if there is a queue assocated with the network
        filters = {'network_id': [port['network_id']]}
        network_queue_id = self._get_network_queue_bindings(
            context, filters, ['queue_id'])

        if network_queue_id:
            # get networks that queue is assocated with
            filters = {'queue_id': [network_queue_id[0]['queue_id']]}
            networks_with_same_queue = self._get_network_queue_bindings(
                context, filters)

            # get the ports on these networks with the same_queue and device_id
            filters = {'device_id': [port.get('device_id')],
                       'network_id': [network['network_id'] for
                                      network in networks_with_same_queue]}
            query = self._model_query(context, models_v2.Port.id)
            query = self._apply_filters_to_query(query, models_v2.Port,
                                                 filters)
            ports_ids = [p[0] for p in query]
            if ports_ids:
                # shared queue already exists find the queue id
                queues = self._get_port_queue_bindings(context,
                                                       {'port_id': ports_ids},
                                                       ['queue_id'])
                if queues:
                    return queues[0]['queue_id']

            # get the size of the queue we want to create
            queue_to_create = self._get_qos_queue(
                context, network_queue_id[0]['queue_id'])

        else:
            # check for default queue
            filters = {'default': [True]}
            # context is elevated since default queue is owned by admin
            queue_to_create = self.get_qos_queues(context.elevated(), filters)
            if not queue_to_create:
                return
            queue_to_create = queue_to_create[0]

        # create the queue
        tenant_id = self._get_tenant_id_for_create(context, port)
        if port.get(ext_qos.RXTX_FACTOR) and queue_to_create.get('max'):
            queue_to_create['max'] *= int(port[ext_qos.RXTX_FACTOR])
        queue = {'qos_queue': {'name': queue_to_create.get('name'),
                               'min': queue_to_create.get('min'),
                               'max': queue_to_create.get('max'),
                               'dscp': queue_to_create.get('dscp'),
                               'qos_marking':
                               queue_to_create.get('qos_marking'),
                               'tenant_id': tenant_id}}
        return self.create_qos_queue(context, queue, False)['id']

    def _validate_qos_queue(self, context, qos_queue):
        if qos_queue.get('default'):
            if context.is_admin:
                if self.get_qos_queues(context, filters={'default': [True]}):
                    raise ext_qos.DefaultQueueAlreadyExists()
            else:
                raise ext_qos.DefaultQueueCreateNotAdmin()
        if (qos_queue.get('qos_marking') == 'trusted' and
            not qos_queue.get('dscp')):
            raise ext_qos.MissingDSCPForTrusted()
        max = qos_queue.get('max')
        min = qos_queue.get('min')
        # Max can be None
        if max and min > max:
            raise ext_qos.QueueMinGreaterMax()

    def _nvp_lqueue(self, queue):
        """Convert fields to nvp fields."""
        nvp_queue = {}
        params = {'name': 'display_name',
                  'qos_marking': 'qos_marking',
                  'min': 'min_bandwidth_rate',
                  'max': 'max_bandwidth_rate',
                  'dscp': 'dscp'}
        nvp_queue = dict(
            (nvp_name, queue.get(api_name))
            for api_name, nvp_name in params.iteritems()
            if attr.is_attr_set(queue.get(api_name))
        )
        if 'display_name' in nvp_queue:
            nvp_queue['display_name'] = nvplib._check_and_truncate_name(
                nvp_queue['display_name'])
        return nvp_queue
