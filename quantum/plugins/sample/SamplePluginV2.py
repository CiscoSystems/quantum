# Copyright (c) 2012 OpenStack, LLC.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#    http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or
# implied.
# See the License for the specific language governing permissions and
# limitations under the License.

import logging
import uuid

import netaddr
from sqlalchemy.orm import exc

from quantum import quantum_plugin_base_v2
from quantum.common import exceptions as q_exc
from quantum.db import api as db
from quantum.db import models_v2


LOG = logging.getLogger(__name__)


class QuantumEchoPlugin(quantum_plugin_base_v2.QuantumPluginBaseV2):

    """
    QuantumEchoPlugin is a demo plugin that doesn't
    do anything but demonstrated the concept of a
    concrete Quantum Plugin. Any call to this plugin
    will result in just a log statement with the name
    method that was called and its arguments.
    """

    def _log(self, name, context, **kwargs):
        kwarg_msg = ' '.join([('%s: |%s|' % (str(key), kwargs[key]))
                              for key in kwargs])

        # TODO(anyone) Add a nice __repr__ and __str__ to context
        #LOG.debug('%s context: %s %s' % (name, context, kwarg_msg))
        LOG.debug('%s %s' % (name, kwarg_msg))

    def create_subnet(self, context, subnet):
        self._log("create_subnet", context, subnet=subnet)
        res = {"id": str(uuid.uuid4())}
        res.update(subnet)
        return res

    def update_subnet(self, context, id, subnet):
        self._log("update_subnet", context, id=id, subnet=subnet)
        res = {"id": id}
        res.update(subnet)
        return res

    def get_subnet(self, context, id, show=None, verbose=None):
        self._log("get_subnet", context, id=id, show=show,
                  verbose=verbose)
        return {"id": id}

    def delete_subnet(self, context, id):
        self._log("delete_subnet", context, id=id)

    def get_subnets(self, context, filters=None, show=None, verbose=None):
        self._log("get_subnets", context, filters=filters, show=show,
                  verbose=verbose)
        return []

    def create_network(self, context, network):
        self._log("create_network", context, network=network)
        res = {"id": str(uuid.uuid4())}
        res.update(network)
        return res

    def update_network(self, context, id, network):
        self._log("update_network", context, id=id, network=network)
        res = {"id": id}
        res.update(network)
        return res

    def get_network(self, context, id, show=None, verbose=None):
        self._log("get_network", context, id=id, show=show,
                  verbose=verbose)
        return {"id": id}

    def delete_network(self, context, id):
        self._log("delete_network", context, id=id)

    def get_networks(self, context, filters=None, show=None, verbose=None):
        self._log("get_networks", context, filters=filters, show=show,
                  verbose=verbose)
        return []

    def create_port(self, context, port):
        self._log("create_port", context, port=port)
        res = {"id": str(uuid.uuid4())}
        res.update(port)
        return res

    def update_port(self, context, id, port):
        self._log("update_port", context, id=id, port=port)
        res = {"id": id}
        res.update(port)
        return res

    def get_port(self, context, id, show=None, verbose=None):
        self._log("get_port", context, id=id, show=show,
                  verbose=verbose)
        return {"id": id}

    def delete_port(self, context, id):
        self._log("delete_port", context, id=id)

    def get_ports(self, context, filters=None, show=None, verbose=None):
        self._log("get_ports", context, filters=filters, show=show,
                  verbose=verbose)
        return []

    supported_extension_aliases = ["FOXNSOX"]

    def method_to_support_foxnsox_extension(self, context):
        self._log("method_to_support_foxnsox_extension", context)


class FakePlugin(quantum_plugin_base_v2.QuantumPluginBaseV2):
    """ A class that implements the v2 Quantum plugin interface
        using SQLAlchemy models.  Whenever a non-read call happens
        the plugin will call an event handler class method (e.g.,
        network_created()).  The result is that this class can be
        sub-classed by other classes that add custom behaviors on
        certain events.
    """

    def __init__(self):
        sql_connection = 'sqlite:///:memory:'
        db.configure_db({'sql_connection': sql_connection,
                         'base': models_v2.model_base.BASEV2})

    def _make_network_dict(self, network):
        return {"id": network.uuid,
                "name": network.name,
                "admin_state_up": network.admin_state_up,
                "op_status": network.op_status,
                "subnets": [s['uuid'] for s in network.subnets]}

    def create_network(self, context, network):
        n = network['network']
        session = db.get_session()

        if context.is_admin and 'tenant_id' in n:
            tenant_id = n['tenant_id']
        else:
            tenant_id = context.tenant_id

        with session.begin():
            network = models_v2.Network(tenant_id=tenant_id,
                                        name=n['name'],
                                        admin_state_up=n['admin_state_up'],
                                        op_status="ACTIVE")
            session.add(network)
        return self._make_network_dict(network)

    def update_network(self, context, id, network):
        n = network['network']
        session = db.get_session()
        with session.begin():
            network = (session.query(models_v2.Network).
                      filter_by(uuid=id).
                      one())
            network.update(n)
        return self._make_network_dict(network)

    def delete_network(self, context, id):
        session = db.get_session()
        try:
            net = (session.query(models_v2.Network).
                   filter_by(uuid=id).
                   one())

            for p in net.ports:
                session.delete(p)

            session.delete(net)
            session.flush()
        except exc.NoResultFound:
            raise q_exc.NetworkNotFound(net_id=id)

    def get_network(self, context, id, show=None, verbose=None):
        session = db.get_session()
        try:
            #TODO(danwent): filter by tenant
            network = (session.query(models_v2.Network).
                      filter_by(uuid=id).
                      one())
            return self._make_network_dict(network)
        except exc.NoResultFound:
            raise q_exc.NetworkNotFound(network_uuid=id)

    def get_networks(self, context, filters=None, show=None, verbose=None):
        session = db.get_session()
        #TODO(danwent): filter by tenant
        all_networks = (session.query(models_v2.Network).all())
        return [self._make_network_dict(s) for s in all_networks]

    def _make_subnet_dict(self, subnet):
        return {"id": subnet.uuid,
                "network_id": subnet.network_uuid,
                "ip_version": subnet.ip_version,
                "prefix": subnet.prefix,
                "gateway_ip": subnet.gateway_ip}

    def create_subnet(self, context, subnet):
        s = subnet['subnet']
        session = db.get_session()
        with session.begin():
            subnet = models_v2.Subnet("",
                                      s['network_id'],
                                      s['ip_version'],
                                      s['prefix'],
                                      s['gateway_ip'])

            session.add(subnet)
            netrange = netaddr.IPNetwork(s['prefix'])
            #TODO(danwent): apply policy to avoid additional ranges
            avoid = [s['gateway_ip'], str(netrange[0]),
                      str(netrange.broadcast)]
            for ip in netrange:
                ip_str = str(ip)
                if ip_str in avoid:
                    continue
                session.add(models_v2.IP_Allocation(ip_str, subnet.uuid))
            session.flush()
            return self._make_subnet_dict(subnet)

    def update_subnet(self, context, id, subnet):
        pass

    def delete_subnet(self, context, id):
        session = db.get_session()
        try:
            subnet = (session.query(models_v2.Subnet).
                   filter_by(uuid=id).
                   one())

            session.query(models_v2.IP_Allocation).\
                    filter_by(subnet_uuid=id).\
                    delete()

            session.delete(subnet)
            session.flush()
        except exc.NoResultFound:
            raise q_exc.SubnetNotFound(subnet_id=id)

    def get_subnet(self, context, id, show=None, verbose=None):
        session = db.get_session()
        try:
            #TODO(danwent): filter by tenant
            subnet = (session.query(models_v2.Subnet).
                      filter_by(uuid=id).
                      one())
            return self._make_subnet_dict(subnet)
        except exc.NoResultFound:
            raise q_exc.SubnetNotFound(subnet_uuid=id)

    def get_subnets(self, context, filters=None, show=None, verbose=None):
        session = db.get_session()
        #TODO(danwent): filter by tenant
        all_subnets = (session.query(models_v2.Subnet).all())
        return [self._make_subnet_dict(s) for s in all_subnets]

    def _make_port_dict(self, port):
        ips = [{"address": f.address,
                "subnet_id": f.subnet_uuid}
                    for f in port.fixed_ips]
        return {"id": port.uuid,
                "network_id": port.network_uuid,
                "mac_address": port.mac_address,
                "admin_state_up": port.admin_state_up,
                "op_status": port.op_status,
                "fixed_ips": ips,
                "device_id": port.device_uuid}

    def create_port(self, context, port):
        p = port['port']
        session = db.get_session()
        #FIXME(danwent): allocate MAC
        mac_address = "ca:fe:de:ad:be:ef"
        with session.begin():
            port = models_v2.Port(network_uuid=p['network_id'],
                                  mac_address=mac_address,
                                  admin_state_up=p['admin_state_up'],
                                  op_status="ACTIVE",
                                  device_uuid=p['device_id'])

            network_uuid = p['network_id']
            network = session.query(models_v2.Network).\
                                    filter_by(uuid=network_uuid).\
                                    first()

            ip_found = {4: False, 6: False}
            for subnet in network.subnets:
                if not ip_found[subnet.ip_version]:
                    ip_alloc = session.query(models_v2.IP_Allocation).\
                                     filter_by(allocated=False).\
                                     filter_by(subnet_uuid=subnet.uuid).\
                                     with_lockmode('update').\
                                     first()
                    if not ip_alloc:
                        continue

                    ip_alloc['allocated'] = True
                    ip_alloc['port_uuid'] = port.uuid
                    session.add(ip_alloc)
                    ip_found[subnet.ip_version] = True

            if not ip_found[4] and not ip_found[6]:
                raise q_exc.FixedIPNotAvailable(network_uuid=network_uuid)
            session.add(port)
            session.flush()
        return self._make_port_dict(port)

    def update_port(self, context, id, port):
        pass

    def delete_port(self, context, id):
        session = db.get_session()
        try:
            port = (session.query(models_v2.Port).
                   filter_by(uuid=id).
                   one())

            session.delete(port)
            session.flush()
        except exc.NoResultFound:
            raise q_exc.PortNotFound(port_id=id)

    def get_port(self, context, id, show=None, verbose=None):
        session = db.get_session()
        try:
            #TODO(danwent): filter by tenant
            port = (session.query(models_v2.Port).
                      filter_by(uuid=id).
                      one())
            return self._make_port_dict(port)
        except exc.NoResultFound:
            raise q_exc.PortNotFound(port_uuid=id)

    def get_ports(self, context, filters=None, show=None, verbose=None):
        session = db.get_session()
        #TODO(danwent): filter by tenant
        all_ports = (session.query(models_v2.Port).all())
        return [self._make_port_dict(p) for p in all_ports]
