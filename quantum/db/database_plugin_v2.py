import logging

import netaddr
from sqlalchemy.orm import exc

from quantum.common import exceptions as q_exc
import quantum.db.api as db
from quantum.db import models_v2
from quantum.quantum_plugin_base_v2 import QuantumPluginBaseV2


LOG = logging.getLogger("q_database_plugin_v2")


class QuantumDBPlugin_V2(QuantumPluginBaseV2):
    """ A class that implements the v2 Quantum plugin interface
        using SQLAlchemy models.  Whenever a non-read call happens
        the plugin will call an event handler class method (e.g.,
        network_created()).  The result is that this class can be
        sub-classed by other classes that add custom behaviors on
        certain events.
    """

    def __init__(self):

        options = {"sql_connection": "sqlite://"}
        db.configure_db(options)

    def _make_network_dict(self, network):
        return { "id": network.uuid,
                 "name": network.name,
                 "admin_state_up": network.admin_state_up,
                 "op_status": network.op_status,
                 "subnets": [ s['uuid'] for s in network.subnets ]
               }

    def create_network(self, auth_context, network_data, **kwargs):
        n = network_data['network']
        session = db.get_session()
        with session.begin():
            network = models_v2.Network("",
                                      n['name'],
                                      n['admin_state_up'],
                                      "ACTIVE")
            session.add(network)
            session.flush()
            return self._make_network_dict(network)

    def update_network(self, auth_context, net_data, **kwargs):
        pass

    def delete_network(self, auth_context, net_id):
        session = db.get_session()
        try:
            net = (session.query(models_v2.Network).
                   filter_by(uuid=net_id).
                   one())

            for p in net.ports:
                session.delete(p)

            session.delete(net)
            session.flush()
        except exc.NoResultFound:
            raise q_exc.NetworkNotFound(net_id=net_id)

    def get_network(self, auth_context, net_uuid, **kwargs):
        session = db.get_session()
        try:
            #TODO(danwent): filter by tenant
            network = (session.query(models_v2.Network).
                      filter_by(uuid=net_uuid).
                      one())
            return self._make_network_dict(network)
        except exc.NoResultFound:
            raise q_exc.NetworkNotFound(network_uuid=net_uuid)

    def get_all_networks(self, auth_context, **kwargs):
        session = db.get_session()
        #TODO(danwent): filter by tenant
        all_networks = (session.query(models_v2.Network).all())
        return [ self._make_network_dict(s) for s in all_networks ]

    def _make_subnet_dict(self, subnet):
        return { "id" : subnet.uuid,
                 "network_id": subnet.network_uuid,
                 "ip_version" : subnet.ip_version,
                 "prefix" : subnet.prefix,
                 "gateway_ip" : subnet.gateway_ip
               }

    def create_subnet(self, auth_context, subnet_data, **kwargs):
        s = subnet_data['subnet']
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
            avoid = [ s['gateway_ip'], str(netrange[0]),
                      str(netrange.broadcast) ]
            for ip in netrange:
                ip_str = str(ip)
                if ip_str in avoid:
                    continue
                session.add(models_v2.IP_Allocation(ip_str, subnet.uuid))
            session.flush()
            return self._make_subnet_dict(subnet)

    def update_subnet(self, tenant_id, subnet_uuid, subnet_data):
        pass

    def delete_subnet(self, tenant_id, subnet_id):
        session = db.get_session()
        try:
            subnet = (session.query(models_v2.Subnet).
                   filter_by(uuid=subnet_id).
                   one())

            session.query(models_v2.IP_Allocation).\
                    filter_by(subnet_uuid=subnet_id).\
                    delete()

            session.delete(subnet)
            session.flush()
        except exc.NoResultFound:
            raise q_exc.SubnetNotFound(subnet_id=subnet_uuid)

    def get_subnet(self, tenant_id, subnet_uuid, **kwargs):
        session = db.get_session()
        try:
            #TODO(danwent): filter by tenant
            subnet = (session.query(models_v2.Subnet).
                      filter_by(uuid=subnet_uuid).
                      one())
            return self._make_subnet_dict(subnet)
        except exc.NoResultFound:
            raise q_exc.SubnetNotFound(subnet_uuid=subnet_uuid)

    def get_all_subnets(self, tenant_id, **kwargs):
        session = db.get_session()
        #TODO(danwent): filter by tenant
        all_subnets = (session.query(models_v2.Subnet).all())
        return [ self._make_subnet_dict(s) for s in all_subnets ]

    def _make_port_dict(self, port):
        ips = [ { "address": f.address,
                  "subnet_id": f.subnet_uuid }
                for f in port.fixed_ips ]
        return { "id" : port.uuid,
                 "network_id": port.network_uuid,
                 "mac_address": port.mac_address,
                 "admin_state_up": port.admin_state_up,
                 "op_status": port.op_status,
                 "fixed_ips": ips,
                 "device_id": port.device_uuid
               }

    def create_port(self, auth_context, port_data, **kwargs):
        p = port_data['port']
        session = db.get_session()
        #FIXME(danwent): allocate MAC
        mac_address = "ca:fe:de:ad:be:ef"
        with session.begin():
            port = models_v2.Port("",
                                     p['network_id'],
                                     mac_address,
                                     p['admin_state_up'],
                                     "ACTIVE",
                                     p['device_id'])
            network_uuid = p['network_id']
            network = session.query(models_v2.Network).\
                                    filter_by(uuid=network_uuid).\
                                    first()

            ip_found = { 4 : False, 6 : False}
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

    def update_port(self, auth_context, port_data, **kwargs):
        pass

    def delete_port(self, auth_context, port_id):
        session = db.get_session()
        try:
            port = (session.query(models_v2.Port).
                   filter_by(uuid=port_id).
                   one())

            session.delete(port)
            session.flush()
        except exc.NoResultFound:
            raise q_exc.PortNotFound(port_id=port_id)

    def get_port(self, auth_context, port_id, **kwargs):
        session = db.get_session()
        try:
            #TODO(danwent): filter by tenant
            port = (session.query(models_v2.Port).
                      filter_by(uuid=port_id).
                      one())
            return self._make_port_dict(port)
        except exc.NoResultFound:
            raise q_exc.PortNotFound(port_uuid=port_id)

    def get_all_ports(self, auth_context, **kwargs):
        session = db.get_session()
        #TODO(danwent): filter by tenant
        all_ports = (session.query(models_v2.Port).all())
        return [ self._make_port_dict(p) for p in all_ports ]

    def clear_state(self):
        db.clear_db()
