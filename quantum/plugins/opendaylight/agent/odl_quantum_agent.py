#!/usr/bin/env python
# vim: tabstop=4 shiftwidth=4 softtabstop=4
#
# Copyright 2013 Cisco Systems, Inc.
#
# Copyright 2012 Isaku Yamahata <yamahata at private email ne jp>
# Based on openvswitch agent.
#
# Copyright 2011 Nicira Networks, Inc.
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
# @author: Kyle Mestery, Cisco Systems, Inc.

import httplib
import socket
import sys
import time

import eventlet
import netifaces
from oslo.config import cfg

from quantum.agent.linux import ovs_lib
from quantum.agent.linux.ovs_lib import VifPort
from quantum.agent.linux import utils
from quantum.agent import rpc as agent_rpc
from quantum.common import config as logging_config
from quantum.common import topics
from quantum import context as q_context
from quantum.openstack.common import log
from quantum.openstack.common.rpc import dispatcher
from quantum.plugins.opendaylight import config  # noqa


LOG = log.getLogger(__name__)


# This is copied of nova.flags._get_my_ip()
# Agent shouldn't depend on nova module
def _get_my_ip():
    """
    Returns the actual ip of the local machine.

    This code figures out what source address would be used if some traffic
    were to be sent out to some well known address on the Internet. In this
    case, a Google DNS server is used, but the specific address does not
    matter much.  No traffic is actually sent.
    """
    csock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    csock.connect(('8.8.8.8', 80))
    (addr, _port) = csock.getsockname()
    csock.close()
    return addr


def _get_ip(cfg_ip_str, cfg_interface_str):
    ip = None
    try:
        ip = getattr(cfg.CONF.ODL, cfg_ip_str)
    except (cfg.NoSuchOptError, cfg.NoSuchGroupError):
        pass
    if ip:
        return ip

    iface = None
    try:
        iface = getattr(cfg.CONF.ODL, cfg_interface_str)
    except (cfg.NoSuchOptError, cfg.NoSuchGroupError):
        pass
    if iface:
        iface = netifaces.ifaddresses(iface)[netifaces.AF_INET][0]
        return iface['addr']

    return _get_my_ip()


def _get_tunnel_ip():
    return _get_ip('tunnel_ip', 'tunnel_interface')


def _get_ovsdb_ip():
    return cfg.CONF.ODL.controllers.split(':', 1)[0]


class OVSBridge(ovs_lib.OVSBridge):
    def __init__(self, br_name, root_helper):
        ovs_lib.OVSBridge.__init__(self, br_name, root_helper)
        self.datapath_id = None

    def find_datapath_id(self):
        self.datapath_id = self.get_datapath_id()

    def set_manager(self, target):
        self.run_vsctl(["set-manager", target])

    def set_controller(self, brname, controller):
        self.run_vsctl(["set-controller", brname, controller])

    def get_ofport(self, name):
        return self.db_get_val("Interface", name, "ofport")

    def _get_ports(self, get_port):
        ports = []
        port_names = self.get_port_name_list()
        for name in port_names:
            if self.get_ofport(name) < 0:
                continue
            port = get_port(name)
            if port:
                ports.append(port)

        return ports

    def _get_external_port(self, name):
        # exclude vif ports
        external_ids = self.db_get_map("Interface", name, "external_ids")
        if external_ids:
            return

        # exclude tunnel ports
        options = self.db_get_map("Interface", name, "options")
        if "remote_ip" in options:
            return

        ofport = self.get_ofport(name)
        return VifPort(name, ofport, None, None, self)

    def get_external_ports(self):
        return self._get_ports(self._get_external_port)


class ODLPluginApi(agent_rpc.PluginApi, object):
    def get_ofp_rest_api_addr(self, context):
        LOG.debug(_("Get Ryu rest API address"))
        return self.call(context,
                         self.make_msg('get_ofp_rest_api'),
                         topic=self.topic)

    def odl_port_create(self, context, port_id, vif_id, switch_id):
        LOG.debug(_("Passing create port to plugin"))
        return self.call(context,
                         self.make_msg("odl_port_create",
                                       port_id=port_id,
                                       vif_id=vif_id,
                                       switch_id=switch_id),
                         topic=self.topic)

    def odl_port_delete(self, context, port_id, vif_id, switch_id):
        LOG.debug(_("Passing delete port to plugin"))
        return self.call(context,
                         self.make_msg("odl_port_delete",
                                       port_id=port_id,
                                       vif_id=vif_id,
                                       switch_id=switch_id),
                         topic=self.topic)

    def get_segmentation_id(self, context, port_id):
        LOG.debug(_("Getting segmentation id for port"))
        return self.call(context,
                         self.make_msg("get_segment_id",
                                       port_id=port_id),
                         topic=self.topic)


class OVSQuantumOFPODLAgent(object):

    RPC_API_VERSION = '1.1'

    def __init__(self, integ_br, tun_br, tunnel_ip, ovsdb_ip, ovsdb_port,
                 polling_interval, enable_tunneling, root_helper):
        super(OVSQuantumOFPODLAgent, self).__init__()
        self.ports = {}
        self.polling_interval = polling_interval
        self.enable_tunneling = enable_tunneling
        self.root_helper = root_helper
        self._setup_rpc()
        self._setup_integration_br(root_helper, integ_br, tunnel_ip,
                                   ovsdb_port, ovsdb_ip)
        if self.enable_tunneling:
            self._setup_tunnel_br(tun_br)

    def _setup_rpc(self):
        self.topic = topics.AGENT
        self.plugin_rpc = ODLPluginApi(topics.PLUGIN)
        self.context = q_context.get_admin_context_without_session()
        self.dispatcher = self._create_rpc_dispatcher()
        consumers = [[topics.PORT, topics.UPDATE],
                     [topics.SECURITY_GROUP, topics.UPDATE]]
        self.connection = agent_rpc.create_consumers(self.dispatcher,
                                                     self.topic,
                                                     consumers)

    def _create_rpc_dispatcher(self):
        return dispatcher.RpcDispatcher([self])

    def _setup_integration_br(self, root_helper, integ_br,
                              tunnel_ip, ovsdb_port, ovsdb_ip):
        self.int_br = OVSBridge(integ_br, root_helper)
        self.int_br.find_datapath_id()

        #rest_api_addr = self.plugin_rpc.get_ofp_rest_api_addr(self.context)
        #if not rest_api_addr:
        #    raise q_exc.Invalid(_("ODL rest API port isn't specified"))
        #LOG.debug(_("Going to ofp controller mode %s"), rest_api_addr)

        #ryu_rest_client = client.OFPClient(rest_api_addr)

        #self.vif_ports = VifPortSet(self.int_br, ryu_rest_client)
        #self.vif_ports.setup()

        #sc_client = client.SwitchConfClient(rest_api_addr)
        #sc_client.set_key(self.int_br.datapath_id,
        #                  conf_switch_key.OVS_TUNNEL_ADDR, tunnel_ip)

        # Currently ODL supports only tcp methods. (ssl isn't supported yet)
        self.int_br.set_manager('ptcp:%d' % ovsdb_port)
        self.int_br.set_controller(integ_br, 'tcp:%s:6633' % ovsdb_ip)
        self.integration_bridge = integ_br
        #sc_client.set_key(self.int_br.datapath_id, conf_switch_key.OVSDB_ADDR,
        #                  'tcp:%s:%d' % (ovsdb_ip, ovsdb_port))

    def _setup_tunnel_br(self, tun_br):
        '''Setup the tunnel bridge.

        Creates tunnel bridge, and links it to the integration bridge
        using a patch port.

        :param tun_br: the name of the tunnel bridge.
        '''
        self.tun_br = ovs_lib.OVSBridge(tun_br, self.root_helper)
        self.tun_br.reset_bridge()
        self.patch_tun_ofport = self.int_br.add_patch_port(
            cfg.CONF.ODL.int_peer_patch_port, cfg.CONF.ODL.tun_peer_patch_port)
        self.patch_int_ofport = self.tun_br.add_patch_port(
            cfg.CONF.ODL.tun_peer_patch_port, cfg.CONF.ODL.int_peer_patch_port)
        if int(self.patch_tun_ofport) < 0 or int(self.patch_int_ofport) < 0:
            LOG.error(_("Failed to create OVS patch port. Cannot have "
                        "tunneling enabled on this agent, since this version "
                        "of OVS does not support tunnels or patch ports. "
                        "Agent terminated!"))
            exit(1)
        self.tun_br.remove_all_flows()
        self.tun_br.add_flow(priority=1, actions="drop")

    def port_update(self, context, **kwargs):
        port = kwargs.get('port')
        vif_port = self.int_br.get_vif_port_by_id(port['id'])
        if not vif_port:
            return

        #details = self.plugin_rpc.get_device_details(self.context,
        #                                             device,
        #                                             self.agent_id)

    def _update_ports(self, registered_ports):
        ports = self.int_br.get_vif_port_set()
        if ports == registered_ports:
            return
        added = ports - registered_ports
        removed = registered_ports - ports

        return {'current': ports,
                'added': added,
                'removed': removed}

    def _process_devices_filter(self, port_info):
        switch_id = utils.get_interface_mac(self.integration_bridge)
        for port in port_info['added']:
            vif_port = self.int_br.get_vif_port_by_id(port)
            self.ports[port] = vif_port
            # Get segmentation id for the port
            seg_id = self.plugin_rpc.get_segmentation_id(self.context,
                                                         str(port))
            # Set port tag to vlan
            self.int_br.set_db_attribute("Port", str(vif_port.port_name),
                                         "tag", str(seg_id))
            # update plugin about port status
            self.plugin_rpc.odl_port_create(
                self.context,
                str(port),
                str(vif_port),
                str(switch_id))

        for port in port_info['removed']:
            vif_port = self.ports[port]
            # update plugin about port status
            self.plugin_rpc.odl_port_delete(
                self.context,
                str(port),
                str(vif_port),
                str(switch_id))
            del self.ports[port]

    def daemon_loop(self):
        ports = set()

        while True:
            start = time.time()
            try:
                port_info = self._update_ports(ports)
                if port_info:
                    LOG.debug(_("Agent loop has new device"))
                    self._process_devices_filter(port_info)
                    ports = port_info['current']
            except Exception:
                LOG.exception(_("Error in agent event loop"))

            elapsed = max(time.time() - start, 0)
            if (elapsed < self.polling_interval):
                time.sleep(self.polling_interval - elapsed)
            else:
                LOG.debug(_("Loop iteration exceeded interval "
                            "(%(polling_interval)s vs. %(elapsed)s)!"),
                          {'polling_interval': self.polling_interval,
                           'elapsed': elapsed})


def main():
    eventlet.monkey_patch()
    cfg.CONF(project='quantum')

    logging_config.setup_logging(cfg.CONF)

    integ_br = cfg.CONF.ODL.integration_bridge
    polling_interval = cfg.CONF.AGENT.polling_interval
    root_helper = cfg.CONF.AGENT.root_helper

    tunnel_ip = _get_tunnel_ip()
    LOG.debug(_('tunnel_ip %s'), tunnel_ip)
    ovsdb_port = cfg.CONF.ODL.ovsdb_port
    LOG.debug(_('ovsdb_port %s'), ovsdb_port)
    ovsdb_ip = _get_ovsdb_ip()
    LOG.debug(_('ovsdb_ip %s'), ovsdb_ip)
    tun_br = cfg.CONF.ODL.tunnel_bridge
    tenant_network_type = cfg.CONF.ODL.tenant_network_type
    enable_tunneling = False
    if (tenant_network_type != 'vlan'):
        enable_tunneling = True

    try:
        agent = OVSQuantumOFPODLAgent(integ_br, tun_br, tunnel_ip, ovsdb_ip,
                                      ovsdb_port, polling_interval,
                                      enable_tunneling, root_helper)
    except httplib.HTTPException, e:
        LOG.error(_("Initialization failed: %s"), e)
        sys.exit(1)

    LOG.info(_("ODL initialization on the node is done. "
               "Agent initialized successfully, now running..."))
    agent.daemon_loop()
    sys.exit(0)


if __name__ == "__main__":
    main()
