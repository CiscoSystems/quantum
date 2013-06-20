# vim: tabstop=4 shiftwidth=4 softtabstop=4
#
# Copyright 2012 Nicira Networks, Inc.  All rights reserved.
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
# @author: Dan Wendlandt, Nicira, Inc
#

import eventlet
from eventlet import semaphore
import netaddr
from oslo.config import cfg

from quantum.agent.common import config
from quantum.agent.linux import external_process
from quantum.agent.linux import interface
from quantum.agent.linux import ip_lib
from quantum.agent.linux import iptables_manager
from quantum.agent.linux import utils
from quantum.agent import rpc as agent_rpc
from quantum.common import constants as l3_constants
from quantum.common import topics
from quantum.common import utils as common_utils
from quantum import context
from quantum import manager
from quantum.openstack.common import importutils
from quantum.openstack.common import log as logging
from quantum.openstack.common import loopingcall
from quantum.openstack.common import periodic_task
from quantum.openstack.common.rpc import common as rpc_common
from quantum.openstack.common.rpc import proxy
from quantum.openstack.common import service
from quantum.plugins.cisco.l3.common import constants as cl3_constants
from quantum.plugins.cisco.l3.agent.csr1000v import cisco_csr_network_driver
from quantum import service as quantum_service

LOG = logging.getLogger(__name__)
NS_PREFIX = 'qrouter-'
INTERNAL_DEV_PREFIX = 'qr-'
EXTERNAL_DEV_PREFIX = 'qg-'


class L3PluginApi(proxy.RpcProxy):
    """Agent side of the l3 agent RPC API.

    API version history:
        1.0 - Initial version.

    """

    BASE_RPC_API_VERSION = '1.0'

    def __init__(self, topic, host):
        super(L3PluginApi, self).__init__(
            topic=topic, default_version=self.BASE_RPC_API_VERSION)
        self.host = host

    def get_routers(self, context, fullsync=True, router_id=None):
        """Make a remote process call to retrieve the sync data for routers."""
        router_ids = [router_id] if router_id else None
        return self.call(context,
                         self.make_msg('sync_routers', host=self.host,
                                       fullsync=fullsync,
                                       router_ids=router_ids),
                         topic=self.topic)

    def get_external_network_id(self, context):
        """Make a remote process call to retrieve the external network id.

        @raise common.RemoteError: with TooManyExternalNetworks
                                   as exc_type if there are
                                   more than one external network
        """
        return self.call(context,
                         self.make_msg('get_external_network_id',
                                       host=self.host),
                         topic=self.topic)


#Hareesh
class HostingEntities(object):

    def __init__(self):
        self.router_id_hosting_entities = {}
        self._drivers = {}

    def get_driver(self, router_id):
        hosting_entity = self.router_id_hosting_entities.get(router_id, None)
        if hosting_entity is not None:
            driver = self._drivers.get(hosting_entity['id'], None)
            if driver is None:
                LOG.error(_("No valid driver found for Hosting Entity: %s"),
                          hosting_entity)['id']
        else:
            LOG.error(_("Cannot find hosting entity for: %s"), hosting_entity['id'])
        return driver

    def set_driver(self, router_id, router):
        hosting_entity = router['hosting_entity']
        _he_id = hosting_entity['id']
        _he_type = hosting_entity['host_type']
        _he_ip = hosting_entity['ip_address']
        _he_port = hosting_entity['port']
        _he_created_at = hosting_entity['created_at']
        _he_user = 'stack'
        _he_passwd = 'cisco'

        _csr_driver = cisco_csr_network_driver.CiscoCSRDriver(_he_ip,
                                                               _he_port,
                                                               _he_user,
                                                               _he_passwd)
        self.router_id_hosting_entities[router_id] = hosting_entity
        self._drivers[_he_id] = _csr_driver

    def remove_driver(self, router_id):
        del self.router_id_hosting_entities[router_id]
        for he_id in self._drivers.keys():
            if he_id not in self.router_id_hosting_entities.values():
                del self._drivers[he_id]

class RouterInfo(object):

    def __init__(self, router_id, root_helper, use_namespaces, router):
        self.router_id = router_id
        self.ex_gw_port = None
        self.internal_ports = []
        self.floating_ips = []
        self.root_helper = root_helper
        self.use_namespaces = use_namespaces
        self.router = router
        self.iptables_manager = iptables_manager.IptablesManager(
            root_helper=root_helper,
            #FIXME(danwent): use_ipv6=True,
            namespace=self.ns_name())

        self.routes = []

    def ns_name(self):
        if self.use_namespaces:
            return NS_PREFIX + self.router_id


class L3NATAgent(manager.Manager):

    OPTS = [
        cfg.StrOpt('external_network_bridge', default='br-ex',
                   help=_("Name of bridge used for external network "
                          "traffic.")),
        cfg.StrOpt('interface_driver',
                   help=_("The driver used to manage the virtual "
                          "interface.")),
        cfg.IntOpt('metadata_port',
                   default=9697,
                   help=_("TCP Port used by Quantum metadata namespace "
                          "proxy.")),
        cfg.IntOpt('send_arp_for_ha',
                   default=3,
                   help=_("Send this many gratuitous ARPs for HA setup, "
                          "set it below or equal to 0 to disable this "
                          "feature.")),
        # Hareesh : Temporarily setting this to False if needed
        cfg.BoolOpt('use_namespaces', default=True,
                    help=_("Allow overlapping IP.")),
        cfg.StrOpt('router_id', default='',
                   help=_("If namespaces is disabled, the l3 agent can only"
                          " confgure a router that has the matching router "
                          "ID.")),
        cfg.BoolOpt('handle_internal_only_routers',
                    default=True,
                    help=_("Agent should implement routers with no gateway")),
        cfg.StrOpt('gateway_external_network_id', default='',
                   help=_("UUID of external network for routers implemented "
                          "by the agents.")),
        cfg.BoolOpt('enable_metadata_proxy', default=True,
                    help=_("Allow running metadata proxy.")),
        cfg.BoolOpt('use_hosting_entities', default=True,
                    help=_("Allow hosting entities for routing service.")),

    ]

    def __init__(self, host, conf=None):
        if conf:
            self.conf = conf
        else:
            self.conf = cfg.CONF
        self.root_helper = config.get_root_helper(self.conf)
        self.router_info = {}

        if not self.conf.interface_driver:
            raise SystemExit(_('An interface driver must be specified'))
        try:
            self.driver = importutils.import_object(self.conf.interface_driver,
                                                    self.conf)
        except Exception:
            msg = _("Error importing interface driver "
                    "'%s'") % self.conf.interface_driver
            raise SystemExit(msg)

        self.context = context.get_admin_context_without_session()
        self.plugin_rpc = L3PluginApi(topics.PLUGIN, host)
        self.fullsync = True
        self.sync_sem = semaphore.Semaphore(1)
        if self.conf.use_namespaces:
            self._destroy_router_namespaces(self.conf.router_id)
        #Hareesh
        if self.conf.use_hosting_entities:
            self._he = HostingEntities()
        super(L3NATAgent, self).__init__(host=self.conf.host)

    # def _init_csr(self):
    #     self._csr_driver = cisco_csr_network_driver.CiscoCSRDriver("localhost",
    #                                                            8000,
    #                                                            "stack",
    #                                                            'cisco')

    def _destroy_router_namespaces(self, only_router_id=None):
        """Destroy router namespaces on the host to eliminate all stale
        linux devices, iptables rules, and namespaces.

        If only_router_id is passed, only destroy single namespace, to allow
        for multiple l3 agents on the same host, without stepping on each
        other's toes on init.  This only makes sense if router_id is set.
        """
        root_ip = ip_lib.IPWrapper(self.root_helper)
        for ns in root_ip.get_namespaces(self.root_helper):
            if ns.startswith(NS_PREFIX):
                if only_router_id and not ns.endswith(only_router_id):
                    continue

                try:
                    self._destroy_router_namespace(ns)
                except Exception:
                    LOG.exception(_("Failed deleting namespace '%s'"), ns)

    def _destroy_router_namespace(self, namespace):
        ns_ip = ip_lib.IPWrapper(self.root_helper, namespace=namespace)
        for d in ns_ip.get_devices(exclude_loopback=True):
            if d.name.startswith(INTERNAL_DEV_PREFIX):
                # device is on default bridge
                self.driver.unplug(d.name, namespace=namespace,
                                   prefix=INTERNAL_DEV_PREFIX)
            elif d.name.startswith(EXTERNAL_DEV_PREFIX):
                self.driver.unplug(d.name,
                                   bridge=self.conf.external_network_bridge,
                                   namespace=namespace,
                                   prefix=EXTERNAL_DEV_PREFIX)
        #TODO(garyk) Address the failure for the deletion of the namespace

    def _create_router_namespace(self, ri):
        ip_wrapper_root = ip_lib.IPWrapper(self.root_helper)
        ip_wrapper = ip_wrapper_root.ensure_namespace(ri.ns_name())
        ip_wrapper.netns.execute(['sysctl', '-w', 'net.ipv4.ip_forward=1'])

    def _csr_get_vrf_name(self, ri):
        return ri.ns_name()[:self.driver.DEV_NAME_LEN]

    def _csr_create_vrf(self, ri):
        _csr_driver = self._he.get_driver(ri.router_id)
        vrf_name = self._csr_get_vrf_name(ri)
        _csr_driver.create_vrf(vrf_name)

    def _csr_remove_vrf(self, ri):
        _csr_driver = self._he.get_driver(ri.router_id)
        vrf_name = self._csr_get_vrf_name(ri)
        _csr_driver.remove_vrf(vrf_name)

    def _csr_create_subinterface(self, ri,  intfc_no,
                                 vlanid, ip_cidrs ):
        #interface_no = '1'
        #vlanid = random.randrange(1, 4096)
        if len(ip_cidrs) > 1:
            #ToDo (Hareesh): Implement ip_cidrs>1
            raise Exception("Not implemented yet")
            #LOG.Error("Multiple entries in ip_cidrs %s" % ip_cidrs)
        vrf_name = self._csr_get_vrf_name(ri)
        ip_cidr = ip_cidrs[0]
        netmask = netaddr.IPNetwork(ip_cidr).netmask
        gateway_ip = ip_cidr.split('/')[0]
        interface = 'GigabitEthernet'+str(intfc_no)+'.'+str(vlanid)
        self._csr_driver.create_subinterface(interface,
                                             vrf_name,
                                             gateway_ip,
                                             vlanid,
                                             netmask)

    def _csr_remove_subinterface(self, ri, intc_no, vlan_id, ip_cidr):
        vrf_name = self._csr_get_vrf_name(ri)
        ip = ip_cidr.split('/')[0]
        netmask = netaddr.IPNetwork(ip_cidr).netmask
        interface = 'GigabitEthernet'+str(intfc_no)+'.'+str(vlanid)
        self._csr_driver.remove_subinterface(interface, vrf_name, ip,
                                             vlan_id, netmask)

    def _csr_add_internalnw_nat_rules(self, ri, int_intfc_no,
                                           ext_intfc_no,
                                           gw_ip, internal_cidr,
                                           inner_vlanid, outer_vlanid):
        vrf_name = self._csr_get_vrf_name(ri)
        acl_no = 'acl_'+str(inner_vlanid)
        internal_net = netaddr.IPNetwork(internal_cidr).network
        #ip_address = internal_cidr.split('/')[0]
        #start_ip = gw_ip
        #end_ip = gw_ip
        netmask = netaddr.IPNetwork(internal_cidr).hostmask
        inner_intfc = 'GigabitEthernet'+str(int_intfc_no)+'.'+str(inner_vlanid)
        outer_intfc = 'GigabitEthernet'+str(ext_intfc_no)+'.'+str(outer_vlanid)

        #nat_pool_name = 'snat_net_'+(ri.ns_name()[:self.driver.DEV_NAME_LEN])

        self._csr_driver.nat_rules_for_internet_access(acl_no,
                                                       internal_net,
                                                       netmask,
                                                       inner_intfc,
                                                       outer_intfc,
                                                       vrf_name)

    def _csr_remove_internalnw_nat_rules(self, ri, int_intfc_no,
                                           ext_intfc_no,
                                           gw_ip, internal_cidr,
                                           inner_vlanid, outer_vlanid):
        vrf_name = self._csr_get_vrf_name(ri)
        acl_no = 'acl_'+str(inner_vlanid)
        internal_net = netaddr.IPNetwork(internal_cidr).network
        netmask = netaddr.IPNetwork(internal_cidr).hostmask
        inner_intfc = 'GigabitEthernet'+str(int_intfc_no)+'.'+str(inner_vlanid)
        outer_intfc = 'GigabitEthernet'+str(ext_intfc_no)+'.'+str(outer_vlanid)
        self._csr_driver.remove_nat_rules_for_internet_access(acl_no,
                                                           internal_net,
                                                           netmask,
                                                           inner_intfc,
                                                           outer_intfc,
                                                           vrf_name)

    def _csr_add_floating_ip(self,ri, floating_ip, fixed_ip):
        vrf_name = self._csr_get_vrf_name(ri)
        self._csr_driver.add_floating_ip(floating_ip, fixed_ip, vrf_name)

    def _csr_remove_floating_ip(self, ri, floating_ip, fixed_ip):
        vrf_name = self._csr_get_vrf_name(ri)
        self._csr_driver.remove_floating_ip(self, floating_ip, fixed_ip,
                                            vrf_name)

    def _csr_update_routing_table(self, ri, cmd, route):
        #cmd = ['ip', 'route', operation, 'to', route['destination'],
        #       'via', route['nexthop']]
        #self._update_routing_table(ri, 'replace', route)
        #self._update_routing_table(ri, 'delete', route)
        vrf_name = self._csr_get_vrf_name(ri)
        destination_net = netaddr.IPNetwork(route['destination'])
        dest = destination_net.network
        dest_mask = destination_net.netmask
        next_hop = route['nexthop']
        if cmd is 'replace':
            self._csr_driver.add_static_route(dest, dest_mask,
                                              next_hop, vrf_name)
        elif cmd is 'delete':
            self._csr_driver.remove_static_route(dest, dest_mask,
                                                 next_hop, vrf_name)
        else:
            LOG.error(_('Unknown route command %s'), cmd)
        pass

    def _fetch_external_net_id(self):
        """Find UUID of single external network for this agent."""
        if self.conf.gateway_external_network_id:
            return self.conf.gateway_external_network_id
        try:
            return self.plugin_rpc.get_external_network_id(self.context)
        except rpc_common.RemoteError as e:
            if e.exc_type == 'TooManyExternalNetworks':
                msg = _(
                    "The 'gateway_external_network_id' option must be "
                    "configured for this agent as Quantum has more than "
                    "one external network.")
                raise Exception(msg)
            else:
                raise

    def _router_added(self, router_id, router):
        ri = RouterInfo(router_id, self.root_helper,
                        self.conf.use_namespaces, router)
        self.router_info[router_id] = ri
        if self.conf.use_namespaces:
            self._create_router_namespace(ri)
        #Hareeesh: CSR, Note that we are not adding the metadata NAT rules now
        if self.conf.use_hosting_entities:
            self._he.set_driver(router_id, router)
            self._csr_create_vrf(ri)
        for c, r in self.metadata_filter_rules():
            ri.iptables_manager.ipv4['filter'].add_rule(c, r)
        for c, r in self.metadata_nat_rules():
            ri.iptables_manager.ipv4['nat'].add_rule(c, r)
        ri.iptables_manager.apply()
        if self.conf.enable_metadata_proxy:
            self._spawn_metadata_proxy(ri)

    def _router_removed(self, router_id):
        ri = self.router_info[router_id]
        ri.router['gw_port'] = None
        ri.router[l3_constants.INTERFACE_KEY] = []
        ri.router[l3_constants.FLOATINGIP_KEY] = []
        self.process_router(ri)
        for c, r in self.metadata_filter_rules():
            ri.iptables_manager.ipv4['filter'].remove_rule(c, r)
        for c, r in self.metadata_nat_rules():
            ri.iptables_manager.ipv4['nat'].remove_rule(c, r)
        ri.iptables_manager.apply()
        if self.conf.enable_metadata_proxy:
            self._destroy_metadata_proxy(ri)
        del self.router_info[router_id]
        self._destroy_router_namespace(ri.ns_name())
        #Hareesh : CSR
        if self.conf.use_hosting_entities:
            self._csr_create_vrf(ri)
            self._he.remove_driver(router_id)


    def _spawn_metadata_proxy(self, router_info):
        def callback(pid_file):
            proxy_cmd = ['quantum-ns-metadata-proxy',
                         '--pid_file=%s' % pid_file,
                         '--router_id=%s' % router_info.router_id,
                         '--state_path=%s' % self.conf.state_path,
                         '--metadata_port=%s' % self.conf.metadata_port]
            proxy_cmd.extend(config.get_log_args(
                cfg.CONF, 'quantum-ns-metadata-proxy-%s.log' %
                router_info.router_id))
            return proxy_cmd

        pm = external_process.ProcessManager(
            self.conf,
            router_info.router_id,
            self.root_helper,
            router_info.ns_name())
        pm.enable(callback)

    def _destroy_metadata_proxy(self, router_info):
        pm = external_process.ProcessManager(
            self.conf,
            router_info.router_id,
            self.root_helper,
            router_info.ns_name())
        pm.disable()

    def _set_subnet_info(self, port):
        ips = port['fixed_ips']
        if not ips:
            raise Exception(_("Router port %s has no IP address") % port['id'])
        if len(ips) > 1:
            LOG.error(_("Ignoring multiple IPs on router port %s"),
                      port['id'])
        prefixlen = netaddr.IPNetwork(port['subnet']['cidr']).prefixlen
        port['ip_cidr'] = "%s/%s" % (ips[0]['ip_address'], prefixlen)

    def process_router(self, ri):

        ex_gw_port = self._get_ex_gw_port(ri)
        internal_ports = ri.router.get(l3_constants.INTERFACE_KEY, [])
        existing_port_ids = set([p['id'] for p in ri.internal_ports])
        current_port_ids = set([p['id'] for p in internal_ports
                                if p['admin_state_up']])
        new_ports = [p for p in internal_ports if
                     p['id'] in current_port_ids and
                     p['id'] not in existing_port_ids]
        old_ports = [p for p in ri.internal_ports if
                     p['id'] not in current_port_ids]

        for p in new_ports:
            self._set_subnet_info(p)
            ri.internal_ports.append(p)
            self.internal_network_added(ri, ex_gw_port,
                                        p['network_id'], p['id'],
                                        p['ip_cidr'], p['mac_address'],
                                        p['trunk_info'])

        for p in old_ports:
            ri.internal_ports.remove(p)
            self.internal_network_removed(ri, ex_gw_port, p['id'],
                                          p['ip_cidr'],
                                          p['trunk_info'])

        internal_cidrs = [p['ip_cidr'] for p in ri.internal_ports]

        if ex_gw_port and not ri.ex_gw_port:
            self._set_subnet_info(ex_gw_port)
            self.external_gateway_added(ri, ex_gw_port, internal_cidrs)
        elif not ex_gw_port and ri.ex_gw_port:
            self.external_gateway_removed(ri, ri.ex_gw_port,
                                          internal_cidrs)

        if ri.ex_gw_port or ex_gw_port:
            self.process_router_floating_ips(ri, ex_gw_port)

        ri.ex_gw_port = ex_gw_port

        self.routes_updated(ri)

    def process_router_floating_ips(self, ri, ex_gw_port):
        floating_ips = ri.router.get(l3_constants.FLOATINGIP_KEY, [])
        existing_floating_ip_ids = set([fip['id'] for fip in ri.floating_ips])
        cur_floating_ip_ids = set([fip['id'] for fip in floating_ips])

        id_to_fip_map = {}

        for fip in floating_ips:
            if fip['port_id']:
                if fip['id'] not in existing_floating_ip_ids:
                    ri.floating_ips.append(fip)
                    self.floating_ip_added(ri, ex_gw_port,
                                           fip['floating_ip_address'],
                                           fip['fixed_ip_address'])

                # store to see if floatingip was remapped
                id_to_fip_map[fip['id']] = fip

        floating_ip_ids_to_remove = (existing_floating_ip_ids -
                                     cur_floating_ip_ids)
        for fip in ri.floating_ips:
            if fip['id'] in floating_ip_ids_to_remove:
                ri.floating_ips.remove(fip)
                self.floating_ip_removed(ri, ri.ex_gw_port,
                                         fip['floating_ip_address'],
                                         fip['fixed_ip_address'])
            else:
                # handle remapping of a floating IP
                new_fip = id_to_fip_map[fip['id']]
                new_fixed_ip = new_fip['fixed_ip_address']
                existing_fixed_ip = fip['fixed_ip_address']
                if (new_fixed_ip and existing_fixed_ip and
                        new_fixed_ip != existing_fixed_ip):
                    floating_ip = fip['floating_ip_address']
                    self.floating_ip_removed(ri, ri.ex_gw_port,
                                             floating_ip, existing_fixed_ip)
                    self.floating_ip_added(ri, ri.ex_gw_port,
                                           floating_ip, new_fixed_ip)
                    ri.floating_ips.remove(fip)
                    ri.floating_ips.append(new_fip)

    def _get_ex_gw_port(self, ri):
        return ri.router.get('gw_port')

    def _send_gratuitous_arp_packet(self, ri, interface_name, ip_address):
        if self.conf.send_arp_for_ha > 0:
            arping_cmd = ['arping', '-A', '-U',
                          '-I', interface_name,
                          '-c', self.conf.send_arp_for_ha,
                          ip_address]
            try:
                if self.conf.use_namespaces:
                    ip_wrapper = ip_lib.IPWrapper(self.root_helper,
                                                  namespace=ri.ns_name())
                    ip_wrapper.netns.execute(arping_cmd, check_exit_code=True)
                else:
                    utils.execute(arping_cmd, check_exit_code=True,
                                  root_helper=self.root_helper)
            except Exception as e:
                LOG.error(_("Failed sending gratuitous ARP: %s"), str(e))

    def get_internal_device_name(self, port_id):
        return (INTERNAL_DEV_PREFIX + port_id)[:self.driver.DEV_NAME_LEN]

    def get_external_device_name(self, port_id):
        return (EXTERNAL_DEV_PREFIX + port_id)[:self.driver.DEV_NAME_LEN]

    def external_gateway_added(self, ri, ex_gw_port, internal_cidrs):

        interface_name = self.get_external_device_name(ex_gw_port['id'])
        ex_gw_ip = ex_gw_port['fixed_ips'][0]['ip_address']
        if not ip_lib.device_exists(interface_name,
                                    root_helper=self.root_helper,
                                    namespace=ri.ns_name()):
            self.driver.plug(ex_gw_port['network_id'],
                             ex_gw_port['id'], interface_name,
                             ex_gw_port['mac_address'],
                             bridge=self.conf.external_network_bridge,
                             namespace=ri.ns_name(),
                             prefix=EXTERNAL_DEV_PREFIX)
        self.driver.init_l3(interface_name, [ex_gw_port['ip_cidr']],
                            namespace=ri.ns_name())
        #Hareesh: CSR
        outer_vlan = 60
        self._csr_create_subinterface(ri, '2', outer_vlan,
                                      [ex_gw_port['ip_cidr']])
        ip_address = ex_gw_port['ip_cidr'].split('/')[0]
        self._send_gratuitous_arp_packet(ri, interface_name, ip_address)

        gw_ip = ex_gw_port['subnet']['gateway_ip']
        if ex_gw_port['subnet']['gateway_ip']:
            cmd = ['route', 'add', 'default', 'gw', gw_ip]
            if self.conf.use_namespaces:
                ip_wrapper = ip_lib.IPWrapper(self.root_helper,
                                              namespace=ri.ns_name())
                ip_wrapper.netns.execute(cmd, check_exit_code=False)
            else:
                utils.execute(cmd, check_exit_code=False,
                              root_helper=self.root_helper)

        for (c, r) in self.external_gateway_nat_rules(ex_gw_ip,
                                                      internal_cidrs,
                                                      interface_name):
            ri.iptables_manager.ipv4['nat'].add_rule(c, r)
        ri.iptables_manager.apply()

    def external_gateway_removed(self, ri, ex_gw_port, internal_cidrs):

        interface_name = self.get_external_device_name(ex_gw_port['id'])
        if ip_lib.device_exists(interface_name,
                                root_helper=self.root_helper,
                                namespace=ri.ns_name()):
            self.driver.unplug(interface_name,
                               bridge=self.conf.external_network_bridge,
                               namespace=ri.ns_name(),
                               prefix=EXTERNAL_DEV_PREFIX)

        #Hareesh: CSR
        outer_vlan = 60
        self._csr_remove_subinterface(ri, '2', outer_vlan,
                                      [ex_gw_port['ip_cidr']])

        ex_gw_ip = ex_gw_port['fixed_ips'][0]['ip_address']
        for c, r in self.external_gateway_nat_rules(ex_gw_ip, internal_cidrs,
                                                    interface_name):
            ri.iptables_manager.ipv4['nat'].remove_rule(c, r)
        ri.iptables_manager.apply()

    def metadata_filter_rules(self):
        rules = []
        rules.append(('INPUT', '-s 0.0.0.0/0 -d 127.0.0.1 '
                      '-p tcp -m tcp --dport %s '
                      '-j ACCEPT' % self.conf.metadata_port))
        return rules

    def metadata_nat_rules(self):
        rules = []
        rules.append(('PREROUTING', '-s 0.0.0.0/0 -d 169.254.169.254/32 '
                     '-p tcp -m tcp --dport 80 -j REDIRECT '
                     '--to-port %s' % self.conf.metadata_port))
        return rules

    def external_gateway_nat_rules(self, ex_gw_ip, internal_cidrs,
                                   interface_name):
        rules = [('POSTROUTING', '! -i %(interface_name)s '
                  '! -o %(interface_name)s -m conntrack ! '
                  '--ctstate DNAT -j ACCEPT' %
                  {'interface_name': interface_name})]
        for cidr in internal_cidrs:
            rules.extend(self.internal_network_nat_rules(ex_gw_ip, cidr))
        return rules

    def internal_network_added(self, ri, ex_gw_port, network_id, port_id,
                               internal_cidr, mac_address, trunk_info):
        interface_name = self.get_internal_device_name(port_id)
        if not ip_lib.device_exists(interface_name,
                                    root_helper=self.root_helper,
                                    namespace=ri.ns_name()):
            self.driver.plug(network_id, port_id, interface_name, mac_address,
                             namespace=ri.ns_name(),
                             prefix=INTERNAL_DEV_PREFIX)

        self.driver.init_l3(interface_name, [internal_cidr],
                            namespace=ri.ns_name())
        #Hareesh: CSR changes
        #Internal Port
        inner_vlan = trunk_info['segmentation_id']
        _name = trunk_info['name']
        #Name will be of format 'T1:x' where x is the index(1,2,..)
        itfc_no = str(int(_name.split(':')[1])*2)
        self._csr_create_subinterface(ri, itfc_no, inner_vlan, [internal_cidr])
        ip_address = internal_cidr.split('/')[0]
        self._send_gratuitous_arp_packet(ri, interface_name, ip_address)

        if ex_gw_port:
            ex_gw_ip = ex_gw_port['fixed_ips'][0]['ip_address']
            for c, r in self.internal_network_nat_rules(ex_gw_ip,
                                                        internal_cidr):
                ri.iptables_manager.ipv4['nat'].add_rule(c, r)
            ri.iptables_manager.apply()
            # Hareesh: Apply CSR internal_network_nat_rules
            #External Port
            outer_vlan = ex_gw_port['trunk_info']['segmentation_id']
            _ext_name = ex_gw_port['trunk_info']['name']
            #Name will be of format 'T2:x' where x is the index(1,2,..)
            ext_infc_no = str(int(_ext_name.split(':')[1])*2)
            self._csr_add_internalnw_nat_rules(ri, itfc_no, ext_infc_no,
                                               ex_gw_ip, internal_cidr,
                                               inner_vlan, outer_vlan)

    def internal_network_removed(self, ri, ex_gw_port, port_id,
                                 internal_cidr, trunk_info):
        interface_name = self.get_internal_device_name(port_id)
        if ip_lib.device_exists(interface_name,
                                root_helper=self.root_helper,
                                namespace=ri.ns_name()):
            self.driver.unplug(interface_name, namespace=ri.ns_name(),
                               prefix=INTERNAL_DEV_PREFIX)
        #Hareesh : CSR
        self._csr_remove_subinterface(ri,'1',inner_vlan,internal_cidr)

        if ex_gw_port:
            ex_gw_ip = ex_gw_port['fixed_ips'][0]['ip_address']
            for c, r in self.internal_network_nat_rules(ex_gw_ip,
                                                        internal_cidr):
                ri.iptables_manager.ipv4['nat'].remove_rule(c, r)
            ri.iptables_manager.apply()
            # Hareesh: Remove CSR internal_network_nat_rules
            self._csr_remove_internalnw_nat_rules(ri, '1', '2', ex_gw_ip, internal_cidr,
                                               inner_vlan, outer_vlan)

    def internal_network_nat_rules(self, ex_gw_ip, internal_cidr):
        rules = [('snat', '-s %s -j SNAT --to-source %s' %
                 (internal_cidr, ex_gw_ip))]
        return rules

    def floating_ip_added(self, ri, ex_gw_port, floating_ip, fixed_ip):
        ip_cidr = str(floating_ip) + '/32'
        interface_name = self.get_external_device_name(ex_gw_port['id'])
        device = ip_lib.IPDevice(interface_name, self.root_helper,
                                 namespace=ri.ns_name())

        if ip_cidr not in [addr['cidr'] for addr in device.addr.list()]:
            net = netaddr.IPNetwork(ip_cidr)
            device.addr.add(net.version, ip_cidr, str(net.broadcast))
            self._send_gratuitous_arp_packet(ri, interface_name, floating_ip)

        for chain, rule in self.floating_forward_rules(floating_ip, fixed_ip):
            ri.iptables_manager.ipv4['nat'].add_rule(chain, rule)
        ri.iptables_manager.apply()
        #Hareesh:CSR
        self._csr_add_floating_ip(ri, floating_ip, fixed_ip)

    def floating_ip_removed(self, ri, ex_gw_port, floating_ip, fixed_ip):
        ip_cidr = str(floating_ip) + '/32'
        net = netaddr.IPNetwork(ip_cidr)
        interface_name = self.get_external_device_name(ex_gw_port['id'])

        device = ip_lib.IPDevice(interface_name, self.root_helper,
                                 namespace=ri.ns_name())
        device.addr.delete(net.version, ip_cidr)

        for chain, rule in self.floating_forward_rules(floating_ip, fixed_ip):
            ri.iptables_manager.ipv4['nat'].remove_rule(chain, rule)
        ri.iptables_manager.apply()
        #Hareesh: CSR
        self._csr_remove_floating_ip(ri,floating_ip, fixed_ip)

    def floating_forward_rules(self, floating_ip, fixed_ip):
        return [('PREROUTING', '-d %s -j DNAT --to %s' %
                 (floating_ip, fixed_ip)),
                ('OUTPUT', '-d %s -j DNAT --to %s' %
                 (floating_ip, fixed_ip)),
                ('float-snat', '-s %s -j SNAT --to %s' %
                 (fixed_ip, floating_ip))]

    def router_deleted(self, context, router_id):
        """Deal with router deletion RPC message."""
        with self.sync_sem:
            if router_id in self.router_info:
                try:
                    self._router_removed(router_id)
                except Exception:
                    msg = _("Failed dealing with router "
                            "'%s' deletion RPC message")
                    LOG.debug(msg, router_id)
                    self.fullsync = True

    def routers_updated(self, context, routers):
        """Deal with routers modification and creation RPC message."""
        if not routers:
            return
        with self.sync_sem:
            try:
                self._process_routers(routers)
            except Exception:
                msg = _("Failed dealing with routers update RPC message")
                LOG.debug(msg)
                self.fullsync = True

    def router_removed_from_agent(self, context, payload):
        self.router_deleted(context, payload['router_id'])

    def router_added_to_agent(self, context, payload):
        self.routers_updated(context, payload)

    def _process_routers(self, routers, all_routers=False):
        if (self.conf.external_network_bridge and
            not ip_lib.device_exists(self.conf.external_network_bridge)):
            LOG.error(_("The external network bridge '%s' does not exist"),
                      self.conf.external_network_bridge)
            return

        target_ex_net_id = self._fetch_external_net_id()
        # if routers are all the routers we have (They are from router sync on
        # starting or when error occurs during running), we seek the
        # routers which should be removed.
        # If routers are from server side notification, we seek them
        # from subset of incoming routers and ones we have now.
        if all_routers:
            prev_router_ids = set(self.router_info)
        else:
            prev_router_ids = set(self.router_info) & set(
                [router['id'] for router in routers])
        cur_router_ids = set()
        for r in routers:
            if not r['admin_state_up']:
                continue

            # If namespaces are disabled, only process the router associated
            # with the configured agent id.
            if (not self.conf.use_namespaces and
                r['id'] != self.conf.router_id):
                continue

            ex_net_id = (r['external_gateway_info'] or {}).get('network_id')
            if not ex_net_id and not self.conf.handle_internal_only_routers:
                continue

            if ex_net_id and ex_net_id != target_ex_net_id:
                continue
            cur_router_ids.add(r['id'])
            if r['id'] not in self.router_info:
                self._router_added(r['id'], r)
            ri = self.router_info[r['id']]
            ri.router = r
            self.process_router(ri)
        # identify and remove routers that no longer exist
        for router_id in prev_router_ids - cur_router_ids:
            self._router_removed(router_id)

    @periodic_task.periodic_task
    def _sync_routers_task(self, context):
        # we need to sync with router deletion RPC message
        with self.sync_sem:
            if self.fullsync:
                try:
                    if not self.conf.use_namespaces:
                        router_id = self.conf.router_id
                    else:
                        router_id = None
                    routers = self.plugin_rpc.get_routers(
                        context, router_id)
                    self._process_routers(routers, all_routers=True)
                    self.fullsync = False
                except Exception:
                    LOG.exception(_("Failed synchronizing routers"))
                    self.fullsync = True

    def after_start(self):
        LOG.info(_("L3 agent started"))

    def _update_routing_table(self, ri, operation, route):
        cmd = ['ip', 'route', operation, 'to', route['destination'],
               'via', route['nexthop']]
        #TODO(nati) move this code to iplib
        if self.conf.use_namespaces:
            ip_wrapper = ip_lib.IPWrapper(self.conf.root_helper,
                                          namespace=ri.ns_name())
            ip_wrapper.netns.execute(cmd, check_exit_code=False)
        else:
            utils.execute(cmd, check_exit_code=False,
                          root_helper=self.conf.root_helper)

    def routes_updated(self, ri):
        new_routes = ri.router['routes']
        old_routes = ri.routes
        adds, removes = common_utils.diff_list_of_dict(old_routes,
                                                       new_routes)
        for route in adds:
            LOG.debug(_("Added route entry is '%s'"), route)
            # remove replaced route from deleted route
            for del_route in removes:
                if route['destination'] == del_route['destination']:
                    removes.remove(del_route)
            #replace success even if there is no existing route
            self._update_routing_table(ri, 'replace', route)
            self._csr_update_routing_table(ri, 'replace', route)

        for route in removes:
            LOG.debug(_("Removed route entry is '%s'"), route)
            self._update_routing_table(ri, 'delete', route)
            self._csr_update_routing_table(ri, 'delete', route)
        ri.routes = new_routes


class L3NATAgentWithStateReport(L3NATAgent):

    def __init__(self, host, conf=None):
        super(L3NATAgentWithStateReport, self).__init__(host=host, conf=conf)
        self.state_rpc = agent_rpc.PluginReportStateAPI(topics.PLUGIN)
        self.agent_state = {
            'binary': 'quantum-l3-cfg-agent',
            'host': host,
            'topic': cl3_constants.L3_CFG_AGENT,
            'configurations': {
                'use_namespaces': self.conf.use_namespaces,
                'router_id': self.conf.router_id,
                'handle_internal_only_routers':
                self.conf.handle_internal_only_routers,
                'gateway_external_network_id':
                self.conf.gateway_external_network_id,
                'interface_driver': self.conf.interface_driver},
            'start_flag': True,
            'agent_type': cl3_constants.AGENT_TYPE_L3_CFG}
        report_interval = cfg.CONF.AGENT.report_interval
        if report_interval:
            self.heartbeat = loopingcall.FixedIntervalLoopingCall(
                self._report_state)
            self.heartbeat.start(interval=report_interval)

    def _report_state(self):
        num_ex_gw_ports = 0
        num_interfaces = 0
        num_floating_ips = 0
        router_infos = self.router_info.values()
        num_routers = len(router_infos)
        for ri in router_infos:
            ex_gw_port = self._get_ex_gw_port(ri)
            if ex_gw_port:
                num_ex_gw_ports += 1
            num_interfaces += len(ri.router.get(l3_constants.INTERFACE_KEY,
                                                []))
            num_floating_ips += len(ri.router.get(l3_constants.FLOATINGIP_KEY,
                                                  []))
        configurations = self.agent_state['configurations']
        configurations['routers'] = num_routers
        configurations['ex_gw_ports'] = num_ex_gw_ports
        configurations['interfaces'] = num_interfaces
        configurations['floating_ips'] = num_floating_ips
        try:
            self.state_rpc.report_state(self.context,
                                        self.agent_state)
            self.agent_state.pop('start_flag', None)
        except AttributeError:
            # This means the server does not support report_state
            LOG.warn(_("Quantum server does not support state report."
                       " State report for this agent will be disabled."))
            self.heartbeat.stop()
            return
        except Exception:
            LOG.exception(_("Failed reporting state!"))

    def agent_updated(self, context, payload):
        """Handle the agent_updated notification event."""
        self.fullsync = True
        LOG.info(_("agent_updated by server side %s!"), payload)


def main():
    #Hareesh
    #eventlet.monkey_patch()
    conf = cfg.CONF
    conf.register_opts(L3NATAgent.OPTS)
    config.register_agent_state_opts_helper(conf)
    config.register_root_helper(conf)
    conf.register_opts(interface.OPTS)
    conf.register_opts(external_process.OPTS)
    conf(project='quantum')
    config.setup_logging(conf)
    server = quantum_service.Service.create(
        binary='quantum-l3-agent',
        topic=topics.L3_AGENT,
        report_interval=cfg.CONF.AGENT.report_interval,
        manager='quantum.agent.l3_agent.L3NATAgentWithStateReport')
    service.launch(server).wait()
