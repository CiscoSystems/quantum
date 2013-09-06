# vim: tabstop=4 shiftwidth=4 softtabstop=4

# Copyright 2012 OpenStack Foundation
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

import abc
import os
import re
import shutil
import socket
import StringIO
import sys
import uuid

import netaddr
from oslo.config import cfg

from neutron.agent.linux import ip_lib
from neutron.agent.linux import utils
from neutron.common import exceptions
from neutron.openstack.common import importutils
from neutron.openstack.common import jsonutils
from neutron.openstack.common import log as logging
from neutron.openstack.common import uuidutils

LOG = logging.getLogger(__name__)

OPTS = [
    cfg.StrOpt('dhcp_confs',
               default='$state_path/dhcp',
               help=_('Location to store DHCP server config files')),
    cfg.StrOpt('dhcp_domain',
               default='openstacklocal',
               help=_('Domain to use for building the hostnames')),
    cfg.StrOpt('dnsmasq_config_file',
               default='',
               help=_('Override the default dnsmasq settings with this file')),
    cfg.StrOpt('dnsmasq_dns_server',
               help=_('Use another DNS server before any in '
                      '/etc/resolv.conf.')),
    cfg.StrOpt('interface_driver',
               help=_("The driver used to manage the virtual interface.")),
]

IPV4 = 4
IPV6 = 6
UDP = 'udp'
TCP = 'tcp'
DNS_PORT = 53
DHCPV4_PORT = 67
DHCPV6_PORT = 547
METADATA_DEFAULT_PREFIX = 16
METADATA_DEFAULT_IP = '169.254.169.254'
METADATA_DEFAULT_CIDR = '%s/%d' % (METADATA_DEFAULT_IP,
                                   METADATA_DEFAULT_PREFIX)
METADATA_PORT = 80
WIN2k3_STATIC_DNS = 249
NS_PREFIX = 'qdhcp-'


class DictModel(object):
    """Convert dict into an object that provides attribute access to values."""
    def __init__(self, d):
        for key, value in d.iteritems():
            if isinstance(value, list):
                value = [DictModel(item) if isinstance(item, dict) else item
                         for item in value]
            elif isinstance(value, dict):
                value = DictModel(value)

            setattr(self, key, value)


class NetModel(DictModel):

    def __init__(self, use_namespaces, d):
        super(NetModel, self).__init__(d)

        self._ns_name = (use_namespaces and
                         "%s%s" % (NS_PREFIX, self.id) or None)

    @property
    def namespace(self):
        return self._ns_name


class DhcpBase(object):
    __metaclass__ = abc.ABCMeta

    def __init__(self, conf, network, root_helper='sudo',
                 version=None, plugin=None):
        self.conf = conf
        self.network = network
        self.root_helper = root_helper
        self.device_manager = DeviceManager(self.conf,
                                            self.root_helper, plugin)
        self.version = version

    @abc.abstractmethod
    def enable(self):
        """Enables DHCP for this network."""

    @abc.abstractmethod
    def disable(self, retain_port=False):
        """Disable dhcp for this network."""

    def restart(self):
        """Restart the dhcp service for the network."""
        self.disable(retain_port=True)
        self.enable()
        self.device_manager.update(self.network)

    @abc.abstractproperty
    def active(self):
        """Boolean representing the running state of the DHCP server."""

    @abc.abstractmethod
    def release_lease(self, mac_address, removed_ips):
        """Release a DHCP lease."""

    @abc.abstractmethod
    def reload_allocations(self):
        """Force the DHCP server to reload the assignment database."""

    @classmethod
    def existing_dhcp_networks(cls, conf, root_helper):
        """Return a list of existing networks ids that we have configs for."""

        raise NotImplementedError

    @classmethod
    def check_version(cls):
        """Execute version checks on DHCP server."""

        raise NotImplementedError


class DhcpLocalProcess(DhcpBase):
    PORTS = []

    def _enable_dhcp(self):
        """check if there is a subnet within the network with dhcp enabled."""
        for subnet in self.network.subnets:
            if subnet.enable_dhcp:
                return True
        return False

    def enable(self):
        """Enables DHCP for this network by spawning a local process."""
        interface_name = self.device_manager.setup(self.network,
                                                   reuse_existing=True)
        if self.active:
            self.restart()
        elif self._enable_dhcp():
            self.interface_name = interface_name
            self.spawn_process()

    def disable(self, retain_port=False):
        """Disable DHCP for this network by killing the local process."""
        pid = self.pid

        if self.active:
            cmd = ['kill', '-9', pid]
            utils.execute(cmd, self.root_helper)
            if not retain_port:
                self.device_manager.destroy(self.network, self.interface_name)

        elif pid:
            LOG.debug(_('DHCP for %(net_id)s pid %(pid)d is stale, ignoring '
                        'command'), {'net_id': self.network.id, 'pid': pid})
        else:
            LOG.debug(_('No DHCP started for %s'), self.network.id)

        self._remove_config_files()

    def _remove_config_files(self):
        confs_dir = os.path.abspath(os.path.normpath(self.conf.dhcp_confs))
        conf_dir = os.path.join(confs_dir, self.network.id)
        shutil.rmtree(conf_dir, ignore_errors=True)

    def get_conf_file_name(self, kind, ensure_conf_dir=False):
        """Returns the file name for a given kind of config file."""
        confs_dir = os.path.abspath(os.path.normpath(self.conf.dhcp_confs))
        conf_dir = os.path.join(confs_dir, self.network.id)
        if ensure_conf_dir:
            if not os.path.isdir(conf_dir):
                os.makedirs(conf_dir, 0o755)

        return os.path.join(conf_dir, kind)

    def _get_value_from_conf_file(self, kind, converter=None):
        """A helper function to read a value from one of the state files."""
        file_name = self.get_conf_file_name(kind)
        msg = _('Error while reading %s')

        try:
            with open(file_name, 'r') as f:
                try:
                    return converter and converter(f.read()) or f.read()
                except ValueError:
                    msg = _('Unable to convert value in %s')
        except IOError:
            msg = _('Unable to access %s')

        LOG.debug(msg % file_name)
        return None

    @property
    def pid(self):
        """Last known pid for the DHCP process spawned for this network."""
        return self._get_value_from_conf_file('pid', int)

    @property
    def active(self):
        pid = self.pid
        if pid is None:
            return False

        cmd = ['cat', '/proc/%s/cmdline' % pid]
        try:
            return self.network.id in utils.execute(cmd, self.root_helper)
        except RuntimeError:
            return False

    @property
    def interface_name(self):
        return self._get_value_from_conf_file('interface')

    @interface_name.setter
    def interface_name(self, value):
        interface_file_path = self.get_conf_file_name('interface',
                                                      ensure_conf_dir=True)
        utils.replace_file(interface_file_path, value)

    @abc.abstractmethod
    def spawn_process(self):
        pass


class Dnsmasq(DhcpLocalProcess):
    # The ports that need to be opened when security policies are active
    # on the Neutron port used for DHCP.  These are provided as a convenience
    # for users of this class.
    PORTS = {IPV4: [(UDP, DNS_PORT), (TCP, DNS_PORT), (UDP, DHCPV4_PORT)],
             IPV6: [(UDP, DNS_PORT), (TCP, DNS_PORT), (UDP, DHCPV6_PORT)],
             }

    _TAG_PREFIX = 'tag%d'

    NEUTRON_NETWORK_ID_KEY = 'NEUTRON_NETWORK_ID'
    NEUTRON_RELAY_SOCKET_PATH_KEY = 'NEUTRON_RELAY_SOCKET_PATH'
    MINIMUM_VERSION = 2.59

    @classmethod
    def check_version(cls):
        ver = 0
        try:
            cmd = ['dnsmasq', '--version']
            out = utils.execute(cmd)
            ver = re.findall("\d+.\d+", out)[0]
            is_valid_version = float(ver) >= cls.MINIMUM_VERSION
            if not is_valid_version:
                LOG.warning(_('FAILED VERSION REQUIREMENT FOR DNSMASQ. '
                              'DHCP AGENT MAY NOT RUN CORRECTLY! '
                              'Please ensure that its version is %s '
                              'or above!'), cls.MINIMUM_VERSION)
        except (OSError, RuntimeError, IndexError, ValueError):
            LOG.warning(_('Unable to determine dnsmasq version. '
                          'Please ensure that its version is %s '
                          'or above!'), cls.MINIMUM_VERSION)
        return float(ver)

    @classmethod
    def existing_dhcp_networks(cls, conf, root_helper):
        """Return a list of existing networks ids that we have configs for."""

        confs_dir = os.path.abspath(os.path.normpath(conf.dhcp_confs))

        class FakeNetwork:
            def __init__(self, net_id):
                self.id = net_id

        return [
            c for c in os.listdir(confs_dir)
            if (uuidutils.is_uuid_like(c) and
                cls(conf, FakeNetwork(c), root_helper).active)
        ]

    def spawn_process(self):
        """Spawns a Dnsmasq process for the network."""
        env = {
            self.NEUTRON_NETWORK_ID_KEY: self.network.id,
        }

        cmd = [
            'dnsmasq',
            '--no-hosts',
            '--no-resolv',
            '--strict-order',
            '--bind-interfaces',
            '--interface=%s' % self.interface_name,
            '--except-interface=lo',
            '--pid-file=%s' % self.get_conf_file_name(
                'pid', ensure_conf_dir=True),
            #TODO (mark): calculate value from cidr (defaults to 150)
            #'--dhcp-lease-max=%s' % ?,
            '--dhcp-hostsfile=%s' % self._output_hosts_file(),
            '--dhcp-optsfile=%s' % self._output_opts_file(),
            '--leasefile-ro',
        ]

        for i, subnet in enumerate(self.network.subnets):
            # if a subnet is specified to have dhcp disabled
            if not subnet.enable_dhcp:
                continue
            if subnet.ip_version == 4:
                mode = 'static'
            else:
                # TODO(mark): how do we indicate other options
                # ra-only, slaac, ra-nameservers, and ra-stateless.
                mode = 'static'
            if self.version >= self.MINIMUM_VERSION:
                set_tag = 'set:'
            else:
                set_tag = ''
            cmd.append('--dhcp-range=%s%s,%s,%s,%ss' %
                       (set_tag, self._TAG_PREFIX % i,
                        netaddr.IPNetwork(subnet.cidr).network,
                        mode,
                        self.conf.dhcp_lease_duration))

        cmd.append('--conf-file=%s' % self.conf.dnsmasq_config_file)
        if self.conf.dnsmasq_dns_server:
            cmd.append('--server=%s' % self.conf.dnsmasq_dns_server)

        if self.conf.dhcp_domain:
            cmd.append('--domain=%s' % self.conf.dhcp_domain)

        if self.network.namespace:
            ip_wrapper = ip_lib.IPWrapper(self.root_helper,
                                          self.network.namespace)
            ip_wrapper.netns.execute(cmd, addl_env=env)
        else:
            # For normal sudo prepend the env vars before command
            cmd = ['%s=%s' % pair for pair in env.items()] + cmd
            utils.execute(cmd, self.root_helper)

    def release_lease(self, mac_address, removed_ips):
        """Release a DHCP lease."""
        for ip in removed_ips or []:
            cmd = ['dhcp_release', self.interface_name, ip, mac_address]
            if self.network.namespace:
                ip_wrapper = ip_lib.IPWrapper(self.root_helper,
                                              self.network.namespace)
                ip_wrapper.netns.execute(cmd)
            else:
                utils.execute(cmd, self.root_helper)

    def reload_allocations(self):
        """Rebuild the dnsmasq config and signal the dnsmasq to reload."""

        # If all subnets turn off dhcp, kill the process.
        if not self._enable_dhcp():
            self.disable()
            LOG.debug(_('Killing dhcpmasq for network since all subnets have '
                        'turned off DHCP: %s'), self.network.id)
            return

        self._output_hosts_file()
        self._output_opts_file()
        if self.active:
            cmd = ['kill', '-HUP', self.pid]
            utils.execute(cmd, self.root_helper)
        else:
            LOG.debug(_('Pid %d is stale, relaunching dnsmasq'), self.pid)
        LOG.debug(_('Reloading allocations for network: %s'), self.network.id)
        self.device_manager.update(self.network)

    def _output_hosts_file(self):
        """Writes a dnsmasq compatible hosts file."""
        r = re.compile('[:.]')
        buf = StringIO.StringIO()

        for port in self.network.ports:
            for alloc in port.fixed_ips:
                name = 'host-%s.%s' % (r.sub('-', alloc.ip_address),
                                       self.conf.dhcp_domain)
                set_tag = ''
                if getattr(port, 'extra_dhcp_opts', False):
                    if self.version >= self.MINIMUM_VERSION:
                        set_tag = 'set:'

                    buf.write('%s,%s,%s,%s%s\n' %
                              (port.mac_address, name, alloc.ip_address,
                               set_tag, port.id))
                else:
                    buf.write('%s,%s,%s\n' %
                              (port.mac_address, name, alloc.ip_address))

        name = self.get_conf_file_name('host')
        utils.replace_file(name, buf.getvalue())
        return name

    def _output_opts_file(self):
        """Write a dnsmasq compatible options file."""

        if self.conf.enable_isolated_metadata:
            subnet_to_interface_ip = self._make_subnet_interface_ip_map()

        options = []
        for i, subnet in enumerate(self.network.subnets):
            if not subnet.enable_dhcp:
                continue
            if subnet.dns_nameservers:
                options.append(
                    self._format_option(i, 'dns-server',
                                        ','.join(subnet.dns_nameservers)))

            gateway = subnet.gateway_ip
            host_routes = []
            for hr in subnet.host_routes:
                if hr.destination == "0.0.0.0/0":
                    gateway = hr.nexthop
                else:
                    host_routes.append("%s,%s" % (hr.destination, hr.nexthop))

            # Add host routes for isolated network segments
            enable_metadata = (
                self.conf.enable_isolated_metadata
                and not subnet.gateway_ip
                and subnet.ip_version == 4)

            if enable_metadata:
                subnet_dhcp_ip = subnet_to_interface_ip[subnet.id]
                host_routes.append(
                    '%s/32,%s' % (METADATA_DEFAULT_IP, subnet_dhcp_ip)
                )

            if host_routes:
                options.append(
                    self._format_option(i, 'classless-static-route',
                                        ','.join(host_routes)))
                options.append(
                    self._format_option(i, WIN2k3_STATIC_DNS,
                                        ','.join(host_routes)))

            if subnet.ip_version == 4:
                if gateway:
                    options.append(self._format_option(i, 'router', gateway))
                else:
                    options.append(self._format_option(i, 'router'))

        for port in self.network.ports:
            if getattr(port, 'extra_dhcp_opts', False):
                options.extend(
                    self._format_option(port.id, opt.opt_name, opt.opt_value)
                    for opt in port.extra_dhcp_opts)

        name = self.get_conf_file_name('opts')
        utils.replace_file(name, '\n'.join(options))
        return name

    def _make_subnet_interface_ip_map(self):
        ip_dev = ip_lib.IPDevice(
            self.interface_name,
            self.root_helper,
            self.network.namespace
        )

        subnet_lookup = dict(
            (netaddr.IPNetwork(subnet.cidr), subnet.id)
            for subnet in self.network.subnets
        )

        retval = {}

        for addr in ip_dev.addr.list():
            ip_net = netaddr.IPNetwork(addr['cidr'])

            if ip_net in subnet_lookup:
                retval[subnet_lookup[ip_net]] = addr['cidr'].split('/')[0]

        return retval

    def _format_option(self, tag, option, *args):
        """Format DHCP option by option name or code."""
        if self.version >= self.MINIMUM_VERSION:
            set_tag = 'tag:'
        else:
            set_tag = ''

        option = str(option)

        if isinstance(tag, int):
            tag = self._TAG_PREFIX % tag

        if not option.isdigit():
            option = 'option:%s' % option

        return ','.join((set_tag + tag, '%s' % option) + args)

    @classmethod
    def lease_update(cls):
        network_id = os.environ.get(cls.NEUTRON_NETWORK_ID_KEY)
        dhcp_relay_socket = os.environ.get(cls.NEUTRON_RELAY_SOCKET_PATH_KEY)

        action = sys.argv[1]
        if action not in ('add', 'del', 'old'):
            sys.exit()

        mac_address = sys.argv[2]
        ip_address = sys.argv[3]

        if action == 'del':
            lease_remaining = 0
        else:
            lease_remaining = int(os.environ.get('DNSMASQ_TIME_REMAINING', 0))

        data = dict(network_id=network_id, mac_address=mac_address,
                    ip_address=ip_address, lease_remaining=lease_remaining)

        if os.path.exists(dhcp_relay_socket):
            sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
            sock.connect(dhcp_relay_socket)
            sock.send(jsonutils.dumps(data))
            sock.close()


class DeviceManager(object):

    def __init__(self, conf, root_helper, plugin):
        self.conf = conf
        self.root_helper = root_helper
        self.plugin = plugin
        if not conf.interface_driver:
            raise SystemExit(_('You must specify an interface driver'))
        try:
            self.driver = importutils.import_object(
                conf.interface_driver, conf)
        except Exception as e:
            msg = (_("Error importing interface driver '%(driver)s': "
                   "%(inner)s") % {'driver': conf.interface_driver,
                                   'inner': e})
            raise SystemExit(msg)

    def get_interface_name(self, network, port):
        """Return interface(device) name for use by the DHCP process."""
        return self.driver.get_device_name(port)

    def get_device_id(self, network):
        """Return a unique DHCP device ID for this host on the network."""
        # There could be more than one dhcp server per network, so create
        # a device id that combines host and network ids

        host_uuid = uuid.uuid5(uuid.NAMESPACE_DNS, socket.gethostname())
        return 'dhcp%s-%s' % (host_uuid, network.id)

    def _get_device(self, network):
        """Return DHCP ip_lib device for this host on the network."""
        device_id = self.get_device_id(network)
        port = self.plugin.get_dhcp_port(network.id, device_id)
        interface_name = self.get_interface_name(network, port)
        return ip_lib.IPDevice(interface_name,
                               self.root_helper,
                               network.namespace)

    def _set_default_route(self, network):
        """Sets the default gateway for this dhcp namespace.

        This method is idempotent and will only adjust the route if adjusting
        it would change it from what it already is.  This makes it safe to call
        and avoids unnecessary perturbation of the system.
        """
        device = self._get_device(network)
        gateway = device.route.get_gateway()
        if gateway:
            gateway = gateway['gateway']

        for subnet in network.subnets:
            skip_subnet = (
                subnet.ip_version != 4
                or not subnet.enable_dhcp
                or subnet.gateway_ip is None)

            if skip_subnet:
                continue

            if gateway != subnet.gateway_ip:
                m = _('Setting gateway for dhcp netns on net %(n)s to %(ip)s')
                LOG.debug(m, {'n': network.id, 'ip': subnet.gateway_ip})

                device.route.add_gateway(subnet.gateway_ip)

            return

        # No subnets on the network have a valid gateway.  Clean it up to avoid
        # confusion from seeing an invalid gateway here.
        if gateway is not None:
            msg = _('Removing gateway for dhcp netns on net %s')
            LOG.debug(msg, network.id)

            device.route.delete_gateway(gateway)

    def setup_dhcp_port(self, network):
        """Create/update DHCP port for the host if needed and return port."""

        device_id = self.get_device_id(network)
        subnets = {}
        dhcp_enabled_subnet_ids = []
        for subnet in network.subnets:
            if subnet.enable_dhcp:
                dhcp_enabled_subnet_ids.append(subnet.id)
                subnets[subnet.id] = subnet

        dhcp_port = None
        for port in network.ports:
            port_device_id = getattr(port, 'device_id', None)
            if port_device_id == device_id:
                port_fixed_ips = []
                for fixed_ip in port.fixed_ips:
                    port_fixed_ips.append({'subnet_id': fixed_ip.subnet_id,
                                           'ip_address': fixed_ip.ip_address})
                    if fixed_ip.subnet_id in dhcp_enabled_subnet_ids:
                        dhcp_enabled_subnet_ids.remove(fixed_ip.subnet_id)

                # If there are dhcp_enabled_subnet_ids here that means that
                # we need to add those to the port and call update.
                if dhcp_enabled_subnet_ids:
                    port_fixed_ips.extend(
                        [dict(subnet_id=s) for s in dhcp_enabled_subnet_ids])
                    dhcp_port = self.plugin.update_dhcp_port(
                        port.id, {'port': {'fixed_ips': port_fixed_ips}})
                else:
                    dhcp_port = port
                # break since we found port that matches device_id
                break

        # DHCP port has not yet been created.
        if dhcp_port is None:
            LOG.debug(_('DHCP port %(device_id)s on network %(network_id)s'
                        ' does not yet exist.'), {'device_id': device_id,
                                                  'network_id': network.id})
            port_dict = dict(
                name='',
                admin_state_up=True,
                device_id=device_id,
                network_id=network.id,
                tenant_id=network.tenant_id,
                fixed_ips=[dict(subnet_id=s) for s in dhcp_enabled_subnet_ids])
            dhcp_port = self.plugin.create_dhcp_port({'port': port_dict})

        # Convert subnet_id to subnet dict
        fixed_ips = [dict(subnet_id=fixed_ip.subnet_id,
                          ip_address=fixed_ip.ip_address,
                          subnet=subnets[fixed_ip.subnet_id])
                     for fixed_ip in dhcp_port.fixed_ips]

        ips = [DictModel(item) if isinstance(item, dict) else item
               for item in fixed_ips]
        dhcp_port.fixed_ips = ips

        return dhcp_port

    def setup(self, network, reuse_existing=False):
        """Create and initialize a device for network's DHCP on this host."""
        port = self.setup_dhcp_port(network)
        interface_name = self.get_interface_name(network, port)

        if ip_lib.device_exists(interface_name,
                                self.root_helper,
                                network.namespace):
            if not reuse_existing:
                raise exceptions.PreexistingDeviceFailure(
                    dev_name=interface_name)

            LOG.debug(_('Reusing existing device: %s.'), interface_name)
        else:
            self.driver.plug(network.id,
                             port.id,
                             interface_name,
                             port.mac_address,
                             namespace=network.namespace)
        ip_cidrs = []
        for fixed_ip in port.fixed_ips:
            subnet = fixed_ip.subnet
            net = netaddr.IPNetwork(subnet.cidr)
            ip_cidr = '%s/%s' % (fixed_ip.ip_address, net.prefixlen)
            ip_cidrs.append(ip_cidr)

        if (self.conf.enable_isolated_metadata and
            self.conf.use_namespaces):
            ip_cidrs.append(METADATA_DEFAULT_CIDR)

        self.driver.init_l3(interface_name, ip_cidrs,
                            namespace=network.namespace)

        # ensure that the dhcp interface is first in the list
        if network.namespace is None:
            device = ip_lib.IPDevice(interface_name,
                                     self.root_helper)
            device.route.pullup_route(interface_name)

        if self.conf.use_namespaces:
            self._set_default_route(network)

        return interface_name

    def update(self, network):
        """Update device settings for the network's DHCP on this host."""
        if self.conf.use_namespaces:
            self._set_default_route(network)

    def destroy(self, network, device_name):
        """Destroy the device used for the network's DHCP on this host."""
        self.driver.unplug(device_name, namespace=network.namespace)

        self.plugin.release_dhcp_port(network.id,
                                      self.get_device_id(network))
