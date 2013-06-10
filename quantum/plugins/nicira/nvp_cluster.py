# vim: tabstop=4 shiftwidth=4 softtabstop=4

# Copyright 2012 Nicira, Inc.
# All Rights Reserved
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
# vim: tabstop=4 shiftwidth=4 softtabstop=4
#

from oslo.config import cfg

from quantum.openstack.common import log as logging
from quantum.plugins.nicira.common import exceptions

LOG = logging.getLogger(__name__)
DEFAULT_PORT = 443
# Raise if one of those attributes is not specified
REQUIRED_ATTRIBUTES = ['default_tz_uuid', 'nvp_user',
                       'nvp_password', 'nvp_controllers']
# Emit a INFO log if one of those attributes is not specified
IMPORTANT_ATTRIBUTES = ['default_l3_gw_service_uuid']
# Deprecated attributes
DEPRECATED_ATTRIBUTES = ['metadata_dhcp_host_route',
                         'nvp_controller_connection']


class NVPCluster(object):
    """NVP cluster class.

    Encapsulates controller connections and the API client for a NVP cluster.
    Accessed within the NvpPluginV2 class.

    Controller-specific parameters, such as timeouts are stored in the
    elements of the controllers attribute, which are dicts.
    """

    def __init__(self, **kwargs):
        self._required_attributes = REQUIRED_ATTRIBUTES[:]
        self._important_attributes = IMPORTANT_ATTRIBUTES[:]
        self._deprecated_attributes = {}
        self._sanity_check(kwargs)

        for opt, val in self._deprecated_attributes.iteritems():
            LOG.deprecated(_("Attribute '%s' has been deprecated or moved "
                             "to a new section. See new configuration file "
                             "for details."), opt)
            depr_func = getattr(self, '_process_%s' % opt, None)
            if depr_func:
                depr_func(val)

        # If everything went according to plan these two lists should be empty
        if self._required_attributes:
            raise exceptions.NvpInvalidClusterConfiguration(
                invalid_attrs=self._required_attributes)
        if self._important_attributes:
            LOG.info(_("The following cluster attributes were "
                       "not specified: %s'"), self._important_attributes)
        # The API client will be explicitly created by users of this class
        self.api_client = None

    def _sanity_check(self, options):
        # Iterating this way ensures the conf parameters also
        # define the structure of this class
        for arg in cfg.CONF:
            if arg not in DEPRECATED_ATTRIBUTES:
                setattr(self, arg, options.get(arg, cfg.CONF.get(arg)))
                self._process_attribute(arg)
            elif options.get(arg) is not None:
                # Process deprecated attributes only if specified
                self._deprecated_attributes[arg] = options.get(arg)
            if arg.startswith("CLUSTER:"):
                cluster_section = cfg.CONF.get(arg)
                for option in cluster_section:
                    v = cluster_section.get(option)
                    if option not in DEPRECATED_ATTRIBUTES:
                        # option may be in dict, but with None value
                        setattr(self, option, options.get(option) or v)
                        self._process_attribute(option)
                    else:
                        self._deprecated_attributes[option] = v

    def _process_attribute(self, attribute):
        # Process the attribute only if it's not empty!
        if getattr(self, attribute, None):
            if attribute in self._required_attributes:
                self._required_attributes.remove(attribute)
            if attribute in self._important_attributes:
                self._important_attributes.remove(attribute)
            handler_func = getattr(self, '_process_%s' % attribute, None)
            if handler_func:
                handler_func()
        else:
            LOG.info(_("Attribute:%s is empty or null"), attribute)

    def _process_nvp_controllers(self):
        # If this raises something is not right, so let it bubble up
        # TODO(salvatore-orlando): Also validate attribute here
        for i, ctrl in enumerate(self.nvp_controllers or []):
            if len(ctrl.split(':')) == 1:
                self.nvp_controllers[i] = '%s:%s' % (ctrl, DEFAULT_PORT)

    def _process_nvp_controller_connection(self, connections):

        def parse_conn_str(ip, port, user, password, req_timeout,
                           http_timeout, retries, redirects):
            # TODO(salvatore-orlando): Set the attributes only
            # if correspondent non-deprecated options have been
            # explicitly specified in the ini file
            # TODO(salvatore-orlando): Validate data to avoid ugly ValueError
            self.nvp_user = user
            self._process_attribute('nvp_user')
            self.nvp_password = password
            self._process_attribute('nvp_password')
            self.req_timeout = int(req_timeout)
            self._process_attribute('req_timeout')
            self.http_timeout = int(http_timeout)
            self._process_attribute('http_timeout')
            self.retries = int(retries)
            self._process_attribute('retries')
            self.redirects = int(redirects)
            self._process_attribute('redirects')
            try:
                nvp_controllers = getattr(self, 'nvp_controllers')
                nvp_controllers.append('%s:%s' % (ip, port))
            except AttributeError:
                self.nvp_controllers = ['%s:%s' % (ip, port)]
                self._process_attribute('nvp_controllers')
        for conn in connections:
            parse_conn_str(*conn.split(':'))
