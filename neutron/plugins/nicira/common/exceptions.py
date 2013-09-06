# vim: tabstop=4 shiftwidth=4 softtabstop=4

# Copyright 2012 Nicira Networks, Inc
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

"""NVP Plugin exceptions"""

from neutron.common import exceptions as q_exc


class NvpPluginException(q_exc.NeutronException):
    message = _("An unexpected error occurred in the NVP Plugin:%(err_msg)s")


class NvpInvalidVersion(NvpPluginException):
    message = _("Unable to fulfill request with version %(version)s.")


class NvpInvalidConnection(NvpPluginException):
    message = _("Invalid NVP connection parameters: %(conn_params)s")


class NvpInvalidClusterConfiguration(NvpPluginException):
    message = _("Invalid cluster values: %(invalid_attrs)s. Please ensure "
                "that these values are specified in the [DEFAULT] "
                "section of the nvp plugin ini file.")


class NvpInvalidNovaZone(NvpPluginException):
    message = _("Unable to find cluster config entry "
                "for nova zone: %(nova_zone)s")


class NvpNoMorePortsException(NvpPluginException):
    message = _("Unable to create port on network %(network)s. "
                "Maximum number of ports reached")


class NvpNatRuleMismatch(NvpPluginException):
    message = _("While retrieving NAT rules, %(actual_rules)s were found "
                "whereas rules in the (%(min_rules)s,%(max_rules)s) interval "
                "were expected")


class NvpInvalidAttachmentType(NvpPluginException):
    message = _("Invalid NVP attachment type '%(attachment_type)s'")


class MaintenanceInProgress(NvpPluginException):
    message = _("The networking backend is currently in maintenance mode and "
                "therefore unable to accept requests which modify its state. "
                "Please try later.")
