# vim: tabstop=4 shiftwidth=4 softtabstop=4
#
# Copyright 2013 Cisco Systems, Inc.  All rights reserved.
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
# @author: Arvind Somya, Cisco Systems, Inc.
# @author: Kyle Mestery, Cisco Systems, Inc.

SWITCH_NORMAL_XML = """
<flowConfig>
    <node id="%s" type="OF" />
    <name>%s</name>
    <priority>%s</priority>
    <actions>NORMAL</actions>
</flowConfig>
"""

PORT_DROP_PACKET_XML = """
<flowConfig>
    <node id="%s" type="OF" />
    <ingressPort>%s</ingressPort>
    <name>%s</name>
    <priority>%d</priority>
    <actions>drop</actions>
</flowConfig>
"""

PORT_VLAN_SET_FLOW_XML = """
<flowConfig>
    <node id="%s" type="OF" />
    <ingressPort>%s</ingressPort>
    <name>%s</name>
    <priority>%d</priority>
    <etherType>0x800</etherType>
    <actions>SET_VLAN_ID=%s</actions>
    <actions>SET_VLAN_PCP=0</actions>
    <actions>HW_PATH</actions>
</flowConfig>
"""

INT_PORT_POP_VLAN_XML = """
<flowConfig>
    <node id="%s" type="OF" />
    <name>%s</name>
    <priority>%d</priority>
    <vlanId>%s</vlanId>
    <actions>POP_VLAN</actions>
    <actions>OUTPUT=%s</actions>
    <actions>HW_PATH</actions>
</flowConfig>
"""

PORT_DHCP_FLOW_XML = """
<flowConfig>
    <node id="%s" type="OF" />
    <ingressPort>%s</ingressPort>
    <name>%s</name>
    <etherType>0x800</etherType>
    <priority>%d</priority>
    <actions>OUTPUT=%s</actions>
    <actions>HW_PATH</actions>
</flowConfig>
"""

PORT_GATEWAY_FLOW_XML = """
<flowConfig>
    <node id="%s" type="OF" />
    <ingressPort>%s</ingressPort>
    <name>%s</name>
    <etherType>0x800</etherType>
    <nwDst>%s</nwDst>
    <priority>%s</priority>
    <actions>POP_VLAN</actions>
    <actions>CONTROLLER</actions>
    <actions>HW_PATH</actions>
</flowConfig>
"""
