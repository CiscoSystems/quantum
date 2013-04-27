PORT_VLAN_SET_FLOW_XML ="""
<flowConfig>
    <node id="%s" type="OF" />
    <ingressPort>%s</ingressPort>
    <name>%s</name>
    <vlanId>1</vlanId>
    <priority>1</priority>
    <actions>mod_vlan_vid:%s</actions>
    <actions>NORMAL</actions>
    <actions>OUTPUT:%s</actions>
</flowConfig>
"""
