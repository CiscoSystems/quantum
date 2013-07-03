#!/bin/bash

# Default values
# --------------
adminUser="admin"
l3AdminTenant="L3AdminTenant"
osnMgmtNw="osn_mgmt_nw"
mgmtSecGrp="mgmt_sec_grp"
mgmtProviderNwName="mgmt_net"
mgmtProviderVlanId=140
osnMgmtSubnetName="mgmt_subnet"
osnMgmtSubnet="10.0.100.0/24"
osnMgmtRangeStart="10.0.100.10"
osnMgmtRangeEnd="10.0.100.254"


tenantId=`keystone tenant-get $l3AdminTenant 2>&1 | awk '/No tenant|id/ { if ($1 == "No") print "No"; else print $4; }'`
if [ "$tenantId" == "No" ]; then
   echo "No $l3AdminTenant exists, please create one using the setup_keystone... script then re-run this script."
   echo "Aborting!"
   exit 1
fi


source ~/devstack/openrc $adminUser $L3adminTenant


echo -n "Checking if $osnMgmtNw network exists ..."
hasMgmtNetwork=`quantum net-show $osnMgmtNw 2>&1 | awk '/Unable to find|enabled/ { if ($1 == "Unable") print "No"; else print "Yes"; }'`

if [ "$hasMgmtNetwork" == "No" ]; then
   echo " No, it does not. Creating it."
   quantum net-create --tenant-id $tenantId $osnMgmtNw --provider:network_type vlan --provider:physical_network pvnet1 --provider:segmentation_id $mgmtProviderVlanId
else
   echo " Yes, it does."
fi


echo -n "Checking if $osnMgmtSubnetName subnet exists ..."
hasMgmtSubnet=`quantum subnet-show $osnMgmtSubnetName 2>&1 | awk '/Unable to find|Value/ { if ($1 == "Unable") print "No"; else print "Yes"; }'`

if [ "$hasMgmtSubnet" == "No" ]; then
   echo " No, it does not. Creating it."
    quantum subnet-create --name $osnMgmtSubnetName --tenant-id $tenantId --allocation-pool start=$osnMgmtRangeStart,end=$osnMgmtRangeEnd $osnMgmtNw $osnMgmtSubnet
else
   echo " Yes, it does."
fi


echo -n "Checking if $mgmtSecGrp security group exists ..."
hasMgmtSecGrp=`quantum security-group-show $mgmtSecGrp 2>&1 | awk '/Unable to find|Value/ { if ($1 == "Unable") print "No"; else print "Yes"; }'`

if [ "$hasMgmtSecGrp" == "No" ]; then
   echo " No, it does not. Creating it."
    quantum security-group-create --description "For CSR1kv management network" --tenant-id $tenantId $mgmtSecGrp
else
   echo " Yes, it does."
fi


proto="icmp"
echo -n "Checking if $mgmtSecGrp security group has $proto rule ..."
def=`quantum security-group-rule-list | awk -v grp=$mgmtSecGrp -v p=$proto  '/'"$proto"'|protocol/ { if ($4 == grp && $8 == p && $10 == "0.0.0.0/0") n++; } END { if (n > 0) print "Yes"; else print "No"; }'`
if [ "$def" == "No" ]; then
   echo " No, it does not. Creating it."
    quantum security-group-rule-create --tenant-id $tenantId --protocol icmp --remote-ip-prefix 0.0.0.0/0 $mgmtSecGrp
else
   echo " Yes, it does."
fi


proto="tcp"
echo -n "Checking if $mgmtSecGrp security group has $proto rule ..."
def=`quantum security-group-rule-list | awk -v grp=$mgmtSecGrp -v p=$proto '/'"$proto"'|protocol/ { if ($4 == grp && $8 == p && $10 == "0.0.0.0/0") n++; } END { if (n > 0) print "Yes"; else print "No"; }'`
if [ "$def" == "No" ]; then
   echo " No, it does not. Creating it."
    quantum security-group-rule-create --tenant-id $tenantId --protocol tcp --port-range-min 22 --port-range-max 22 --remote-ip-prefix 0.0.0.0/0 $mgmtSecGrp
else
   echo " Yes, it does."
fi

