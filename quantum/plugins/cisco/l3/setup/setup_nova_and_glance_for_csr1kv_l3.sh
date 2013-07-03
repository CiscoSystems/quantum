#!/bin/bash

# Default values
# --------------
adminUser="admin"
l3AdminTenant="L3AdminTenant"
csr1kvFlavorName="csr1kv_router"
csr1kvFlavorId=621
networkHostsAggregateName="compute_network_hosts"
aggregateMetadataKey="network_host"
aggregateMetadataValue="True"
aggregateMetadata=$aggregateMetadataKey"="$aggregateMetadataValue
computeNetworkNodes=(ComputeNode1 ComputeNode3)
csr1kvImageSrc="/home/stack/csr1000v-XE310_Throttle_20130506.qcow2"
csr1kvImageName="csr1kv_openstack_img"
#csr1kvImageName='cirros-0.3.0-x86_64-uec'
csr1kvDiskFormat="qcow2"
csr1kvContainerFormat="bare"
csr1kvGlanceExtraParams="--property hw_vif_model=e1000 --property hw_disk_bus=ide --property hw_cdrom_bus=ide"

tenantId=`keystone tenant-get $l3AdminTenant 2>&1 | awk '/No tenant|id/ { if ($1 == "No") print "No"; else print $4; }'`
if [ "$tenantId" == "No" ]; then
   echo "No $l3AdminTenant exists, please create one using the setup_keystone... script then re-run this script."
   echo "Aborting!"
   exit 1
fi


source ~/devstack/openrc $adminUser $L3adminTenant


echo -n "Checking if $csr1kvFlavorName flavor exists ..."
flavorId=`nova flavor-show $csr1kvFlavorId 2>&1 | awk '/No flavor|id/ { if ($2 == "No") print "No"; else print $4; }'`

if [ "$flavorId" == "No" ]; then
   echo " No, it does not. Creating it."
   flavorId=`nova flavor-create $csr1kvFlavorName $csr1kvFlavorId 8192 8 4 --is-public False | awk -v r=$csr1kvFlavorName '$0 ~ r { print $2 }'`
else
   echo " Yes, it does."
fi


echo -n "Checking if flavor $csr1kvFlavorName has metadata $aggregateMetadata ..."
hasMetadata=`nova flavor-show 621 | awk -v key=$aggregateMetadataKey -v value=$aggregateMetadataValue 'BEGIN { res = "No" } { if ($2 == "extra_specs" && index($4, key) > 0  && index($5, value) > 0) res = "Yes" } END { print res }'`

if [ "$hasMetadata" == "No" ]; then
   echo " No, it does not. Adding it."
   nova flavor-key $csr1kvFlavorId set $aggregateMetadata > /dev/null 2>&1
else 
   echo " Yes, it does."
fi


echo -n "Checking if $networkHostsAggregateName aggregate exists ..."
aggregateId=`nova aggregate-list 2>&1 | awk -v name=$networkHostsAggregateName -v r=$networkHostsAggregateName"|Id" 'BEGIN { res = "No" } $0 ~ r { if ($2 != "Id" && $4 == name) res = $2; } END { print res; }'`

if [ "$aggregateId" == "No" ]; then
   echo " No, it does not. Creating it."
   aggregateId=`nova aggregate-create $networkHostsAggregateName 2>&1 | awk -v name=$networkHostsAggregateName -v r=$networkHostsAggregateName"|Id" 'BEGIN { res = "No" } $0 ~ r { if ($2 != "Id" && $4 == name) res = $2; } END { print res; }'`
  echo $aggregateId
else
   echo " Yes, it does."
fi


echo "Setting metadata for aggregate" $networkHostsAggregateName
nova aggregate-set-metadata $aggregateId $aggregateMetadata > /dev/null 2>&1


echo "Configuring compute nodes to act as network hosts ..."

for host in ${computeNetworkNodes[*]}
do
   host_exists=`nova host-describe $host 2>&1 | awk 'BEGIN { res = "Yes" } /ERROR/ { if ($1 == "ERROR:") res = "No"; } END { print res; } '` 
   if [ "$host_exists" == "Yes" ]; then
       host_added=`nova aggregate-details $aggregateId 2>&1 | awk -v host=$host 'BEGIN { res = "No" } { if (index($8, host) > 0) res = "Yes"; } END { print res }'`
       if [ "$host_added" == "No" ]; then
           echo "    Adding host" $host "to" $networkHostsAggregateName "aggregate"
           nova aggregate-add-host $aggregateId $host > /dev/null 2>&1
       else
           echo "    Skipping host" $host "since it has already been added"
       fi
   else
       echo "    Skipping host" $host "which is not up"
   fi
done


echo -n "Checking if $csr1kvImageName image exists ..."
hasImage=`glance image-show $csr1kvImageName 2>&1 | awk '/Property|No/ { if ($1 == "No") print "No"; else print "Yes"; }'`

if [ "$hasImage" == "No" ]; then
   echo " No, it does not. Creating it."
   echo "glance image-create --name $csr1kvImageName --owner $tenantId --disk-format $csr1kvDiskFormat --container-format $csr1kvContainerFormat --file $csr1kvImageSrc $csr1kvGlanceExtraParams"
else
   echo " Yes, it does."
fi

