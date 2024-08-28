#/bin/bash
result=`grep TLSVerifyClient /etc/openldap/slapd.conf`
echo $result
if [[ $result != "" ]]; then
   find "/etc/openldap" -name slapd.conf|xargs sed -i "s/^TLSVerifyClient.*/TLSVerifyClient demand/g"
else 
   echo "TLSVerifyClient demand" >>  /etc/openldap/slapd.conf
fi
find "/etc/sysconfig" -name openldap|xargs sed -i "s/^OPENLDAP_START_LDAPS.*/OPENLDAP_START_LDAPS=\"yes\"/g"
