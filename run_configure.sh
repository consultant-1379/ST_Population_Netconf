#!/bin/bash -f

#
# run_configure.sh script for HSS-FE project
#
#
# REVISION B /
# VERSION 0.2 /
# DATE 2011-05-26 /
# AUTHOR rdcfaxs /
# COMMENTS  Adapted to HSS CBA ISM/SDA/AVG 
#
#
# REVISION A /
# VERSION 0.2 /
# DATE 2011-05-26 /
# AUTHOR ejoafra /
# COMMENTS  Adapted to prompt for a password 
#           if the password is missing
#
#
# REVISION A /
# VERSION 0.1 /
# DATE 2009-06-12 /
# AUTHOR ebeljea /
# COMMENTS First version
#

# Adaptation for IPv6 
# Andras Gyulai eandgyu
# 07/11/2017

###################################################################

if [ "$1" == "-h" ] ; then
   echo -e "\033[1m NAME\033[0m"
   echo "  run_configure.sh"
   echo -e "\033[1m SYNOPSIS\033[0m"
   echo "  run_configure.sh -h"
   echo -e "\033[1m DESCRIPTION\033[0m"
   echo "  Starts configuration for CBA node via Netconf interface"
   echo "  Configuration setting is in ism_sda_node.data file, no parameters"
   echo -e "\033[1m OPTIONS\033[0m"
   echo "  -h      prints command description"
   echo -e "\033[1m EXIT STATUS\033[0m"
   echo "  0       Command successfully executed or help text is displayed"
   echo "  >0      Failure in command. Sumary:"
   echo "  1       Error on run_configure.sh running path"
   echo "  2       No provisioning information on this download (no LDAP and no XML)"
   echo "  3       Error on provisioning process"
   echo -e "\033[1m BUGS\033[0m"
   echo "  run_configure.sh needs to be started on its own directory, because all needed files are"
   echo "  searched relatively to this path"
   echo -e "\033[1m DEBUG\033[0m"
   echo "  For debug please run the script with one of the following methods. Option -x for debug option -v for verbose"
   echo "  bash -x run_configure.sh"
   echo "  bash -xv run_configure.sh"

   exit 0
fi

#
# WARNING: run_configure.sh needs to be started on its own directory
#

echo
echo "Looking for run_configure.sh in this directory..."
echo

if [ ! -e run_configure.sh ] ; then
  echo
  echo "Actual path is:" `pwd`
  echo
  echo "ERROR: I cannot find run_configure.sh in this path."
  echo
  echo "Please, execute ./run_configure.sh in the path"
  echo "where the script is located."
  echo
  exit 1
fi

source ./ism_sda_node.data
echo "### CONFIGURATION PARAMS ###"
echo "MODULES      : ${MODULES[*]}"
echo "MODULES[@]   : ${#MODULES[@]}"
#echo "USER-TYPE    : ${USER_TYPE}"
#echo "ACTIVATE_A&A : ${ACTIVATE_AUTH_FEAT}"
echo "RE-POPULATION: ${RE_POPULATION}"
echo "DIA-PEER-NODES: ${DIA_PEER_NODES}"
echo "BASE VECTOR SUPPLIER: ${BASE_VECTOR_SUPPLIER}"
echo "NUM_PLS      : $NUM_PLS"
echo "VIPOAM_IPV4      : $VIPOAM_IPV4"
echo "RADDIA IPV4  : $RADDIA_IPV4"
echo "DIASCTP IPV4 : $DIASCTP_IPV4"
echo "LDAP_IPV4    : $LDAP_IPV4"
echo "EXTDB_IPV4   : $EXTDB_IPV4"
echo "IS_IPV6      : $IS_IPV6"
echo "SHA256_RSA4906 : $SHA256_RSA4906"

if [ "$IS_IPV6" == "TRUE" ]; then
  
  echo "RADDIA IPV6  : $RADDIA_IPV6"
  echo "DIASCTP IPV6 : $DIASCTP_IPV6"
  echo "VIPOAM_IPV6  : $VIPOAM_IPV6"
  echo "LDAP_IPV6    : $LDAP_IPV6"
  echo "EXTDB_IPV6   : $EXTDB_IPV6"
fi

# Analize license to activate 
license_ISMSDA=0
license_SM=0
license_ESM=0
license_AVG=0

if ((${#MODULES[@]} == 0 ))
  then echo "MODULES list array is empty. All modules will be activated."
  license_ISMSDA=1
  license_SM=1
  license_ESM=1
  license_AVG=1
else  
  for module in ${MODULES[*]}
  do
	case "$module" in
	  'ISMSDA') license_ISMSDA=1
	  ;;
	  'SM') license_SM=1
	  ;;
	  'ESM') license_ESM=1
	  ;;
	  'AVG') license_AVG=1
	  ;;
	  *) echo "Unknown module:$module"
	    echo "Valid modules are: ISMSDA SM ESM AVG"
	    exit 1
	esac
  done
fi



#
# Prepare RADVIP and EXTDB IP addaptation
#

rm -f ./node_configuration/temp_*
cp ./node_configuration/diameter1.xml ./node_configuration/temp_diameter1.xml
cp ./node_configuration/diameter2.xml ./node_configuration/temp_diameter2.xml
cp ./node_configuration/diameter4.xml ./node_configuration/temp_diameter4.xml
cp ./node_configuration/diameter5.xml ./node_configuration/temp_diameter5.xml
cp ./node_configuration/diameter6.xml ./node_configuration/temp_diameter6.xml
cp ./node_configuration/diameter_HSS_ESM_2.xml ./node_configuration/temp_diameter_HSS_ESM_2.xml
cp ./node_configuration/diameter_SM_1.xml ./node_configuration/temp_diameter_SM_1.xml
cp ./node_configuration/diameter_SM_4.xml ./node_configuration/temp_diameter_SM_4.xml

cp ./node_configuration/extdb_cudb.xml ./node_configuration/temp_extdb_cudb.xml
cp ./node_configuration/extdb_ldaps.xml ./node_configuration/temp_1_extdb_ldaps.xml
cp ./node_configuration/avg_0.xml ./node_configuration/temp_avg_0.xml
cp ./node_configuration/extldap.xml ./node_configuration/temp_extldap.xml
cp ./node_configuration/HSS_HTTP2_UDM_01.xml ./node_configuration/temp_HSS_HTTP2_UDM_01.xml
cp ./node_configuration/HSS_evip_02.xml ./node_configuration/temp_HSS_evip_02.xml
cp ./node_configuration/HSS_UDICOM_PATCH_SUPPORT.xml ./node_configuration/temp_HSS_UDICOM_PATCH_SUPPORT.xml
cp ./node_configuration/HSS_UDICOM_01.xml ./node_configuration/temp_HSS_UDICOM_01.xml
#cp ./node_configuration/radius_client1.xml ./node_configuration/temp_radius_client1_1.xml
#cp ./node_configuration/radius_client1.xml ./node_configuration/temp_radius_client1_2.xml
#cp ./node_configuration/radius_client1.xml ./node_configuration/temp_radius_client1_3.xml
#cp ./node_configuration/radius_client1.xml ./node_configuration/temp_radius_client1_4.xml
#cp ./node_configuration/radius_client1.xml ./node_configuration/temp_radius_client1_5.xml
#cp ./node_configuration/radius_client1.xml ./node_configuration/temp_radius_client1_6.xml
#cp ./node_configuration/radius_client1.xml ./node_configuration/temp_radius_client1_7.xml
#cp ./node_configuration/radius_client1.xml ./node_configuration/temp_radius_client1_8.xml
#cp ./node_configuration/radius_client2.xml ./node_configuration/temp_radius_client2.xml


## MPV-BeList deprecated https://udm-hss-jira.rnd.ki.sw.ericsson.se/browse/HSSDM-2861

#cp ./node_configuration/mpv4_esm.xml ./node_configuration/temp_mpv4_esm.xml
#cp ./node_configuration/mpv4_ism.xml ./node_configuration/temp_mpv4_ism.xml
#
# Prepare number of PLs addaptation
#
#if ([ "$NUM_PLS" != "10" ]); then
#    echo "Number of PLs:$NUM_PLS"
#    sed -i '7,$d' ./node_configuration/temp_mpv4_esm.xml
#    sed -i '7,$d' ./node_configuration/temp_mpv4_ism.xml
#    for((BE=1;BE<="$NUM_PLS";BE++))
#    do
#        echo "<mpv-BeList>$BE:$BE</mpv-BeList>" >> ./node_configuration/temp_mpv4_esm.xml
#        echo "<mpv-BeList>$BE:$BE</mpv-BeList>" >> ./node_configuration/temp_mpv4_ism.xml
#    done
#
#    echo '</MPV-AppInstance>' >> ./node_configuration/temp_mpv4_esm.xml
#    echo '</MPV-Application>' >> ./node_configuration/temp_mpv4_esm.xml
#    echo '</HSS-Function>' >> ./node_configuration/temp_mpv4_esm.xml
#    echo '</ManagedElement>' >> ./node_configuration/temp_mpv4_esm.xml
#
#    echo '</MPV-AppInstance>' >> ./node_configuration/temp_mpv4_ism.xml
#    echo '</MPV-Application>' >> ./node_configuration/temp_mpv4_ism.xml
#    echo '</HSS-Function>' >> ./node_configuration/temp_mpv4_ism.xml
#    echo '</ManagedElement>' >> ./node_configuration/temp_mpv4_ism.xml
#
#fi


## RADDIA Compose list with both IPv4 + IPv6 

## <ipAddressesList>OWN_NODE_CONFIG_IP_ADDR_LIST_TCP</ipAddressesList>
## <sctpAddressesList>OWN_NODE_CONFIG_IP_ADDR_LIST_SCTP</sctpAddressesList>

if [ "$IS_IPV6" == "TRUE" ]; then
  OWN_NODE_CONFIG_IP_ADDR_LIST_TCP="<ipAddressesList>0:$RADDIA_IPV4<\/ipAddressesList>\n<ipAddressesList>1:$RADDIA_IPV6<\/ipAddressesList>"
  
else
  OWN_NODE_CONFIG_IP_ADDR_LIST_TCP="<ipAddressesList>0:$RADDIA_IPV4<\/ipAddressesList>"
  
fi
echo "OWN_NODE_CONFIG_IP_ADDR_LIST_TCP: $OWN_NODE_CONFIG_IP_ADDR_LIST_TCP"
find ./node_configuration -name 'temp_diameter*' | xargs sed -i "s/.*OWN_NODE_CONFIG_IP_ADDR_LIST_TCP.*/$OWN_NODE_CONFIG_IP_ADDR_LIST_TCP/g"

## SCTP DIA Compose list with both IPv4 + IPv6 

if [ "$IS_IPV6" == "TRUE" ]; then
  OWN_NODE_CONFIG_IP_ADDR_LIST_SCTP="<sctpAddressesList>0:$DIASCTP_IPV4<\/sctpAddressesList>\n<sctpAddressesList>1:$DIASCTP_IPV6<\/sctpAddressesList>"
else
  OWN_NODE_CONFIG_IP_ADDR_LIST_SCTP="<sctpAddressesList>0:$DIASCTP_IPV4<\/sctpAddressesList>"
fi

echo "OWN_NODE_CONFIG_IP_ADDR_LIST_SCTP: $OWN_NODE_CONFIG_IP_ADDR_LIST_SCTP"
find ./node_configuration -name 'temp_diameter*' | xargs sed -i "s/.*OWN_NODE_CONFIG_IP_ADDR_LIST_SCTP.*/$OWN_NODE_CONFIG_IP_ADDR_LIST_SCTP/g"

## UDM configuration with both IPv4 + IPv6 

if [ "$IS_IPV6" == "TRUE" ]; then
  UDM_IP_ON_HSS="$UDM_IPV6"
else
  UDM_IP_ON_HSS="$UDM_IPV4"
fi

echo "UDM_IP_ON_HSS: $UDM_IP_ON_HSS"
find ./node_configuration -name 'temp_HSS_HTTP2_UDM_01*' | xargs sed -i "s/UDM_IP_ON_HSS/$UDM_IP_ON_HSS/g"
find ./node_configuration -name 'temp_HSS_UDICOM_01*' | xargs sed -i "s/UDM_IP_ON_HSS/$UDM_IP_ON_HSS/g"

if [ "$HTTP2_TLSMODE" == "0" ]; then
  echo "PORT_OF_UDICOM: $PORT_OF_UDICOM"
  find ./node_configuration -name 'temp_HSS_UDICOM_01*' | xargs sed -i "s/CLEARTEXT_PORT/$PORT_OF_UDICOM/g"
  find ./node_configuration -name 'temp_HSS_UDICOM_01*' | xargs sed -i "s/TLS_PORT/0/g"
  find ./node_configuration -name 'temp_HSS_UDICOM_01*' | xargs sed -i "s/TLS_MODE/MTLS/g"
elif [ "$HTTP2_TLSMODE" == "2" ]; then
  echo "PORT_OF_UDICOM_TLS: $PORT_OF_UDICOM_TLS"
  find ./node_configuration -name 'temp_HSS_UDICOM_01*' | xargs sed -i "s/CLEARTEXT_PORT/$PORT_OF_UDICOM/g"
  find ./node_configuration -name 'temp_HSS_UDICOM_01*' | xargs sed -i "s/TLS_PORT/$PORT_OF_UDICOM_TLS/g"
  find ./node_configuration -name 'temp_HSS_UDICOM_01*' | xargs sed -i "s/TLS_MODE/TLS/g"
elif [ "$HTTP2_TLSMODE" == "1" ]; then
  echo "PORT_OF_UDICOM_MTLS: $PORT_OF_UDICOM_TLS"
  find ./node_configuration -name 'temp_HSS_UDICOM_01*' | xargs sed -i "s/CLEARTEXT_PORT/$PORT_OF_UDICOM/g"
  find ./node_configuration -name 'temp_HSS_UDICOM_01*' | xargs sed -i "s/TLS_PORT/$PORT_OF_UDICOM_TLS/g"
  find ./node_configuration -name 'temp_HSS_UDICOM_01*' | xargs sed -i "s/TLS_MODE/MTLS/g"
fi

if [ "$IS_IPV6" == "TRUE" ]; then
  find ./node_configuration -name 'temp_HSS_evip_02*' | xargs sed -i "s/ipv4/ipv6/g"
  find ./node_configuration -name 'temp_HSS_evip_02*' | xargs sed -i "s/rest20/rest20_ipv6/g"
  find ./node_configuration -name 'temp_HSS_evip_02*' | xargs sed -i "s/rest21/rest21_ipv6/g"
fi

find ./node_configuration -name 'temp_HSS_evip_02*' | xargs sed -i "s/UDM_IP_ON_HSS/$UDM_IP_ON_HSS/g"
find ./node_configuration -name 'temp_HSS_evip_02*' | xargs sed -i "s/CLEARTEXT_PORT/$PORT_OF_UDICOM/g"
find ./node_configuration -name 'temp_HSS_evip_02*' | xargs sed -i "s/TLS_PORT/$PORT_OF_UDICOM_TLS/g"

echo "HTTP2_MAXOUTGOINGCONNECTIONS: $HTTP2_MAXOUTGOINGCONNECTIONS"
find ./node_configuration -name 'temp_HSS_HTTP2_UDM_01*' | xargs sed -i "s/HTTP2_MAXOUTGOINGCONNECTIONS/$HTTP2_MAXOUTGOINGCONNECTIONS/g"

if [ "$IS_IPV6" == "TRUE" ]; then
  HTTP2_URI_LIST="$HTTP2_URI_LIST_IPV6"
else
  HTTP2_URI_LIST="$HTTP2_URI_LIST_IPV4"
fi

echo "HTTP2_TLSMODE: $HTTP2_TLSMODE"

if [ "$IS_IPV6" == "TRUE" ]; then
   HOSTNAME=${HTTP2_URI_LIST%]*}
   HOST_NAME=${HOSTNAME#*[}
else 
   HOST_NAME=${HTTP2_URI_LIST%:*}
fi

echo "HOST_NAME: $HOST_NAME"
cp ./node_configuration/temp_HSS_HTTP2_UDM_01.xml ./node_configuration/temp_HSS_TMP_HTTP2_UDM_01.xml
find ./node_configuration -name 'temp_HSS_HTTP2_UDM_*' | xargs sed -i "s/HTTP_CLIENT_LIST/0:http:\/\/$HTTP2_URI_LIST\$$HTTP2_TLSMODE\$$HOST_NAME/g"
find ./node_configuration -name 'temp_HSS_TMP_HTTP2_UDM_*' | xargs sed -i "s/HTTP_CLIENT_LIST/0:http:\/\/$HTTP2_URI_LIST\$0\$$HOST_NAME/g"
find ./node_configuration -name 'temp_HSS_HTTP2_UDM_*' | xargs sed -i "s/HTTP2_URI/$HOST_NAME/g"
find ./node_configuration -name 'temp_HSS_TMP_HTTP2_UDM_*' | xargs sed -i "s/HTTP2_URI/$HOST_NAME/g"

cp ./node_configuration/temp_HSS_UDICOM_01.xml ./node_configuration/temp_HSS_TMP_UDICOM_01.xml
find ./node_configuration -name 'temp_HSS_TMP_UDICOM_01*' | xargs sed -i "s/$PORT_OF_UDICOM_TLS/0/g"

if [ "$IS_IPV6" == "TRUE" ]; then
  EXTDB="$EXTDB_IPV6"
else
  EXTDB="$EXTDB_IPV4"
fi

## EXT DB (in the future it can be extended to be a real list)
EXTDB_LDAPS_TLSMODE="NO_TLS"
if [ "$LDAPS_TLSMODE" == "0" ]; then
  EXT_DB_CONFIG_URL_LIST="0:ldap://$EXTDB:389\$$DN_EXTDBURLCONFIGLIST\$simple"
  echo "EXT_DB_CONFIG_URL_LIST $EXT_DB_CONFIG_URL_LIST"
  find ./node_configuration -name 'temp_extdb*' | xargs sed -i "s/EXT_DB_CONFIG_URL_LIST/0:ldap:\/\/$EXTDB:389\$$DN_EXTDBURLCONFIGLIST\$simple/g"
else
  EXT_DB_CONFIG_URL_LIST="0:ldap://$EXTDB:636\$$DN_EXTDBURLCONFIGLIST\$simple"
  echo "EXT_DB_CONFIG_URL_LIST $EXT_DB_CONFIG_URL_LIST"
  find ./node_configuration -name 'temp_extdb*' | xargs sed -i "s/EXT_DB_CONFIG_URL_LIST/0:ldap:\/\/$EXTDB:636\$$DN_EXTDBURLCONFIGLIST\$simple/g"
fi 
  EXTDBNODECREDENTIALID="HssExtDbTLS"
  find ./node_configuration -name 'temp_extdb*' | xargs sed -i "s/LDAPS_TLSMODE/$EXTDB_LDAPS_TLSMODE/g"
  find ./node_configuration -name 'temp_extdb*' | xargs sed -i "s/EXTDBNODECREDENTIALID/$EXTDBNODECREDENTIALID/g"
  find ./node_configuration -name 'temp_extdb*' | xargs sed -i "s/EXTDBTLSVERSION/$EXTDBTLSVERSION/g"

## EXT DB PASSW 

EXT_DB_URL_PASSW_LIST="0:$PASSWORD_EXTDB"

echo "EXT_DB_URL_PASSW_LIST: $EXT_DB_URL_PASSW_LIST"
find ./node_configuration -name 'temp_extdb*' | xargs sed -i "s/EXT_DB_URL_PASSW_LIST/$EXT_DB_URL_PASSW_LIST/g"

echo "ENCRYPT TYPE     : ${ENCRYPT}"
find ./node_configuration -name 'temp_avg*' | xargs sed -i "s/PARAMETER_AvgDefaultA4Algorithm/${ENCRYPT}/g"

#echo "ACTIVATE A&A FEAT: ${ACTIVATE_AUTH_FEAT}"

#if [ "$RE_POPULATION" == "FALSE" ] ; then

    echo "OPENLDAP_AA_IP    : ${LDAP_IPADDRESS}"
    find ./node_configuration -name 'temp_extldap*' | xargs sed -i "s/PARAMETER_LdapIpAddress/${LDAP_IPADDRESS}/g"

    echo "OPENLDAP_AA_PORT  : ${LDAP_PORT}"
    find ./node_configuration -name 'temp_extldap*' | xargs sed -i "s/PARAMETER_LdapPort/${LDAP_PORT}/g"
    
#fi
    
echo "MPV_OWNGTADDRESS : ${MPV_OWNGTADDRESS}"
find ./node_configuration -name 'mpv4_*' | xargs sed -i "s/PARAMETER_MpvOwnGTaddress/${MPV_OWNGTADDRESS}/g"


echo "RADIUS clients population : ${RADIUS_CLIENT_SM}"


if [ "$RADIUS_CLIENT_SM" == "TRUE" ] ; then

  if ((${#RADIUS_CLIENT_LIST[@]} == 0 )); then
    echo "RADIUS_CLIENT_LIST is empty but RADIUS_CLIENT_SM is true. At least one IP address must be given."
    exit 1
  fi
  
  echo "RADIUS_CLIENT_LIST: ${RADIUS_CLIENT_LIST[@]}"
   
  for address in ${!RADIUS_CLIENT_LIST[@]}
  do
   
     CHECKIP=`echo ${RADCLIENT1IP} |awk -F "." '{ if ( ( $1 > 255 || $1 < 0 ) || ( $2 > 255 || $2 < 0 ) || ( $3 > 255 || $3 < 0) || ( $4 > 255 || $4 < 0 ) || ( NF > 4 ) ) print $0 }'`

     if [ "$CHECKIP" == "" ]; then

       echo "RADIUS CLIENT $address is IPV4"
       RADCLIENT1="trafficgen${address}r"
       echo "RADIUS CLIENT name will be: $RADCLIENT1"

     else

       echo "RADIUS CLIENT ${address}'s IP is incorrect."
       echo ${CHECKIP}
       exit 1
  
     fi
     
     cp ./node_configuration/radius_client1.xml ./node_configuration/temp_radius_client1_${address}.xml
     find ./node_configuration -name "temp_radius_client1_${address}.xml" | xargs sed -i "s/PARAMETER_RadiusClientIP/${RADIUS_CLIENT_LIST[$address]}/g"
     find ./node_configuration -name "temp_radius_client1_${address}.xml" | xargs sed -i "s/PARAMETER_RadiusClientID/${RADCLIENT1}/g"

  done

  cp ./node_configuration/radius_client2.xml ./node_configuration/temp_radius_client2.xml
  find ./node_configuration -name 'temp_radius_client2.xml' | xargs sed -i "s/OWN_NODE_CONFIG_IP_ADDR_LIST_TCP/0:${RADDIA_IPV4}/g"


fi

#echo "PASSWORD for NON A&A : ${PASSWORD}"
echo "DN for EXTDB         : ${DN_EXTDB}"

find ./node_configuration -name 'temp_extdb*' | xargs sed -i "s/dc=operator,dc=com/${DN_EXTDB}/g"


#
# Start configuration
#

#if [ "$ACTIVATE_AUTH_FEAT" == "TRUE" ] ; then
#   LDAPSEVRWORK=`ldapsearch -x -h ${LDAP_IPADDRESS} -p ${LDAP_PORT} -D "cn=Manager,dc=example,dc=com" -w "ldaproot" -b "cn=hssadministrator,ou=Group,dc=example,dc=com"|grep -i success`
#   if [ "$LDAPSEVRWORK" == "" ]; then
#
#      echo "LDAP server for A&A is down."
#      echo 
#      exit 1
#   else
#      echo "LDAP server for A&A is up."
#      echo 
#   fi
#fi

#if [ "$ACTIVATE_AUTH_FEAT" == "TRUE" ]; then
#   echo "#######"
#   echo "ACTIVATE_AUTH_FEAT : $ACTIVATE_AUTH_FEAT"                           
#   echo "The feature A&A is going to be activated"                                                                                      
#
#fi 

#if [ "$USER_TYPE" == "hssadministrator" ]  ; then
if [ "$CUSTOM_USER" == "FALSE" ]  ; then

   USERCOMEMERGENCY=com-emergency
   COMEMERGENCYPASSWD=com-emergency
   USERCOMMON=hssadministrator
   COMMONPASSWD=hsstest
   USERLICENSE=ericssonhsssupport
   LICENSEPASSWD=hsstest
   USERAVG=hssavgkeyadministrator
   AVGPASSWD=hsstest
   USEREVIP=SystemAdministrator
   EVIPPASSWD=hsstest
   USERROOT=root
   ROOTPASSWD=rootroot
   
   PROXYCOMMONUSER=hss_est
   PROXYCOMMONPW=hss_est 
 
   echo "##########"
   echo "The following credentials will be used:"
   echo "USERCOMEMERGENCY=com-emergency"
   echo "USERCOMMON=hssadministrator"
   echo "USERLICENSE=ericssonhsssupport"
   echo "USERAVG=hssavgkeyadministrator"
   echo "USEREVIP=SystemAdministrator"
 
   echo "COMEMERGENCYPASSWD=com-emergency"
   echo "COMMONPASSWD=hsstest"
   echo "LICENSEPASSWD=hsstest"
   echo "AVGPASSWD=hsstest"
   echo "EVIPPASSWD=hsstest"
   echo "##########"
   
fi

#$if [ "$USER_TYPE" == "root" ]  ; then
#  
#  USERCOMMON=root
#   USERLICENSE=root
#   USERAVG=root
#   PASSWD=rootroot
#   USEREVIP=root
#   EVIPPASSWD=rootroot
#   
#   echo "##########"
#   echo "USERCOMMON=root"
#   echo "USERLICENSE=root"
#   echo "USERAVG=root"
#   echo "PASSWD=rootroot"
#   echo "##########"
#fi
#
#PASSWDROOT=rootroot

if [ "$CUSTOM_USER" == "TRUE" ]  ; then

   echo "##########"
   echo "Custom user type and credits will be used:"
   echo ""
   echo "USERCOMEMERGENCY : $USERCOMEMERGENCY"
   echo "COMEMERGENCYPASSWD : $COMEMERGENCYPASSWD"
   echo "USERCOMMON  : $USERCOMMON"
   echo "COMMONPASSWD : $COMMONPASSWD"
   echo "USERLICENSE : $USERLICENSE"
   echo "LICENSEPASSWD : $LICENSEPASSWD"
   echo "USERAVG     : $USERAVG"
   echo "AVGPASSWD      : $AVGPASSWD"
   echo "USEREVIP    : $USEREVIP"
   echo "EVIPPASSWD  : $EVIPPASSWD"
   echo "USERROOT    : $USERROOT"
   echo "ROOTPASSWD  : $ROOTPASSWD"
fi

# JAVA path for 64bit environment
#JAVA_PATH=/tsp/3rdParty/jre1.6.0_37_x86_64/bin

# JAVA path for 32bit environment
#JAVA_PATH=/tsp/3rdParty/jre-6u20-linux-i586/jre1.6.0_20/bin

UNAME=`uname -i`
echo "Running environment : ${UNAME}"
echo "Java path           : ${JAVA_PATH}"
echo "PDB Config Tool     : ${PDB_CONFIG_TOOL}"



if [ "$IS_IPV6" == "TRUE" ]; then
  VIPOAM=$VIPOAM_IPV6
else
  VIPOAM=$VIPOAM_IPV4
fi

#if [ -z ${PASSWORD} ]; then
#   echo "PASSWORD is needed"
#else		

echo "################################"
echo "##### Configuration begins #####"
echo "################################"

   ####### Configure and Activate A&A
   ## 
   #if [ "${RE_POPULATION}" == "FALSE" ] ; then
      echo "Starting for extldap.xml"
      ${JAVA_PATH}/java -jar ${PDB_CONFIG_TOOL} --host ${VIPOAM} --port "830" --user ${USERCOMEMERGENCY} --password ${COMEMERGENCYPASSWD} --type cba \
                       --operation configure --input-file node_configuration/temp_extldap.xml --log out_extldap.$$

      echo "Starting for active_auth.xml"
      ${JAVA_PATH}/java -jar ${PDB_CONFIG_TOOL} --host ${VIPOAM} --port "830" --user ${USERCOMEMERGENCY} --password ${COMEMERGENCYPASSWD} --type cba \
                       --operation configure --input-file node_configuration/active_auth.xml --log out_active_auth.$$

   ####### Wait for A&A activation
   echo "Wait 180s for A&A activation..."
   sleep 180

   #fi

   ####### Activate ISMSDA module
   if [ "$license_ISMSDA" == "1" ]; then
      echo "Starting for license_ismsda.xml"
      ${JAVA_PATH}/java -jar ${PDB_CONFIG_TOOL} --host ${VIPOAM} --port "830" --user ${USERLICENSE} --password ${LICENSEPASSWD} --type cba \
                       --operation configure --input-file node_configuration/license_ismsda.xml --log out_license_ismsda.$$
   fi


   ####### Activate AVG module
   if [ "$license_AVG" == "1" ]; then
      echo "Starting for license_avg.xml"
      ${JAVA_PATH}/java -jar ${PDB_CONFIG_TOOL} --host ${VIPOAM} --port "830" --user ${USERLICENSE} --password ${LICENSEPASSWD} --type cba \
                       --operation configure --input-file node_configuration/license_avg.xml --log out_license_avg.$$
   fi

   ####### Activate SM module
   if [ "$license_SM" == "1" ]; then
      echo "Starting for license_sm.xml"
      ${JAVA_PATH}/java -jar ${PDB_CONFIG_TOOL} --host ${VIPOAM} --port "830" --user ${USERLICENSE} --password ${LICENSEPASSWD} --type cba \
                       --operation configure --input-file node_configuration/license_sm.xml --log out_license_sm.$$
   fi

   ####### Activate ESM module
   if [ "$license_ESM" == "1" ]; then
      echo "Starting for license_esm.xml"
      ${JAVA_PATH}/java -jar ${PDB_CONFIG_TOOL} --host ${VIPOAM} --port "830" --user ${USERLICENSE} --password ${LICENSEPASSWD} --type cba \
                       --operation configure --input-file node_configuration/license_esm.xml --log out_license_esm.$$
   fi

   if [ "$RE_POPULATION" == "FALSE" ] ; then
      ####### Wait for module activation
      echo "Wait 240s for module activation..."
      sleep 240
   fi

  
   ####### Populate ISMSDA module
   if [ "$license_ISMSDA" == "1" ]; then

      echo "Starting for diameter4.xml"
         ${JAVA_PATH}/java -jar ${PDB_CONFIG_TOOL} --host ${VIPOAM} --port "830" --user ${USERCOMMON} --password ${COMMONPASSWD} --type cba \
                          --operation configure --input-file node_configuration/temp_diameter4.xml --log out_diameter4.$$

      echo "Starting for diameter5.xml"
         ${JAVA_PATH}/java -jar ${PDB_CONFIG_TOOL} --host ${VIPOAM} --port "830" --user ${USERCOMMON} --password ${COMMONPASSWD} --type cba \
                          --operation configure --input-file node_configuration/temp_diameter5.xml --log out_diameter5.$$

      echo "Starting for diameter6.xml"
         ${JAVA_PATH}/java -jar ${PDB_CONFIG_TOOL} --host ${VIPOAM} --port "830" --user ${USERCOMMON} --password ${COMMONPASSWD} --type cba \
                          --operation configure --input-file node_configuration/temp_diameter6.xml --log out_diameter6.$$

      if [ "$DIA_PEER_NODES" == "TRUE" ]; then
         echo "Starting for diameter1.xml"
         ${JAVA_PATH}/java -jar ${PDB_CONFIG_TOOL} --host ${VIPOAM} --port "830" --user ${USERCOMMON} --password ${COMMONPASSWD} --type cba \
                          --operation configure --input-file node_configuration/temp_diameter1.xml --log out_diameter1.$$

         echo "Starting for diameter2.xml"
         ${JAVA_PATH}/java -jar ${PDB_CONFIG_TOOL} --host ${VIPOAM} --port "830" --user ${USERCOMMON} --password ${COMMONPASSWD} --type cba \
                          --operation configure --input-file node_configuration/temp_diameter2.xml --log out_diameter2.$$
      fi

      # echo "Starting for diameter3.xml"
      # ${JAVA_PATH}/java -jar ${PDB_CONFIG_TOOL} --host ${VIPOAM} --port "830" --user ${USERCOMMON} --password ${PASSWD} --type cba \
      #                  --operation configure --input-file node_configuration/diameter3.xml --log out_diameter3.$$

      echo "Starting for hss_0.xml"
      ${JAVA_PATH}/java -jar ${PDB_CONFIG_TOOL} --host ${VIPOAM} --port "830" --user ${USERCOMMON} --password ${COMMONPASSWD} --type cba \
                       --operation configure --input-file node_configuration/hss_0.xml --log out_hss_0.$$

      echo "Starting for hss_1.xml"
      ${JAVA_PATH}/java -jar ${PDB_CONFIG_TOOL} --host ${VIPOAM} --port "830" --user ${USERCOMMON} --password ${COMMONPASSWD} --type cba \
                       --operation configure --input-file node_configuration/hss_1.xml --log out_hss_1.$$

      echo "Starting for hss_2.xml"
      ${JAVA_PATH}/java -jar ${PDB_CONFIG_TOOL} --host ${VIPOAM} --port "830" --user ${USERCOMMON} --password ${COMMONPASSWD} --type cba \
                       --operation configure --input-file node_configuration/hss_2.xml --log out_hss_2.$$

      echo "Starting for hss_3.xml"
      ${JAVA_PATH}/java -jar ${PDB_CONFIG_TOOL} --host ${VIPOAM} --port "830" --user ${USERCOMMON} --password ${COMMONPASSWD} --type cba \
                       --operation configure --input-file node_configuration/hss_3.xml --log out_hss_3.$$

      echo "Starting for hss_4.xml"
      ${JAVA_PATH}/java -jar ${PDB_CONFIG_TOOL} --host ${VIPOAM} --port "830" --user ${USERCOMMON} --password ${COMMONPASSWD} --type cba \
                       --operation configure --input-file node_configuration/hss_4.xml --log out_hss_4.$$

      echo "Starting for hss_5.xml"
      ${JAVA_PATH}/java -jar ${PDB_CONFIG_TOOL} --host ${VIPOAM} --port "830" --user ${USERCOMMON} --password ${COMMONPASSWD} --type cba \
                       --operation configure --input-file node_configuration/hss_5.xml --log out_hss_5.$$
      if [ "$license_ESM" == "1" ]; then
         echo "Starting for hss_8.xml"
         ${JAVA_PATH}/java -jar ${PDB_CONFIG_TOOL} --host ${VIPOAM} --port "830" --user ${USERCOMMON} --password ${COMMONPASSWD} --type cba \
                       --operation configure --input-file node_configuration/hss_8.xml --log out_hss_8.$$
      fi

      if [ "$SHA256_RSA4906" == "TRUE" ]; then
         echo "Starting for license_RSA4096_CRC.XML"
         ${JAVA_PATH}/java -jar ${PDB_CONFIG_TOOL} --host ${VIPOAM} --port "830" --user ${USERCOMMON} --password ${COMMONPASSWD} --type cba \
                          --operation configure --input-file node_configuration/license_RSA4096_CRC.xml --log out_license_RSA4096_CRC.XML.$$
      fi

      echo "Starting for hss_9.xml"
      ${JAVA_PATH}/java -jar ${PDB_CONFIG_TOOL} --host ${VIPOAM} --port "830" --user ${USERLICENSE} --password ${LICENSEPASSWD} --type cba \
                       --operation configure --input-file node_configuration/hss_9.xml --log out_hss_9.$$

      echo "Starting for servtype1_1.xml"
      ${JAVA_PATH}/java -jar ${PDB_CONFIG_TOOL} --host ${VIPOAM} --port "830" --user ${USERCOMMON} --password ${COMMONPASSWD} --type cba \
                       --operation configure --input-file node_configuration/servtype1_1.xml --log out_servtype1_1.$$

      echo "Starting for servtype1_2.xml"
      ${JAVA_PATH}/java -jar ${PDB_CONFIG_TOOL} --host ${VIPOAM} --port "830" --user ${USERCOMMON} --password ${COMMONPASSWD} --type cba \
                       --operation configure --input-file node_configuration/servtype1_2.xml --log out_servtype1_2.$$

      echo "Starting for servtype1_3.xml"
      ${JAVA_PATH}/java -jar ${PDB_CONFIG_TOOL} --host ${VIPOAM} --port "830" --user ${USERCOMMON} --password ${COMMONPASSWD} --type cba \
                       --operation configure --input-file node_configuration/servtype1_3.xml --log out_servtype1_3.$$

      echo "Starting for servtype1_4.xml"
      ${JAVA_PATH}/java -jar ${PDB_CONFIG_TOOL} --host ${VIPOAM} --port "830" --user ${USERCOMMON} --password ${COMMONPASSWD} --type cba \
                       --operation configure --input-file node_configuration/servtype1_4.xml --log out_servtype1_4.$$

      echo "Starting for servtype1_5.xml"
      ${JAVA_PATH}/java -jar ${PDB_CONFIG_TOOL} --host ${VIPOAM} --port "830" --user ${USERCOMMON} --password ${COMMONPASSWD} --type cba \
                       --operation configure --input-file node_configuration/servtype1_5.xml --log out_servtype1_5.$$

      echo "Starting for servtype1_6.xml"
      ${JAVA_PATH}/java -jar ${PDB_CONFIG_TOOL} --host ${VIPOAM} --port "830" --user ${USERCOMMON} --password ${COMMONPASSWD} --type cba \
                       --operation configure --input-file node_configuration/servtype1_6.xml --log out_servtype1_6.$$

      echo "Starting for servtype1_7.xml"
      ${JAVA_PATH}/java -jar ${PDB_CONFIG_TOOL} --host ${VIPOAM} --port "830" --user ${USERCOMMON} --password ${COMMONPASSWD} --type cba \
                       --operation configure --input-file node_configuration/servtype1_7.xml --log out_servtype1_7.$$

      echo "Starting for servtype1_8.xml"
      ${JAVA_PATH}/java -jar ${PDB_CONFIG_TOOL} --host ${VIPOAM} --port "830" --user ${USERCOMMON} --password ${COMMONPASSWD} --type cba \
                       --operation configure --input-file node_configuration/servtype1_8.xml --log out_servtype1_8.$$

      echo "Starting for servtype2_1.xml"
      ${JAVA_PATH}/java -jar ${PDB_CONFIG_TOOL} --host ${VIPOAM} --port "830" --user ${USERCOMMON} --password ${COMMONPASSWD} --type cba \
                       --operation configure --input-file node_configuration/servtype2_1.xml --log out_servtype2_1.$$

      echo "Starting for servtype2_2.xml"
      ${JAVA_PATH}/java -jar ${PDB_CONFIG_TOOL} --host ${VIPOAM} --port "830" --user ${USERCOMMON} --password ${COMMONPASSWD} --type cba \
                       --operation configure --input-file node_configuration/servtype2_2.xml --log out_servtype2_2.$$

      echo "Starting for servtype2_3.xml"
      ${JAVA_PATH}/java -jar ${PDB_CONFIG_TOOL} --host ${VIPOAM} --port "830" --user ${USERCOMMON} --password ${COMMONPASSWD} --type cba \
                       --operation configure --input-file node_configuration/servtype2_3.xml --log out_servtype2_3.$$

      echo "Starting for servtype2_4.xml"
      ${JAVA_PATH}/java -jar ${PDB_CONFIG_TOOL} --host ${VIPOAM} --port "830" --user ${USERCOMMON} --password ${COMMONPASSWD} --type cba \
                       --operation configure --input-file node_configuration/servtype2_4.xml --log out_servtype2_4.$$

      echo "Starting for servtype2_5.xml"
      ${JAVA_PATH}/java -jar ${PDB_CONFIG_TOOL} --host ${VIPOAM} --port "830" --user ${USERCOMMON} --password ${COMMONPASSWD} --type cba \
                       --operation configure --input-file node_configuration/servtype2_5.xml --log out_servtype2_5.$$

      echo "Starting for servtype2_6.xml"
      ${JAVA_PATH}/java -jar ${PDB_CONFIG_TOOL} --host ${VIPOAM} --port "830" --user ${USERCOMMON} --password ${COMMONPASSWD} --type cba \
                       --operation configure --input-file node_configuration/servtype2_6.xml --log out_servtype2_6.$$

      echo "Starting for servtype2_7.xml"
      ${JAVA_PATH}/java -jar ${PDB_CONFIG_TOOL} --host ${VIPOAM} --port "830" --user ${USERCOMMON} --password ${COMMONPASSWD} --type cba \
                       --operation configure --input-file node_configuration/servtype2_7.xml --log out_servtype2_7.$$

      echo "Starting for servtype2_8.xml"
      ${JAVA_PATH}/java -jar ${PDB_CONFIG_TOOL} --host ${VIPOAM} --port "830" --user ${USERCOMMON} --password ${COMMONPASSWD} --type cba \
                       --operation configure --input-file node_configuration/servtype2_8.xml --log out_servtype2_8.$$

      echo "Starting for servtype2_9.xml"
      ${JAVA_PATH}/java -jar ${PDB_CONFIG_TOOL} --host ${VIPOAM} --port "830" --user ${USERCOMMON} --password ${COMMONPASSWD} --type cba \
                       --operation configure --input-file node_configuration/servtype2_9.xml --log out_servtype2_9.$$

      echo "Starting for servtype2_10.xml"
      ${JAVA_PATH}/java -jar ${PDB_CONFIG_TOOL} --host ${VIPOAM} --port "830" --user ${USERCOMMON} --password ${COMMONPASSWD} --type cba \
                       --operation configure --input-file node_configuration/servtype2_10.xml --log out_servtype2_10.$$

      echo "Starting for servtype2_11.xml"
      ${JAVA_PATH}/java -jar ${PDB_CONFIG_TOOL} --host ${VIPOAM} --port "830" --user ${USERCOMMON} --password ${COMMONPASSWD} --type cba \
                       --operation configure --input-file node_configuration/servtype2_11.xml --log out_servtype2_11.$$

      echo "Starting for servtype2_12.xml"
      ${JAVA_PATH}/java -jar ${PDB_CONFIG_TOOL} --host ${VIPOAM} --port "830" --user ${USERCOMMON} --password ${COMMONPASSWD} --type cba \
                       --operation configure --input-file node_configuration/servtype2_12.xml --log out_servtype2_12.$$

      echo "Starting for servtype2_13.xml"
      ${JAVA_PATH}/java -jar ${PDB_CONFIG_TOOL} --host ${VIPOAM} --port "830" --user ${USERCOMMON} --password ${COMMONPASSWD} --type cba \
                       --operation configure --input-file node_configuration/servtype2_13.xml --log out_servtype2_13.$$

      echo "Starting for servtype2_14.xml"
      ${JAVA_PATH}/java -jar ${PDB_CONFIG_TOOL} --host ${VIPOAM} --port "830" --user ${USERCOMMON} --password ${COMMONPASSWD} --type cba \
                       --operation configure --input-file node_configuration/servtype2_14.xml --log out_servtype2_14.$$

      echo "Starting for servtype2_15.xml"
      ${JAVA_PATH}/java -jar ${PDB_CONFIG_TOOL} --host ${VIPOAM} --port "830" --user ${USERCOMMON} --password ${COMMONPASSWD} --type cba \
                       --operation configure --input-file node_configuration/servtype2_15.xml --log out_servtype2_15.$$

      echo "Starting for servtype2_16.xml"
      ${JAVA_PATH}/java -jar ${PDB_CONFIG_TOOL} --host ${VIPOAM} --port "830" --user ${USERCOMMON} --password ${COMMONPASSWD} --type cba \
                       --operation configure --input-file node_configuration/servtype2_16.xml --log out_servtype2_16.$$

      echo "Starting for servtype2_17.xml"
      ${JAVA_PATH}/java -jar ${PDB_CONFIG_TOOL} --host ${VIPOAM} --port "830" --user ${USERCOMMON} --password ${COMMONPASSWD} --type cba \
                       --operation configure --input-file node_configuration/servtype2_17.xml --log out_servtype2_17.$$

      echo "Starting for servtype2_18.xml"
      ${JAVA_PATH}/java -jar ${PDB_CONFIG_TOOL} --host ${VIPOAM} --port "830" --user ${USERCOMMON} --password ${COMMONPASSWD} --type cba \
                       --operation configure --input-file node_configuration/servtype2_18.xml --log out_servtype2_18.$$

      echo "Starting for servtype2_19.xml"
      ${JAVA_PATH}/java -jar ${PDB_CONFIG_TOOL} --host ${VIPOAM} --port "830" --user ${USERCOMMON} --password ${COMMONPASSWD} --type cba \
                       --operation configure --input-file node_configuration/servtype2_19.xml --log out_servtype2_19.$$

      echo "Starting for servtype2_20.xml"
      ${JAVA_PATH}/java -jar ${PDB_CONFIG_TOOL} --host ${VIPOAM} --port "830" --user ${USERCOMMON} --password ${COMMONPASSWD} --type cba \
                       --operation configure --input-file node_configuration/servtype2_20.xml --log out_servtype2_20.$$

      echo "Starting for servtype2_21.xml"
      ${JAVA_PATH}/java -jar ${PDB_CONFIG_TOOL} --host ${VIPOAM} --port "830" --user ${USERCOMMON} --password ${COMMONPASSWD} --type cba \
                       --operation configure --input-file node_configuration/servtype2_21.xml --log out_servtype2_21.$$

      echo "Starting for servtype2_22.xml"
      ${JAVA_PATH}/java -jar ${PDB_CONFIG_TOOL} --host ${VIPOAM} --port "830" --user ${USERCOMMON} --password ${COMMONPASSWD} --type cba \
                       --operation configure --input-file node_configuration/servtype2_22.xml --log out_servtype2_22.$$

      echo "Starting for servtype2_23.xml"
      ${JAVA_PATH}/java -jar ${PDB_CONFIG_TOOL} --host ${VIPOAM} --port "830" --user ${USERCOMMON} --password ${COMMONPASSWD} --type cba \
                       --operation configure --input-file node_configuration/servtype2_23.xml --log out_servtype2_23.$$

      echo "Starting for servtype2_24.xml"
      ${JAVA_PATH}/java -jar ${PDB_CONFIG_TOOL} --host ${VIPOAM} --port "830" --user ${USERCOMMON} --password ${COMMONPASSWD} --type cba \
                       --operation configure --input-file node_configuration/servtype2_24.xml --log out_servtype2_24.$$

      echo "Starting for servtype2_25.xml"
      ${JAVA_PATH}/java -jar ${PDB_CONFIG_TOOL} --host ${VIPOAM} --port "830" --user ${USERCOMMON} --password ${COMMONPASSWD} --type cba \
                       --operation configure --input-file node_configuration/servtype2_25.xml --log out_servtype2_25.$$

      echo "Starting for servtype2_26.xml"
      ${JAVA_PATH}/java -jar ${PDB_CONFIG_TOOL} --host ${VIPOAM} --port "830" --user ${USERCOMMON} --password ${COMMONPASSWD} --type cba \
                       --operation configure --input-file node_configuration/servtype2_26.xml --log out_servtype2_26.$$

      echo "Starting for servtype2_27.xml"
      ${JAVA_PATH}/java -jar ${PDB_CONFIG_TOOL} --host ${VIPOAM} --port "830" --user ${USERCOMMON} --password ${COMMONPASSWD} --type cba \
                       --operation configure --input-file node_configuration/servtype2_27.xml --log out_servtype2_27.$$

      echo "Starting for servtype3_1.xml"
      ${JAVA_PATH}/java -jar ${PDB_CONFIG_TOOL} --host ${VIPOAM} --port "830" --user ${USERCOMMON} --password ${COMMONPASSWD} --type cba \
                       --operation configure --input-file node_configuration/servtype3_1.xml --log out_servtype3_1.$$

      echo "Starting for servtype3_2.xml"
      ${JAVA_PATH}/java -jar ${PDB_CONFIG_TOOL} --host ${VIPOAM} --port "830" --user ${USERCOMMON} --password ${COMMONPASSWD} --type cba \
                       --operation configure --input-file node_configuration/servtype3_2.xml --log out_servtype3_2.$$

      echo "Starting for servtype3_3.xml"
      ${JAVA_PATH}/java -jar ${PDB_CONFIG_TOOL} --host ${VIPOAM} --port "830" --user ${USERCOMMON} --password ${COMMONPASSWD} --type cba \
                       --operation configure --input-file node_configuration/servtype3_3.xml --log out_servtype3_3.$$

      echo "Starting for servtype3_4.xml"
      ${JAVA_PATH}/java -jar ${PDB_CONFIG_TOOL} --host ${VIPOAM} --port "830" --user ${USERCOMMON} --password ${COMMONPASSWD} --type cba \
                       --operation configure --input-file node_configuration/servtype3_4.xml --log out_servtype3_4.$$

      echo "Starting for servtype3_5.xml"
      ${JAVA_PATH}/java -jar ${PDB_CONFIG_TOOL} --host ${VIPOAM} --port "830" --user ${USERCOMMON} --password ${COMMONPASSWD} --type cba \
                       --operation configure --input-file node_configuration/servtype3_5.xml --log out_servtype3_5.$$

      echo "Starting for servtype3_6.xml"
      ${JAVA_PATH}/java -jar ${PDB_CONFIG_TOOL} --host ${VIPOAM} --port "830" --user ${USERCOMMON} --password ${COMMONPASSWD} --type cba \
                       --operation configure --input-file node_configuration/servtype3_6.xml --log out_servtype3_6.$$

      echo "Starting for servtype3_7.xml"
      ${JAVA_PATH}/java -jar ${PDB_CONFIG_TOOL} --host ${VIPOAM} --port "830" --user ${USERCOMMON} --password ${COMMONPASSWD} --type cba \
                       --operation configure --input-file node_configuration/servtype3_7.xml --log out_servtype3_7.$$

      echo "Starting for servtype3_8.xml"
      ${JAVA_PATH}/java -jar ${PDB_CONFIG_TOOL} --host ${VIPOAM} --port "830" --user ${USERCOMMON} --password ${COMMONPASSWD} --type cba \
                       --operation configure --input-file node_configuration/servtype3_8.xml --log out_servtype3_8.$$

      echo "Starting for servtype3_9.xml"
      ${JAVA_PATH}/java -jar ${PDB_CONFIG_TOOL} --host ${VIPOAM} --port "830" --user ${USERCOMMON} --password ${COMMONPASSWD} --type cba \
                       --operation configure --input-file node_configuration/servtype3_9.xml --log out_servtype3_9.$$

      echo "Starting for servtype3_10.xml"
      ${JAVA_PATH}/java -jar ${PDB_CONFIG_TOOL} --host ${VIPOAM} --port "830" --user ${USERCOMMON} --password ${COMMONPASSWD} --type cba \
                       --operation configure --input-file node_configuration/servtype3_10.xml --log out_servtype3_10.$$

      echo "Starting for servtype3_11.xml"
      ${JAVA_PATH}/java -jar ${PDB_CONFIG_TOOL} --host ${VIPOAM} --port "830" --user ${USERCOMMON} --password ${COMMONPASSWD} --type cba \
                       --operation configure --input-file node_configuration/servtype3_11.xml --log out_servtype3_11.$$

      echo "Starting for servtype3_12.xml"
      ${JAVA_PATH}/java -jar ${PDB_CONFIG_TOOL} --host ${VIPOAM} --port "830" --user ${USERCOMMON} --password ${COMMONPASSWD} --type cba \
                       --operation configure --input-file node_configuration/servtype3_12.xml --log out_servtype3_12.$$
      echo "Starting for servtype3_13.xml"
      ${JAVA_PATH}/java -jar ${PDB_CONFIG_TOOL} --host ${VIPOAM} --port "830" --user ${USERCOMMON} --password ${COMMONPASSWD} --type cba \
                       --operation configure --input-file node_configuration/servtype3_13.xml --log out_servtype3_13.$$

      echo "Starting for servtype4_1.xml"
      ${JAVA_PATH}/java -jar ${PDB_CONFIG_TOOL} --host ${VIPOAM} --port "830" --user ${USERCOMMON} --password ${COMMONPASSWD} --type cba \
                       --operation configure --input-file node_configuration/servtype4_1.xml --log out_servtype4_1.$$

      echo "Starting for servtype4_2.xml"
      ${JAVA_PATH}/java -jar ${PDB_CONFIG_TOOL} --host ${VIPOAM} --port "830" --user ${USERCOMMON} --password ${COMMONPASSWD} --type cba \
                       --operation configure --input-file node_configuration/servtype4_2.xml --log out_servtype4_2.$$

      echo "Starting for servtype4_3.xml"
      ${JAVA_PATH}/java -jar ${PDB_CONFIG_TOOL} --host ${VIPOAM} --port "830" --user ${USERCOMMON} --password ${COMMONPASSWD} --type cba \
                       --operation configure --input-file node_configuration/servtype4_3.xml --log out_servtype4_3.$$

      echo "Starting for servtype4_4.xml"
      ${JAVA_PATH}/java -jar ${PDB_CONFIG_TOOL} --host ${VIPOAM} --port "830" --user ${USERCOMMON} --password ${COMMONPASSWD} --type cba \
                       --operation configure --input-file node_configuration/servtype4_4.xml --log out_servtype4_4.$$

      echo "Starting for servtype4_5.xml"
      ${JAVA_PATH}/java -jar ${PDB_CONFIG_TOOL} --host ${VIPOAM} --port "830" --user ${USERCOMMON} --password ${COMMONPASSWD} --type cba \
                       --operation configure --input-file node_configuration/servtype4_5.xml --log out_servtype4_5.$$

      echo "Starting for servtype4_6.xml"
      ${JAVA_PATH}/java -jar ${PDB_CONFIG_TOOL} --host ${VIPOAM} --port "830" --user ${USERCOMMON} --password ${COMMONPASSWD} --type cba \
                       --operation configure --input-file node_configuration/servtype4_6.xml --log out_servtype4_6.$$

      echo "Starting for servtype4_7.xml"
      ${JAVA_PATH}/java -jar ${PDB_CONFIG_TOOL} --host ${VIPOAM} --port "830" --user ${USERCOMMON} --password ${COMMONPASSWD} --type cba \
                       --operation configure --input-file node_configuration/servtype4_7.xml --log out_servtype4_7.$$

      echo "Starting for servtype4_8.xml"
      ${JAVA_PATH}/java -jar ${PDB_CONFIG_TOOL} --host ${VIPOAM} --port "830" --user ${USERCOMMON} --password ${COMMONPASSWD} --type cba \
                       --operation configure --input-file node_configuration/servtype4_8.xml --log out_servtype4_8.$$

      echo "Starting for servtype4_9.xml"
      ${JAVA_PATH}/java -jar ${PDB_CONFIG_TOOL} --host ${VIPOAM} --port "830" --user ${USERCOMMON} --password ${COMMONPASSWD} --type cba \
                       --operation configure --input-file node_configuration/servtype4_9.xml --log out_servtype4_9.$$

   fi

   ###### Populate AVG module
   if [ "$license_AVG" == "1" ]; then
   
      ##  https://udm-hss-jira.rnd.ki.sw.ericsson.se/browse/HSSTR-471
      
      if [ "$RE_POPULATION" == "FALSE" -o \( "$RE_POPULATION" == "TRUE" -a "$VECTOR_PREV_CONFIGURED" == "FALSE" \) ];then
      
          echo "Starting for avg_0.xml"
          ${JAVA_PATH}/java -jar ${PDB_CONFIG_TOOL} --host ${VIPOAM} --port "830" --user ${USERAVG} --password ${AVGPASSWD} --type cba \
                       --operation configure --input-file node_configuration/temp_avg_0.xml --log out_avg_0.$$
                       
          echo "Starting for avg_1.xml"
          ${JAVA_PATH}/java -jar ${PDB_CONFIG_TOOL} --host ${VIPOAM} --port "830" --user ${USERAVG} --password ${AVGPASSWD} --type cba \
                       --operation configure --input-file node_configuration/avg_1.xml --log out_avg_1.$$

      fi


      echo "Starting for avg_2.xml"
      ${JAVA_PATH}/java -jar ${PDB_CONFIG_TOOL} --host ${VIPOAM} --port "830" --user ${USERAVG} --password ${AVGPASSWD} --type cba \
                       --operation configure --input-file node_configuration/avg_2.xml --log out_avg_2.$$

      echo "Starting for avg_3.xml"
      ${JAVA_PATH}/java -jar ${PDB_CONFIG_TOOL} --host ${VIPOAM} --port "830" --user ${USERAVG} --password ${AVGPASSWD} --type cba \
                       --operation configure --input-file node_configuration/avg_3.xml --log out_avg_3.$$

      echo "Starting for avg_4.xml"
      ${JAVA_PATH}/java -jar ${PDB_CONFIG_TOOL} --host ${VIPOAM} --port "830" --user ${USERAVG} --password ${AVGPASSWD} --type cba \
                       --operation configure --input-file node_configuration/avg_4.xml --log out_avg_4.$$

      echo "Starting for avg_5.xml"
      ${JAVA_PATH}/java -jar ${PDB_CONFIG_TOOL} --host ${VIPOAM} --port "830" --user ${USERAVG} --password ${AVGPASSWD} --type cba \
                       --operation configure --input-file node_configuration/avg_5.xml --log out_avg_5.$$

      echo "Starting for avg_6.xml"
      ${JAVA_PATH}/java -jar ${PDB_CONFIG_TOOL} --host ${VIPOAM} --port "830" --user ${USERAVG} --password ${AVGPASSWD} --type cba \
                       --operation configure --input-file node_configuration/avg_6.xml --log out_avg_6.$$
   fi

   ####### Populate SM module
   if [ "$license_SM" == "1" ]; then
      echo "Starting for diameter_SM_1.xml"
      ${JAVA_PATH}/java -jar ${PDB_CONFIG_TOOL} --host ${VIPOAM} --port "830" --user ${USERCOMMON} --password ${COMMONPASSWD} --type cba \
                       --operation configure --input-file node_configuration/temp_diameter_SM_1.xml --log out_diameter_SM_1.$$

      echo "Starting for diameter_SM_2.xml"
      ${JAVA_PATH}/java -jar ${PDB_CONFIG_TOOL} --host ${VIPOAM} --port "830" --user ${USERCOMMON} --password ${COMMONPASSWD} --type cba \
                       --operation configure --input-file node_configuration/diameter_SM_2.xml --log out_diameter_SM_2.$$

      echo "Starting for diameter_SM_3.xml"
      ${JAVA_PATH}/java -jar ${PDB_CONFIG_TOOL} --host ${VIPOAM} --port "830" --user ${USERCOMMON} --password ${COMMONPASSWD} --type cba \
                       --operation configure --input-file node_configuration/diameter_SM_3.xml --log out_diameter_SM_3.$$

      echo "Starting for diameter_SM_4.xml"
      ${JAVA_PATH}/java -jar ${PDB_CONFIG_TOOL} --host ${VIPOAM} --port "830" --user ${USERCOMMON} --password ${COMMONPASSWD} --type cba \
                       --operation configure --input-file node_configuration/temp_diameter_SM_4.xml --log out_diameter_SM_4.$$

      echo "Starting for HSS_SM_01.xml"
      ${JAVA_PATH}/java -jar ${PDB_CONFIG_TOOL} --host ${VIPOAM} --port "830" --user ${USERCOMMON} --password ${COMMONPASSWD} --type cba \
                       --operation configure --input-file node_configuration/HSS_SM_01.xml --log out_HSS_SM_01.$$

      if [ "$RADIUS_CLIENT_SM" == "TRUE" ] ; then

        for client in ${!RADIUS_CLIENT_LIST[@]}
        do
          echo "Starting for temp_radius_client1_${client}.xml"
          ${JAVA_PATH}/java -jar ${PDB_CONFIG_TOOL} --host ${VIPOAM} --port "830" --user ${USERCOMMON} --password ${COMMONPASSWD} --type cba \
                       --operation configure --input-file node_configuration/temp_radius_client1_${client}.xml --log out_temp_radius_client1_${client}.$$
        done

        echo "Starting for temp_radius_client2.xml"
        ${JAVA_PATH}/java -jar ${PDB_CONFIG_TOOL} --host ${VIPOAM} --port "830" --user ${USERCOMMON} --password ${COMMONPASSWD} --type cba \
                       --operation configure --input-file node_configuration/temp_radius_client2.xml --log out_temp_radius_client2.$$

      fi
      
      echo "Starting for HSS_SM_02.xml"
      ${JAVA_PATH}/java -jar ${PDB_CONFIG_TOOL} --host ${VIPOAM} --port "830" --user ${USERLICENSE} --password ${LICENSEPASSWD} --type cba \
                       --operation configure --input-file node_configuration/HSS_SM_02.xml --log out_HSS_SM_02.$$

      echo "Starting for HSS_SM_03.xml"
      ${JAVA_PATH}/java -jar ${PDB_CONFIG_TOOL} --host ${VIPOAM} --port "830" --user ${USERLICENSE} --password ${LICENSEPASSWD} --type cba \
                       --operation configure --input-file node_configuration/HSS_SM_03.xml --log out_HSS_SM_03.$$

      echo "Starting for HSS_SM_04.xml"
      ${JAVA_PATH}/java -jar ${PDB_CONFIG_TOOL} --host ${VIPOAM} --port "830" --user ${USERCOMMON} --password ${COMMONPASSWD} --type cba \
                       --operation configure --input-file node_configuration/HSS_SM_04.xml --log out_HSS_SM_04.$$

   fi

   ####### Populate ESM module
   if [ "$license_ESM" == "1" ]; then
      echo "Starting for HSS_ESM_0.xml"
      ${JAVA_PATH}/java -jar ${PDB_CONFIG_TOOL} --host ${VIPOAM} --port "830" --user ${USERCOMMON} --password ${COMMONPASSWD} --type cba \
                       --operation configure --input-file node_configuration/HSS_ESM_0.xml --log out_HSS_ESM_0.$$

      if [ "$DIA_PEER_NODES" == "TRUE" ]; then
         echo "Starting for diameter_HSS_ESM_1.xml"
         ${JAVA_PATH}/java -jar ${PDB_CONFIG_TOOL} --host ${VIPOAM} --port "830" --user ${USERCOMMON} --password ${COMMONPASSWD} --type cba \
                          --operation configure --input-file node_configuration/diameter_HSS_ESM_1.xml --log out_diameter_HSS_ESM_1.$$
      fi
  
      echo "Starting for diameter_HSS_ESM_2.xml"
         ${JAVA_PATH}/java -jar ${PDB_CONFIG_TOOL} --host ${VIPOAM} --port "830" --user ${USERCOMMON} --password ${COMMONPASSWD} --type cba \
                          --operation configure --input-file node_configuration/temp_diameter_HSS_ESM_2.xml --log out_diameter_HSS_ESM_2.$$

      echo "Starting for HSS_ESM_01.xml"
      ${JAVA_PATH}/java -jar ${PDB_CONFIG_TOOL} --host ${VIPOAM} --port "830" --user ${USERCOMMON} --password ${COMMONPASSWD} --type cba \
                       --operation configure --input-file node_configuration/HSS_ESM_01.xml --log out_HSS_ESM_01.$$

      echo "Starting for HSS_ESM_02.xml"
      ${JAVA_PATH}/java -jar ${PDB_CONFIG_TOOL} --host ${VIPOAM} --port "830" --user ${USERCOMMON} --password ${COMMONPASSWD} --type cba \
                       --operation configure --input-file node_configuration/HSS_ESM_02.xml --log out_HSS_ESM_02.$$

      echo "Starting for HSS_ESM_025.xml"
      ${JAVA_PATH}/java -jar ${PDB_CONFIG_TOOL} --host ${VIPOAM} --port "830" --user ${USERCOMMON} --password ${COMMONPASSWD} --type cba \
                       --operation configure --input-file node_configuration/HSS_ESM_025.xml  --log out_HSS_ESM_025.$$
 
      echo "Starting for HSS_ESM_03.xml"
      ${JAVA_PATH}/java -jar ${PDB_CONFIG_TOOL} --host ${VIPOAM} --port "830" --user ${USERCOMMON} --password ${COMMONPASSWD} --type cba \
                       --operation configure --input-file node_configuration/HSS_ESM_03.xml --log out_HSS_ESM_03.$$

      echo "Starting for HSS_ESM_04.xml"
      ${JAVA_PATH}/java -jar ${PDB_CONFIG_TOOL} --host ${VIPOAM} --port "830" --user ${USERCOMMON} --password ${COMMONPASSWD} --type cba \
                       --operation configure --input-file node_configuration/HSS_ESM_04.xml --log out_HSS_ESM_04.$$

      echo "Starting for HSS_ESM_05.xml"
      ${JAVA_PATH}/java -jar ${PDB_CONFIG_TOOL} --host ${VIPOAM} --port "830" --user ${USERCOMMON} --password ${COMMONPASSWD} --type cba \
                       --operation configure --input-file node_configuration/HSS_ESM_05.xml --log out_HSS_ESM_05.$$

      echo "Starting for HSS_ESM_07.xml"
      ${JAVA_PATH}/java -jar ${PDB_CONFIG_TOOL} --host ${VIPOAM} --port "830" --user ${USERCOMMON} --password ${COMMONPASSWD} --type cba \
                       --operation configure --input-file node_configuration/HSS_ESM_07.xml --log out_HSS_ESM_07.$$

      echo "Starting for HSS_ESM_08.xml"
      ${JAVA_PATH}/java -jar ${PDB_CONFIG_TOOL} --host ${VIPOAM} --port "830" --user ${USERCOMMON} --password ${COMMONPASSWD} --type cba \
                       --operation configure --input-file node_configuration/HSS_ESM_08.xml --log out_HSS_ESM_08.$$

      echo "Starting for HSS_ESM_09.xml"
      ${JAVA_PATH}/java -jar ${PDB_CONFIG_TOOL} --host ${VIPOAM} --port "830" --user ${USERCOMMON} --password ${COMMONPASSWD} --type cba \
                       --operation configure --input-file node_configuration/HSS_ESM_09.xml --log out_HSS_ESM_09.$$

      echo "Starting for HSS_ESM_10.xml"
      ${JAVA_PATH}/java -jar ${PDB_CONFIG_TOOL} --host ${VIPOAM} --port "830" --user ${USERCOMMON} --password ${COMMONPASSWD} --type cba \
                       --operation configure --input-file node_configuration/HSS_ESM_10.xml --log out_HSS_ESM_10.$$

      echo "Starting for HSS_ESM_11.xml"
      ${JAVA_PATH}/java -jar ${PDB_CONFIG_TOOL} --host ${VIPOAM} --port "830" --user ${USERCOMMON} --password ${COMMONPASSWD} --type cba \
                       --operation configure --input-file node_configuration/HSS_ESM_11.xml --log out_HSS_ESM_11.$$

      echo "Starting for HSS_ESM_12.xml"
      ${JAVA_PATH}/java -jar ${PDB_CONFIG_TOOL} --host ${VIPOAM} --port "830" --user ${USERCOMMON} --password ${COMMONPASSWD} --type cba \
                       --operation configure --input-file node_configuration/HSS_ESM_12.xml --log out_HSS_ESM_12.$$

     fi
 
   if [ "$VECTOR_SUPPLIER" == "AVG" ] ; then
      if [ "$license_ESM" == "1" ]; then

           if [ "$RE_POPULATION" == "TRUE" -a "$BASE_VECTOR_SUPPLIER" == "HLR" ]; then
                  echo "Starting for avg_10.xml"
                  ${JAVA_PATH}/java -jar ${PDB_CONFIG_TOOL} --host ${VIPOAM} --port "830" --user ${USERLICENSE} --password ${LICENSEPASSWD} --type cba \
                          --operation configure --input-file node_configuration/avg_10.xml --log out_avg_10.$$
           fi
            echo "Starting for esm_hlr1.xml"
                  ${JAVA_PATH}/java -jar ${PDB_CONFIG_TOOL} --host ${VIPOAM} --port "830" --user ${USERLICENSE} --password ${LICENSEPASSWD} --type cba \
                          --operation configure --input-file node_configuration/esm_hlr1.xml --log out_esm_hlr1.$$
            echo "Starting for hss_6.xml"
            ${JAVA_PATH}/java -jar ${PDB_CONFIG_TOOL} --host ${VIPOAM} --port "830" --user ${USERLICENSE} --password ${LICENSEPASSWD} --type cba \
                       --operation configure --input-file node_configuration/hss_6.xml --log out_hss_6.$$
            echo "Starting for avg_7.xml"
            ${JAVA_PATH}/java -jar ${PDB_CONFIG_TOOL} --host ${VIPOAM} --port "830" --user ${USERLICENSE} --password ${LICENSEPASSWD} --type cba \
                       --operation configure --input-file node_configuration/avg_7.xml --log out_avg_7.$$
            echo "Starting for HSS_ESM_06.xml"
            ${JAVA_PATH}/java -jar ${PDB_CONFIG_TOOL} --host ${VIPOAM} --port "830" --user ${USERLICENSE} --password ${LICENSEPASSWD} --type cba \
                       --operation configure --input-file node_configuration/HSS_ESM_06.xml --log out_HSS_ESM_06.$$
      fi
      if [ "$license_ISMSDA" == "1" ]; then

            echo "Starting for avg_8.xml"
            ${JAVA_PATH}/java -jar ${PDB_CONFIG_TOOL} --host ${VIPOAM} --port "830" --user ${USERLICENSE} --password ${LICENSEPASSWD} --type cba \
                       --operation configure --input-file node_configuration/avg_8.xml --log out_avg_8.$$
            if [ "$RE_POPULATION" == "TRUE" -a "$BASE_VECTOR_SUPPLIER" == "HLR" ]; then
                  echo "Starting for avg_9.xml"
                  ${JAVA_PATH}/java -jar ${PDB_CONFIG_TOOL} --host ${VIPOAM} --port "830" --user ${USERLICENSE} --password ${LICENSEPASSWD} --type cba \
                          --operation configure --input-file node_configuration/avg_9.xml --log out_avg_9.$$
            fi
      fi
      
      echo "wait 120s for MPV stack up..."
      sleep 120s

     echo "Starting for mpv1.xml"
     ${JAVA_PATH}/java -jar ${PDB_CONFIG_TOOL} --host ${VIPOAM} --port "830" --user ${USERCOMMON} --password ${COMMONPASSWD} --type cba \
                         --operation configure --input-file node_configuration/mpv1.xml --log out_mpv1.$$

     echo "Starting for mpv2.xml"
     ${JAVA_PATH}/java -jar ${PDB_CONFIG_TOOL} --host ${VIPOAM} --port "830" --user ${USERCOMMON} --password ${COMMONPASSWD} --type cba \
                         --operation configure --input-file node_configuration/mpv2.xml --log out_mpv2.$$

     echo "Starting for mpv3.xml"
     ${JAVA_PATH}/java -jar ${PDB_CONFIG_TOOL} --host ${VIPOAM} --port "830" --user ${USERCOMMON} --password ${COMMONPASSWD} --type cba \
                         --operation configure --input-file node_configuration/mpv3.xml --log out_mpv3.$$

     if [ "$license_ESM" == "1" ]; then
        echo "Starting for mpv4_esm.xml"
        ${JAVA_PATH}/java -jar ${PDB_CONFIG_TOOL} --host ${VIPOAM} --port "830" --user ${USERCOMMON} --password ${COMMONPASSWD} --type cba \
                         --operation configure --input-file node_configuration/mpv4_esm.xml --log out_mpv4_esm.$$
     fi

   fi
   
   #Rsyslog remove
   if [ "$LOG_STREAM_AUTO" == "TRUE" ]; then 
     ./certificate/remove_hss_logm.expect $SC_IP_ADDRESS_IPV4 $USERCOMEMERGENCY $COMEMERGENCYPASSWD 
   fi
     echo "Starting for HSS_UDM_02.xml"
      ${JAVA_PATH}/java -jar ${PDB_CONFIG_TOOL} --host ${VIPOAM} --port "830" --user ${USERCOMMON} --password ${COMMONPASSWD} --type cba \
                       --operation configure --input-file node_configuration/HSS_UDM_02.xml --log out_HSS_UDM_02.$$
     echo "Starting for HSS_UDICOM_PATCH_SUPPORT"
      ${JAVA_PATH}/java -jar ${PDB_CONFIG_TOOL} --host ${VIPOAM} --port "830" --user ${USERCOMMON} --password ${COMMONPASSWD} --type cba \
                       --operation configure --input-file node_configuration/temp_HSS_UDICOM_PATCH_SUPPORT.xml --log out_HSS_UDICOM_PATCH_SUPPORT.$$			   
     echo "Starting for HSS_UDICOM_01.xml by resetting tlsport as 0"
     ${JAVA_PATH}/java -jar ${PDB_CONFIG_TOOL} --host ${VIPOAM} --port "830" --user ${USERCOMMON} --password ${COMMONPASSWD} --type cba \
                       --operation configure --input-file node_configuration/temp_HSS_TMP_UDICOM_01.xml --log out_temp_HSS_TMP_UDICOM_01.$$
     echo "Starting for HSS_HTTP2_UDM_01.xml by resetting tlsmode as 0"
     ${JAVA_PATH}/java -jar ${PDB_CONFIG_TOOL} --host ${VIPOAM} --port "830" --user ${USERCOMMON} --password ${COMMONPASSWD} --type cba \
                       --operation configure --input-file node_configuration/temp_HSS_TMP_HTTP2_UDM_01.xml --log out_HSS_TMP_HTTP2_UDM_01.$$
     sleep 10
     ./certificate/remove_hss_http2.expect $SC_IP_ADDRESS_IPV4 $USERCOMEMERGENCY $COMEMERGENCYPASSWD

   if [ "$HTTP2_TLSMODE" != 0 ]; then
     if [ "$IS_IPV6" == "TRUE" ]; then
          SC_IP_ADDRESS="$SC_IP_ADDRESS_IPV6"
          SC_IP_ADDRESS_1="[""$SC_IP_ADDRESS""]"
          HOST_NAME_1="[""$HOST_NAME""]"
          PROXY_BACKEND_IP_ADDRESS="$PROXY_BACKEND_IP_ADDRESS_IPV6"
     else
          SC_IP_ADDRESS="$SC_IP_ADDRESS_IPV4"
          SC_IP_ADDRESS_1="$SC_IP_ADDRESS"
          HOST_NAME_1="$HOST_NAME"
          PROXY_BACKEND_IP_ADDRESS="$PROXY_BACKEND_IP_ADDRESS_IPV4"
     fi

     ./certificate/generate_certificateChain.sh $UDM_IP_ON_HSS $HOST_NAME $HOST_NAME_1 $SC_IP_ADDRESS $SC_IP_ADDRESS_1 ${USERCOMMON} ${COMMONPASSWD} $HSS_INTERMEDIATE_DEPTH $UDM_INTERMEDIATE_DEPTH $PROXY_BACKEND_IP_ADDRESS $PROXY_OAM_IP_ADDRESS $PROXYCOMMONUSER $PROXYCOMMONPW $PROXY_INTERMEDIATE_DEPTH

   fi
   echo "Starting for HSS_UDICOM_01.xml"
      ${JAVA_PATH}/java -jar ${PDB_CONFIG_TOOL} --host ${VIPOAM} --port "830" --user ${USERCOMMON} --password ${COMMONPASSWD} --type cba \
                       --operation configure --input-file node_configuration/temp_HSS_UDICOM_01.xml --log out_temp_HSS_UDICOM_01.$$

   echo "Starting for HSS_HTTP2_UDM_01.xml"
      ${JAVA_PATH}/java -jar ${PDB_CONFIG_TOOL} --host ${VIPOAM} --port "830" --user ${USERCOMMON} --password ${COMMONPASSWD} --type cba \
                       --operation configure --input-file node_configuration/temp_HSS_HTTP2_UDM_01.xml --log out_HSS_HTTP2_UDM_01.$$
					   
   if [ "$RE_POPULATION" == "TRUE" ] ; then
   echo "Starting for clear HSS-CommonIMSISeries=26228000011,HSS-CommonIMSISeries=26228000076,HSS-CommonIMSISeries=26228000077"
    ./scripts/remove_IMSISeries.expect $SC_IP_ADDRESS_IPV4 $USERCOMEMERGENCY $COMEMERGENCYPASSWD
   fi
   
   echo "Starting for hss_10.xml"
      ${JAVA_PATH}/java -jar ${PDB_CONFIG_TOOL} --host ${VIPOAM} --port "830" --user ${USERCOMEMERGENCY} --password ${COMEMERGENCYPASSWD} --type cba \
                      --operation configure --input-file node_configuration/hss_10.xml --log out_hss_10.$$
                
   ## https://udm-hss-jira.rnd.ki.sw.ericsson.se/browse/HSSTR-471
   ## Removed if condition will result in population error but at least is always executed

      echo "Starting for HSS_evip_02.xml"
         ${JAVA_PATH}/java -jar ${PDB_CONFIG_TOOL} --host ${VIPOAM} --port "830" --user ${USEREVIP} --password ${EVIPPASSWD} --type cba \
                          --operation configure --input-file node_configuration/temp_HSS_evip_02.xml --log out_HSS_evip_02.$$
  
    if [ "$RE_POPULATION" == "TRUE" ] ; then
   echo "Starting for clear EvipFlowPolicy=rest11"
    ./scripts/remove_EvipFlowPolicy_rest11.expect ${VIPOAM} $USERCOMEMERGENCY $COMEMERGENCYPASSWD > out_delete_rest11.$$
   fi
 
   
   echo "Starting for extdb_cudb.xml"
   ${JAVA_PATH}/java -jar ${PDB_CONFIG_TOOL} --host ${VIPOAM} --port "830" --user ${USERCOMMON} --password ${COMMONPASSWD} --type cba \
                       --operation configure --input-file node_configuration/temp_extdb_cudb.xml --log out_extdb_cudb.$$
   
   sleep 10

   ###Remove HSS LDAPS configurations
   ./certificate/remove_hss_ldaps.expect $SC_IP_ADDRESS_IPV4 $USERCOMEMERGENCY $COMEMERGENCYPASSWD
   

   if [ "$LDAPS_TLSMODE" == "1" ]; then
     EXTDB_LDAPS_TLSMODE="ldaps_MTLS"
     find ./node_configuration -name 'temp_1_extdb_ldaps.xml*' | xargs sed -i "s/LDAPS_TLSMODE/$EXTDB_LDAPS_TLSMODE/g"
     ${JAVA_PATH}/java -jar ${PDB_CONFIG_TOOL} --host ${VIPOAM} --port "830" --user ${USERCOMMON} --password ${COMMONPASSWD} --type cba \
                      --operation configure --input-file node_configuration/temp_1_extdb_ldaps.xml --log out_extdb_ldaps.$$
   fi

   if [ "$LDAPS_TLSMODE" == "2" ]; then
     EXTDB_LDAPS_TLSMODE="ldaps_TLS"
     find ./node_configuration -name 'temp_1_extdb_ldaps.xml*' | xargs sed -i "s/LDAPS_TLSMODE/$EXTDB_LDAPS_TLSMODE/g"
     ${JAVA_PATH}/java -jar ${PDB_CONFIG_TOOL} --host ${VIPOAM} --port "830" --user ${USERCOMMON} --password ${COMMONPASSWD} --type cba \
                      --operation configure --input-file node_configuration/temp_1_extdb_ldaps.xml --log out_extdb_ldaps.$$
   fi
  

   if [ "$LDAPS_TLSMODE" != 0 ]; then 
    if [ "$IS_IPV6" == "TRUE" ]; then
      HSS_LDAP_IP_ADDRESS="$LDAP_IPV6"
    else
      HSS_LDAP_IP_ADDRESS="$LDAP_IPV4"
    fi
   ./certificate/generate_ldaps_certificateChain.sh $HSS_LDAP_IP_ADDRESS $EXTDB $SC_IP_ADDRESS_IPV4 ${USERCOMMON} ${COMMONPASSWD} $HSSLDAPS_INTERMEDIATE_DEPTH $EXTDBLDAPS_INTERMEDIATE_DEPTH $LDAPS_TLSMODE $CUDB 
   fi   

   ## Rsyslog installation 
   if [ "$LOG_STREAM_AUTO" == "TRUE" ]; then
     ./certificate/install_hss_logm_certificate.expect $RSYSLOG_SERVER_IPADDRESS $SC_IP_ADDRESS_IPV4 ${USERCOMMON} ${COMMONPASSWD} ${USERROOT} ${ROOTPASSWD}
   fi  

   ###### HLR related population
   if [ "$VECTOR_SUPPLIER" == "HLR" ] ; then

     if [ "$license_ISMSDA" == "1" ]; then
        if [ \( "$BASE_VECTOR_SUPPLIER" == "AVG" -a "$VECTOR_PREV_CONFIGURED" == "FALSE" \) -o \( "$RE_POPULATION" == "FALSE" \) ] ; then
          echo "Starting for ism_hlr1.xml"
	  ${JAVA_PATH}/java -jar ${PDB_CONFIG_TOOL} --host ${VIPOAM} --port "830" --user ${USERLICENSE} --password ${LICENSEPASSWD} --type cba \
                           --operation configure --input-file node_configuration/ism_hlr1.xml --log out_ism_hlr1.$$
        fi

        echo "Starting for ism_hlr2.xml"
	${JAVA_PATH}/java -jar ${PDB_CONFIG_TOOL} --host ${VIPOAM} --port "830" --user ${USERLICENSE} --password ${LICENSEPASSWD} --type cba \
                         --operation configure --input-file node_configuration/ism_hlr2.xml --log out_ism_hlr2.$$                                
     fi

     if [ "$license_ESM" == "1" ]; then
       if [ \( "$BASE_VECTOR_SUPPLIER" == "AVG" -a "$VECTOR_PREV_CONFIGURED" == "FALSE" \) -o \( "$RE_POPULATION" == "FALSE" \) ] ; then
          echo "Starting for esm_hlr1.xml"
	  ${JAVA_PATH}/java -jar ${PDB_CONFIG_TOOL} --host ${VIPOAM} --port "830" --user ${USERLICENSE} --password ${LICENSEPASSWD} --type cba \
                           --operation configure --input-file node_configuration/esm_hlr1.xml --log out_esm_hlr1.$$
       fi

        echo "Starting for esm_hlr2.xml"
	${JAVA_PATH}/java -jar ${PDB_CONFIG_TOOL} --host ${VIPOAM} --port "830" --user ${USERLICENSE} --password ${LICENSEPASSWD} --type cba \
                         --operation configure --input-file node_configuration/esm_hlr2.xml --log out_esm_hlr2.$$
        echo "Starting for hss_7.xml"
            ${JAVA_PATH}/java -jar ${PDB_CONFIG_TOOL} --host ${VIPOAM} --port "830" --user ${USERLICENSE} --password ${LICENSEPASSWD} --type cba \
                       --operation configure --input-file node_configuration/hss_7.xml --log out_hss_7.$$                                
     fi

     echo "wait 120s for MPV stack up..."
     sleep 120

     echo "Starting for mpv1.xml"
     ${JAVA_PATH}/java -jar ${PDB_CONFIG_TOOL} --host ${VIPOAM} --port "830" --user ${USERCOMMON} --password ${COMMONPASSWD} --type cba \
                         --operation configure --input-file node_configuration/mpv1.xml --log out_mpv1.$$

     echo "Starting for mpv2.xml"
     ${JAVA_PATH}/java -jar ${PDB_CONFIG_TOOL} --host ${VIPOAM} --port "830" --user ${USERCOMMON} --password ${COMMONPASSWD} --type cba \
                         --operation configure --input-file node_configuration/mpv2.xml --log out_mpv2.$$

     echo "Starting for mpv3.xml"
     ${JAVA_PATH}/java -jar ${PDB_CONFIG_TOOL} --host ${VIPOAM} --port "830" --user ${USERCOMMON} --password ${COMMONPASSWD} --type cba \
                         --operation configure --input-file node_configuration/mpv3.xml --log out_mpv3.$$
    

     if [ "$license_ISMSDA" == "1" ]; then
        echo "Starting for mpv4_ism.xml"
	${JAVA_PATH}/java -jar ${PDB_CONFIG_TOOL} --host ${VIPOAM} --port "830" --user ${USERCOMMON} --password ${COMMONPASSWD} --type cba \
                         --operation configure --input-file node_configuration/mpv4_ism.xml --log out_mpv4_ism.$$

        echo "Starting for ism_hlr3.xml"
	${JAVA_PATH}/java -jar ${PDB_CONFIG_TOOL} --host ${VIPOAM} --port "830" --user ${USERCOMMON} --password ${COMMONPASSWD} --type cba \
                         --operation configure --input-file node_configuration/ism_hlr3.xml --log out_ism_hlr3.$$                                
     fi

     if [ "$license_ESM" == "1" ]; then
        echo "Starting for mpv4_esm.xml"
	${JAVA_PATH}/java -jar ${PDB_CONFIG_TOOL} --host ${VIPOAM} --port "830" --user ${USERCOMMON} --password ${COMMONPASSWD} --type cba \
                         --operation configure --input-file node_configuration/mpv4_esm.xml --log out_mpv4_esm.$$

        echo "Starting for esm_hlr3.xml"
	${JAVA_PATH}/java -jar ${PDB_CONFIG_TOOL} --host ${VIPOAM} --port "830" --user ${USERLICENSE} --password ${LICENSEPASSWD} --type cba \
                         --operation configure --input-file node_configuration/esm_hlr3.xml --log out_esm_hlr3.$$   

        echo "Starting for esm_hlr4.xml"
	${JAVA_PATH}/java -jar ${PDB_CONFIG_TOOL} --host ${VIPOAM} --port "830" --user ${USERCOMMON} --password ${COMMONPASSWD} --type cba \
                         --operation configure --input-file node_configuration/esm_hlr4.xml --log out_esm_hlr4.$$ 

        echo "Starting for esm_hlr5.xml"
        ${JAVA_PATH}/java -jar ${PDB_CONFIG_TOOL} --host ${VIPOAM} --port "830" --user ${USERLICENSE} --password ${LICENSEPASSWD} --type cba \
                         --operation configure --input-file node_configuration/esm_hlr5.xml --log out_esm_hlr5.$$

        echo "Starting for common_hlr1.xml"
        ${JAVA_PATH}/java -jar ${PDB_CONFIG_TOOL} --host ${VIPOAM} --port "830" --user ${USERCOMMON} --password ${COMMONPASSWD} --type cba \
                         --operation configure --input-file node_configuration/common_hlr1.xml --log out_common_hlr1.$$  

     fi                         
                         
   fi

#fi
	
exit $?
