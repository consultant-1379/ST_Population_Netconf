#!/bin/sh -f
CERTIFICATE_STORE_PATH=./ldaps_tmp/
EXTDB_CERTIFICATE_PATH=./extdbCertificate/
HSSLDAPS_CERTIFICATE_PATH=./hssldapsCertificate/
hssldapsIntermediateDepth=$6
extdbIntermediateDepth=$7
hssldapsIpAddress=$1
extdbIpAddress=$2
tlsmode=$8
cudb=$9

echo "HSS_LDAP_IP: $1"
echo "EXTDB: $2"
echo "SC-IP: $3"
echo "User: $4"
echo "Password: $5"
echo "$PWD"
BASEDIR=$(dirname "$0")
echo "$BASEDIR"
path=$PWD/$BASEDIR
CERTIFICATE_PATH=$path/$CERTIFICATE_STORE_PATH
echo $CERTIFICATE_PATH

create_certificate_path(){
   umask_ori=$(umask)
   umask 0002
   mkdir -p $CERTIFICATE_PATH
   cd $CERTIFICATE_PATH
   mkdir -p $EXTDB_CERTIFICATE_PATH
   mkdir -p $HSSLDAPS_CERTIFICATE_PATH
   umask $umask_ori
} 

generate_hssldaps_certificate(){
    openssl genrsa -aes256 -passout pass:123456 -out $HSSLDAPS_CERTIFICATE_PATH/CAldapscert.key 4096
    openssl req -new -x509 -days 1826 -sha256 -passin pass:123456 -key $HSSLDAPS_CERTIFICATE_PATH/CAldapscert.key -out $HSSLDAPS_CERTIFICATE_PATH/CAldapscert.pem -subj "/C=US/O=xzy/OU=abc/CN=ROOT-CALDAPSCERT-CN"
    
    openssl genrsa -out $HSSLDAPS_CERTIFICATE_PATH/hssldapscert.key 2048
    openssl req -new -sha256 -passin pass:123456 -key $HSSLDAPS_CERTIFICATE_PATH/hssldapscert.key -out $HSSLDAPS_CERTIFICATE_PATH/hssldapscert.csr -subj "/CN=$hssldapsIpAddress"
   
    if [ "$hssldapsIntermediateDepth" == "0" ]; then
      #create leaf HSSLDAPS certificates directly based on RootCA
      openssl x509 -req -sha256 -passin pass:123456 -in $HSSLDAPS_CERTIFICATE_PATH/hssldapscert.csr -CA $HSSLDAPS_CERTIFICATE_PATH/CAldapscert.pem -CAkey $HSSLDAPS_CERTIFICATE_PATH/CAldapscert.key -CAcreateserial -out $HSSLDAPS_CERTIFICATE_PATH/hssldapscert.pem -days 5000
    else 
    #create Intermediate HSSLDAPSCERT1 CA
    openssl genrsa -aes256 -passout pass:123456 -out $HSSLDAPS_CERTIFICATE_PATH/IntermediateCA_HSSLDAPSCERT1.key 4096
    openssl req -new -sha256 -passin pass:123456 -key $HSSLDAPS_CERTIFICATE_PATH/IntermediateCA_HSSLDAPSCERT1.key -nodes -out $HSSLDAPS_CERTIFICATE_PATH/IntermediateCA_HSSLDAPSCERT1.csr -subj "/C=US/O=xyz/OU=abc/CN=INTERIM-HSSLDAPSCERT1-CN"
    openssl x509 -req -sha256 -passin pass:123456 -days 1000 -extfile $path/MyOpenssl.conf -extensions int_ca -in $HSSLDAPS_CERTIFICATE_PATH/IntermediateCA_HSSLDAPSCERT1.csr -CA $HSSLDAPS_CERTIFICATE_PATH/CAldapscert.pem -CAkey $HSSLDAPS_CERTIFICATE_PATH/CAldapscert.key -CAcreateserial -out $HSSLDAPS_CERTIFICATE_PATH/IntermediateCA_HSSLDAPSCERT1.pem
    catCmd="$HSSLDAPS_CERTIFICATE_PATH/IntermediateCA_HSSLDAPSCERT1.pem"
    m=2
    while [ $m -le $hssldapsIntermediateDepth ]
    do
        openssl genrsa -aes256 -passout pass:123456 -out $HSSLDAPS_CERTIFICATE_PATH/IntermediateCA_HSSLDAPSCERT$m.key 4096
        openssl req -new -sha256 -passin pass:123456 -key $HSSLDAPS_CERTIFICATE_PATH/IntermediateCA_HSSLDAPSCERT$m.key -nodes -out $HSSLDAPS_CERTIFICATE_PATH/IntermediateCA_HSSLDAPSCERT$m.csr -subj "/C=US/O=xyz/OU=abc/CN=INTERIM-HSSLDAPSCERT$m-CN"
        openssl x509 -req -sha256 -passin pass:123456 -days 1000 -extfile $path/MyOpenssl.conf -extensions int_ca -in $HSSLDAPS_CERTIFICATE_PATH/IntermediateCA_HSSLDAPSCERT$m.csr -CA $HSSLDAPS_CERTIFICATE_PATH/IntermediateCA_HSSLDAPSCERT$((m-1)).pem -CAkey $HSSLDAPS_CERTIFICATE_PATH/IntermediateCA_HSSLDAPSCERT$((m-1)).key -CAcreateserial -out $HSSLDAPS_CERTIFICATE_PATH/IntermediateCA_HSSLDAPSCERT$m.pem
        catCmd="$HSSLDAPS_CERTIFICATE_PATH/IntermediateCA_HSSLDAPSCERT$m.pem ${catCmd}"
        m=$(( m+1 ))
    done
 
    #create leaf HSSLDAPS certificates based on intermediateCA
    openssl x509 -req -sha256 -passin pass:123456 -in $HSSLDAPS_CERTIFICATE_PATH/hssldapscert.csr -CA $HSSLDAPS_CERTIFICATE_PATH/IntermediateCA_HSSLDAPSCERT$hssldapsIntermediateDepth.pem -CAkey $HSSLDAPS_CERTIFICATE_PATH/IntermediateCA_HSSLDAPSCERT$hssldapsIntermediateDepth.key -CAcreateserial -out $HSSLDAPS_CERTIFICATE_PATH/hssldapscert_crt.pem -days 5000
    catCmd="cat $HSSLDAPS_CERTIFICATE_PATH/hssldapscert_crt.pem ${catCmd}"
    ${catCmd}>$HSSLDAPS_CERTIFICATE_PATH/hssldapscert.pem
    fi
    openssl pkcs12 -export -inkey $HSSLDAPS_CERTIFICATE_PATH/hssldapscert.key -in $HSSLDAPS_CERTIFICATE_PATH/hssldapscert.pem -out $HSSLDAPS_CERTIFICATE_PATH/hssldapscert_cert.p12 -password pass:123456
    openssl dgst -c -hex -sha224 $HSSLDAPS_CERTIFICATE_PATH/hssldapscert_cert.p12
}

generate_extdb_certificate(){
    cp $HSSLDAPS_CERTIFICATE_PATH/CAldapscert.pem $EXTDB_CERTIFICATE_PATH/CAldapscert.pem
    cp $HSSLDAPS_CERTIFICATE_PATH/CAldapscert.key $EXTDB_CERTIFICATE_PATH
    openssl genrsa -out $EXTDB_CERTIFICATE_PATH/extdbldapscert.key 2048
    openssl req -new -sha256 -passin pass:123456 -key $EXTDB_CERTIFICATE_PATH/extdbldapscert.key -out $EXTDB_CERTIFICATE_PATH/extdbldapscert.csr -subj "/CN=$extdbIpAddress"
    if [ "$extdbIntermediateDepth" == "0" ]; then
      #create EXTDB certificates directly based on RootCA
      openssl x509 -req -sha256 -passin pass:123456 -in $EXTDB_CERTIFICATE_PATH/extdbldapscert.csr -CA $EXTDB_CERTIFICATE_PATH/CAldapscert.pem -CAkey $EXTDB_CERTIFICATE_PATH/CAldapscert.key -set_serial 01 -out $EXTDB_CERTIFICATE_PATH/extdbldapscert.pem -days 500
    else 
    #create Intermediate EXTDB1 CA
    openssl genrsa -aes256 -passout pass:123456 -out $EXTDB_CERTIFICATE_PATH/IntermediateCA_EXTDB1.key 4096
    openssl req -new -sha256 -passin pass:123456 -key $EXTDB_CERTIFICATE_PATH/IntermediateCA_EXTDB1.key -nodes -out $EXTDB_CERTIFICATE_PATH/IntermediateCA_EXTDB1.csr -subj "/C=US/O=xyz/OU=abc/CN=INTERIM-EXTDB1-CN"
    openssl x509 -req -sha256 -passin pass:123456 -days 1000 -extfile $path/MyOpenssl.conf -extensions int_ca -in $EXTDB_CERTIFICATE_PATH/IntermediateCA_EXTDB1.csr -CA $EXTDB_CERTIFICATE_PATH/CAldapscert.pem -CAkey $EXTDB_CERTIFICATE_PATH/CAldapscert.key -CAcreateserial -out $EXTDB_CERTIFICATE_PATH/IntermediateCA_EXTDB1.pem
    catCmd="$EXTDB_CERTIFICATE_PATH/IntermediateCA_EXTDB1.pem"
    m=2
    while [ $m -le $extdbIntermediateDepth ]
    do
        openssl genrsa -aes256 -passout pass:123456 -out $EXTDB_CERTIFICATE_PATH/IntermediateCA_EXTDB$m.key 4096
        openssl req -new -sha256 -passin pass:123456 -key $EXTDB_CERTIFICATE_PATH/IntermediateCA_EXTDB$m.key -nodes -out $EXTDB_CERTIFICATE_PATH/IntermediateCA_EXTDB$m.csr -subj "/C=US/O=xyz/OU=abc/CN=INTERIM-EXTDB$m-CN"
        openssl x509 -req -sha256 -passin pass:123456 -days 1000 -extfile $path/MyOpenssl.conf -extensions int_ca -in $EXTDB_CERTIFICATE_PATH/IntermediateCA_EXTDB$m.csr -CA $EXTDB_CERTIFICATE_PATH/IntermediateCA_EXTDB$((m-1)).pem -CAkey $EXTDB_CERTIFICATE_PATH/IntermediateCA_EXTDB$((m-1)).key -CAcreateserial -out $EXTDB_CERTIFICATE_PATH/IntermediateCA_EXTDB$m.pem
        catCmd="$EXTDB_CERTIFICATE_PATH/IntermediateCA_EXTDB$m.pem ${catCmd}"
        m=$(( m+1 ))
    done
    #create EXTDB certificates based on intermediateCA
    openssl x509 -req -sha256 -passin pass:123456 -in $EXTDB_CERTIFICATE_PATH/extdbldapscert.csr -CA $EXTDB_CERTIFICATE_PATH/IntermediateCA_EXTDB$extdbIntermediateDepth.pem -CAkey $EXTDB_CERTIFICATE_PATH/IntermediateCA_EXTDB$extdbIntermediateDepth.key -set_serial 01 -out $EXTDB_CERTIFICATE_PATH/extdbldapscert.pem -days 500
    catCmd="cat ${catCmd} $EXTDB_CERTIFICATE_PATH/CAldapscert.pem"
    ${catCmd}>$EXTDB_CERTIFICATE_PATH/CAldapscert_extdb.pem
    fi
  
}

tar_hssldaps_certificate(){ 
   tar -cvf hssldapsCertificate.tar $HSSLDAPS_CERTIFICATE_PATH/hssldapscert_cert.p12 $HSSLDAPS_CERTIFICATE_PATH/CAldapscert.pem
}

tar_extdb_certificate(){
   cp $EXTDB_CERTIFICATE_PATH/CAldapscert_extdb.pem CAldapscert.pem
   cp $EXTDB_CERTIFICATE_PATH/CAldapscert.key CAldapscert.key
   cp $EXTDB_CERTIFICATE_PATH/extdbldapscert.pem extdb.crt
   cp $EXTDB_CERTIFICATE_PATH/extdbldapscert.key extdb.key
   if [ "$cudb" == "FALSE" ]; then
     cp ../config_tlsmode1.sh config_tlsmode1.sh
     cp ../config_tlsmode2.sh config_tlsmode2.sh
     tar -cvf extdbCertificate.tar CAldapscert.pem CAldapscert.key extdb.crt extdb.key config_tlsmode1.sh config_tlsmode2.sh
   else
     tar -cvf extdbCertificate.tar CAldapscert.pem CAldapscert.key extdb.crt extdb.key 
     mv extdbCertificate.tar ../
   fi
}
  
create_certificate_path
generate_hssldaps_certificate
generate_extdb_certificate
tar_hssldaps_certificate
tar_extdb_certificate
cd ..
$path/install_hss_ldaps_certificate.expect $3 $4 $5 $CERTIFICATE_PATH

if [ "$cudb" == "FALSE" ]; then
  $path/install_extdb_certificate.expect $2 $8 $CERTIFICATE_PATH
fi

rm -rf $CERTIFICATE_PATH
