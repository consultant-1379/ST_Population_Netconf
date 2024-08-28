#!/bin/sh -f
CERTIFICATE_STORE_PATH=./tmp/
UDM_CERTIFICATE_PATH=./udmCertificate/
HSS_CERTIFICATE_PATH=./hssCertificate/
PROXY_CERTIFICATE_PATH=./proxyCertificate/
hssIntermediateDepth=$8
udmIntermediateDepth=$9
proxyIntermediateDepth=${14}
hssIpAddress=$1
udmIpAddress=$2
proxyIpAddress=${10}


echo "HSS_IP: $1"
echo "UDM_IP: $2"
echo "PROXY_IP: ${10}"
echo "PROXY_OAM_IP: ${11}"
echo "SC-IP: $4"
echo "User: $6"
echo "Password: $7"
echo "$PWD"
BASEDIR=$(dirname "$0")
echo "$BASEDIR"
path=$PWD/$BASEDIR
CERTIFICATE_PATH=$path/$CERTIFICATE_STORE_PATH
echo $CERTIFICATE_PATH

#1. generate 
create_certificate_path(){
   umask_ori=$(umask)
   umask 0002
   mkdir -p $CERTIFICATE_PATH
   cd $CERTIFICATE_PATH
   mkdir -p $UDM_CERTIFICATE_PATH
   mkdir -p $HSS_CERTIFICATE_PATH
   mkdir -p $PROXY_CERTIFICATE_PATH
   umask $umask_ori
} 
generate_hss_certificate(){
    openssl genrsa -aes256 -passout pass:123456 -out $HSS_CERTIFICATE_PATH/RootCA_HSS.key 4096
    openssl req -new -x509 -days 1826 -sha256 -passin pass:123456 -key $HSS_CERTIFICATE_PATH/RootCA_HSS.key -out $HSS_CERTIFICATE_PATH/RootCA_HSS.pem -subj "/C=US/O=xzy/OU=abc/CN=ROOT-HSS-CN"
    
    openssl genrsa -out $HSS_CERTIFICATE_PATH/hss.key 2048
    openssl req -new -sha256 -passin pass:123456 -key $HSS_CERTIFICATE_PATH/hss.key -out $HSS_CERTIFICATE_PATH/hss.csr -subj "/CN=$hssIpAddress"
   
    if [ "$hssIntermediateDepth" == "0" ]; then
      #create leaf HSS certificates directly based on RootCA
      openssl x509 -req -sha256 -passin pass:123456 -in $HSS_CERTIFICATE_PATH/hss.csr -CA $HSS_CERTIFICATE_PATH/RootCA_HSS.pem -CAkey $HSS_CERTIFICATE_PATH/RootCA_HSS.key -CAcreateserial -out $HSS_CERTIFICATE_PATH/hss.pem -days 5000
    else 
    #create Intermediate HSS1 CA
    openssl genrsa -aes256 -passout pass:123456 -out $HSS_CERTIFICATE_PATH/IntermediateCA_HSS1.key 4096
    openssl req -new -sha256 -passin pass:123456 -key $HSS_CERTIFICATE_PATH/IntermediateCA_HSS1.key -nodes -out $HSS_CERTIFICATE_PATH/IntermediateCA_HSS1.csr -subj "/C=US/O=xyz/OU=abc/CN=INTERIM-HSS1-CN"
    openssl x509 -req -sha256 -passin pass:123456 -days 1000 -extfile $path/MyOpenssl.conf -extensions int_ca -in $HSS_CERTIFICATE_PATH/IntermediateCA_HSS1.csr -CA $HSS_CERTIFICATE_PATH/RootCA_HSS.pem -CAkey $HSS_CERTIFICATE_PATH/RootCA_HSS.key -CAcreateserial -out $HSS_CERTIFICATE_PATH/IntermediateCA_HSS1.pem
    catCmd="$HSS_CERTIFICATE_PATH/IntermediateCA_HSS1.pem"
    m=2
    while [ $m -le $hssIntermediateDepth ]
    do
        openssl genrsa -aes256 -passout pass:123456 -out $HSS_CERTIFICATE_PATH/IntermediateCA_HSS$m.key 4096
        openssl req -new -sha256 -passin pass:123456 -key $HSS_CERTIFICATE_PATH/IntermediateCA_HSS$m.key -nodes -out $HSS_CERTIFICATE_PATH/IntermediateCA_HSS$m.csr -subj "/C=US/O=xyz/OU=abc/CN=INTERIM-HSS$m-CN"
        openssl x509 -req -sha256 -passin pass:123456 -days 1000 -extfile $path/MyOpenssl.conf -extensions int_ca -in $HSS_CERTIFICATE_PATH/IntermediateCA_HSS$m.csr -CA $HSS_CERTIFICATE_PATH/IntermediateCA_HSS$((m-1)).pem -CAkey $HSS_CERTIFICATE_PATH/IntermediateCA_HSS$((m-1)).key -CAcreateserial -out $HSS_CERTIFICATE_PATH/IntermediateCA_HSS$m.pem
        catCmd="$HSS_CERTIFICATE_PATH/IntermediateCA_HSS$m.pem ${catCmd}"
        m=$(( m+1 ))
    done
 
    #create leaf HSS certificates based on intermediateCA
    openssl x509 -req -sha256 -passin pass:123456 -in $HSS_CERTIFICATE_PATH/hss.csr -CA $HSS_CERTIFICATE_PATH/IntermediateCA_HSS$hssIntermediateDepth.pem -CAkey $HSS_CERTIFICATE_PATH/IntermediateCA_HSS$hssIntermediateDepth.key -CAcreateserial -out $HSS_CERTIFICATE_PATH/hss_crt.pem -days 5000
    catCmd="cat $HSS_CERTIFICATE_PATH/hss_crt.pem ${catCmd}"
    ${catCmd}>$HSS_CERTIFICATE_PATH/hss.pem
    fi
    openssl pkcs12 -export -inkey $HSS_CERTIFICATE_PATH/hss.key -in $HSS_CERTIFICATE_PATH/hss.pem -out $HSS_CERTIFICATE_PATH/hss_cert.p12 -password pass:123456
    openssl dgst -c -hex -sha224 $HSS_CERTIFICATE_PATH/hss_cert.p12
}

generate_udm_certificate(){
    cp $HSS_CERTIFICATE_PATH/RootCA_HSS.pem $UDM_CERTIFICATE_PATH
    cp $HSS_CERTIFICATE_PATH/RootCA_HSS.key $UDM_CERTIFICATE_PATH
    openssl genrsa -out $UDM_CERTIFICATE_PATH/udm.key 2048
    openssl req -new -sha256 -passin pass:123456 -key $UDM_CERTIFICATE_PATH/udm.key -out $UDM_CERTIFICATE_PATH/udm.csr -subj "/CN=$udmIpAddress"

    if [ "$udmIntermediateDepth" == "0" ]; then
      #create Enduser certificates directly based on RootCA
      openssl x509 -req -sha256 -passin pass:123456 -in $UDM_CERTIFICATE_PATH/udm.csr -CA $UDM_CERTIFICATE_PATH/RootCA_HSS.pem -CAkey $UDM_CERTIFICATE_PATH/RootCA_HSS.key -set_serial 01 -out $UDM_CERTIFICATE_PATH/udm.pem -days 500
    else 
    #create Intermediate UDM1 CA
    openssl genrsa -aes256 -passout pass:123456 -out $UDM_CERTIFICATE_PATH/IntermediateCA_UDM1.key 4096
    openssl req -new -sha256 -passin pass:123456 -key $UDM_CERTIFICATE_PATH/IntermediateCA_UDM1.key -nodes -out $UDM_CERTIFICATE_PATH/IntermediateCA_UDM1.csr -subj "/C=US/O=xyz/OU=abc/CN=INTERIM-UDM1-CN"
    openssl x509 -req -sha256 -passin pass:123456 -days 1000 -extfile $path/MyOpenssl.conf -extensions int_ca -in $UDM_CERTIFICATE_PATH/IntermediateCA_UDM1.csr -CA $UDM_CERTIFICATE_PATH/RootCA_HSS.pem -CAkey $UDM_CERTIFICATE_PATH/RootCA_HSS.key -CAcreateserial -out $UDM_CERTIFICATE_PATH/IntermediateCA_UDM1.pem
    catCmd="$UDM_CERTIFICATE_PATH/IntermediateCA_UDM1.pem"
    m=2
    while [ $m -le $udmIntermediateDepth ]
    do
        openssl genrsa -aes256 -passout pass:123456 -out $UDM_CERTIFICATE_PATH/IntermediateCA_UDM$m.key 4096
        openssl req -new -sha256 -passin pass:123456 -key $UDM_CERTIFICATE_PATH/IntermediateCA_UDM$m.key -nodes -out $UDM_CERTIFICATE_PATH/IntermediateCA_UDM$m.csr -subj "/C=US/O=xyz/OU=abc/CN=INTERIM-UDM$m-CN"
        openssl x509 -req -sha256 -passin pass:123456 -days 1000 -extfile $path/MyOpenssl.conf -extensions int_ca -in $UDM_CERTIFICATE_PATH/IntermediateCA_UDM$m.csr -CA $UDM_CERTIFICATE_PATH/IntermediateCA_UDM$((m-1)).pem -CAkey $UDM_CERTIFICATE_PATH/IntermediateCA_UDM$((m-1)).key -CAcreateserial -out $UDM_CERTIFICATE_PATH/IntermediateCA_UDM$m.pem
        catCmd="$UDM_CERTIFICATE_PATH/IntermediateCA_UDM$m.pem ${catCmd}"
        m=$(( m+1 ))
    done
    #create EndUser certificates based on intermediateCA
    openssl x509 -req -sha256 -passin pass:123456 -in $UDM_CERTIFICATE_PATH/udm.csr -CA $UDM_CERTIFICATE_PATH/IntermediateCA_UDM$udmIntermediateDepth.pem -CAkey $UDM_CERTIFICATE_PATH/IntermediateCA_UDM$udmIntermediateDepth.key -set_serial 01 -out $UDM_CERTIFICATE_PATH/udm_crt.pem -days 500
    catCmd="cat $UDM_CERTIFICATE_PATH/udm_crt.pem ${catCmd}"
    ${catCmd}>$UDM_CERTIFICATE_PATH/udm.pem
    fi
  
}

generate_proxy_certificate(){
    cp $HSS_CERTIFICATE_PATH/RootCA_HSS.pem $PROXY_CERTIFICATE_PATH
    cp $HSS_CERTIFICATE_PATH/RootCA_HSS.key $PROXY_CERTIFICATE_PATH
    openssl genrsa -out $PROXY_CERTIFICATE_PATH/proxy.key 2048
    openssl req -new -sha256 -passin pass:123456 -key $PROXY_CERTIFICATE_PATH/proxy.key -out $PROXY_CERTIFICATE_PATH/proxy.csr -subj "/CN=$proxyIpAddress"

    if [ "$proxyIntermediateDepth" == "0" ]; then
      #create Enduser certificates directly based on RootCA
      openssl x509 -req -passin pass:123456 -in $PROXY_CERTIFICATE_PATH/proxy.csr -CA $PROXY_CERTIFICATE_PATH/RootCA_HSS.pem -CAkey $PROXY_CERTIFICATE_PATH/RootCA_HSS.key -set_serial 01 -out $PROXY_CERTIFICATE_PATH/proxy.pem -days 500 -sha256
    else 
    #create Intermediate PROXY1 CA
    openssl genrsa -aes256 -passout pass:123456 -out $PROXY_CERTIFICATE_PATH/IntermediateCA_PROXY1.key 4096
    openssl req -new -sha256 -passin pass:123456 -key $PROXY_CERTIFICATE_PATH/IntermediateCA_PROXY1.key -nodes -out $PROXY_CERTIFICATE_PATH/IntermediateCA_PROXY1.csr -subj "/C=US/O=xyz/OU=abc/CN=INTERIM-PROXY1-CN"
    openssl x509 -req -sha256 -passin pass:123456 -days 1000 -extfile $path/MyOpenssl.conf -extensions int_ca -in $PROXY_CERTIFICATE_PATH/IntermediateCA_PROXY1.csr -CA $PROXY_CERTIFICATE_PATH/RootCA_HSS.pem -CAkey $PROXY_CERTIFICATE_PATH/RootCA_HSS.key -CAcreateserial -out $PROXY_CERTIFICATE_PATH/IntermediateCA_PROXY1.pem
    catCmd="$PROXY_CERTIFICATE_PATH/IntermediateCA_PROXY1.pem"
    m=2
    while [ $m -le $proxyIntermediateDepth ]
    do
        openssl genrsa -aes256 -passout pass:123456 -out $PROXY_CERTIFICATE_PATH/IntermediateCA_PROXY$m.key 4096
        openssl req -new -sha256 -passin pass:123456 -key $PROXY_CERTIFICATE_PATH/IntermediateCA_PROXY$m.key -nodes -out $PROXY_CERTIFICATE_PATH/IntermediateCA_PROXY$m.csr -subj "/C=US/O=xyz/OU=abc/CN=INTERIM-PROXY$m-CN"
        openssl x509 -req -sha256 -passin pass:123456 -days 1000 -extfile $path/MyOpenssl.conf -extensions int_ca -in $PROXY_CERTIFICATE_PATH/IntermediateCA_PROXY$m.csr -CA $PROXY_CERTIFICATE_PATH/IntermediateCA_PROXY$((m-1)).pem -CAkey $PROXY_CERTIFICATE_PATH/IntermediateCA_PROXY$((m-1)).key -CAcreateserial -out $PROXY_CERTIFICATE_PATH/IntermediateCA_PROXY$m.pem
        catCmd="$PROXY_CERTIFICATE_PATH/IntermediateCA_PROXY$m.pem ${catCmd}"
        m=$(( m+1 ))
    done
    #create EndUser certificates based on intermediateCA
    openssl x509 -req -passin pass:123456 -in $PROXY_CERTIFICATE_PATH/proxy.csr -CA $PROXY_CERTIFICATE_PATH/IntermediateCA_PROXY$proxyIntermediateDepth.pem -CAkey $PROXY_CERTIFICATE_PATH/IntermediateCA_PROXY$proxyIntermediateDepth.key -set_serial 01 -out $PROXY_CERTIFICATE_PATH/proxy_crt.pem -days 500 -sha256
    catCmd="cat $PROXY_CERTIFICATE_PATH/proxy_crt.pem ${catCmd}"
    ${catCmd}>$PROXY_CERTIFICATE_PATH/proxy.pem
    fi
  
}

tar_hss_certificate(){ 
   tar -cvf hssCertificate.tar $HSS_CERTIFICATE_PATH/hss_cert.p12 $HSS_CERTIFICATE_PATH/RootCA_HSS.pem
}

tar_udm_certificate(){
   cp $UDM_CERTIFICATE_PATH/RootCA_HSS.pem ca.crt
   cp $UDM_CERTIFICATE_PATH/RootCA_HSS.key ca.key
   cp $UDM_CERTIFICATE_PATH/udm.pem server.crt
   cp $UDM_CERTIFICATE_PATH/udm.key server.key
   tar -cvf udmCertificate.tar ca.crt ca.key server.crt server.key
}
  
tar_proxy_certificate(){
   cp $PROXY_CERTIFICATE_PATH/RootCA_HSS.pem ca.crt
   cp $PROXY_CERTIFICATE_PATH/proxy.pem nghttpx.crt
   cp $PROXY_CERTIFICATE_PATH/proxy.key nghttpx.key
   tar -cvf proxyCertificate.tar ca.crt nghttpx.crt nghttpx.key
}

create_certificate_path
generate_hss_certificate
generate_udm_certificate
generate_proxy_certificate
tar_hss_certificate
tar_udm_certificate
tar_proxy_certificate
cd ..
$path/install_hss_certificate.expect $4 $5 $6 $7 $CERTIFICATE_PATH
$path/install_udm_certificate.expect $2 $3 $CERTIFICATE_PATH
$path/install_proxy_certificate.expect ${11} ${12} ${13} $CERTIFICATE_PATH

rm -rf $CERTIFICATE_PATH
