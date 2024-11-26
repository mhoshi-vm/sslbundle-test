DIR=$PWD/src/main/resources/self-signed
mkdir -p ${DIR}

# Create CA certificate
openssl req -new -nodes -out ${DIR}/ca.csr -keyout ${DIR}/ca.key -subj "/CN=demo/O=tanzu/C=JP"
chmod og-rwx ${DIR}/ca.key

cat <<EOF > ${DIR}/ext_ca.txt
basicConstraints=CA:TRUE
keyUsage=digitalSignature,keyCertSign
EOF

openssl x509 -req -in ${DIR}/ca.csr -days 3650 -signkey ${DIR}/ca.key -out ${DIR}/ca.crt -extfile ${DIR}/ext_ca.txt

cat <<EOF > ${DIR}/ext.txt
basicConstraints=CA:FALSE
keyUsage=digitalSignature,dataEncipherment,keyEncipherment,keyAgreement
extendedKeyUsage=serverAuth,clientAuth
subjectAltName = @alt_names
[alt_names]
DNS.1 = localhost
EOF

# Create Server certificate signed by CA
openssl req -new -nodes -out ${DIR}/server.csr -keyout ${DIR}/server.key -subj "/CN=localhost"
chmod og-rwx ${DIR}/server.key
openssl x509 -req -in ${DIR}/server.csr -days 3650 -CA ${DIR}/ca.crt -CAkey ${DIR}/ca.key -CAcreateserial -out ${DIR}/server.crt -extfile ${DIR}/ext.txt