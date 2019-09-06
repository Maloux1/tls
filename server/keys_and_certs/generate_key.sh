read -p "key and cert name :" x

openssl genrsa -out $(echo $x).key 2048
openssl req -new -key $(echo $x).key -out $(echo $x).csr
openssl x509 -req -in $(echo $x).csr -CA CA/CA.crt -CAkey CA/CA.key -CAcreateserial -out $(echo $x).crt -days 3650 -sha256
rm CA/CA.srl $(echo $x).csr
