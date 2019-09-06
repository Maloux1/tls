openssl req -x509 -sha256 -days 3650 -newkey rsa:4096 -keyout CA.key -out CA.crt
sudo chown root CA.key
sudo chgrp root CA.key
sudo chmod 600 CA.key
