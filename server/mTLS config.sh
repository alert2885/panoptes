mkdir -p ~/mtls/certs
cd ~/mtls/certs

# CA private key
openssl genrsa -out ca.key 4096

# CA certificate (self-signed)
openssl req -x509 -new -nodes -key ca.key -sha256 -days 3650 \
  -subj "/C=AZ/ST=Baku/L=Baku/O=Panoptes/CN=Panoptes-CA" \
  -out ca.crt

# Server private key
openssl genrsa -out server.key 4096

# CSR (use FQDN or IP as CN if you want; ideally FQDN)
openssl req -new -key server.key \
  -subj "/C=AZ/ST=Baku/L=Baku/O=Panoptes/CN=panoptes-srv1" \
  -out server.csr

# Sign server cert with your CA
openssl x509 -req -in server.csr -CA ca.crt -CAkey ca.key \
  -CAcreateserial -out server.crt -days 365 -sha256

# client key
openssl genrsa -out agent-desktop-rev.key 4096

# client CSR
openssl req -new -key agent-desktop-rev.key \
  -subj "/C=AZ/ST=Baku/L=Baku/O=Panoptes/CN=agent-desktop-rev" \
  -out agent-desktop-rev.csr

# Sign client cert with your CA
openssl x509 -req -in agent-desktop-rev.csr -CA ca.crt -CAkey ca.key \
  -CAcreateserial -out agent-desktop-rev.crt -days 365 -sha256

# CONFIG

sudo mkdir -p /etc/ssl/panoptes
sudo cp ~/mtls/certs/ca.crt /etc/ssl/panoptes/
sudo cp ~/mtls/certs/server.crt /etc/ssl/panoptes/
sudo cp ~/mtls/certs/server.key /etc/ssl/panoptes/
sudo chown root:root /etc/ssl/panoptes/*
sudo chmod 600 /etc/ssl/panoptes/server.key


