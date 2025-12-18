openssl genrsa -out agent-02.key 4096

openssl req -new -key agent-02.key -out agent-02.csr \
  -subj "/C=AZ/ST=Baku/L=Baku/O=Panoptes/CN=agent-02"

openssl x509 -req \
  -in agent-02.csr \
  -CA ../ca.crt -CAkey ../ca.key -CAcreateserial \
  -out agent-02.crt \
  -days 365 \
  -sha256 \
  -extfile <(printf "extendedKeyUsage=clientAuth\nkeyUsage=digitalSignature,keyEncipherment")

openssl x509 -in agent-02.crt -noout -subject -issuer
