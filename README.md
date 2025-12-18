# PANOPTES - The next generation File Integrity Monitoring System



# Installation and Setup

---

## Installation - Server

- Note the IP address of the server because you will need it when you manage the agents


1. Update and upgrade existing packages and install these dependencies

```bash
sudo apt update && sudo apt upgrade
sudo apt install python3 postgres git
```


2. Set up the environment
   - Create a home directory for the project
   - Copy the `server/` folder contents into the project home
   - Create a virtual environment there

```bash
mkdir ~/Panoptes
cd ~/Panoptes
python3 -m venv venv
```

### PostgreSQL database

1. Login to the database as `postgres`

```bash
sudo-u postgres psql
```

2. Create a user and give it permissions

```sql
CREATE ROLE refer_user LOGIN PASSWORD 'CHANGE_ME';

GRANT CONNECT ON DATABASE fim_db TO refer_user;
GRANT USAGE ON SCHEMA fim TO refer_user;

GRANT SELECT, INSERT, UPDATE, DELETE ON ALL TABLES IN SCHEMA fim TO refer_user;
GRANT USAGE, SELECT ON ALL SEQUENCES IN SCHEMA fim TO refer_user;
GRANT EXECUTE ON ALL FUNCTIONS IN SCHEMA fim TO refer_user;

ALTER DEFAULT PRIVILEGES IN SCHEMA fim
GRANT SELECT, INSERT, UPDATE, DELETE ON TABLES TO refer_user;
ALTER DEFAULT PRIVILEGES IN SCHEMA fim
GRANT USAGE, SELECT ON SEQUENCES TO refer_user;
ALTER DEFAULT PRIVILEGES IN SCHEMA fim
GRANT EXECUTE ON FUNCTIONS TO refer_user;
```

3. Connect to the database as `refer_user` and create the database

```bash
psql -h localhost -U refer_user -d postres -f schema.sql
```


---

### Agent Handler 

1. Go to the project home directory and use the venv

```bash
cd ~/Panoptes
source venv/bin/activate
```

2. Install dependencies

```bash
pip install -r requirements.txt
```

3. Copy `example.env` and fill it accordingly. Name the new file `.env`

```txt
FIM_DB_HOST=127.0.0.1
FIM_DB_PORT=5432
FIM_DB_NAME=fim_db
FIM_DB_USER=refer_user
FIM_EVENTS_TABLE=fim.fim_events

FIM_DB_PASSWORD=DB_PASSWORD
FIM_API_KEY=API_KEY
```

4. Start the server using `uvicorn`

```bash
uvicorn agent_handler:app --host 0.0.0.0 --port 8000
```

---

## mTLS certificate generation


### 1. Create Certificate Authority (CA)

Generate the CA private key:

`openssl genrsa -out ca.key 4096`

Create the CA self-signed certificate:

`openssl req -x509 -new -nodes \   -key ca.key \   -sha256 \   -days 3650 \   -out ca.crt`



### 2. Create Server Certificate

Generate the server private key:

`openssl genrsa -out server.key 4096`

Create the server certificate signing request (CSR):

`openssl req -new \   -key server.key \   -out server.csr`

Sign the server certificate with the CA:

`openssl x509 -req \   -in server.csr \   -CA ca.crt \   -CAkey ca.key \   -CAcreateserial \   -out server.crt \   -days 825 \   -sha256`



### 3. Create Client Certificate

Generate the client private key:

`openssl genrsa -out client.key 4096`

Create the client certificate signing request (CSR):

`openssl req -new \   -key client.key \   -out client.csr`

Sign the client certificate with the CA:

`openssl x509 -req \   -in client.csr \   -CA ca.crt \   -CAkey ca.key \   -CAcreateserial \   -out client.crt \   -days 825 \   -sha256`



### 4. (Optional) Verify Certificates

Verify server certificate:

`openssl verify -CAfile ca.crt server.crt`

Verify client certificate:

`openssl verify -CAfile ca.crt client.crt`


---

## Installation - Endpoints (Agents)

1. Download the `agent/` folder to the endpoint 
2. Edit `config.json`:

```json
{
  "endpoint": "ENDPOINT_TYPE",
  "agent_id": "AGENT_ID",
  "watch_dirs": [
    "C:\\path\\to\\watch",
    "C:\\path\\to\\watch2"
  ],
  "exclude_dirs": [
    "C:\\path\\to\\ignoreme"
  ],
  "exclude_globs": [
    "*.tmp",
    "*.swp",
    "~*"
  ],
  "central_api_url": "DB_IP",
  "api_key": "API_KEY",
  "ca_cert": "certs\\ca.crt",
  "client_cert": "certs\\agent-01.crt",
  "client_key": "certs\\agent-01.key",
  
  "timezone": "+04:00",
  
  "chunk_size": 4096,
  "chunk_max_bytes": 10485760,
  "heartbeat_interval": 50,
  
  "debug_http": false
}
```


- Fill in `ENDPOINT_TYPE`, `AGENT_ID`, `watch_dirs`, `exclude_dirs`, `DB_IP`, `API_KEY` accordingly. `AGENT_ID` must be unique between agents

- Set `exclude_dirs` to the following if you want to monitor the whole filesystem (`C:\`):
```json
"exclude_dirs":
[
  "C:\\Program Files",
  "C:\\Program Files (x86)",
  "C:\\Users\\User\\AppData",
  "C:\\Windows",
  "C:\\path\\to\\agent\\folder",
  "C:\\$Recycle.Bin"
]
```
3. Download and install Python 3

4. Move `agent.crt`, `agent.key`, and `ca.crt` from the server to `agent/certs/` 

5. Run `agent.py` and enjoy!