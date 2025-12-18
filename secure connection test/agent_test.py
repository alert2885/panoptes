import requests

API_URL = "http://192.168.100.115:8000/test"

payload = {
    "device_id": "TEST-123",
    "temperature": 25.1,
    "status": "OK",
    "timestamp": "Help me please"
}

resp = requests.post(API_URL, json=payload)
print("Response:", resp.status_code, resp.json())
