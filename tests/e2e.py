import requests
import sys
import time
import os
import subprocess
import signal

BASE_URL = os.getenv("BASE_URL", "http://localhost:8080/v1")

def wait_for_service(url, max_retries=30, delay=2):
    for i in range(max_retries):
        try:
            result = subprocess.run(
                ["curl", "-s", "-o", "/dev/null", "-w", "%{http_code}", "-X", "POST", f"{url}/auth/login", "-H", "Content-Type: application/json", "-d", "{}"],
                capture_output=True, text=True, timeout=5
            )
            code = result.stdout.strip()
            if code and code != "000":
                return True
        except subprocess.TimeoutExpired:
            pass
        time.sleep(delay)
    return False

def test_e2e():
    print("Waiting for service to be ready...")
    if not wait_for_service(BASE_URL):
        print("ERROR: Service not ready")
        sys.exit(1)

    print("Testing registration...")
    username = f"testuser_{int(time.time())}"
    email = f"{username}@example.com"
    password = "SecurePass123!"

    r = requests.post(f"{BASE_URL}/users", json={
        "username": username,
        "email": email,
        "password": password
    })
    if r.status_code != 201:
        print(f"FAILED: Registration returned {r.status_code}: {r.text}")
        sys.exit(1)
    user_id = r.json()["userId"]
    print(f"Registered user: {username}")

    print("Testing login...")
    r = requests.post(f"{BASE_URL}/auth/login", json={
        "email": email,
        "password": password
    })
    if r.status_code != 200:
        print(f"FAILED: Login returned {r.status_code}: {r.text}")
        sys.exit(1)
    token = r.json()["accessToken"]
    user_id = r.json()["user"]["id"]
    headers = {"Authorization": f"Bearer {token}"}
    print("Logged in successfully")

    print("Testing get profile...")
    r = requests.get(f"{BASE_URL}/users/{user_id}", headers=headers)
    if r.status_code != 200:
        print(f"FAILED: Get profile returned {r.status_code}: {r.text}")
        sys.exit(1)
    user = r.json()
    if user["username"] != username:
        print(f"FAILED: Username mismatch: {user['username']} != {username}")
        sys.exit(1)
    print(f"Got profile: {user['username']}")

    print("Testing update profile...")
    new_display = f"{username}_updated"
    r = requests.put(f"{BASE_URL}/users/{user_id}", headers=headers, json={
        "misc": {"display_name": new_display}
    })
    if r.status_code != 200:
        print(f"FAILED: Update profile returned {r.status_code}: {r.text}")
        sys.exit(1)
    print("Profile updated")

    print("Testing get updated profile...")
    r = requests.get(f"{BASE_URL}/users/{user_id}", headers=headers)
    if r.status_code != 200:
        print(f"FAILED: Get profile returned {r.status_code}: {r.text}")
        sys.exit(1)
    user_data = r.json()
    if user_data.get("misc", {}).get("display_name") != new_display:
        print(f"FAILED: Display name not updated")
        sys.exit(1)
    print("Verified profile update")

    print("Testing delete account...")
    r = requests.delete(f"{BASE_URL}/users/{user_id}", headers=headers)
    if r.status_code != 204:
        print(f"FAILED: Delete account returned {r.status_code}: {r.text}")
        sys.exit(1)
    print("Account deleted")

    print("Testing login after deletion...")
    r = requests.post(f"{BASE_URL}/auth/login", json={
        "email": email,
        "password": password
    })
    if r.status_code != 401:
        print(f"FAILED: Expected 401 after account deletion, got {r.status_code}")
        sys.exit(1)
    print("Verified account deleted (login fails)")

    print("\n=== ALL TESTS PASSED ===")

if __name__ == "__main__":
    test_e2e()