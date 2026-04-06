import requests
import sys
import time
import os
import subprocess
import uuid

BASE_URL = os.getenv("BASE_URL", "http://localhost:8080/v1")


def wait_for_service(url, max_retries=30, delay=2):
    if url.endswith("/v1"):
        health_url = url[:-3] + "/debug/coverage"
    else:
        health_url = url + "/debug/coverage"

    for i in range(max_retries):
        try:
            response = requests.get(health_url, timeout=5)
            if response.status_code == 200:
                return True
        except requests.RequestException:
            pass
        time.sleep(delay)
    return False

def fail(message):
    print(f"FAILED: {message}")
    sys.exit(1)


def expect_status(response, expected, context):
    if response.status_code != expected:
        fail(f"{context} returned {response.status_code}: {response.text}")


def make_user(label):
    unique = uuid.uuid4().hex[:8]
    username = f"{label}_{unique}"
    email = f"{username}@example.com"
    password = "SecurePass123!"
    return username, email, password


def register_user(label):
    username, email, password = make_user(label)
    response = requests.post(
        f"{BASE_URL}/users",
        json={"username": username, "email": email, "password": password},
        timeout=10,
    )
    expect_status(response, 201, f"Registration for {username}")
    user_id = response.json().get("userId")
    if not user_id:
        fail(f"Registration for {username} did not return userId")
    print(f"Registered user: {username}")
    return {"id": user_id, "username": username, "email": email, "password": password}


def login_user(user, expected_status=200):
    response = requests.post(
        f"{BASE_URL}/auth/login",
        json={"email": user["email"], "password": user["password"]},
        timeout=10,
    )
    expect_status(response, expected_status, f"Login for {user['username']}")
    if expected_status != 200:
        return None

    data = response.json()
    token = data.get("accessToken")
    api_user = data.get("user", {})
    if not token:
        fail(f"Login for {user['username']} did not return accessToken")
    if api_user.get("id") != user["id"]:
        fail(f"Login userId mismatch for {user['username']}: {api_user.get('id')} != {user['id']}")
    print(f"Logged in successfully: {user['username']}")
    return {"Authorization": f"Bearer {token}"}


def promote_to_admin(user_id):
    sql = (
        "INSERT IGNORE INTO user_roles (id, user_id, role, created_at) "
        f"VALUES (UUID(), '{user_id}', 'admin', NOW());"
    )
    cmd = [
        "docker",
        "compose",
        "exec",
        "-T",
        "mariadb",
        "mariadb",
        "-uuserservice",
        "-puserservice",
        "userservice",
        "-e",
        sql,
    ]
    result = subprocess.run(cmd, capture_output=True, text=True, timeout=20)
    if result.returncode != 0:
        stderr = result.stderr.strip() or "no stderr"
        fail(f"Failed to promote user to admin via database command: {stderr}")


def test_e2e():
    print("Waiting for service to be ready...")
    if not wait_for_service(BASE_URL):
        print("ERROR: Service not ready")
        sys.exit(1)

    print("Preparing users for e2e scenarios...")
    user = register_user("e2e_user")
    user_headers = login_user(user)

    admin = register_user("e2e_admin")
    promote_to_admin(admin["id"])
    admin_headers = login_user(admin)

    print("Testing admin endpoint access control...")
    response = requests.get(f"{BASE_URL}/admin/users", headers=user_headers, timeout=10)
    expect_status(response, 403, "Non-admin access to admin list")
    print("Verified non-admin user is forbidden on admin endpoints")

    print("Testing admin list users endpoint...")
    response = requests.get(f"{BASE_URL}/admin/users?page=1&pageSize=20", headers=admin_headers, timeout=10)
    expect_status(response, 200, "Admin list users")
    users = response.json().get("users", [])
    listed_ids = {item.get("id") for item in users if item.get("id")}
    if user["id"] not in listed_ids or admin["id"] not in listed_ids:
        fail("Admin list users response did not include expected users")
    print("Verified admin user listing")

    print("Testing admin get user endpoint...")
    response = requests.get(f"{BASE_URL}/admin/users/{user['id']}", headers=admin_headers, timeout=10)
    expect_status(response, 200, "Admin get user")
    if response.json().get("id") != user["id"]:
        fail("Admin get user returned unexpected user id")
    print("Verified admin get user")

    print("Testing admin update user endpoint (disable + emailVerified + roles)...")
    response = requests.put(
        f"{BASE_URL}/admin/users/{user['id']}",
        headers=admin_headers,
        json={"disabled": True, "emailVerified": True, "roles": ["user"]},
        timeout=10,
    )
    expect_status(response, 200, "Admin update user")
    updated_user = response.json()
    if updated_user.get("disabled") is not True:
        fail("Admin update did not disable user")
    if updated_user.get("emailVerified") is not True:
        fail("Admin update did not set emailVerified=true")
    if "user" not in updated_user.get("roles", []):
        fail("Admin update did not persist roles")
    print("Verified admin update user")

    print("Testing login behavior for disabled account...")
    response = requests.post(
        f"{BASE_URL}/auth/login",
        json={"email": user["email"], "password": user["password"]},
        timeout=10,
    )
    expect_status(response, 403, "Login for disabled account")
    print("Verified disabled account cannot login")

    print("Re-enabling user through admin endpoint...")
    response = requests.put(
        f"{BASE_URL}/admin/users/{user['id']}",
        headers=admin_headers,
        json={"disabled": False},
        timeout=10,
    )
    expect_status(response, 200, "Admin re-enable user")
    if response.json().get("disabled") is not False:
        fail("Admin re-enable did not set disabled=false")
    user_headers = login_user(user)
    print("Verified user can login again after re-enable")

    print("Testing admin delete user endpoint...")
    victim = register_user("e2e_victim")
    response = requests.delete(f"{BASE_URL}/admin/users/{victim['id']}", headers=admin_headers, timeout=10)
    expect_status(response, 204, "Admin delete user")
    response = requests.get(f"{BASE_URL}/admin/users/{victim['id']}", headers=admin_headers, timeout=10)
    expect_status(response, 404, "Admin get deleted user")
    print("Verified admin delete user")

    print("Testing get profile...")
    response = requests.get(f"{BASE_URL}/users/{user['id']}", headers=user_headers, timeout=10)
    expect_status(response, 200, "Get profile")
    profile = response.json()
    if profile.get("username") != user["username"]:
        fail(f"Username mismatch: {profile.get('username')} != {user['username']}")
    print(f"Got profile: {profile['username']}")

    print("Testing update profile...")
    new_display = f"{user['username']}_updated"
    response = requests.put(
        f"{BASE_URL}/users/{user['id']}",
        headers=user_headers,
        json={"misc": {"display_name": new_display}},
        timeout=10,
    )
    expect_status(response, 200, "Update profile")
    print("Profile updated")

    print("Testing get updated profile...")
    response = requests.get(f"{BASE_URL}/users/{user['id']}", headers=user_headers, timeout=10)
    expect_status(response, 200, "Get updated profile")
    user_data = response.json()
    if user_data.get("misc", {}).get("display_name") != new_display:
        fail("Display name was not updated")
    print("Verified profile update")

    print("Testing delete account...")
    response = requests.delete(f"{BASE_URL}/users/{user['id']}", headers=user_headers, timeout=10)
    expect_status(response, 202, "Delete account")
    print("Account deleted")

    print("Testing login after deletion...")
    login_user(user, expected_status=401)
    print("Verified account deleted (login fails)")

    print("\n=== ALL TESTS PASSED ===")

if __name__ == "__main__":
    test_e2e()
