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


def insert_verification_token(user_id, token_type, token):
    sql = (
        f"INSERT INTO verification_tokens (id, user_id, token, type, expires_at, created_at) "
        f"VALUES (UUID(), '{user_id}', '{token}', '{token_type}', DATE_ADD(NOW(), INTERVAL 1 HOUR), NOW());"
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
        fail(f"Failed to insert verification token via database command: {stderr}")


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

    print("\n=== Testing Registration and Password Reset Endpoints ===")

    print("Testing registration validation - invalid username...")
    response = requests.post(
        f"{BASE_URL}/users",
        json={"username": "ab", "email": "test@example.com", "password": "SecurePass123!"},
        timeout=10,
    )
    expect_status(response, 400, "Registration with short username")
    print("Verified registration rejects short username")

    print("Testing registration validation - invalid email...")
    response = requests.post(
        f"{BASE_URL}/users",
        json={"username": "validuser", "email": "not-an-email", "password": "SecurePass123!"},
        timeout=10,
    )
    expect_status(response, 400, "Registration with invalid email")
    print("Verified registration rejects invalid email")

    print("Testing registration validation - weak password...")
    response = requests.post(
        f"{BASE_URL}/users",
        json={"username": "validuser2", "email": "test2@example.com", "password": "short"},
        timeout=10,
    )
    expect_status(response, 400, "Registration with weak password")
    print("Verified registration rejects weak password")

    print("Testing registration with duplicate username...")
    dupe_user = make_user("dupe_test")
    requests.post(
        f"{BASE_URL}/users",
        json={"username": dupe_user[0], "email": dupe_user[1], "password": dupe_user[2]},
        timeout=10,
    )
    response = requests.post(
        f"{BASE_URL}/users",
        json={"username": dupe_user[0], "email": "different@example.com", "password": dupe_user[2]},
        timeout=10,
    )
    expect_status(response, 409, "Registration with duplicate username")
    print("Verified registration rejects duplicate username")

    print("Testing password recovery when not configured...")
    response = requests.post(
        f"{BASE_URL}/auth/password-recovery",
        json={"email": "nonexistent@example.com"},
        timeout=10,
    )
    expect_status(response, 501, "Password recovery not configured")
    print("Verified password recovery returns 501 when not configured")

    print("Testing password recovery with valid email...")
    recovery_user = register_user("recovery_test")
    response = requests.post(
        f"{BASE_URL}/auth/password-recovery",
        json={"email": recovery_user["email"]},
        timeout=10,
    )
    if response.status_code == 501:
        print("Skipping password recovery test - mail service not configured")
    else:
        expect_status(response, 202, "Password recovery request")
        print("Verified password recovery returns 202 for valid email")

    print("Testing reset password with invalid token...")
    response = requests.post(
        f"{BASE_URL}/auth/reset-password",
        json={"token": "invalid-token-12345", "newPassword": "NewPassword123!"},
        timeout=10,
    )
    expect_status(response, 400, "Reset password with invalid token")
    print("Verified reset password rejects invalid token")

    print("Testing reset password with valid token...")
    recovery_user2 = register_user("recovery_test2")
    token = uuid.uuid4().hex
    insert_verification_token(recovery_user2["id"], "recovery", token)
    response = requests.post(
        f"{BASE_URL}/auth/reset-password",
        json={"token": token, "newPassword": "NewSecurePass456!"},
        timeout=10,
    )
    expect_status(response, 200, "Reset password with valid token")
    print("Verified reset password succeeds with valid token")

    print("Testing login with new password after reset...")
    recovery_user2["password"] = "NewSecurePass456!"
    login_user(recovery_user2)
    print("Verified login works with new password after reset")

    print("Testing verify registration endpoint with invalid token...")
    response = requests.post(
        f"{BASE_URL}/auth/verify-registration",
        json={"token": "invalid-registration-token"},
        timeout=10,
    )
    expect_status(response, 400, "Verify registration with invalid token")
    print("Verified verify registration rejects invalid token")

    print("Testing verify registration endpoint with valid token...")
    verify_user = register_user("verify_test")
    verify_token = uuid.uuid4().hex
    insert_verification_token(verify_user["id"], "registration", verify_token)
    response = requests.post(
        f"{BASE_URL}/auth/verify-registration",
        json={"token": verify_token},
        timeout=10,
    )
    expect_status(response, 200, "Verify registration with valid token")
    print("Verified verify registration succeeds with valid token")

    print("\n=== ALL TESTS PASSED ===")

if __name__ == "__main__":
    test_e2e()
