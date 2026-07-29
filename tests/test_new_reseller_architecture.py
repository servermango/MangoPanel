import json
import secrets
import pytest
from http import HTTPStatus
from mangopanel.app import MangoHandler
from mangopanel.config import CONFIG
from mangopanel.db import connect, seed_dev_data
from mangopanel.security import create_jwt, hash_password


@pytest.fixture
def test_db(tmp_path, monkeypatch):
    db_file = str(tmp_path / "test_reseller_arch.db")
    monkeypatch.setattr(CONFIG, "db_path", db_file)
    seed_dev_data(db_file, account_root=str(tmp_path / "accounts"))
    return db_file


class DummyReq:
    def __init__(self, headers=None, body=None):
        self.headers = headers or {}
        self.body = body
        self.query_params = {}

    def get(self, key, default=""):
        return self.headers.get(key, default)


class MockMangoHandler:
    def __init__(self, headers=None, body=None):
        self.headers = headers or {}
        self.query_params = {}
        self.body_data = body or {}

    def read_json(self):
        return self.body_data

    def json_response(self, data, status=HTTPStatus.OK):
        return {"status": status, "data": data}


def test_admin_reseller_plans_crud(test_db):
    admin_actor = {"id": 1, "actor_type": "admin", "role": "super_admin"}
    handler = MockMangoHandler(
        body={
            "name": "Gold Enterprise Reseller",
            "max_storage_mb": 500000,
            "max_clients": 100,
            "max_hosting_accounts": 200,
            "max_ram_mb": 65536,
            "max_websites": 300,
            "max_databases": 300,
            "max_subplans": 50,
        }
    )

    # 1. Create Reseller Plan
    res = MangoHandler.admin_api(handler, "POST", "/api/admin/reseller-plans", {}, admin_actor)
    assert res["status"] == HTTPStatus.CREATED
    plan_id = res["data"]["reseller_plan"]["id"]
    assert res["data"]["reseller_plan"]["name"] == "Gold Enterprise Reseller"

    # 2. Get Reseller Plans List
    res_list = MangoHandler.admin_api(handler, "GET", "/api/admin/reseller-plans", {}, admin_actor)
    assert res_list["status"] == HTTPStatus.OK
    plan_names = [p["name"] for p in res_list["data"]["reseller_plans"]]
    assert "Gold Enterprise Reseller" in plan_names

    # 3. Patch Reseller Plan
    handler.body_data = {"name": "Gold Enterprise Reseller V2", "max_clients": 150}
    res_patch = MangoHandler.admin_api(handler, "PATCH", f"/api/admin/reseller-plans/{plan_id}", {}, admin_actor)
    assert res_patch["status"] == HTTPStatus.OK
    assert res_patch["data"]["reseller_plan"]["name"] == "Gold Enterprise Reseller V2"
    assert res_patch["data"]["reseller_plan"]["max_clients"] == 150

    # 4. Delete Reseller Plan
    res_del = MangoHandler.admin_api(handler, "DELETE", f"/api/admin/reseller-plans/{plan_id}", {}, admin_actor)
    assert res_del["status"] == HTTPStatus.OK
    assert res_del["data"]["deleted"] is True


def test_admin_reseller_users_creation_without_container(test_db):
    admin_actor = {"id": 1, "actor_type": "admin", "role": "super_admin"}
    
    with connect(test_db) as conn:
        rp = conn.execute("SELECT id FROM reseller_plans LIMIT 1").fetchone()
        rp_id = rp["id"]

    target_email = f"newpartner_{secrets.token_hex(4)}@agency.com"
    handler = MockMangoHandler(
        body={
            "email": target_email,
            "password": "SecurePassword123!",
            "full_name": "Agency Partner",
            "reseller_plan_id": rp_id,
        }
    )

    # Create Reseller User
    res = MangoHandler.admin_api(handler, "POST", "/api/admin/reseller-users", {}, admin_actor)
    assert res["status"] == HTTPStatus.CREATED
    ru_id = res["data"]["reseller_user"]["id"]
    assert res["data"]["reseller_user"]["email"] == target_email
    assert res["data"]["reseller_user"]["is_reseller"] == 1

    # Verify that NO hosting account container was created for the reseller user itself
    with connect(test_db) as conn:
        account_count = conn.execute("SELECT COUNT(*) AS c FROM hosting_accounts WHERE user_id = ?", (ru_id,)).fetchone()["c"]
        assert account_count == 0, "Creating reseller user should NOT provision a container account for the reseller"

    # Reseller User Dashboard API Access
    reseller_actor = {"id": ru_id, "actor_type": "reseller"}
    res_dash = MangoHandler.route_reseller_api(handler, "GET", "/api/reseller/dashboard", {}, reseller_actor)
    assert res_dash["status"] == HTTPStatus.OK
    assert "counts" in res_dash["data"]
