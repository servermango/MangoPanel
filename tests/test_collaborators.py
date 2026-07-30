import unittest
import json
from mangopanel.db import connect, SCHEMA, ensure_schema
from mangopanel.app import get_collaborator_scope

class TestCollaborators(unittest.TestCase):
    def setUp(self):
        self.conn = connect(":memory:")
        self.conn.executescript(SCHEMA)
        ensure_schema(self.conn)
        
        # Create Dummy Plan & Node
        self.conn.execute("INSERT INTO plans (name, cpu_limit, memory_mb, storage_mb, inode_limit, max_websites, max_databases, max_mailboxes, max_cron_jobs, daily_email_limit, backup_retention_days, max_processes, php_workers, bandwidth_limit_gb) VALUES ('Default', '1', 1024, 10240, 100000, 10, 10, 10, 10, 100, 7, 20, 5, 100)")
        self.conn.execute("INSERT INTO nodes (name, hostname, ip_address) VALUES ('Node 1', 'node1.test', '127.0.0.1')")

        # Create Owner User
        cur = self.conn.execute("INSERT INTO users (email, password_hash, full_name, status) VALUES ('owner@example.com', 'hash1', 'Owner User', 'active')")
        self.owner_id = cur.lastrowid
        
        # Create Collaborator User
        cur = self.conn.execute("INSERT INTO users (email, password_hash, full_name, status) VALUES ('collab@example.com', 'hash2', 'Collab User', 'active')")
        self.collab_id = cur.lastrowid
        
        # Create Hosting Account
        cur = self.conn.execute("INSERT INTO hosting_accounts (user_id, plan_id, node_id, username, base_path) VALUES (?, 1, 1, 'u1001', '/home/u1001')", (self.owner_id,))
        self.account_id = cur.lastrowid
        
        # Create Websites
        cur = self.conn.execute("INSERT INTO websites (account_id, domain, document_root) VALUES (?, 'site1.com', '/root1')", (self.account_id,))
        self.site1_id = cur.lastrowid
        cur = self.conn.execute("INSERT INTO websites (account_id, domain, document_root) VALUES (?, 'site2.com', '/root2')", (self.account_id,))
        self.site2_id = cur.lastrowid

    def tearDown(self):
        self.conn.close()

    def test_owner_scope(self):
        scope = get_collaborator_scope(self.conn, self.owner_id, self.account_id)
        self.assertFalse(scope["is_collaborator"])
        self.assertIsNone(scope["allowed_website_ids"])
        self.assertTrue(scope["can_create_websites"])

    def test_collaborator_grant_scoping(self):
        # Grant access to only site1
        perms = {
            "all_websites": False,
            "website_ids": [self.site1_id],
            "all_databases": True,
            "allowed_menus": ["websites", "files"],
            "can_create_websites": False,
            "can_edit_websites": True,
        }
        self.conn.execute(
            """
            INSERT INTO collaborators (owner_user_id, invited_email, invited_name, target_user_id, hosting_account_id, permissions_json, status)
            VALUES (?, 'collab@example.com', 'Collab User', ?, ?, ?, 'active')
            """,
            (self.owner_id, self.collab_id, self.account_id, json.dumps(perms)),
        )

        scope = get_collaborator_scope(self.conn, self.collab_id, self.account_id)
        self.assertTrue(scope["is_collaborator"])
        self.assertEqual(scope["allowed_website_ids"], [self.site1_id])
        self.assertIn("websites", scope["allowed_menus"])
        self.assertIn("files", scope["allowed_menus"])
        self.assertNotIn("databases", scope["allowed_menus"])
        self.assertFalse(scope["can_create_websites"])

if __name__ == "__main__":
    unittest.main()
