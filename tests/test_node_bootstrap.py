import tempfile
import unittest
from pathlib import Path

from mangopanel.db import connect, ensure_local_node, init_db


class NodeBootstrapTests(unittest.TestCase):
    def test_ensure_local_node_is_idempotent(self):
        with tempfile.TemporaryDirectory() as tmp:
            db_path = Path(tmp) / "mangopanel.sqlite3"
            init_db(db_path)

            first_id = ensure_local_node(db_path, name="server", hostname="panel.example.com")
            second_id = ensure_local_node(db_path, name="another", hostname="other.example.com")

            with connect(db_path) as conn:
                nodes = conn.execute("SELECT * FROM nodes ORDER BY id").fetchall()

            self.assertEqual(first_id, second_id)
            self.assertEqual(len(nodes), 1)
            self.assertEqual(nodes[0]["name"], "server")
            self.assertEqual(nodes[0]["hostname"], "panel.example.com")
            self.assertEqual(nodes[0]["status"], "online")


if __name__ == "__main__":
    unittest.main()
