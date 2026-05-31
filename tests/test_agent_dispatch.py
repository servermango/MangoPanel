import re
import unittest
from pathlib import Path


PROJECT_ROOT = Path(__file__).resolve().parent.parent


class AgentDispatchTests(unittest.TestCase):
    def test_every_app_enqueued_job_type_has_agent_dispatch(self):
        app_text = (PROJECT_ROOT / "mangopanel" / "app.py").read_text(encoding="utf-8")
        agent_text = (PROJECT_ROOT / "mangopanel" / "agent.py").read_text(encoding="utf-8")

        enqueued = set(re.findall(r'enqueue_agent_job\([^,\n]+,\s*"([^"]+)"', app_text))
        dispatched = set(re.findall(r'job_type == "([^"]+)"', agent_text))

        self.assertTrue(enqueued)
        self.assertFalse(enqueued - dispatched, "Missing dispatch handlers: {}".format(sorted(enqueued - dispatched)))

    def test_phase_sync_job_types_have_agent_dispatch(self):
        agent_text = (PROJECT_ROOT / "mangopanel" / "agent.py").read_text(encoding="utf-8")
        dispatched = set(re.findall(r'job_type == "([^"]+)"', agent_text))
        expected = {
            "sync_remote_mysql",
            "sync_hotlink_protection",
            "install_site_builder",
            "optimize_images",
            "sync_cron_jobs",
            "sync_pg_databases",
            "install_custom_ssl",
            "delete_website",
        }
        self.assertFalse(expected - dispatched, "Missing phase sync dispatch handlers: {}".format(sorted(expected - dispatched)))


if __name__ == "__main__":
    unittest.main()
