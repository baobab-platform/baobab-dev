"""DEV-10 PROM-01 approval monitor tests."""
import importlib.util
from datetime import datetime, timezone, timedelta
from pathlib import Path
import unittest

p=Path(__file__).resolve().parents[1]/"scripts/promotion_approval_monitor.py"
spec=importlib.util.spec_from_file_location("promotion_monitor",p)
m=importlib.util.module_from_spec(spec);spec.loader.exec_module(m)


class MonitorTests(unittest.TestCase):
    def test_thresholds_and_environment_isolation(self):
        now=datetime(2026,11,13,12,tzinfo=timezone.utc)
        for age,level in ((2,"PENDING"),(16,"REMIND"),(46,"ESCALATE"),(121,"EXPIRED_REQUIRES_MANUAL_CANCELLATION")):
            with self.subTest(age=age):
                run=dict(id=123,status="waiting",environment=m.ENV,
                         created_at=(now-timedelta(minutes=age)).isoformat(),html_url="https://github.com/example/run/123")
                self.assertEqual(m.decide([run],now)[0]["level"],level)
                self.assertEqual(m.decide([{**run,"environment":"staging"}],now),[])
                self.assertEqual(m.decide([{**run,"status":"completed"}],now),[])

    def test_malformed_and_future_timestamps_refused(self):
        now=datetime.now(timezone.utc)
        self.assertEqual(m.decide([dict(status="waiting",environment=m.ENV,created_at="bad")],now),[])
        self.assertEqual(m.decide([dict(status="waiting",environment=m.ENV,created_at=(now+timedelta(hours=1)).isoformat())],now),[])


if __name__=="__main__":
    unittest.main()
