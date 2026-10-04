from unittest.mock import patch
import unittest
from soclab.loki import Loki, nanoseconds


class LokiTests(unittest.TestCase):
    def test_integer_timestamp_conversion_and_timezone(self):
        self.assertEqual(nanoseconds("1970-01-01T00:00:00.000001Z"),1000)
        self.assertEqual(nanoseconds("1970-01-01T07:00:00+07:00"),0)
        with self.assertRaises(ValueError): nanoseconds("2026-01-01T00:00:00")

    def test_external_endpoints_and_embedded_credentials_rejected(self):
        for url in ("https://127.0.0.1:3100","http://example.com","http://user:secret@localhost:3100","http://localhost:3100/evil","http://localhost:3100?x=1"):
            with self.assertRaises(ValueError): Loki(url)

    def test_batched_replay_retains_original_evidence_and_avoids_guid_labels(self):
        event={"event_uid":"a"*64,"source_sha256":"b"*64,"source_line":1,"host":"LAB","channel":"Security","provider":"Test","event_id":4625,"record_id":1,"timestamp":"2026-01-01T00:00:00Z","event_data":{"ProcessGuid":"unique","CommandLine":"inert"}}
        client=Loki()
        with patch.object(client,"request",return_value={}) as transport:
            result=client.replay(iter([event,event,event]),case_id="case-005",run_id="unit",kind="synthetic",mode="replay_now",batch_size=2)
            self.assertEqual(result["sent_records"],3)
            self.assertEqual(transport.call_count,2)
            stream=transport.call_args_list[0].args[1]["streams"][0]
            self.assertNotIn("process_guid",stream["stream"])
            import json
            line=json.loads(stream["values"][0][1])
            self.assertEqual(line["original_timestamp"],event["timestamp"])
            self.assertEqual(line["event_uid"],event["event_uid"])
            self.assertEqual(line["replay_mode"],"replay_now")
