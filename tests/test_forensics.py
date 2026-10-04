import base64
from copy import deepcopy
import unittest
from soclab.events import normalize_event
from soclab.forensics import reconstruct, decode_command


def fragment(number, total, script, line=1, source="a"*64):
    return normalize_event({"timestamp":"2026-09-01T00:00:00Z","host":"LAB","channel":"Microsoft-Windows-PowerShell/Operational","provider":"Microsoft-Windows-PowerShell","event_id":4104,"record_id":line,"event_data":{"ScriptBlockId":"block-one","MessageNumber":str(number),"MessageTotal":str(total),"ScriptBlockText":script}},source,line)


class ForensicsTests(unittest.TestCase):
    def test_out_of_order_fragments_reconstruct_once_with_duplicate_refs(self):
        result=reconstruct([fragment(2,2,"'data'",2),fragment(1,2,"Write-Output "),fragment(1,2,"Write-Output ",3)])
        block=result["blocks"][0]
        self.assertTrue(block["complete"])
        self.assertEqual(block["script"],"Write-Output 'data'")
        self.assertEqual(len(block["evidence"]),3)

    def test_missing_or_conflicting_parts_never_return_full_script(self):
        for records in ([fragment(1,2,"first")],[fragment(1,1,"one"),fragment(1,1,"different",2)],[fragment(1,1,"one"),fragment(2,2,"two",2)]):
            block=reconstruct(records)["blocks"][0]
            self.assertFalse(block["complete"])
            self.assertIsNone(block["script"])

    def test_cross_file_same_block_id_does_not_complete_collection(self):
        blocks=reconstruct([fragment(1,2,"first"),fragment(2,2,"second",2,"b"*64)])["blocks"]
        self.assertEqual(len(blocks),2)
        self.assertTrue(all(not block["complete"] for block in blocks))

    def test_size_limit_and_invalid_metadata_fail_closed(self):
        self.assertFalse(reconstruct([fragment(1,1,"abcdef")],maximum_chars=3)["blocks"][0]["complete"])
        self.assertFalse(reconstruct([fragment(0,1,"x")])["blocks"][0]["complete"])

    def test_encoded_text_decodes_without_execution(self):
        script="Write-Output 'inert fixture'"
        encoded=base64.b64encode(script.encode("utf-16-le")).decode()
        result=decode_command('powershell.exe -NoProfile -enc '+encoded)
        self.assertEqual(result["script"],script)
        for command in ('powershell.exe -Command echo -enc '+encoded,'cmd.exe -enc '+encoded,'powershell.exe -enc $$$','powershell.exe -enc QQ=='):
            with self.assertRaises(ValueError): decode_command(command)
