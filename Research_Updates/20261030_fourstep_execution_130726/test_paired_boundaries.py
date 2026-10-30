"""Boundary checks for the new metadata adapter; no attack claims."""
import ast
from pathlib import Path
import unittest
import tempfile
import paired_runner
from paired_runner import unwrap, current_text, event_key


class AdapterTests(unittest.TestCase):
    def test_reused_uuid_is_distinguished_by_native_time_and_operation(self):
        self.assertNotEqual(event_key('same',100,'EVENT_READ'),event_key('same',101,'EVENT_READ'))
        self.assertNotEqual(event_key('same',100,'EVENT_READ'),event_key('same',100,'EVENT_WRITE'))
    def test_avro_optional_strings(self):
        self.assertEqual(current_text({'string': '/usr/bin/example'}), '/usr/bin/example')
        self.assertEqual(unwrap({'com.bbn.tc.schema.avro.cdm18.UUID': 'uuid'}), 'uuid')

    def test_missing_metadata_is_not_a_token(self):
        for value in [None, '<unknown>', 'null', 'None', 3, {}]:
            self.assertEqual(current_text(value), '')

    def test_multiple_fields_are_not_guessed(self):
        self.assertEqual(current_text({'left':'a','right':'b'}), '')

    def test_predictor_has_no_label_file_entrypoint(self):
        tree=ast.parse(Path('paired_runner.py').read_text())
        functions={n.name:n for n in tree.body if isinstance(n,ast.FunctionDef)}
        for name in ['prepare','train','test']:
            strings=[n.value for n in ast.walk(functions[name]) if isinstance(n,ast.Constant) and isinstance(n.value,str)]
            self.assertFalse(any('y_true' in s or 'ground_truth' in s or 'node_Nginx' in s for s in strings))

    def test_test_requires_sealed_training(self):
        with tempfile.TemporaryDirectory() as directory:
            paired_runner.OUT=Path(directory)
            with self.assertRaises(ValueError):
                paired_runner.test(None,None)
            (paired_runner.OUT/'TEST_RESULT.json').write_text('{}')
            with self.assertRaises(FileExistsError):
                paired_runner.test(None,None)


if __name__=='__main__':
    unittest.main()
