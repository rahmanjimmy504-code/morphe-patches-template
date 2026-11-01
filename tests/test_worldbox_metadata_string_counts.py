import importlib.util
import pathlib
import unittest

MODULE = pathlib.Path(__file__).resolve().parents[1] / '.github/scripts/worldbox_metadata_string_counts.py'
SPEC = importlib.util.spec_from_file_location('worldbox_metadata_string_counts', MODULE)
metadata_counts = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(metadata_counts)


class WorldBoxMetadataStringCountsTest(unittest.TestCase):
    def test_ascii_utf16le_and_repeated_markers(self):
        data = (
            b'UnityPurchasing\0UnityPurchasing\0'
            + 'IUnityCallback\0PremiumWindow\0'.encode('utf-16le')
            + b'OnPurchaseSucceeded\0PremiumElementsChecker\0'
        )
        result = metadata_counts.count_string_leads(data)
        self.assertEqual(result['unity_purchasing'], {'ascii': 2, 'utf16le': 0})
        self.assertEqual(result['unity_callback'], {'ascii': 0, 'utf16le': 1})
        self.assertEqual(result['premium_window'], {'ascii': 0, 'utf16le': 1})
        self.assertEqual(result['purchase_succeeded'], {'ascii': 1, 'utf16le': 0})
        self.assertEqual(result['premium_elements_checker'], {'ascii': 1, 'utf16le': 0})
        self.assertEqual(result['purchase_failed'], {'ascii': 0, 'utf16le': 0})

    def test_overlapping_occurrences(self):
        self.assertEqual(metadata_counts._overlapping_count(b'aaaa', b'aa'), 3)
        self.assertEqual(metadata_counts.occurrence_offsets(b'aa---aa', 'aa'), [0, 5])
        self.assertEqual(metadata_counts.occurrence_offsets(b'aaaa', 'aa'), [0, 1, 2])

    def test_candidate_string_heap_base_fixture(self):
        data = bytearray(2048)
        texts = ('PremiumElementsChecker', 'PremiumWindow', 'PremiumUnlockAnimation', 'UnityPurchasing')
        positions = (512, 768, 1024, 1280)
        base = 128
        for table_offset, (text, position) in enumerate(zip(texts, positions)):
            data[table_offset * 4:table_offset * 4 + 4] = (position - base).to_bytes(4, 'little')
            data[position:position + len(text)] = text.encode('ascii')
        candidates = metadata_counts.candidate_string_heap_bases(bytes(data), texts, min_support=4)
        self.assertIn({'base': base, 'support': 4}, candidates)

    def test_printable_contexts_are_bounded_and_contain_marker(self):
        data = b'\0Namespace.Type::PremiumWindow\0HelperAfter\0' + b'X' * 512
        contexts = metadata_counts.printable_run_contexts(data, 'PremiumWindow', radius=16, limit=4)
        self.assertEqual(contexts, ['Namespace.Type::PremiumWindow'])

    def test_printable_contexts_cap_length(self):
        data = b'A' * 200 + b'PremiumWindow' + b'B' * 200
        context = metadata_counts.printable_run_contexts(data, 'PremiumWindow', radius=64)
        self.assertEqual(len(context), 1)
        self.assertLessEqual(len(context[0]), 13 + 128)
        self.assertIn('PremiumWindow', context[0])

    def test_nearby_nul_identifiers_are_heuristic_and_exclude_marker(self):
        data = b'\0'.join((b'$', b'+', b'a', b'TypeBefore', b'PremiumWindow', b'0', b'8', b'HelperAfter')) + b'\0' + b'\0' * 256
        names = metadata_counts.nearby_null_identifiers(data, 'PremiumWindow', radius=64, limit=4)
        self.assertEqual(set(names), {'TypeBefore', 'HelperAfter'})
        self.assertNotIn('PremiumWindow', names)


if __name__ == '__main__':
    unittest.main()
