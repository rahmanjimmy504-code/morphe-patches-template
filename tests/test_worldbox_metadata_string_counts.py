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

    def test_nearby_identifier_names_are_bounded_and_exclude_marker(self):
        data = b'TypeBefore\0PremiumWindow\0HelperAfter\0' + b'\x01' * 512
        names = metadata_counts.nearby_identifier_runs(data, 'PremiumWindow', radius=64, limit=4)
        self.assertEqual(set(names), {'TypeBefore', 'HelperAfter'})
        self.assertNotIn('PremiumWindow', names)


if __name__ == '__main__':
    unittest.main()
