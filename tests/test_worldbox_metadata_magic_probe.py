import hashlib
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

import sys
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / '.github' / 'scripts'))
import worldbox_metadata_magic_probe as probe


class Section(dict):
    def __init__(self, name, **attrs):
        super().__init__(attrs)
        self.name = name

    def data(self):
        return b''


class FakeElf:
    elfclass = 64
    little_endian = True

    def __init__(self, sections):
        self.sections = sections

    def __getitem__(self, key):
        if key == 'e_machine':
            return 'EM_AARCH64'
        raise KeyError(key)

    def iter_sections(self):
        return iter(self.sections)


class MetadataMagicProbeTests(unittest.TestCase):
    def test_occurrences_finds_overlapping_and_caps(self):
        data = b'\xaf\x1b\xb1\xfa\xaf\x1b\xb1\xfa'
        self.assertEqual(probe.occurrences(data), ([0, 4], False))
        self.assertEqual(probe.occurrences(data, limit=1), ([0], True))

    def test_scan_maps_magic_hit_to_allocated_section_address(self):
        payload = b'prefix' + probe.MAGIC + b'suffix'
        section = Section('.rodata', sh_type='SHT_PROGBITS', sh_flags=2,
                          sh_offset=0, sh_size=len(payload), sh_addr=0x4000)
        with tempfile.TemporaryDirectory() as temp:
            binary = Path(temp) / 'libil2cpp.so'
            binary.write_bytes(payload)
            digest = hashlib.sha256(payload).hexdigest()
            with patch.object(probe, 'EXPECTED_SHA256', digest), patch.object(probe, 'ELFFile', return_value=FakeElf([section])):
                result = probe.scan_binary(binary)
        self.assertEqual(result['hitCount'], 1)
        self.assertEqual(result['hits'][0]['fileOffset'], '0x6')
        self.assertEqual(result['hits'][0]['virtualAddress'], '0x4006')
        self.assertEqual(result['hits'][0]['section'], '.rodata')
        self.assertFalse(result['hits'][0]['executable'])

    def test_hash_mismatch_refuses_scan(self):
        with tempfile.TemporaryDirectory() as temp:
            binary = Path(temp) / 'libil2cpp.so'
            binary.write_bytes(b'not the pinned library')
            with patch.object(probe, 'EXPECTED_SHA256', '0' * 64):
                with self.assertRaisesRegex(ValueError, 'hash does not match'):
                    probe.scan_binary(binary)


if __name__ == '__main__':
    unittest.main()
