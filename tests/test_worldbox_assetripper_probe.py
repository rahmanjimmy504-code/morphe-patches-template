#!/usr/bin/env python3
"""Synthetic bounds and output-sanitization tests for AssetRipper probe."""
from pathlib import Path
import tempfile
import zipfile

import sys
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / '.github' / 'scripts'))
import worldbox_assetripper_probe as probe


def test_extracts_only_fixed_assets():
    with tempfile.TemporaryDirectory() as td:
        root = Path(td)
        apk_path = root / 'base.apk'
        with zipfile.ZipFile(apk_path, 'w') as apk:
            for name in probe.ASSETS:
                apk.writestr(name, b'fixture:' + name.encode())
            apk.writestr('../outside.txt', b'not extracted')
        extracted, size = probe.extract_inputs(apk_path, root / 'input')
        assert extracted == len(probe.ASSETS)
        assert size == sum(len(b'fixture:' + name.encode())
                           for name in probe.ASSETS)
        assert not (root / 'outside.txt').exists()
        assert (root / 'input' / probe.ASSETS[0]).read_bytes() == (
            b'fixture:' + probe.ASSETS[0].encode())


def test_summarize_export_emits_only_counts():
    with tempfile.TemporaryDirectory() as td:
        root = Path(td)
        (root / 'ButtonPremium.yaml').write_text(
            'm_Script: ButtonPremium\nmethod: clickPremium\n' +
            'state: premium_unlocked\n')
        (root / 'ignore.bin').write_bytes(b'clickPremium')
        report = probe.summarize_export(root)
    assert report['exportFileCount'] == 2
    assert report['targetLabelCounts']['ButtonPremium'] == 1
    assert report['targetLabelCounts']['clickPremium'] == 1
    assert report['targetLabelCounts']['premium_unlocked'] == 1
    assert report['targetLabelCounts']['m_Script'] == 1
    assert report['filesWithTargetLabels'] == 1
    assert 'method: clickPremium' not in str(report)


def test_asset_list_is_fixed_and_safe():
    assert len(probe.ASSETS) == 9
    assert all(name.startswith('assets/bin/Data/') for name in probe.ASSETS)
    assert all('..' not in Path(name).parts for name in probe.ASSETS)
    assert 'does not reveal IL2CPP method bodies' in probe.LIMITATIONS


if __name__ == '__main__':
    test_extracts_only_fixed_assets()
    test_summarize_export_emits_only_counts()
    test_asset_list_is_fixed_and_safe()
    print('AssetRipper probe tests passed')
