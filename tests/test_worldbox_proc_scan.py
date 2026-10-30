"""Test aggregate-only scanning against synthetic child processes, never game data."""
import json
import pathlib
import shutil
import subprocess
import sys
import tempfile
import unittest

SOURCE = pathlib.Path(__file__).resolve().parents[1] / 'docs/worldbox/proc_scan.c'
FIXTURE = r'''
import ctypes, mmap, os, struct, tempfile, time
ctypes.CDLL(None).prctl(0x59616d61, -1, 0, 0, 0)
m = mmap.mmap(-1, 2 * 1024 * 1024 + 4096)
for pos, version in ((1024 * 1024 - 1, 29), (1024 * 1024 + 128, 30)):
    m.seek(pos)
    m.write(struct.pack('<II', 0xfab11baf, version))
    m.write(b''.join(struct.pack('<I', i * 16) for i in range(2, 16)))
f = tempfile.TemporaryFile()
f.write(struct.pack('<II', 0xfab11baf, 31))
f.write(b''.join(struct.pack('<I', i * 16) for i in range(2, 16)))
f.write(b'\0' * 4096)
f.flush()
read_only = mmap.mmap(f.fileno(), 0, access=mmap.ACCESS_READ)
print('ready', flush=True)
time.sleep(60)
'''

@unittest.skipUnless(sys.platform.startswith('linux') and shutil.which('cc'), 'Linux and C compiler required')
class ProcScannerTest(unittest.TestCase):
    def scan_fixture(self, budget=None):
        with tempfile.TemporaryDirectory() as directory:
            exe = pathlib.Path(directory) / 'proc-scan'
            cmd = ['cc', '-std=c11', '-Wall', '-Wextra', '-Werror', '-O2']
            if budget is not None:
                cmd.append('-DGROUP_BUDGET=' + str(budget))
            subprocess.run(cmd + [str(SOURCE), '-o', str(exe)], check=True)
            with subprocess.Popen([sys.executable, '-c', FIXTURE], stdout=subprocess.PIPE, text=True) as child:
                try:
                    self.assertEqual(child.stdout.readline().strip(), 'ready')
                    scan = subprocess.run([str(exe), str(child.pid)], text=True, capture_output=True, timeout=20)
                    if scan.returncode and 'Operation not permitted' in scan.stderr:
                        self.skipTest('ptrace not permitted in this environment')
                    self.assertEqual(scan.returncode, 0, scan.stderr)
                    result = json.loads(scan.stdout)
                    self.assertIsNone(child.poll(), 'scanner must resume the target')
                    return result
                finally:
                    child.terminate()

    def test_priority_and_later_partial_window_selection(self):
        # Compile the production selector into a tiny synthetic harness.
        source = r"""
#define main scanner_main
#include "%s"
#undef main
#include <assert.h>
int main(void) {
    uint64_t start, end;
    Range priority = {100, 1000, 1}, later = {100, 1000, 0};
    assert(select_window(&priority, 0, 200, &start, &end) && start == 100 && end == 300);
    assert(!select_window(&priority, 1, 200, &start, &end));
    assert(!select_window(&later, 0, 200, &start, &end));
    assert(select_window(&later, 1, 200, &start, &end) && start == 800 && end == 1000);
    assert(select_window(&later, 1, 2000, &start, &end) && start == 100 && end == 1000);
    assert(!select_window(&later, 1, 0, &start, &end));
    return 0;
}
""" % SOURCE
        with tempfile.TemporaryDirectory() as directory:
            harness = pathlib.Path(directory) / 'harness.c'
            harness.write_text(source)
            exe = pathlib.Path(directory) / 'harness'
            subprocess.run(['cc', '-std=c11', '-Wall', '-Wextra', '-Werror', str(harness), '-o', str(exe)], check=True)
            subprocess.run([str(exe)], check=True)

    def test_synthetic_headers_and_boundary(self):
        result = self.scan_fixture()
        self.assertGreaterEqual(result['candidates'], 3)
        self.assertTrue({29, 30, 31}.issubset(result['versions']))
        self.assertGreaterEqual(result['priority']['candidates'], 2)
        self.assertGreaterEqual(result['later']['candidates'], 1)
        self.assertFalse(result['validationLimited'])
        for group in ('priority', 'later'):
            stats = result[group]
            self.assertLessEqual(stats['bytesRead'], stats['attemptedBytes'])
            self.assertLessEqual(stats['attemptedBytes'], stats['eligibleBytes'])
        self.assertEqual(result['candidates'], result['priority']['candidates'] + result['later']['candidates'])
        self.assertNotIn('bytes', result)

    def test_disjoint_group_budgets_and_truncation(self):
        budget = 65536
        result = self.scan_fixture(budget)
        self.assertTrue(result['truncated'])
        for group in ('priority', 'later'):
            stats = result[group]
            self.assertGreaterEqual(stats['eligibleBytes'], budget)
            self.assertEqual(stats['attemptedBytes'], budget)
            self.assertGreater(stats['rangesScanned'], 0)

if __name__ == '__main__':
    unittest.main()
