"""Exercise the aggregate-only /proc scanner on a synthetic child, never game data."""
import json
import pathlib
import shutil
import subprocess
import sys
import tempfile
import time
import unittest

SOURCE = pathlib.Path(__file__).resolve().parents[1] / 'docs/worldbox/proc_scan.c'
FIXTURE = r'''
import ctypes, mmap, struct, time
ctypes.CDLL(None).prctl(0x59616d61, -1, 0, 0, 0)
m = mmap.mmap(-1, 2 * 1024 * 1024 + 4096)
for pos, version in ((1024 * 1024 - 1, 29), (1024 * 1024 + 128, 30)):
    m.seek(pos)
    m.write(struct.pack('<II', 0xfab11baf, version))
    m.write(b''.join(struct.pack('<I', i * 16) for i in range(2, 16)))
print('ready', flush=True)
time.sleep(60)
'''

@unittest.skipUnless(sys.platform.startswith('linux') and shutil.which('cc'), 'Linux and C compiler required')
class ProcScannerTest(unittest.TestCase):
    def test_synthetic_process_and_resume(self):
        with tempfile.TemporaryDirectory() as directory:
            exe = pathlib.Path(directory) / 'proc-scan'
            subprocess.run(['cc', '-std=c11', '-Wall', '-Wextra', '-Werror', '-O2', str(SOURCE), '-o', str(exe)], check=True)
            with subprocess.Popen([sys.executable, '-c', FIXTURE], stdout=subprocess.PIPE, text=True) as child:
                try:
                    self.assertEqual(child.stdout.readline().strip(), 'ready')
                    scan = subprocess.run([str(exe), str(child.pid)], text=True, capture_output=True, timeout=20)
                    if scan.returncode and 'Operation not permitted' in scan.stderr:
                        self.skipTest('ptrace not permitted in this environment')
                    self.assertEqual(scan.returncode, 0, scan.stderr)
                    result = json.loads(scan.stdout)
                    self.assertGreaterEqual(result['candidates'], 2)
                    self.assertIn(29, result['versions'])
                    self.assertIn(30, result['versions'])
                    self.assertNotIn('bytes', result)
                    self.assertIsNone(child.poll(), 'scanner must resume the target')
                finally:
                    child.terminate()

if __name__ == '__main__':
    unittest.main()
