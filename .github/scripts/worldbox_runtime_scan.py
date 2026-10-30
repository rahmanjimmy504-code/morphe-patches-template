#!/usr/bin/env python3
"""Attach to the fresh emulator's original game and report aggregates, not memory bytes."""
import json
import sys
import threading
from pathlib import Path

import frida

if len(sys.argv) != 2 or not sys.argv[1].isdigit():
    raise SystemExit('usage: worldbox_runtime_scan.py PID')

finished = threading.Event()
result = None

def on_message(message, data):
    global result
    if message.get('type') == 'send' and isinstance(message.get('payload'), dict):
        result = message['payload']
        finished.set()
    elif message.get('type') == 'error':
        result = {'kind': 'error', 'message': message.get('description', 'Frida script error')}
        finished.set()

try:
    device = frida.get_usb_device(timeout=20)
    session = device.attach(int(sys.argv[1]))
    try:
        script = session.create_script(Path('docs/worldbox/scan-metadata.js').read_text())
        script.on('message', on_message)
        script.load()
        if not finished.wait(180):
            raise TimeoutError('metadata scan did not finish within 180 seconds')
        if result.get('kind') != 'result':
            raise RuntimeError(result.get('message', 'scan failed'))
        print('::notice title=WorldBox runtime metadata scan::' + json.dumps(result, separators=(',', ':')))
        if result['candidates'] == 0:
            print('::warning title=WorldBox metadata::No candidate found; this is not proof that metadata is absent.')
    finally:
        session.detach()
except Exception as exc:
    print('::error title=WorldBox runtime metadata scan::' + str(exc).replace('%', '%25').replace('\n', '%0A'))
    raise SystemExit(1)
