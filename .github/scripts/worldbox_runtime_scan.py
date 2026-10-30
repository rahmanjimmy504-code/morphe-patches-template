#!/usr/bin/env python3
"""Frida smoke test or aggregate-only scan of a disposable emulator process."""
import argparse
import json
import os
import threading
from pathlib import Path

import frida

parser = argparse.ArgumentParser()
parser.add_argument('pid', type=int)
parser.add_argument('--smoke', action='store_true')
args = parser.parse_args()
if args.pid <= 0:
    parser.error('PID must be positive')

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
    device = frida.get_local_device() if os.environ.get('WORLDBOX_FRIDA_LOCAL') == '1' else frida.get_usb_device(timeout=20)
    print('::notice title=Frida diagnostic::Attaching to ' + ('emulator smoke process' if args.smoke else 'WorldBox process'), flush=True)
    session = device.attach(args.pid)
    try:
        source = "send({kind:'smoke',arch:Process.arch});" if args.smoke else Path('docs/worldbox/scan-metadata.js').read_text()
        script = session.create_script(source)
        script.on('message', on_message)
        script.load()
        if not finished.wait(30 if args.smoke else 180):
            raise TimeoutError('Frida script did not finish')
        expected = 'smoke' if args.smoke else 'result'
        if result.get('kind') != expected:
            raise RuntimeError(result.get('message', 'unexpected scan result'))
        title = 'Frida smoke test' if args.smoke else 'WorldBox runtime metadata scan'
        print('::notice title=' + title + '::' + json.dumps(result, separators=(',', ':')))
        if not args.smoke and result['candidates'] == 0:
            print('::warning title=WorldBox metadata::No candidate found; this is not proof that metadata is absent.')
    finally:
        session.detach()
except Exception as exc:
    # This is a warning: the caller may still succeed via the /proc fallback.
    title = 'Frida smoke test' if args.smoke else 'WorldBox runtime metadata scan'
    print('::warning title=' + title + '::' + str(exc).replace('%', '%25').replace('\r', '%0D').replace('\n', '%0A'))
    raise SystemExit(1)
