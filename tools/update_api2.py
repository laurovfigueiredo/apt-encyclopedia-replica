#!/usr/bin/env python3
import http.server
import json
import os
import subprocess
import sys
import threading
from urllib.parse import urlparse

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
STATE = os.path.join(ROOT, '.update_push_state.json')
LOG = os.path.join(ROOT, '.update_push.log')

def ws(d):
    try:
        with open(STATE,'w') as f:
            json.dump(d,f)
    except Exception: pass
def rs():
    try:
        with open(STATE) as f:
            return json.load(f)
    except Exception:
        return {'status':'idle','log':'','last':'','exit':None,'ts':0}
def read_log():
    try:
        if os.path.exists(LOG):
            with open(LOG) as f:
                data=f.read()
            return data[-300000:] if len(data)>300000 else data
    except Exception: return ''

def run():
    ws({'status':'running','log':'','exit':None,'ts':__import__('time').time()})
    open(LOG,'w').close()
    try:
        p=subprocess.Popen([sys.executable, os.path.join(ROOT,'tools','update_with_push.py')], cwd=ROOT, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, bufsize=1, text=True)
        for line in p.stdout:
            with open(LOG,'a') as f:
                f.write(line)
            s=rs(); s['log']=read_log(); ws(s)
        rc=p.wait()
        s=rs(); s['status']='done' if rc==0 else 'error'; s['exit']=rc; s['log']=read_log()
        try:
            with open(os.path.join(ROOT,'data','last_update.txt')) as f:
                s['last']=f.read().strip()
        except Exception: pass
        ws(s)
    except Exception as e:
        with open(LOG,'a') as f:
            f.write(str(e)+'\n')
        s=rs(); s['status']='error'; s['exit']=-1; s['log']=read_log(); ws(s)

class H(http.server.BaseHTTPRequestHandler):
    def _send(self,code,ct,body=b''):
        b=body if isinstance(body,bytes) else str(body).encode('utf-8')
        self.send_response(code)
        for h,v in [('Content-Type',ct),('Access-Control-Allow-Origin','*'),('Content-Length',str(len(b)))]:
            self.send_header(h,v)
        self.end_headers(); self.wfile.write(b)
    def do_OPTIONS(self):
        self.send_response(204); self.send_header('Access-Control-Allow-Origin','*'); self.send_header('Access-Control-Allow-Methods','GET,POST,OPTIONS'); self.send_header('Access-Control-Allow-Headers','Content-Type'); self.end_headers()
    def do_GET(self):
        p=urlparse(self.path)
        if p.path=='/api/status':
            s=rs(); s['log']=read_log()
            try:
                with open(os.path.join(ROOT,'data','last_update.txt')) as f:
                    s['last']=f.read().strip()
            except Exception: pass
            self._send(200,'application/json',json.dumps(s,ensure_ascii=False)); return
        self._send(404,'text/plain','not found')
    def do_POST(self):
        p=urlparse(self.path)
        if p.path=='/api/run':
            s=rs()
            if s.get('status')=='running': self._send(409,'application/json',json.dumps({'ok':False,'err':'running'})); return
            threading.Thread(target=run,daemon=True).start(); self._send(200,'application/json',json.dumps({'ok':True})); return
        self._send(404,'text/plain','not found')
    def log_message(self,*a): return

if __name__=='__main__':
    port=int(sys.argv[1]) if len(sys.argv)>1 else 8781
    import time
    httpd=http.server.HTTPServer(('0.0.0.0',port),H)
    httpd.serve_forever()
