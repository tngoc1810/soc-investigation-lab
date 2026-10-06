"""Loopback-only operations console, separate from the historical casebook."""
from contextlib import closing
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
from pathlib import Path
import re
import secrets
import sqlite3
from urllib.parse import urlparse, parse_qs

from . import live


def build_handler(workspace):
    workspace=Path(workspace).resolve(); token=secrets.token_urlsafe(32)
    assets={'/':('live.html','text/html'),'/live.css':('live.css','text/css'),'/live.js':('live.js','text/javascript')}
    class Handler(BaseHTTPRequestHandler):
        def log_message(self,*args): pass
        def respond(self,status,data,mime='application/json'):
            raw=data if isinstance(data,bytes) else json.dumps(data,ensure_ascii=False).encode()
            self.send_response(status); self.send_header('Content-Type',mime+'; charset=utf-8')
            self.send_header('Content-Length',str(len(raw))); self.send_header('Cache-Control','no-store')
            self.send_header('X-Content-Type-Options','nosniff')
            self.send_header('Content-Security-Policy',"default-src 'self'; object-src 'none'; frame-ancestors 'none'; base-uri 'none'")
            self.end_headers(); self.wfile.write(raw)
        def host_allowed(self):
            return len(self.headers.get_all('Host',[]))==1 and self.headers.get('Host') in (f'127.0.0.1:{self.server.server_port}',f'localhost:{self.server.server_port}')
        def do_GET(self):
            if not self.host_allowed(): return self.respond(403,{'error':'exact loopback Host required'})
            url=urlparse(self.path); args=parse_qs(url.query)
            try:
                if url.path in assets:
                    name,mime=assets[url.path]; return self.respond(200,(live.ROOT/'web'/name).read_bytes(),mime)
                if url.path=='/api/status': return self.respond(200,{**live.status(workspace),'csrf':token})
                if url.path=='/api/alerts': return self.respond(200,live.list_alerts(workspace,state=args.get('state',[None])[0]))
                if url.path=='/api/alert': return self.respond(200,live.alert_detail(workspace,args.get('id',[''])[0]))
                if url.path=='/api/event':
                    uid=args.get('uid',[''])[0]
                    if not re.fullmatch('[a-f0-9]{64}',uid): raise ValueError('invalid event UID')
                    with closing(sqlite3.connect((workspace/'live.sqlite').as_uri()+'?mode=ro',uri=True)) as conn:
                        row=conn.execute('SELECT original_json,source_sha256,source_line FROM events WHERE event_uid=?',(uid,)).fetchone()
                    if not row: raise ValueError('event not in this workspace')
                    return self.respond(200,{'event_uid':uid,'source_sha256':row[1],'source_line':row[2],'original':json.loads(row[0])})
                if url.path=='/api/download':
                    name=args.get('file',[''])[0]
                    if not re.fullmatch(r'alert-[a-f0-9]{64}-r[1-9][0-9]*-case-[a-f0-9]{32}-r[1-9][0-9]*\.zip',name): raise ValueError('invalid filename')
                    return self.respond(200,(workspace/'exports'/name).read_bytes(),'application/zip')
                if url.path=='/metrics':
                    data=live.status(workspace)
                    lines=['# SOC operations pilot aggregate metrics; no host or account labels']
                    for key in ('events','duplicates','oldest_pending_seconds','overdue_alerts','database_bytes'):
                        lines.append(f'soclab_{key} {data[key]}')
                    for group in ('queue','alerts'):
                        for state,count in data[group].items(): lines.append(f'soclab_{group}{{state="{state}"}} {count}')
                    return self.respond(200,('\n'.join(lines)+'\n').encode(),'text/plain; version=0.0.4')
                return self.respond(404,{'error':'route not found'})
            except (ValueError,OSError,sqlite3.Error,TypeError) as exc:
                return self.respond(400,{'error':str(exc)})
        def do_POST(self):
            if not self.host_allowed() or len(self.headers.get_all('Origin',[]))!=1 or self.headers.get('Origin')!='http://'+self.headers.get('Host',''):
                return self.respond(403,{'error':'same-origin request required'})
            csrf=self.headers.get('X-SOC-CSRF','')
            if len(self.headers.get_all('X-SOC-CSRF',[]))!=1 or not secrets.compare_digest(csrf.encode('utf-8'),token.encode()):
                return self.respond(403,{'error':'invalid CSRF token'})
            try:
                if self.headers.get('Transfer-Encoding') or self.headers.get('Content-Type','').split(';')[0]!='application/json' or len(self.headers.get_all('Content-Length',[]))!=1:
                    raise ValueError('bounded JSON request required')
                size=int(self.headers['Content-Length'])
                if not 1<=size<=65536: raise ValueError('body must be 1..65536 bytes')
                self.connection.settimeout(10)
                data=json.loads(self.rfile.read(size))
                if not isinstance(data,dict): raise ValueError('JSON object required')
                path=urlparse(self.path).path
                if path=='/api/review':
                    result=live.update_alert(workspace,data.get('id'),revision=data.get('revision'),actor=data.get('actor'),reason=data.get('reason'),owner=data.get('owner'),target=data.get('target'),verdict=data.get('verdict'))
                elif path=='/api/promote': result=live.promote_case(workspace,data.get('id'),actor=data.get('actor'),reason=data.get('reason'))
                elif path=='/api/export':
                    result=live.export_review(workspace,data.get('id'))
                else: return self.respond(404,{'error':'unsupported operation'})
                return self.respond(200,result)
            except (ValueError,OSError,sqlite3.Error,TypeError,RecursionError) as exc:
                return self.respond(409 if 'revision conflict' in str(exc) else 400,{'error':str(exc)})
    return Handler


def serve(workspace,port=8766):
    if not 1024<=port<=65535: raise ValueError('port must be 1024..65535')
    with ThreadingHTTPServer(('127.0.0.1',port),build_handler(workspace)) as server:
        print(f'Operations pilot: http://127.0.0.1:{port}; local single-user workflow, actor labels self-declared.',flush=True)
        try: server.serve_forever()
        except KeyboardInterrupt: pass
