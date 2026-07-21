# Minimal fedhost: a static OpenID Federation entity host. Serves pre-signed entity configurations
# and subordinate statements from a content file (public JWTs only — no private keys):
#   GET /e/<slug>/.well-known/openid-federation  -> entityConfigs[slug]      (entity config JWT)
#   GET /e/<iss>/fetch?sub=<subject>             -> subStmts[iss][subject]   (subordinate statement JWT)
#   GET /e/<iss>/list                            -> [subjects...]            (JSON array)
#
# The content file is chosen per environment via FEDHOST_CONTENT (config-as-code), so one image
# serves the right federation in each env: content.staging.json vs content.production.json.
import json, os
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import urlparse, parse_qs

C = json.load(open(os.environ.get('FEDHOST_CONTENT', 'content.json')))
CFG, SUB = C['entityConfigs'], C['subStmts']

class H(BaseHTTPRequestHandler):
    def _s(self, code, body, ctype='application/entity-statement+jwt'):
        b = body.encode() if isinstance(body, str) else body
        self.send_response(code)
        self.send_header('Content-Type', ctype)
        self.send_header('Content-Length', str(len(b)))
        self.end_headers()
        self.wfile.write(b)
    def do_GET(self):
        u = urlparse(self.path)
        p = u.path.strip('/').split('/')
        if len(p) >= 3 and p[0] == 'e' and p[-1] == 'openid-federation':
            return self._s(200, CFG[p[1]]) if p[1] in CFG else self._s(404, '{"error":"not_found"}', 'application/json')
        if len(p) == 3 and p[0] == 'e' and p[2] == 'fetch':
            sub = (parse_qs(u.query).get('sub') or [''])[0]
            stmts = SUB.get(p[1], {})
            return self._s(200, stmts[sub]) if sub in stmts else self._s(404, '{"error":"not_found"}', 'application/json')
        if len(p) == 3 and p[0] == 'e' and p[2] == 'list':
            return self._s(200, json.dumps(list(SUB.get(p[1], {}).keys())), 'application/json')
        return self._s(404, '{"error":"not_found"}', 'application/json')
    def log_message(self, *a):
        pass

port = int(os.environ.get('PORT', '8080'))
print(f'fedhost serving {len(CFG)} entities, {sum(len(v) for v in SUB.values())} subordinate statements on :{port}', flush=True)
ThreadingHTTPServer(('0.0.0.0', port), H).serve_forever()
