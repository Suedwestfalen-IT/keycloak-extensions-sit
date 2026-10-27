"""
Shared helpers for the curl-driven Keycloak end-to-end tests (ci/login-e2e, ci/idp-mapper-e2e).

A test imports this module, calls init(<base-url>) once and then uses:

  check(label, fn)        runs fn, prints OK/FAIL, records the failure
  api(method, path, ...)  admin / token REST call via urllib; token=ADMIN uses a master-realm
                          admin token that is fetched on demand and renewed before it expires
  Browser()               curl with a cookie jar and no automatic redirects, for the login pages
  form_action(body, id)   action URL of a login form
  snippet(body)           first 300 characters of a page, whitespace collapsed, for messages

ci/kerberos-e2e has its own copies on purpose: its api() needs the Location header and its
Browser speaks SPNEGO (two header rounds per request), so the helpers are not the same.
"""
import html
import json
import os
import re
import subprocess
import tempfile
import time
import urllib.error
import urllib.parse
import urllib.request

BASE = None
failures = []
opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))

# token=ADMIN: api() fetches the master-realm admin token itself and renews it when it is older
# than ADMIN_TOKEN_MAX_AGE. The master realm's default access token lifespan is 60 s; a scenario
# with several brokered logins and dozens of admin calls can take longer on a slow CI runner.
ADMIN = object()
ADMIN_TOKEN_MAX_AGE = 30
_admin_token = {"value": None, "at": 0.0}


def init(base_url):
    """Sets the Keycloak base URL (no trailing slash) and returns it."""
    global BASE
    BASE = base_url.rstrip("/")
    return BASE


def check(label, fn):
    try:
        detail = fn()
        print("OK    %s%s" % (label, (" - " + detail) if detail else ""))
        return True
    except Exception as e:  # noqa: BLE001 - every deviation is a finding
        failures.append(label)
        print("FAIL  %s - %s" % (label, e))
        return False


def api(method, path, body=None, token=None, form=None, expect=(200, 201, 204)):
    url = path if path.startswith("http") else BASE + path
    headers = {}
    data = None
    if form is not None:
        data = urllib.parse.urlencode(form).encode()
        headers["Content-Type"] = "application/x-www-form-urlencoded"
    elif body is not None:
        data = json.dumps(body).encode()
        headers["Content-Type"] = "application/json"
    if token is ADMIN:
        token = admin_token()
    if token:
        headers["Authorization"] = "Bearer " + token
    req = urllib.request.Request(url, data=data, method=method, headers=headers)
    try:
        with opener.open(req, timeout=60) as resp:
            raw, status = resp.read(), resp.status
    except urllib.error.HTTPError as e:
        raw, status = e.read(), e.code
    if status not in expect:
        raise RuntimeError("%s %s -> HTTP %d: %s" % (method, path, status, raw[:300].decode("utf-8", "replace")))
    if raw:
        try:
            return json.loads(raw)
        except ValueError:
            return raw.decode("utf-8", "replace")
    return None


def admin_token():
    """Master-realm admin token (admin/admin), cached and renewed every ADMIN_TOKEN_MAX_AGE seconds."""
    now = time.monotonic()
    if _admin_token["value"] is None or now - _admin_token["at"] > ADMIN_TOKEN_MAX_AGE:
        tok = api("POST", "/realms/master/protocol/openid-connect/token", form={
            "grant_type": "password", "client_id": "admin-cli", "username": "admin", "password": "admin"})
        _admin_token["value"], _admin_token["at"] = tok["access_token"], now
    return _admin_token["value"]


class Browser:
    """curl with a cookie jar and no automatic redirects."""

    def __init__(self, prefix="e2e-"):
        self.dir = tempfile.mkdtemp(prefix=prefix)
        self.jar = os.path.join(self.dir, "cookies")

    def request(self, method, url, data=None):
        hdr = os.path.join(self.dir, "headers")
        cmd = ["curl", "-s", "--noproxy", "*", "-c", self.jar, "-b", self.jar, "-D", hdr,
               "-o", "-", "-w", "\n%{http_code}", "-X", method, "-H", "Accept-Language: en"]
        if data is not None:
            cmd += ["--data", urllib.parse.urlencode(data)]
        cmd.append(url)
        out = subprocess.run(cmd, capture_output=True, text=True, timeout=60)
        if out.returncode != 0:
            raise RuntimeError("curl failed (%d): %s" % (out.returncode, out.stderr.strip()[:300]))
        body, _, status = out.stdout.rpartition("\n")
        headers = {}
        with open(hdr) as fh:
            for line in fh.read().splitlines()[1:]:
                if ":" in line:
                    k, v = line.split(":", 1)
                    headers[k.strip().lower()] = v.strip()
        return int(status), headers, body


def form_action(body, form_id):
    m = re.search(r'<form[^>]*id="%s"[^>]*action="([^"]+)"' % re.escape(form_id), body)
    if not m:
        raise RuntimeError("form '%s' not in page" % form_id)
    return html.unescape(m.group(1))


def snippet(body):
    return re.sub(r"\s+", " ", body)[:300]
