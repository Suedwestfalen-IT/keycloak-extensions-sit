#!/usr/bin/env python3
"""
End-to-end test for sit-oidc-group-idp-mapper against a running Keycloak.

One Keycloak, two realms: "upstream" is the OIDC identity provider (alice, a
"sso-groups" claim with full group paths), "broker" brokers it with our mapper.
Every login is played with curl through the real broker endpoints.

For each sync mode of the mapper the same story runs twice:

  update   login 1 with /SSO/HEME/koki-user, move alice upstream to koki-admin, login 2
  late     login 1 without any group, add koki-user upstream, login 2
           (a user who logged in before the group was assigned upstream)

Expected (Keycloak semantics, see IdentityProviderMapperSyncModeDelegate):

  IMPORT, INHERIT(IdP=IMPORT)   login 2 leaves the memberships as they were after login 1
  FORCE, LEGACY                 login 2 syncs the memberships to the new claim

Running the same checks against two jars (before/after removing
preprocessFederatedIdentity) shows both behave identically.

Additional check: the federated identity link stores the upstream "sub" as userId,
while BrokeredIdentityContext#getBrokerUserId() is "<alias>.<sub>" - the lookup the
removed preprocessFederatedIdentity did could never find the user.

Usage: idp_mapper_e2e.py <base-url>
"""
import html
import json
import os
import re
import subprocess
import sys
import tempfile
import urllib.error
import urllib.parse
import urllib.request

BASE = sys.argv[1].rstrip("/")
UP = "upstream"
BR = "broker"
IDP_ALIAS = "upstream"
APP = "app"
APP_REDIRECT = BASE + "/app/callback"
BROKER_CLIENT = "broker-client"
BROKER_SECRET = "broker-secret"
MAPPER = "sit-oidc-group-idp-mapper"
GROUPS = ("/SSO/HEME/koki-user", "/SSO/HEME/koki-admin")

failures = []
opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))


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
    tok = api("POST", "/realms/master/protocol/openid-connect/token", form={
        "grant_type": "password", "client_id": "admin-cli", "username": "admin", "password": "admin"})
    return tok["access_token"]


class Browser:
    """curl with a cookie jar and no automatic redirects."""

    def __init__(self):
        self.dir = tempfile.mkdtemp(prefix="idpm-")
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


def snippet(body):
    return re.sub(r"\s+", " ", body)[:300]


# ── setup ───────────────────────────────────────────────────────────────────

def group_id(t, realm, path):
    g = api("GET", "/admin/realms/%s/group-by-path/%s" % (realm, path.lstrip("/")), token=t)
    return g["id"]


def create_group_path(t, realm, path):
    parent = None
    walked = ""
    for seg in path.strip("/").split("/"):
        walked += "/" + seg
        existing = api("GET", "/admin/realms/%s/group-by-path/%s" % (realm, walked.lstrip("/")),
                       token=t, expect=(200, 404))
        if isinstance(existing, dict) and existing.get("id"):
            parent = existing["id"]
            continue
        url = "/admin/realms/%s/groups" % realm if parent is None \
            else "/admin/realms/%s/groups/%s/children" % (realm, parent)
        api("POST", url, {"name": seg}, token=t)
        parent = group_id(t, realm, walked)


def setup(t):
    for realm in (UP, BR):
        api("DELETE", "/admin/realms/" + realm, token=t, expect=(204, 404))
        api("POST", "/admin/realms", {"realm": realm, "enabled": True}, token=t)

    # upstream: the IdP with alice and a full-path group claim "sso-groups"
    api("POST", "/admin/realms/%s/clients" % UP, {
        "clientId": BROKER_CLIENT, "enabled": True, "publicClient": False, "secret": BROKER_SECRET,
        "standardFlowEnabled": True,
        "redirectUris": [BASE + "/realms/%s/broker/%s/endpoint" % (BR, IDP_ALIAS)],
        "protocolMappers": [{
            "name": "sso-groups", "protocol": "openid-connect",
            "protocolMapper": "oidc-group-membership-mapper",
            "config": {"claim.name": "sso-groups", "full.path": "true", "id.token.claim": "true",
                       "access.token.claim": "true", "userinfo.token.claim": "true"}}]}, token=t)
    api("POST", "/admin/realms/%s/users" % UP, {
        "username": "alice", "enabled": True, "email": "alice@example.test", "emailVerified": True,
        "firstName": "Alice", "lastName": "Example",
        "credentials": [{"type": "password", "value": "alicepw", "temporary": False}]}, token=t)
    for realm in (UP, BR):
        for path in GROUPS:
            create_group_path(t, realm, path)

    # broker: app client + OIDC IdP pointing at the upstream realm
    api("POST", "/admin/realms/%s/clients" % BR, {
        "clientId": APP, "enabled": True, "publicClient": True, "standardFlowEnabled": True,
        "redirectUris": [APP_REDIRECT]}, token=t)
    up = BASE + "/realms/" + UP + "/protocol/openid-connect"
    api("POST", "/admin/realms/%s/identity-provider/instances" % BR, {
        "alias": IDP_ALIAS, "providerId": "oidc", "enabled": True, "trustEmail": True,
        "firstBrokerLoginFlowAlias": "first broker login",
        "config": {
            "authorizationUrl": up + "/auth", "tokenUrl": up + "/token", "userInfoUrl": up + "/userinfo",
            "jwksUrl": up + "/certs", "useJwksUrl": "true", "validateSignature": "true",
            "issuer": BASE + "/realms/" + UP, "clientId": BROKER_CLIENT, "clientSecret": BROKER_SECRET,
            "clientAuthMethod": "client_secret_post", "defaultScope": "openid email profile",
            "syncMode": "IMPORT"}}, token=t)


def configure(t, idp_sync_mode, mapper_sync_mode):
    """(Re)creates the mapper with the given sync mode and resets both sides."""
    r = "/admin/realms/" + BR
    idp = api("GET", r + "/identity-provider/instances/" + IDP_ALIAS, token=t)
    idp["config"]["syncMode"] = idp_sync_mode
    api("PUT", r + "/identity-provider/instances/" + IDP_ALIAS, idp, token=t)
    for m in api("GET", r + "/identity-provider/instances/%s/mappers" % IDP_ALIAS, token=t):
        api("DELETE", r + "/identity-provider/instances/%s/mappers/%s" % (IDP_ALIAS, m["id"]), token=t)
    api("POST", r + "/identity-provider/instances/%s/mappers" % IDP_ALIAS, {
        "name": "sso-groups", "identityProviderAlias": IDP_ALIAS, "identityProviderMapper": MAPPER,
        "config": {"syncMode": mapper_sync_mode, "claim": "sso-groups", "groupPrefix": "",
                   "targetPrefix": "", "createMissing": "false", "removeNotListed": "true",
                   "managedPrefix": "/SSO/HEME"}}, token=t)
    for u in api("GET", r + "/users?username=alice&exact=true", token=t):
        api("DELETE", r + "/users/" + u["id"], token=t)
    set_upstream_groups(t, [])


def upstream_user(t):
    return api("GET", "/admin/realms/%s/users?username=alice&exact=true" % UP, token=t)[0]


def set_upstream_groups(t, paths):
    uid = upstream_user(t)["id"]
    base = "/admin/realms/%s/users/%s/groups" % (UP, uid)
    for g in api("GET", base, token=t):
        api("DELETE", base + "/" + g["id"], token=t)
    for p in paths:
        api("PUT", base + "/" + group_id(t, UP, p), token=t)


def broker_user(t):
    users = api("GET", "/admin/realms/%s/users?username=alice&exact=true" % BR, token=t)
    return users[0] if users else None


def broker_groups(t):
    u = broker_user(t)
    if u is None:
        raise RuntimeError("alice was not created in the broker realm")
    return sorted(g["path"] for g in api("GET", "/admin/realms/%s/users/%s/groups" % (BR, u["id"]), token=t))


# ── login through the broker ────────────────────────────────────────────────

def login():
    b = Browser()
    url = BASE + "/realms/%s/protocol/openid-connect/auth?" % BR + urllib.parse.urlencode({
        "client_id": APP, "response_type": "code", "redirect_uri": APP_REDIRECT, "scope": "openid",
        "kc_idp_hint": IDP_ALIAS})
    method, data = "GET", None
    for _ in range(20):
        status, headers, body = b.request(method, url, data)
        method, data = "GET", None
        if status in (302, 303):
            url = urllib.parse.urljoin(url, headers["location"])
            if url.startswith(APP_REDIRECT):
                if "code=" not in url:
                    raise RuntimeError("redirect without code: " + url)
                return
            continue
        if status == 200 and 'id="kc-form-login"' in body:
            m = re.search(r'<form[^>]*id="kc-form-login"[^>]*action="([^"]+)"', body)
            url, method, data = html.unescape(m.group(1)), "POST", {"username": "alice", "password": "alicepw"}
            continue
        raise RuntimeError("unexpected page HTTP %d at %s: %s" % (status, url, snippet(body)))
    raise RuntimeError("too many redirects")


# ── scenarios ───────────────────────────────────────────────────────────────

MODES = [
    # label, IdP sync mode, mapper sync mode override, does login 2 sync?
    ("IMPORT", "IMPORT", "IMPORT", False),
    ("INHERIT(IdP=IMPORT)", "IMPORT", "INHERIT", False),
    ("FORCE", "IMPORT", "FORCE", True),
    ("LEGACY", "IMPORT", "LEGACY", True),
    ("INHERIT(IdP=FORCE)", "FORCE", "INHERIT", True),
]


def scenario_update(t, label, idp_mode, mapper_mode, syncs):
    def run():
        configure(t, idp_mode, mapper_mode)
        set_upstream_groups(t, ["/SSO/HEME/koki-user"])
        login()
        after1 = broker_groups(t)
        if after1 != ["/SSO/HEME/koki-user"]:
            raise RuntimeError("after login 1: %s" % after1)
        set_upstream_groups(t, ["/SSO/HEME/koki-admin"])
        login()
        after2 = broker_groups(t)
        want = ["/SSO/HEME/koki-admin"] if syncs else ["/SSO/HEME/koki-user"]
        if after2 != want:
            raise RuntimeError("after login 2: %s, expected %s" % (after2, want))
        return "login1=%s login2=%s" % (after1, after2)
    check("%-20s update: group change upstream %s on login 2" % (label, "synced" if syncs else "ignored"), run)


def scenario_late(t, label, idp_mode, mapper_mode, syncs):
    def run():
        configure(t, idp_mode, mapper_mode)
        login()
        after1 = broker_groups(t)
        if after1:
            raise RuntimeError("after login 1: %s" % after1)
        set_upstream_groups(t, ["/SSO/HEME/koki-user"])
        login()
        after2 = broker_groups(t)
        want = ["/SSO/HEME/koki-user"] if syncs else []
        if after2 != want:
            raise RuntimeError("after login 2: %s, expected %s" % (after2, want))
        return "login1=%s login2=%s" % (after1, after2)
    check("%-20s late:   group assigned after login 1 %s" % (label, "picked up" if syncs else "not picked up"), run)


def federated_link(t):
    def run():
        configure(t, "IMPORT", "IMPORT")
        login()
        u = broker_user(t)
        links = api("GET", "/admin/realms/%s/users/%s/federated-identity" % (BR, u["id"]), token=t)
        link = [li for li in links if li["identityProvider"] == IDP_ALIAS][0]
        sub = upstream_user(t)["id"]
        if link["userId"] != sub:
            raise RuntimeError("stored userId %s != upstream sub %s" % (link["userId"], sub))
        broker_user_id = IDP_ALIAS + "." + sub  # what OIDCIdentityProvider sets as brokerUserId
        found = api("GET", "/admin/realms/%s/users?idpAlias=%s&idpUserId=%s" % (
            BR, IDP_ALIAS, urllib.parse.quote(broker_user_id)), token=t)
        found_sub = api("GET", "/admin/realms/%s/users?idpAlias=%s&idpUserId=%s" % (
            BR, IDP_ALIAS, urllib.parse.quote(sub)), token=t)
        if found or len(found_sub) != 1:
            raise RuntimeError("lookup by brokerUserId found %d, by sub found %d" % (len(found), len(found_sub)))
        return "stored userId=<sub>; lookup by '%s.<sub>' finds 0 users, by '<sub>' finds 1" % IDP_ALIAS
    check("federated link: userId is the plain sub, '<alias>.<sub>' never matches", run)


def main():
    t = admin_token()
    setup(t)
    for label, idp_mode, mapper_mode, syncs in MODES:
        t = admin_token()
        scenario_update(t, label, idp_mode, mapper_mode, syncs)
        scenario_late(t, label, idp_mode, mapper_mode, syncs)
    federated_link(admin_token())
    print()
    if failures:
        print("FAILED: %d check(s): %s" % (len(failures), ", ".join(failures)))
        sys.exit(1)
    print("All checks passed")


if __name__ == "__main__":
    main()
