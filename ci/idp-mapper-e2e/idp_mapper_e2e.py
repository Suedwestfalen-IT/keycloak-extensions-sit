#!/usr/bin/env python3
"""
End-to-end test for sit-oidc-group-idp-mapper against a running Keycloak.

One Keycloak, two realms: "upstream" is the OIDC identity provider (alice, a
"sso-groups" claim with full group paths), "broker" brokers it with our mapper.
Every login is played with curl through the real broker endpoints.

For each sync mode of the mapper the same story runs twice:

  update   login 1 with /SSO/ORG/koki-user, move alice upstream to koki-admin, login 2
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

Keycloak log (KC_LOG, set by run.sh; the mapper's logger must be on DEBUG): every sync
has to leave exactly one summary line "IdpGroupMapper: user=... idp=... mapper=... added=..."
(INFO when memberships changed, DEBUG otherwise) and Keycloak must not log the
"does not explicitly support sync mode" warning for the mapper.

Usage: idp_mapper_e2e.py <base-url>
"""
import os
import re
import sys
import urllib.parse

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "lib"))
from kc_e2e import ADMIN, Browser, api, check, failures, form_action, init, snippet  # noqa: E402

BASE = init(sys.argv[1])
UP = "upstream"
BR = "broker"
IDP_ALIAS = "upstream"
APP = "app"
APP_REDIRECT = BASE + "/app/callback"
BROKER_CLIENT = "broker-client"
BROKER_SECRET = "broker-secret"
MAPPER = "sit-oidc-group-idp-mapper"
GROUPS = ("/SSO/ORG/koki-user", "/SSO/ORG/koki-admin")

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
                   "managedPrefix": "/SSO/ORG"}}, token=t)
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
    b = Browser(prefix="idpm-")
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
            url, method, data = form_action(body, "kc-form-login"), "POST", {"username": "alice", "password": "alicepw"}
            continue
        raise RuntimeError("unexpected page HTTP %d at %s: %s" % (status, url, snippet(body)))
    raise RuntimeError("too many redirects")


# ── scenarios ───────────────────────────────────────────────────────────────

# Summary lines the mapper must have written by the end: one per sync (login 1 always syncs,
# login 2 only in the modes that sync), INFO when the sync changed a membership, DEBUG otherwise.
expected_log = {"syncs": 0, "info": 0}


def expect_sync(changed):
    expected_log["syncs"] += 1
    if changed:
        expected_log["info"] += 1


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
        set_upstream_groups(t, ["/SSO/ORG/koki-user"])
        login()
        expect_sync(changed=True)  # joined koki-user
        after1 = broker_groups(t)
        if after1 != ["/SSO/ORG/koki-user"]:
            raise RuntimeError("after login 1: %s" % after1)
        set_upstream_groups(t, ["/SSO/ORG/koki-admin"])
        login()
        if syncs:
            expect_sync(changed=True)  # joined koki-admin, left koki-user
        after2 = broker_groups(t)
        want = ["/SSO/ORG/koki-admin"] if syncs else ["/SSO/ORG/koki-user"]
        if after2 != want:
            raise RuntimeError("after login 2: %s, expected %s" % (after2, want))
        return "login1=%s login2=%s" % (after1, after2)
    check("%-20s update: group change upstream %s on login 2" % (label, "synced" if syncs else "ignored"), run)


def scenario_late(t, label, idp_mode, mapper_mode, syncs):
    def run():
        configure(t, idp_mode, mapper_mode)
        login()
        expect_sync(changed=False)  # no groups upstream yet: a sync that changes nothing
        after1 = broker_groups(t)
        if after1:
            raise RuntimeError("after login 1: %s" % after1)
        set_upstream_groups(t, ["/SSO/ORG/koki-user"])
        login()
        if syncs:
            expect_sync(changed=True)  # joined koki-user
        after2 = broker_groups(t)
        want = ["/SSO/ORG/koki-user"] if syncs else []
        if after2 != want:
            raise RuntimeError("after login 2: %s, expected %s" % (after2, want))
        return "login1=%s login2=%s" % (after1, after2)
    check("%-20s late:   group assigned after login 1 %s" % (label, "picked up" if syncs else "not picked up"), run)


def federated_link(t):
    def run():
        configure(t, "IMPORT", "IMPORT")
        login()
        expect_sync(changed=False)
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


# ── Keycloak log ────────────────────────────────────────────────────────────

# "2026-10-27 14:07:43,123 DEBUG [nrw.sit.keycloak.mapper.IdpGroupMapper] (executor-thread-1) IdpGroupMapper: user=alice idp=upstream mapper=sso-groups added=[] ..."
# The "idp=" anchor keeps the mapper's DEBUG detail lines ("user=alice prefixes=...",
# "user=alice currentGroups=...") out of the count.
SUMMARY_LINE = re.compile(r"^\S+ \S+ (?P<level>[A-Z]+)\s+\[nrw\.sit\.keycloak\.mapper\.IdpGroupMapper\] .*"
                          r"IdpGroupMapper: user=\S+ idp=\S+ mapper=\S+ added=")
SYNC_MODE_WARNING = "does not explicitly support sync mode"


def log_checks(scenarios_passed):
    path = os.environ.get("KC_LOG")
    if not path:
        print("SKIP  Keycloak log: KC_LOG not set")
        return
    with open(path, errors="replace") as fh:
        lines = fh.read().splitlines()
    levels = [m.group("level") for m in map(SUMMARY_LINE.match, lines) if m]

    def warning_free():
        hits = [ln for ln in lines if SYNC_MODE_WARNING in ln]
        if hits:
            raise RuntimeError("%d line(s): %s" % (len(hits), snippet(hits[0])))
        return "0 lines"
    check("log: no '%s' warning" % SYNC_MODE_WARNING, warning_free)

    def one_summary_per_sync():
        if not scenarios_passed:
            raise RuntimeError("not compared, a scenario failed (found %d summary line(s))" % len(levels))
        got = {"syncs": len(levels), "info": levels.count("INFO")}
        if got != expected_log:
            raise RuntimeError("found %s, expected %s (levels: %s)" % (got, expected_log, levels))
        if levels.count("WARN") or levels.count("ERROR"):
            raise RuntimeError("WARN/ERROR summary lines: %s" % levels)
        return "%d summary line(s), %d of them INFO (changed memberships), rest DEBUG" % (
            got["syncs"], got["info"])
    check("log: one summary line per sync, INFO only when memberships changed", one_summary_per_sync)


def main():
    t = ADMIN  # api() fetches and renews the admin token itself
    setup(t)
    for label, idp_mode, mapper_mode, syncs in MODES:
        scenario_update(t, label, idp_mode, mapper_mode, syncs)
        scenario_late(t, label, idp_mode, mapper_mode, syncs)
    federated_link(t)
    log_checks(scenarios_passed=not failures)
    print()
    if failures:
        print("FAILED: %d check(s): %s" % (len(failures), ", ".join(failures)))
        sys.exit(1)
    print("All checks passed")


if __name__ == "__main__":
    main()
