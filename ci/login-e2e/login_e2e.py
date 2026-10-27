#!/usr/bin/env python3
"""
End-to-end test for sit-auth-username-password-form against a running Keycloak.

Builds two browser flows through the admin API and plays the login with curl:

  pwf-alternative (the form as ALTERNATIVE, no wrapper sub-flow)
    ├─ Cookie                                   ALTERNATIVE
    └─ login (sub-flow)                         ALTERNATIVE
       ├─ first (sub-flow)                      REQUIRED
       │  ├─ SIT: Username Password Form        ALTERNATIVE
       │  └─ Passkey (WebAuthn passwordless)    ALTERNATIVE
       └─ otp (sub-flow)                        CONDITIONAL
          ├─ Condition - user role "stepup"     REQUIRED
          └─ OTP Form                           REQUIRED

  pwf-required (the form as REQUIRED, like the built-in one)
    ├─ Cookie                                   ALTERNATIVE
    └─ forms (sub-flow)                         ALTERNATIVE
       └─ SIT: Username Password Form           REQUIRED

Checks:
  A1  the password form is what the login page shows (first alternative)
  A2  "try another way" lists password and passkey, with readable texts (shipped messages)
  A3  picking the password option on that page leads back to the form
  A4  a wrong password re-renders the form with an error (no "page expired")
  A5  the right password logs alice in (302 with code, token for alice)
  A6  bob (role stepup) continues into the conditional OTP sub-flow after the form
  B1  as REQUIRED the form logs alice in

Usage: login_e2e.py <base-url>
"""
import base64
import html
import json
import os
import re
import sys
import urllib.parse

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "lib"))
from kc_e2e import ADMIN, Browser, api, check, failures, form_action, init, snippet  # noqa: E402

BASE = init(sys.argv[1])
REALM = "pwf"
CLIENT_ID = "pwf-client"
REDIRECT_URI = BASE + "/pwf/callback"
PROVIDER = "sit-auth-username-password-form"
PASSKEY = "webauthn-authenticator-passwordless"
FLOW_ALT = "pwf-alternative"
FLOW_REQ = "pwf-required"

def selection_form(body, exec_id):
    for m in re.finditer(r'<form[^>]*action="([^"]+)"[^>]*>(.*?)</form>', body, re.S):
        if 'name="authenticationExecution"' in m.group(2) and exec_id in m.group(2):
            return html.unescape(m.group(1))
    raise RuntimeError("execution %s not offered on the select-authenticator page" % exec_id)


def auth_url():
    return BASE + "/realms/%s/protocol/openid-connect/auth?" % REALM + urllib.parse.urlencode({
        "client_id": CLIENT_ID, "response_type": "code", "redirect_uri": REDIRECT_URI, "scope": "openid"})


# ── setup ───────────────────────────────────────────────────────────────────

def setup(t):
    r = "/admin/realms/" + REALM
    api("DELETE", r, token=t, expect=(204, 404))
    api("POST", "/admin/realms", {"realm": REALM, "enabled": True, "defaultLocale": "en",
                                   "internationalizationEnabled": False}, token=t)
    api("POST", r + "/clients", {"clientId": CLIENT_ID, "publicClient": True, "standardFlowEnabled": True,
                                  "redirectUris": [REDIRECT_URI], "enabled": True}, token=t)
    api("POST", r + "/roles", {"name": "stepup"}, token=t)
    for name in ("alice", "bob"):
        api("POST", r + "/users", {
            "username": name, "enabled": True, "email": name + "@example.test", "emailVerified": True,
            "firstName": name.capitalize(), "lastName": "Example",
            "credentials": [{"type": "password", "value": name + "pw", "temporary": False}]}, token=t)
    users = api("GET", r + "/users?username=bob&exact=true", token=t)
    role = api("GET", r + "/roles/stepup", token=t)
    api("POST", r + "/users/%s/role-mappings/realm" % users[0]["id"], [role], token=t)

    ids = {}
    ids["alt"], ids["alt_passkey"] = build_alternative_flow(t)
    ids["req"] = build_required_flow(t)
    return ids


class FlowBuilder:
    def __init__(self, t):
        self.t = t
        self.r = "/admin/realms/" + REALM

    def executions(self, alias):
        execs = api("GET", self.r + "/authentication/flows/%s/executions" % urllib.parse.quote(alias), token=self.t)
        return execs

    def top(self, alias):
        return [e for e in self.executions(alias) if e.get("level", 0) == 0]

    def requirement(self, alias, execution, requirement):
        rep = dict(execution)
        rep["requirement"] = requirement
        api("PUT", self.r + "/authentication/flows/%s/executions" % urllib.parse.quote(alias), rep, token=self.t)

    def flow(self, alias):
        api("POST", self.r + "/authentication/flows",
            {"alias": alias, "providerId": "basic-flow", "topLevel": True, "builtIn": False, "description": ""},
            token=self.t)
        return alias

    def execution(self, alias, provider, requirement, config=None):
        api("POST", self.r + "/authentication/flows/%s/executions/execution" % urllib.parse.quote(alias),
            {"provider": provider}, token=self.t)
        ex = [e for e in self.top(alias) if e.get("providerId") == provider][-1]
        self.requirement(alias, ex, requirement)
        if config:
            api("POST", self.r + "/authentication/executions/%s/config" % ex["id"],
                {"alias": "%s-%s" % (alias, provider), "config": config}, token=self.t)
        return ex["id"]

    def subflow(self, parent, alias, requirement):
        api("POST", self.r + "/authentication/flows/%s/executions/flow" % urllib.parse.quote(parent),
            {"alias": alias, "type": "basic-flow", "provider": "registration-page-form", "description": ""},
            token=self.t)
        ex = [e for e in self.top(parent) if e.get("displayName") == alias][-1]
        self.requirement(parent, ex, requirement)
        return alias


def build_alternative_flow(t):
    f = FlowBuilder(t)
    f.flow(FLOW_ALT)
    f.execution(FLOW_ALT, "auth-cookie", "ALTERNATIVE")
    login = f.subflow(FLOW_ALT, FLOW_ALT + " login", "ALTERNATIVE")
    first = f.subflow(login, FLOW_ALT + " first", "REQUIRED")
    pw = f.execution(first, PROVIDER, "ALTERNATIVE")
    passkey = f.execution(first, PASSKEY, "ALTERNATIVE")
    otp = f.subflow(login, FLOW_ALT + " otp", "CONDITIONAL")
    f.execution(otp, "conditional-user-role", "REQUIRED", {"condUserRole": "stepup", "negate": "false"})
    f.execution(otp, "auth-otp-form", "REQUIRED")
    if os.environ.get("E2E_DEBUG"):
        print("  %s: %s" % (FLOW_ALT, [(e["level"], e.get("providerId") or e.get("displayName"), e["requirement"])
                                       for e in f.executions(FLOW_ALT)]))
    return pw, passkey


def build_required_flow(t):
    f = FlowBuilder(t)
    f.flow(FLOW_REQ)
    f.execution(FLOW_REQ, "auth-cookie", "ALTERNATIVE")
    forms = f.subflow(FLOW_REQ, FLOW_REQ + " forms", "ALTERNATIVE")
    return f.execution(forms, PROVIDER, "REQUIRED")


def bind(t, alias):
    api("PUT", "/admin/realms/" + REALM, {"browserFlow": alias}, token=t)


# ── scenarios ───────────────────────────────────────────────────────────────

def login(b, username, password):
    status, _, body = b.request("GET", auth_url())
    if status != 200 or 'id="kc-form-login"' not in body:
        raise RuntimeError("login form expected, got HTTP %d: %s" % (status, snippet(body)))
    return b.request("POST", form_action(body, "kc-form-login"), data={"username": username, "password": password})


def token_user(location):
    code = urllib.parse.parse_qs(urllib.parse.urlparse(location).query)["code"][0]
    tok = api("POST", "/realms/%s/protocol/openid-connect/token" % REALM, form={
        "grant_type": "authorization_code", "client_id": CLIENT_ID, "redirect_uri": REDIRECT_URI, "code": code})
    payload = tok["access_token"].split(".")[1]
    payload += "=" * (-len(payload) % 4)
    return json.loads(base64.urlsafe_b64decode(payload)).get("preferred_username")


def scenario_alternative(ids):
    state = {}

    def form_first():
        b = Browser(prefix="pwf-")
        status, _, body = b.request("GET", auth_url())
        if status != 200 or 'id="kc-form-login"' not in body:
            raise RuntimeError("HTTP %d without the login form: %s" % (status, snippet(body)))
        state["browser"], state["page"] = b, body
        return "login form rendered by the ALTERNATIVE execution"
    if not check("A1 the password form is the first alternative", form_first):
        return

    def offered():
        b = state["browser"]
        action = form_action(state["page"], "kc-select-try-another-way-form")
        status, _, body = b.request("POST", action, data={"tryAnotherWay": "on"})
        if status != 200:
            raise RuntimeError("HTTP %d" % status)
        state["select_page"] = body
        selection_form(body, ids["alt"])
        selection_form(body, ids["alt_passkey"])
        if PROVIDER + "-display-name" in body or PROVIDER + "-help-text" in body:
            raise RuntimeError("raw message key on the page, messages not loaded")
        if "Username and password" not in body:
            raise RuntimeError("display name 'Username and password' missing: %s" % snippet(body))
        return "password and passkey listed, texts resolved"
    if not check("A2 'try another way' lists password and passkey with readable texts", offered):
        return

    def reselect():
        b = state["browser"]
        status, _, body = b.request("POST", selection_form(state["select_page"], ids["alt"]),
                                    data={"authenticationExecution": ids["alt"]})
        if status != 200 or 'id="kc-form-login"' not in body:
            raise RuntimeError("HTTP %d without the login form: %s" % (status, snippet(body)))
        return "selecting the password option shows the form"
    check("A3 picking the password option leads back to the form", reselect)

    def wrong_password():
        b = Browser(prefix="pwf-")
        status, _, body = login(b, "alice", "wrong")
        if status != 200 or 'id="kc-form-login"' not in body:
            raise RuntimeError("HTTP %d: %s" % (status, snippet(body)))
        if "expired" in body.lower():
            raise RuntimeError("page expired")
        if "Invalid username or password" not in body:
            raise RuntimeError("no error message: %s" % snippet(body))
        return "form again with 'Invalid username or password'"
    check("A4 a wrong password re-renders the form with an error", wrong_password)

    def right_password():
        b = Browser(prefix="pwf-")
        status, headers, body = login(b, "alice", "alicepw")
        loc = headers.get("location", "")
        if status != 302 or not loc.startswith(REDIRECT_URI) or "code=" not in loc:
            raise RuntimeError("HTTP %d %s: %s" % (status, loc, snippet(body)))
        user = token_user(loc)
        if user != "alice":
            raise RuntimeError("token for %r" % user)
        return "302 with code, token for alice"
    check("A5 the right password logs alice in", right_password)

    def step_up():
        b = Browser(prefix="pwf-")
        status, headers, body = login(b, "bob", "bobpw")
        loc = headers.get("location", "")
        if status == 302 and loc.startswith(REDIRECT_URI):
            raise RuntimeError("logged in without the OTP step")
        # bob has no OTP credential: the OTP form sends him to OTP enrolment
        if status != 302 or "/login-actions/required-action" not in loc or "CONFIGURE_TOTP" not in loc:
            raise RuntimeError("redirect to CONFIGURE_TOTP expected, got HTTP %d %s: %s" % (status, loc, snippet(body)))
        return "302 to CONFIGURE_TOTP: conditional OTP sub-flow entered after the form"
    check("A6 bob continues into the conditional OTP sub-flow", step_up)


def scenario_required():
    def required_login():
        b = Browser(prefix="pwf-")
        status, headers, body = login(b, "alice", "alicepw")
        loc = headers.get("location", "")
        if status != 302 or not loc.startswith(REDIRECT_URI):
            raise RuntimeError("HTTP %d %s: %s" % (status, loc, snippet(body)))
        if token_user(loc) != "alice":
            raise RuntimeError("wrong user in token")
        return "302 with code, token for alice"
    check("B1 as REQUIRED the form logs alice in", required_login)


def main():
    t = ADMIN  # api() fetches and renews the admin token itself
    ids = setup(t)
    print("realm %s configured: %s" % (REALM, ids))

    bind(t, FLOW_ALT)
    scenario_alternative(ids)

    bind(t, FLOW_REQ)
    scenario_required()

    print()
    print("%d check(s) failed" % len(failures) if failures else "all checks passed")
    return 1 if failures else 0


if __name__ == "__main__":
    sys.exit(main())
