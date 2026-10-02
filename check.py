"""SSO by default: every application must authenticate through SSO.

Queries the Okta Applications API and flags any app whose sign-on mode
is not a federated SSO protocol (SAML 2.0, OpenID Connect, or
WS-Federation). Password-based modes such as SWA, browser plugin, and
bookmarks are findings: they bypass central authentication policy,
MFA enforcement, and deprovisioning.

Live mode reads OKTA_DOMAIN and OKTA_API_TOKEN from the environment.
Sample mode (default when no credentials are present, or with --sample)
evaluates a built-in fixture so the control runs end to end in CI and in
the lab without a tenant.

Findings are written to evidence/findings_sso.json in the standard
schema. The script always exits 0; findings are the signal, not the
exit code.
"""

import argparse
import json
import os
import sys
import urllib.request
import urllib.error

BASE_DIR = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
FINDINGS_PATH = os.path.join(BASE_DIR, "evidence", "findings_sso.json")

# Federated sign-on modes accepted by this control. Anything else means
# credentials are handled outside the IdP.
SSO_MODES = {"SAML_2_0", "OPENID_CONNECT", "WS_FEDERATION"}

# Sample fixture: four apps, two compliant and two violating, so a fresh
# clone demonstrates both sides of the control in CI.
SAMPLE_APPS = [
    {"id": "0oa1sample0001", "label": "Salesforce", "signOnMode": "SAML_2_0", "status": "ACTIVE"},
    {"id": "0oa1sample0002", "label": "GitHub", "signOnMode": "OPENID_CONNECT", "status": "ACTIVE"},
    {"id": "0oa1sample0003", "label": "Legacy VPN Portal", "signOnMode": "SWA", "status": "ACTIVE"},
    {"id": "0oa1sample0004", "label": "Old Wiki", "signOnMode": "BOOKMARK", "status": "ACTIVE"},
]


def evaluate(apps):
    """Return findings for apps that do not use federated SSO."""
    findings = []
    for app in apps:
        mode = (app.get("signOnMode") or "").upper()
        if mode in SSO_MODES:
            continue
        findings.append(
            {
                "control": "sso_by_default",
                "severity": "high",
                "owner": "identity_engineering",
                "resource": f"{app.get('label')} ({app.get('id')})",
                "finding": (
                    f"App uses sign-on mode {mode or 'UNKNOWN'} instead of "
                    "federated SSO. Migrate to SAML 2.0 or OIDC."
                ),
                "sign_on_mode": mode or "UNKNOWN",
            }
        )
    return findings


def fetch_okta_apps(domain, token):
    """Page through the Okta Applications API and return app dicts."""
    apps = []
    url = f"https://{domain}/api/v1/apps?limit=200"
    headers = {
        "Authorization": f"SSWS {token}",
        "Accept": "application/json",
        "Content-Type": "application/json",
    }
    while url:
        req = urllib.request.Request(url, headers=headers)
        try:
            with urllib.request.urlopen(req, timeout=30) as resp:
                page = json.loads(resp.read().decode("utf-8"))
                apps.extend(page)
                url = None
                # Follow Okta's Link header for the next page.
                link = resp.headers.get("Link", "")
                for part in link.split(","):
                    if 'rel="next"' in part:
                        url = part.split(";")[0].strip().strip("<>")
        except urllib.error.HTTPError as exc:
            print(f"Okta API error: HTTP {exc.code}", file=sys.stderr)
            sys.exit(2)
        except urllib.error.URLError as exc:
            print(f"Okta API network error: {exc.reason}", file=sys.stderr)
            sys.exit(2)
    return apps


def main():
    parser = argparse.ArgumentParser(description="SSO by default control")
    parser.add_argument("--sample", action="store_true", help="Force sample mode")
    args = parser.parse_args()

    domain = os.environ.get("OKTA_DOMAIN")
    token = os.environ.get("OKTA_API_TOKEN")

    if args.sample or not (domain and token):
        if not args.sample:
            print("No Okta credentials found; running in sample mode.")
        apps = SAMPLE_APPS
        source = "sample"
    else:
        apps = fetch_okta_apps(domain, token)
        source = f"okta:{domain}"

    findings = evaluate(apps)
    os.makedirs(os.path.dirname(FINDINGS_PATH), exist_ok=True)
    with open(FINDINGS_PATH, "w") as f:
        json.dump(findings, f, indent=2)

    compliant = len(apps) - len(findings)
    print(f"Source: {source}")
    print(f"Evaluated {len(apps)} apps: {compliant} on SSO, {len(findings)} findings.")
    print(f"Wrote {len(findings)} findings to {FINDINGS_PATH}")


if __name__ == "__main__":
    main()
