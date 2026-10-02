# SSO by default

## What it checks

Every application in the identity provider must authenticate through federated SSO (SAML 2.0, OpenID Connect, or WS-Federation). Apps using password-based sign-on modes such as SWA, browser plugin, or bookmarks bypass central authentication policy, MFA enforcement, and deprovisioning, so each one is a high severity finding.

## How it works

1. `check.py` pages through the Okta Applications API (`/api/v1/apps`), following the `Link` header for pagination.
2. Each app whose `signOnMode` is not in the accepted SSO set becomes one high severity finding with the offending mode recorded.
3. Findings are written to `evidence/findings_sso.json` in the standard schema.

## Run it

```
python controls/sso_by_default/check.py --sample   # no tenant needed
python controls/sso_by_default/check.py            # live, needs env vars below
```

Live mode reads credentials from the environment, never hardcoded:

1. `OKTA_DOMAIN` your Okta tenant domain, for example `dev-12345.okta.com`.
2. `OKTA_API_TOKEN` an API token with read access to applications. In CI, store it as a GitHub Actions secret. Without both variables the script runs the sample fixture instead, so scheduled runs stay green.

## Current state

Working. Sample mode demonstrates both sides of the control: Salesforce (SAML) and GitHub (OIDC) pass, the legacy VPN portal (SWA) and old wiki (bookmark) fail. Point it at the free Okta developer tenant from the SaaS config lab to evaluate real apps.

## Sample output

```json
[
  {
    "control": "sso_by_default",
    "severity": "high",
    "owner": "identity_engineering",
    "resource": "Legacy VPN Portal (0oa1sample0003)",
    "finding": "App uses sign-on mode SWA instead of federated SSO. Migrate to SAML 2.0 or OIDC.",
    "sign_on_mode": "SWA"
  }
]
```
