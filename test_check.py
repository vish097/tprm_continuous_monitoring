"""Tests for the SSO by default evaluation logic."""
import importlib.util
import os

HERE = os.path.dirname(os.path.abspath(__file__))


def load_check():
    spec = importlib.util.spec_from_file_location(
        "sso_check", os.path.join(HERE, "check.py")
    )
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


check = load_check()
evaluate = check.evaluate
SSO_MODES = check.SSO_MODES


def test_saml_app_produces_no_findings():
    apps = [{"id": "1", "label": "crm", "signOnMode": "SAML_2_0"}]
    assert evaluate(apps) == []


def test_oidc_app_produces_no_findings():
    apps = [{"id": "2", "label": "code", "signOnMode": "OPENID_CONNECT"}]
    assert evaluate(apps) == []


def test_swa_app_produces_high_finding():
    apps = [{"id": "3", "label": "legacy-vpn", "signOnMode": "SWA"}]
    findings = evaluate(apps)
    assert len(findings) == 1
    assert findings[0]["severity"] == "high"
    assert "legacy-vpn" in findings[0]["resource"]
    assert "SWA" in findings[0]["finding"]


def test_bookmark_app_produces_high_finding():
    apps = [{"id": "4", "label": "old-wiki", "signOnMode": "BOOKMARK"}]
    findings = evaluate(apps)
    assert len(findings) == 1
    assert findings[0]["control"] == "sso_by_default"


def test_missing_sign_on_mode_produces_finding():
    apps = [{"id": "5", "label": "mystery"}]
    findings = evaluate(apps)
    assert len(findings) == 1
    assert findings[0]["sign_on_mode"] == "UNKNOWN"


def test_mixed_apps_flag_only_violations():
    apps = [
        {"id": "1", "label": "ok-app", "signOnMode": "SAML_2_0"},
        {"id": "2", "label": "bad-app", "signOnMode": "SWA"},
    ]
    findings = evaluate(apps)
    assert len(findings) == 1
    assert "bad-app" in findings[0]["resource"]


def test_all_accepted_modes_are_sso():
    assert SSO_MODES == {"SAML_2_0", "OPENID_CONNECT", "WS_FEDERATION"}
