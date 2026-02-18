from __future__ import annotations

import json
import sys

import httpx
import pytest
import inboxlayer_sdk.cli as cli

from inboxlayer_sdk.client import (
    _coerce_json_payload,
    _coerce_password_payload,
    _coerce_wrapper_payload,
    InboxLayerClient,
)
from inboxlayer_sdk.exceptions import InboxLayerValidationError


def test_diff_contracts_handles_missing_and_extra() -> None:
    discovered = {"GET /api/v1/auth"}
    contract = {
        "GET /api/v1/auth": "get_me",
        "POST /api/v1/auth": "authenticate",
    }
    missing, extra = cli._diff_contracts(discovered, contract)
    assert missing == ["POST /api/v1/auth"]
    assert extra == []


def test_cli_main_passes_with_matching_contract(monkeypatch, tmp_path) -> None:
    monkeypatch.setattr(
        sys,
        "argv",
        ["inboxlayer-check-contract", "--openapi", str(tmp_path / "openapi.json")],
    )
    monkeypatch.setattr(
        cli,
        "SDK_ENDPOINT_COVERAGE",
        {"GET /api/v1/auth": "get_me"},
    )
    (tmp_path / "openapi.json").write_text(json.dumps({"paths": {"/api/v1/auth": {"get": {}}}}))

    assert cli._main() == 0


def test_cli_main_fails_on_mismatch(monkeypatch, tmp_path, capsys) -> None:
    monkeypatch.setattr(
        sys,
        "argv",
        ["inboxlayer-check-contract", "--openapi", str(tmp_path / "openapi.json")],
    )
    monkeypatch.setattr(
        cli,
        "SDK_ENDPOINT_COVERAGE",
        {"GET /api/v1/auth": "get_me"},
    )
    (tmp_path / "openapi.json").write_text(json.dumps({"paths": {}}))

    assert cli._main() == 1
    output = capsys.readouterr().out
    assert "Contract coverage check failed" in output


def test_coerce_password_payload_from_mapping() -> None:
    payload = _coerce_password_payload(
        {
            "current_password": "old",
            "password": "new",
            "password_confirmation": "new",
        }
    )
    assert payload == {
        "user": {
            "current_password": "old",
            "password": "new",
            "password_confirmation": "new",
        }
    }


def test_coerce_password_payload_from_wrapped_dict() -> None:
    payload = _coerce_password_payload(
        {
            "user": {
                "current_password": "old",
                "password": "new",
                "password_confirmation": "new",
            }
        }
    )
    assert payload == {
        "user": {
            "current_password": "old",
            "password": "new",
            "password_confirmation": "new",
        }
    }


def test_coerce_password_payload_rejects_list() -> None:
    with pytest.raises(InboxLayerValidationError, match="must be a mapping"):
        _coerce_password_payload(["bad", "payload"])


def test_coerce_wrapper_payload_adds_resource_key() -> None:
    assert _coerce_wrapper_payload({"domain": "app.example.com"}, "custom_domain") == {
        "custom_domain": {"domain": "app.example.com"}
    }


def test_coerce_wrapper_payload_keeps_existing_resource_key() -> None:
    payload = {"custom_domain": {"domain": "app.example.com"}}
    assert _coerce_wrapper_payload(payload, "custom_domain") is payload


def test_coerce_json_payload_from_dict() -> None:
    payload = {
        "user": {
            "current_password": "old",
            "password": "new",
            "password_confirmation": "new",
        }
    }
    assert _coerce_json_payload(payload) == payload


def test_create_custom_domain_wrapps_flat_payload() -> None:
    captured: dict[str, object] = {}

    def send_request(request: httpx.Request) -> httpx.Response:
        captured["body"] = json.loads(request.content.decode())
        return httpx.Response(
            200,
            json={"id": "cd_1", "domain": "app.example.com"},
            request=request,
        )

    transport = httpx.MockTransport(send_request)
    with InboxLayerClient(
        base_url="https://api.example.com",
        api_token="test",
        httpx_client=httpx.Client(base_url="https://api.example.com", transport=transport),
    ) as client:
        response = client.create_custom_domain({"domain": "app.example.com"})

    assert response["id"] == "cd_1"
    assert captured["body"] == {"custom_domain": {"domain": "app.example.com"}}
