"""JSON Schema for declarative contract files (format version 1)."""

from __future__ import annotations

from typing import Any

_FIELD: dict[str, Any] = {
    "oneOf": [
        {"type": "string"},
        {
            "type": "object",
            "additionalProperties": False,
            "required": ["from"],
            "properties": {
                "from": {"type": "string"},
                "max_chars": {"type": "integer", "minimum": 1},
                "max_items": {"type": "integer", "minimum": 1},
                "transform": {"type": "string"},
                "default": {},
                "shape": {"$ref": "#/$defs/shape"},
            },
        },
    ]
}

CONTRACT_SCHEMA: dict[str, Any] = {
    "$schema": "https://json-schema.org/draft/2020-12/schema",
    "title": "Toolbound contract file",
    "type": "object",
    "additionalProperties": False,
    "required": ["version", "service", "operations"],
    "properties": {
        "version": {"const": 1},
        "status": {"enum": ["active", "draft"]},
        "service": {
            "type": "object",
            "additionalProperties": False,
            "required": ["name", "base_url"],
            "properties": {
                "name": {"type": "string"},
                "base_url": {"type": "string"},
                "auth": {
                    "type": "object",
                    "additionalProperties": False,
                    "required": ["type"],
                    "properties": {
                        "type": {"enum": ["none", "bearer", "api_key", "basic"]},
                        "credential": {"type": "string"},
                        "header": {"type": "string"},
                        "query": {"type": "string"},
                    },
                },
                "headers": {"type": "object", "additionalProperties": {"type": "string"}},
                "network": {
                    "type": "object",
                    "additionalProperties": False,
                    "properties": {
                        "allow_hosts": {"type": "array", "items": {"type": "string"}},
                        "allow_ports": {"type": "array", "items": {"type": "integer"}},
                        "allow_http": {"type": "boolean"},
                        "allow_networks": {"type": "array", "items": {"type": "string"}},
                        "follow_redirects": {"type": "boolean"},
                        "max_redirects": {"type": "integer", "minimum": 0},
                    },
                },
                "limits": {
                    "type": "object",
                    "additionalProperties": False,
                    "properties": {
                        "timeout": {"type": "number", "exclusiveMinimum": 0},
                        "connect_timeout": {"type": "number", "exclusiveMinimum": 0},
                        "max_request_bytes": {"type": "integer", "minimum": 1},
                        "max_response_bytes": {"type": "integer", "minimum": 1},
                        "max_concurrency": {"type": "integer", "minimum": 1},
                    },
                },
                "retry": {
                    "type": "object",
                    "additionalProperties": False,
                    "properties": {
                        "max_attempts": {"type": "integer", "minimum": 1},
                        "backoff_base": {"type": "number", "minimum": 0},
                        "backoff_max": {"type": "number", "minimum": 0},
                        "retry_statuses": {"type": "array", "items": {"type": "integer"}},
                        "max_retry_after": {"type": "number", "minimum": 0},
                    },
                },
            },
        },
        "operations": {"type": "array", "minItems": 1, "items": {"$ref": "#/$defs/operation"}},
    },
    "$defs": {
        "shape": {"type": "object", "additionalProperties": _FIELD},
        "operation": {
            "type": "object",
            "additionalProperties": False,
            "required": ["name", "description", "path"],
            "properties": {
                "name": {"type": "string"},
                "description": {"type": "string"},
                "method": {"type": "string"},
                "path": {"type": "string"},
                "effect": {"enum": ["read", "write", "destructive"]},
                "input": {"type": "object"},
                "bind": {"type": "object"},
                "required_scopes": {"type": "array", "items": {"type": "string"}},
                "tags": {"type": "array", "items": {"type": "string"}},
                "group": {"type": "string"},
                "requires_approval": {"type": "boolean"},
                "rate_limit": {
                    "type": "object",
                    "additionalProperties": False,
                    "required": ["calls", "per_seconds"],
                    "properties": {
                        "calls": {"type": "integer", "minimum": 1},
                        "per_seconds": {"type": "number", "exclusiveMinimum": 0},
                        "scope": {"enum": ["actor", "tenant", "global"]},
                    },
                },
                "query": {"type": "array", "items": {"type": "string"}},
                "body": {"type": "array", "items": {"type": "string"}},
                "body_format": {"enum": ["json", "form"]},
                "headers": {"type": "object", "additionalProperties": {"type": "string"}},
                "idempotency_header": {"type": "string"},
                "pagination": {
                    "type": "object",
                    "additionalProperties": False,
                    "required": ["type"],
                    "properties": {
                        "type": {"enum": ["cursor", "link", "page"]},
                        "param": {"type": "string"},
                        "next_path": {"type": "string"},
                        "start": {"type": "integer"},
                        "page_size": {"type": "integer", "minimum": 1},
                    },
                },
                "output": {
                    "type": "object",
                    "additionalProperties": False,
                    "properties": {
                        "root": {"type": "string"},
                        "shape": {"$ref": "#/$defs/shape"},
                        "required": {"type": "array", "items": {"type": "string"}},
                        "max_items": {"type": "integer", "minimum": 1},
                        "max_chars": {"type": "integer", "minimum": 1},
                        "max_tokens": {"type": ["integer", "null"], "minimum": 16},
                        "overflow": {"enum": ["truncate", "reject"]},
                        "selectable": {"type": "boolean"},
                        "redact_keys": {"type": "array", "items": {"type": "string"}},
                        "redact_secrets": {"type": "boolean"},
                        "schema": {"type": "object"},
                        "schema_mode": {"enum": ["strict", "warn"]},
                        "error_shape": {"$ref": "#/$defs/shape"},
                        "accept_text": {"type": "boolean"},
                        "continuation": {"type": "boolean"},
                    },
                },
            },
        },
    },
}
