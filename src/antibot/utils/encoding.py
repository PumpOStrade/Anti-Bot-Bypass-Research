"""Encoding and obfuscation helpers."""

import base64
import json
import urllib.parse


def b64_encode(data: str | bytes) -> str:
    if isinstance(data, str):
        data = data.encode()
    return base64.b64encode(data).decode()


def b64_decode(data: str) -> bytes:
    return base64.b64decode(data)


def url_encode(data: str) -> str:
    return urllib.parse.quote(data, safe="")


def url_decode(data: str) -> str:
    return urllib.parse.unquote(data)


def json_dumps(obj: object) -> str:
    return json.dumps(obj, separators=(",", ":"))


def json_loads(data: str) -> object:
    return json.loads(data)


def pipe_join(values: list[str]) -> str:
    """Join values with pipe delimiter (sensor_data format)."""
    return "|".join(str(v) for v in values)


def pipe_split(data: str) -> list[str]:
    return data.split("|")


def semicolon_join(values: list[str]) -> str:
    """Join values with semicolon delimiter (alternate sensor_data format)."""
    return ";".join(str(v) for v in values)
