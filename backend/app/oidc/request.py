from __future__ import annotations

from collections import defaultdict
from functools import cached_property
from typing import Any
from urllib.parse import urlencode

from authlib.oauth2.rfc6749 import JsonPayload, JsonRequest, OAuth2Payload, OAuth2Request
from starlette.requests import Request

from app.sessions import request_is_https


class StarletteOAuth2Payload(OAuth2Payload):
    def __init__(self, data: dict[str, Any], datalist: dict[str, list[Any]]):
        self._data = data
        self._datalist = defaultdict(list, datalist)

    @property
    def data(self):
        return self._data

    @property
    def datalist(self) -> defaultdict[str, list]:
        return self._datalist


class StarletteOAuth2Request(OAuth2Request):
    def __init__(
        self,
        method: str,
        uri: str,
        headers: dict[str, str],
        args: dict[str, Any],
        form: dict[str, Any],
        args_list: dict[str, list[Any]] | None = None,
        form_list: dict[str, list[Any]] | None = None,
    ):
        super().__init__(method=method, uri=uri, headers=headers)
        merged = {**args, **form}
        merged_list: dict[str, list[Any]] = defaultdict(list)
        for source in (args_list or {k: [v] for k, v in args.items()}, form_list or {k: [v] for k, v in form.items()}):
            for key, values in source.items():
                merged_list[key].extend(values)
        self.payload = StarletteOAuth2Payload(merged, merged_list)
        self._args = args
        self._form = form

    @property
    def args(self):
        return self._args

    @property
    def form(self):
        return self._form


class StarletteJsonPayload(JsonPayload):
    def __init__(self, data: dict[str, Any] | None):
        self._data = data or {}

    @property
    def data(self):
        return self._data


class StarletteJsonRequest(JsonRequest):
    def __init__(self, method: str, uri: str, headers: dict[str, str], data: dict[str, Any] | None):
        super().__init__(method, uri, headers)
        self.payload = StarletteJsonPayload(data)


def _multi_dict(items) -> tuple[dict[str, Any], dict[str, list[Any]]]:
    data: dict[str, Any] = {}
    datalist: dict[str, list[Any]] = defaultdict(list)
    for key, value in items:
        datalist[key].append(value)
        data[key] = value
    return data, datalist


def public_uri(request: Request) -> str:
    """Request URL as the client sent it.

    uvicorn runs with --no-proxy-headers, so behind a TLS proxy ``request.url``
    is ``http://`` and Authlib rejects it as insecure transport. The scheme is
    upgraded only on X-Forwarded-Proto from a trusted proxy: a plain HTTP
    request straight to uvicorn must still be refused.
    """
    url = request.url
    if url.scheme == "http" and request_is_https(request):
        url = url.replace(scheme="https")
    return str(url)


async def build_oauth2_request(request: Request) -> StarletteOAuth2Request:
    args, args_list = _multi_dict(request.query_params.multi_items())
    form: dict[str, Any] = {}
    form_list: dict[str, list[Any]] = defaultdict(list)
    content_type = request.headers.get("content-type", "")
    if request.method in {"POST", "PUT", "PATCH"} and "application/x-www-form-urlencoded" in content_type:
        form_data = await request.form()
        form, form_list = _multi_dict(form_data.multi_items())
    return StarletteOAuth2Request(
        method=request.method,
        uri=public_uri(request),
        headers=dict(request.headers),
        args=args,
        form=form,
        args_list=args_list,
        form_list=form_list,
    )


async def build_json_request(request: Request) -> StarletteJsonRequest:
    try:
        data = await request.json()
    except Exception:
        data = {}
    return StarletteJsonRequest(
        method=request.method,
        uri=public_uri(request),
        headers=dict(request.headers),
        data=data if isinstance(data, dict) else {},
    )


def oauth2_request_from_params(params: dict[str, Any], base_uri: str) -> StarletteOAuth2Request:
    query = urlencode([(k, v) for k, v in params.items() if v is not None])
    uri = f"{base_uri}?{query}" if query else base_uri
    args = {k: v for k, v in params.items() if v is not None}
    args_list = {k: [v] for k, v in args.items()}
    return StarletteOAuth2Request(
        method="GET",
        uri=uri,
        headers={},
        args=args,
        form={},
        args_list=args_list,
        form_list={},
    )
