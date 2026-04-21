"""
core/injector.py

position(query / body / cookie / header / path / form_field) 에 따라
페이로드를 HTTP 요청에 삽입하고 requests.PreparedRequest 를 반환한다.

[통합 이력]
  - form_field position 추가 : analyzer.py 의 build_targets() 가 생성하는
    ScanTarget(position="form_field") 을 엔진에서 그대로 처리할 수 있도록 지원.
    form_field 는 body 주입과 동일하게 동작하되 method 는 ScanTarget.method 를 따름.

새로운 position 추가 시 : _INJECTORS 딕셔너리에 함수 하나만 등록하면 됨.
"""

from __future__ import annotations

from typing import Callable, Any
from urllib.parse import urlencode, quote
import requests

from core.models import ScanTarget, Position


# ──────────────────────────────────────────────
# 내부 주입 함수 시그니처
# fn(url, param, payload, extra, headers) -> PreparedRequest
# ──────────────────────────────────────────────

_InjectorFn = Callable[
    [str, str, str, dict[str, Any], dict[str, str]],
    requests.PreparedRequest,
]


def _inject_body(url, param, payload, extra, headers):
    data = extra.copy()
    data[param] = payload

    headers = headers.copy()
    headers.setdefault("Content-Type", "application/x-www-form-urlencoded")

    req = requests.Request(method="POST", url=url, data=data, headers=headers)
    return req.prepare()


def _inject_query(url, param, payload, extra, headers):
    params = extra.copy()
    params[param] = payload

    base_url = url.split("?")[0]
    full_url = f"{base_url}?{urlencode(params)}"

    req = requests.Request(method="GET", url=full_url, headers=headers)
    return req.prepare()


# form_field: analyzer 의 build_targets() 가 생성하는 position.
# 동작은 body 와 동일하며 method 는 호출부(build_request)에서 덮어씀.
_inject_form_field = _inject_body


def _inject_cookie(url, param, payload, extra, headers) -> requests.PreparedRequest:
    cookies = {**extra, param: payload}
    req     = requests.Request(method="GET", url=url, cookies=cookies, headers=headers)
    return req.prepare()


def _inject_header(url, param, payload, extra, headers) -> requests.PreparedRequest:
    hdrs = {**headers, param: payload}
    req  = requests.Request(method="GET", url=url, headers=hdrs)
    return req.prepare()


def _inject_path(url, param, payload, extra, headers) -> requests.PreparedRequest:
    """
    URL 경로 내의 {param} 플레이스홀더를 페이로드로 치환.
    예: https://example.com/files/{filename}  →  /files/../../etc/passwd
    """
    injected_url = url.replace(f"{{{param}}}", quote(payload, safe=""))
    req = requests.Request(method="GET", url=injected_url, headers=headers)
    return req.prepare()


# ── 레지스트리 ─────────────────────────────────

_INJECTORS: dict[str, _InjectorFn] = {
    "query":      _inject_query,
    "body":       _inject_body,
    "form_field": _inject_form_field,   # analyzer.py 신규 position
    "cookie":     _inject_cookie,
    "header":     _inject_header,
    "path":       _inject_path,
}


# ──────────────────────────────────────────────
# 공개 API
# ──────────────────────────────────────────────

def build_request(
    target:          ScanTarget,
    payload:         str,
    method_override: str | None     = None,
    extra_headers:   dict[str, str] = {},
) -> requests.PreparedRequest:
    """
    ScanTarget + 페이로드 → PreparedRequest.

    method_override : 템플릿 definition 의 method 를 강제 적용할 때 사용.
    extra_headers   : 템플릿 level headers 를 추가 전달.
    """
    position = target.position
    fn = _INJECTORS.get(position)
    if fn is None:
        raise ValueError(
            f"Unsupported injection position: {position!r}. "
            f"Supported: {list(_INJECTORS)}"
        )

    prepared = fn(
        target.url,
        target.param,        # 구 analyzer: name → 현재: param
        payload,
        target.extra,        # 구 analyzer: base_data → 현재: extra
        extra_headers,
    )

    # method 덮어쓰기
    # form_field 는 ScanTarget.method(GET/POST) 를 그대로 따름
    method = (method_override or target.method).upper()
    prepared.method = method

    return prepared