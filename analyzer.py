"""
analyzer.py — 주입 지점 분석기
"""
from __future__ import annotations

import json
import logging
import urllib.parse as urlparse
from http.cookies import SimpleCookie

from core.models import CrawledPage, ScanTarget

logger = logging.getLogger("Analyzer")

# 'select' 타입 추가
_INJECTABLE_TYPES = {
    "text", "password", "email", "search", "url",
    "number", "tel", "hidden", "textarea", "select",
}

class Analyzer:
    def parse_request(self, crawl_data: dict) -> list[ScanTarget]:
        targets: list[ScanTarget] = []

        url      = crawl_data.get("url", "")
        method   = crawl_data.get("method", "GET").upper()
        headers  = crawl_data.get("headers", {})
        raw_body = crawl_data.get("body", "")

        parsed_url = urlparse.urlparse(url)
        base_url   = url.split("?")[0]
        all_query  = {k: v[0] for k, v in urlparse.parse_qs(parsed_url.query).items()}

        for name in all_query:
            targets.append(ScanTarget(
                position = "query",
                url      = base_url,
                method   = method,
                param    = name,
                extra    = dict(all_query),
                found_on = url,
            ))

        if method in ("POST", "PUT", "PATCH"):
            body_dict = self._parse_body(raw_body, headers, url)
            for name in body_dict:
                targets.append(ScanTarget(
                    position = "body",
                    url      = url,
                    method   = method,
                    param    = name,
                    extra    = dict(body_dict),
                    found_on = url,
                ))

        # 쿠키 문자열 분리 및 헤더 처리 수정
        for h_name, h_val in headers.items():
            if h_name.lower() == "cookie":
                cookie = SimpleCookie()
                cookie.load(h_val)
                cookie_dict = {k: v.value for k, v in cookie.items()}
                for c_name in cookie_dict:
                    targets.append(ScanTarget(
                        position = "cookie",
                        url      = base_url,
                        method   = method,
                        param    = c_name,
                        extra    = cookie_dict,
                        found_on = url,
                    ))
            else:
                targets.append(ScanTarget(
                    position = "header",
                    url      = base_url,
                    method   = method,
                    param    = h_name,
                    extra    = {},
                    found_on = url,
                ))

        logger.debug("parse_request → ScanTarget %d개 (%s)", len(targets), url)
        return targets

    @staticmethod
    def _parse_body(raw_body, headers: dict, url: str) -> dict:
        if isinstance(raw_body, dict):
            return raw_body

        if not isinstance(raw_body, str) or not raw_body:
            return {}

        content_type = next(
            (v.lower() for k, v in headers.items() if k.lower() == "content-type"),
            "",
        )

        if "application/json" in content_type:
            try:
                parsed = json.loads(raw_body)
                return parsed if isinstance(parsed, dict) else {}
            except json.JSONDecodeError:
                logger.warning("[!] JSON 파싱 에러: %s", url)
                return {}

        if "application/x-www-form-urlencoded" in content_type:
            return {k: v[0] for k, v in urlparse.parse_qs(raw_body).items()}

        return {}

    def build_targets(self, pages: list[CrawledPage]) -> list[ScanTarget]:
        targets: list[ScanTarget] = []
        seen:    set[str]         = set()

        for page in pages:
            if page.query_params:
                base_url = page.url.split("?")[0]
                all_qp   = dict(page.query_params)
                for param_name in page.query_params:
                    key = f"query|GET|{base_url}|{param_name}"
                    if key in seen:
                        continue
                    seen.add(key)
                    targets.append(ScanTarget(
                        position = "query",
                        url      = base_url,
                        method   = "GET",
                        param    = param_name,
                        extra    = dict(all_qp),
                        found_on = page.url,
                    ))

            for form in page.forms:
                base_data = {
                    f.name: (f.options[0] if f.options else f.value)
                    for f in form.fields
                }
                for fld in form.fields:
                    if fld.field_type not in _INJECTABLE_TYPES:
                        continue
                    key = f"form_field|{form.method}|{form.action}|{fld.name}"
                    if key in seen:
                        continue
                    seen.add(key)
                    targets.append(ScanTarget(
                        position = "form_field",
                        url      = form.action,
                        method   = form.method,
                        param    = fld.name,
                        extra    = dict(base_data),
                        found_on = form.found_on,
                    ))

        logger.info(
            "build_targets → ScanTarget %d개 (query: %d, form_field: %d)",
            len(targets), 
            sum(1 for t in targets if t.position == "query"), 
            sum(1 for t in targets if t.position == "form_field")
        )
        return targets