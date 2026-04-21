"""
engine.py  ─  통합 페이로드 삽입 엔진 (공개 진입점)

파이프라인 위치:
  크롤링 → 파라미터 탐색·분류(Analyzer) → [ScanEngine.run()] → 결과 출력·시각화

Analyzer 와의 연결:
  # 방식 1: raw dict
  analyzer = Analyzer()
  targets  = analyzer.parse_request(crawl_data)
  results  = engine.run(targets)

  # 방식 2: CrawledPage 목록
  targets  = analyzer.build_targets(pages)
  results  = engine.run(targets)

  두 방식 모두 동일한 List[ScanTarget] 을 반환하므로 engine.run() 호출이 동일함.
"""

from __future__ import annotations

import time
import requests
from pathlib import Path

from core.models          import ScanTarget, ScanResult
from core.template_loader import ScanTemplate, load_templates
from core.injector        import build_request
from core.matcher         import evaluate_matchers


# ──────────────────────────────────────────────
# HTTP 요청 실행
# ──────────────────────────────────────────────

def _execute(
    prepared: requests.PreparedRequest,
    session:  requests.Session,
    timeout:  float,
) -> tuple[requests.Response | None, float, str]:
    """PreparedRequest 를 실행하고 (response, elapsed, error) 반환."""
    try:
        t0   = time.perf_counter()
        resp = session.send(prepared, timeout=timeout, allow_redirects=True)
        return resp, time.perf_counter() - t0, ""
    except requests.exceptions.Timeout:
        return None, timeout, "Timeout"
    except Exception as exc:
        return None, 0.0, str(exc)


# ──────────────────────────────────────────────
# 단일 (target × template × payload) 실행
# ──────────────────────────────────────────────

def _scan_one(
    target:   ScanTarget,
    template: ScanTemplate,
    payload:  str,
    session:  requests.Session,
    timeout:  float,
) -> ScanResult:

    # ── definition 필터 ──────────────────────────
    if target.method.upper() not in template.allowed_methods:
        return ScanResult(
            target=target, template_id=template.id,
            template_name=template.name, severity=template.severity,
            payload=payload, matched=False,
            error=f"Skipped: method {target.method!r} not in {template.allowed_methods}",
        )
    if target.position not in template.allowed_positions:
        return ScanResult(
            target=target, template_id=template.id,
            template_name=template.name, severity=template.severity,
            payload=payload, matched=False,
            error=f"Skipped: position {target.position!r} not in {template.allowed_positions}",
        )

    # ── 페이로드 삽입 → PreparedRequest ──────────
    try:
        prepared = build_request(
            target          = target,
            payload         = payload,
            method_override = target.method,
            extra_headers   = template.headers,
        )
    except Exception as exc:
        return ScanResult(
            target=target, template_id=template.id,
            template_name=template.name, severity=template.severity,
            payload=payload, matched=False, error=str(exc),
        )

    # ── HTTP 요청 실행 ────────────────────────────
    resp, elapsed, error = _execute(prepared, session, timeout)

    # ── 매처 평가 ────────────────────────────────
    matched, match_results = evaluate_matchers(template, resp, elapsed)

    return ScanResult(
        target        = target,
        template_id   = template.id,
        template_name = template.name,
        severity      = template.severity,
        payload       = payload,
        matched       = matched,
        match_results = match_results,
        elapsed       = round(elapsed, 3),
        status_code   = resp.status_code if resp else 0,
        response_body = resp.text[:2000] if resp else "",
        error         = error,
    )


# ──────────────────────────────────────────────
# 공개 엔진 클래스
# ──────────────────────────────────────────────

class ScanEngine:
    """
    통합 페이로드 삽입 엔진.

    Parameters
    ----------
    templates_root  : 템플릿 루트 경로 (기본 "templates/")
    categories      : 로드할 대분류 폴더명 리스트. None 이면 전체.
    template_ids    : 특정 템플릿 ID만 로드. None 이면 전체.
    request_timeout : 기본 타임아웃(초). time matcher 가 있으면 자동 연장.
    session         : 외부에서 주입하는 requests.Session (쿠키·인증 유지 용).
    """

    def __init__(
        self,
        templates_root:  str | Path = "templates",
        categories:      list[str]  | None = None,
        template_ids:    list[str]  | None = None,
        request_timeout: float = 10.0,
        session:         requests.Session | None = None,
    ) -> None:
        self.templates = load_templates(templates_root, categories, template_ids)
        self.base_timeout = request_timeout
        self.session = session or requests.Session()

    # ── 타임아웃 계산 ─────────────────────────────

    def _timeout_for(self, template: ScanTemplate) -> float:
        """time matcher 가 있으면 그 delay + 3초를 타임아웃으로 사용."""
        for m in template.matchers:
            if m.type == "time":
                delay = float(m.data.get("delay", 5))
                return max(self.base_timeout, delay + 3)
        return self.base_timeout

    # ── 공개 실행 메서드 ──────────────────────────

    def run(
        self,
        targets:           list[ScanTarget],
        stop_on_first_hit: bool = False,
    ) -> list[ScanResult]:
        """
        Analyzer 가 반환한 List[ScanTarget] 을 받아
        모든 (target × template × payload) 조합을 실행.

        stop_on_first_hit : True 이면 타겟+템플릿 쌍에서 첫 양성 후
                            나머지 페이로드를 건너뜀.
        반환값 : List[ScanResult]  → 다음 단계(시각화·리포트)로 전달
        """
        all_results: list[ScanResult] = []

        for target in targets:
            for template in self.templates:
                timeout  = self._timeout_for(template)
                hit_found = False

                for payload in template.payloads:
                    if stop_on_first_hit and hit_found:
                        break

                    result = _scan_one(target, template, payload, self.session, timeout)
                    all_results.append(result)

                    self._log(result)
                    if result.matched:
                        hit_found = True

        return all_results

    # ── 로그 출력 ─────────────────────────────────

    @staticmethod
    def _log(r: ScanResult) -> None:
        tag = "[VULN]" if r.matched else "[ ok ]"
        if r.error and not r.matched:
            tag = "[SKIP]"
        detail = (
            f"{tag} [{r.template_id}] {r.target.url} "
            f"| param={r.target.param} | payload={r.payload!r} "
            f"| elapsed={r.elapsed}s | status={r.status_code}"
        )
        if r.error:
            detail += f" | err={r.error}"
        if r.matched:
            hits = [f"{mr.mtype}:{mr.detail}" for mr in r.match_results if mr.hit]
            detail += f" | hits={hits}"
        print(detail)