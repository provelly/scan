"""
core/matcher.py

템플릿의 matchers[] 를 평가한다.
지원 타입 : word / time / status / regex / size
"""

from __future__ import annotations

import re
from typing import Callable

import requests

from core.models import MatcherResult
from core.template_loader import MatcherDef, ScanTemplate

_EvalFn = Callable[
    [MatcherDef, requests.Response | None, float],
    MatcherResult,
]


def _eval_word(defn: MatcherDef, resp: requests.Response | None, _elapsed: float) -> MatcherResult:
    if resp is None:
        return MatcherResult(hit=False, mtype="word", detail=[])

    body  = resp.text
    words = defn.data.get("words", [])

    if defn.condition == "and":
        found = [w for w in words if w in body]
        hit   = len(found) == len(words) and len(words) > 0
    else:
        found = [w for w in words if w in body]
        hit   = len(found) > 0

    if defn.negate:
        hit = not hit
    return MatcherResult(hit=hit, mtype="word", detail=found)


def _eval_time(defn: MatcherDef, _resp: requests.Response | None, elapsed: float) -> MatcherResult:
    delay = float(defn.data.get("delay", 5))
    hit   = elapsed >= delay
    if defn.negate:
        hit = not hit
    return MatcherResult(hit=hit, mtype="time", detail=[f"{elapsed:.2f}s >= {delay}s"])


def _eval_status(defn: MatcherDef, resp: requests.Response | None, _elapsed: float) -> MatcherResult:
    if resp is None:
        return MatcherResult(hit=False, mtype="status", detail=[])

    codes  = [int(c) for c in defn.data.get("status", [])]
    actual = resp.status_code

    if defn.condition == "and":
        hit = all(actual == c for c in codes) and len(codes) > 0
    else:
        hit = actual in codes

    if defn.negate:
        hit = not hit
    return MatcherResult(hit=hit, mtype="status", detail=[str(actual)])


def _eval_regex(defn: MatcherDef, resp: requests.Response | None, _elapsed: float) -> MatcherResult:
    if resp is None:
        return MatcherResult(hit=False, mtype="regex", detail=[])

    body     = resp.text
    patterns = defn.data.get("regex", [])
    matched  = []
    
    # 정규식 문법 오류 방어
    for p in patterns:
        try:
            if re.search(p, body):
                matched.append(p)
        except re.error as e:
            print(f"[WARN] Invalid regex pattern {p!r}: {e}")
            continue

    if defn.condition == "and":
        hit = len(matched) == len(patterns) and len(patterns) > 0
    else:
        hit = len(matched) > 0

    if defn.negate:
        hit = not hit
    return MatcherResult(hit=hit, mtype="regex", detail=matched)


def _eval_size(defn: MatcherDef, resp: requests.Response | None, _elapsed: float) -> MatcherResult:
    if resp is None:
        return MatcherResult(hit=False, mtype="size", detail=[])

    body_len = len(resp.content)
    sizes    = [int(s) for s in defn.data.get("size", [])]

    if defn.condition == "and":
        hit = all(body_len == s for s in sizes) and len(sizes) > 0
    else:
        hit = body_len in sizes

    if defn.negate:
        hit = not hit
    return MatcherResult(hit=hit, mtype="size", detail=[str(body_len)])


_EVALUATORS: dict[str, _EvalFn] = {
    "word":   _eval_word,
    "time":   _eval_time,
    "status": _eval_status,
    "regex":  _eval_regex,
    "size":   _eval_size,
}


def evaluate_matchers(
    template: ScanTemplate,
    response: requests.Response | None,
    elapsed:  float,
) -> tuple[bool, list[MatcherResult]]:
    results: list[MatcherResult] = []

    for defn in template.matchers:
        fn = _EVALUATORS.get(defn.type)
        if fn is None:
            print(f"[WARN] Unknown matcher type: {defn.type!r} — skipped")
            continue
        results.append(fn(defn, response, elapsed))

    if not results:
        return False, []

    if template.matchers_condition == "and":
        overall = all(r.hit for r in results)
    else:
        overall = any(r.hit for r in results)

    return overall, results