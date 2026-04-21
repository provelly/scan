"""
core/models.py
파이프라인 전체에서 공유하는 데이터 모델 정의

[통합 이력]
  - ScanTarget (analyzer.py) + TargetParam (engine) → ScanTarget 으로 일원화
      · name      → param
      · base_data → extra
  - CrawledPage / FormDef / FieldDef : analyzer.py + crawler.py 통합
  - crawler.py 의 FormField → FieldDef 로 통일
  - crawler.py 의 CrawledForm → FormDef 로 통일
  - CrawledPage 에 crawler.py 가 사용하는 확장 필드 추가
      (status_code / content_type / links / response_headers / depth)
"""

from __future__ import annotations
from dataclasses import dataclass, field
from typing import Literal, Any

Method   = Literal["GET", "POST", "PUT", "PATCH", "DELETE"]
Position = Literal["query", "body", "cookie", "header", "path", "form_field"]


# ══════════════════════════════════════════════
# 크롤러 → 분석기 구간 모델  (crawler.py / analyzer.py 가 소비)
# ══════════════════════════════════════════════

@dataclass
class FieldDef:
    """
    HTML <input> / <textarea> / <select> 한 개.
    (구 crawler.py 의 FormField 와 통합)
    """
    name:       str
    field_type: str                                        # text / password / hidden / textarea / select …
    value:      str       = ""
    options:    list[str] = field(default_factory=list)    # <select> 옵션값 목록

# 하위 호환 별칭 — 기존 코드가 FormField 를 참조할 경우를 대비
FormField = FieldDef


@dataclass
class FormDef:
    """
    HTML <form> 한 개.
    (구 crawler.py 의 CrawledForm 과 통합)
    """
    action:   str
    method:   Method
    fields:   list[FieldDef]
    found_on: str = ""    # 폼이 발견된 원본 페이지 URL

# 하위 호환 별칭
CrawledForm = FormDef


@dataclass
class CrawledPage:
    """
    WebCrawler 가 반환하는 페이지 단위.

    Analyzer 가 필요로 하는 핵심 필드:
      url / query_params / forms / headers / cookies

    Crawler 가 추가로 기록하는 메타 필드 (선택, 기본값 있음):
      status_code / content_type / links / response_headers / depth
    """
    # ── Analyzer 핵심 필드 ──────────────────────────
    url:          str
    query_params: dict[str, str]  = field(default_factory=dict)
    forms:        list[FormDef]   = field(default_factory=list)
    headers:      dict[str, str]  = field(default_factory=dict)   # 요청 헤더
    cookies:      dict[str, str]  = field(default_factory=dict)

    # ── Crawler 확장 메타 필드 ───────────────────────
    status_code:      int              = 0
    content_type:     str              = ""
    links:            list[str]        = field(default_factory=list)
    response_headers: dict[str, str]   = field(default_factory=dict)
    depth:            int              = 0


# ══════════════════════════════════════════════
# 분석기 → 엔진 구간 모델  (engine.py 가 소비)
# ══════════════════════════════════════════════

@dataclass
class ScanTarget:
    """
    Analyzer 가 엔진으로 넘기는 주입 단위.

    필드 대응 (구 이름 → 현재):
      ScanTarget.name      → param
      ScanTarget.base_data → extra
    """
    url:      str
    method:   Method
    position: Position
    param:    str                                           # 주입 대상 파라미터 이름
    extra:    dict[str, Any] = field(default_factory=dict)  # 나머지 파라미터 원본값 포함
    found_on: str            = ""                           # 리포트용 출처 URL

    @property
    def original(self) -> str:
        """주입 대상 파라미터의 원본값 (extra 에서 조회, 없으면 빈 문자열)."""
        return str(self.extra.get(self.param, ""))


# ══════════════════════════════════════════════
# 엔진 → 시각화 구간 모델
# ══════════════════════════════════════════════

@dataclass
class MatcherResult:
    hit:    bool
    mtype:  str         # word / time / status / regex / size
    detail: list[str]   # 매칭된 단어, 상태코드 등


@dataclass
class ScanResult:
    """다음 단계(시각화·리포트)로 전달되는 결과 단위."""
    target:        ScanTarget
    template_id:   str
    template_name: str
    severity:      str
    payload:       str
    matched:       bool
    match_results: list[MatcherResult] = field(default_factory=list)
    elapsed:       float               = 0.0
    status_code:   int                 = 0
    response_body: str                 = ""
    error:         str                 = ""
