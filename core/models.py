"""
core/models.py
파이프라인 전체에서 공유하는 데이터 모델 정의

[통합 이력]
  - ScanTarget (analyzer.py)  + TargetParam (engine) → ScanTarget 으로 일원화
    · name      → param  (엔진 내부 필드명 통일)
    · base_data → extra  (요청 재현에 필요한 나머지 파라미터 dict)
    · found_on  유지      (리포트용 출처 URL)
  - CrawledPage / FormDef / FieldDef : analyzer.py 가 사용하는 크롤 결과 모델 포함
"""

from __future__ import annotations
from dataclasses import dataclass, field
from typing import Literal, Any

Method   = Literal["GET", "POST", "PUT", "PATCH", "DELETE"]
Position = Literal["query", "body", "cookie", "header", "path", "form_field"]


# ══════════════════════════════════════════════
# 크롤러 → 분석기 구간 모델  (analyzer.py 가 소비)
# ══════════════════════════════════════════════

@dataclass
class FieldDef:
    """HTML <input> / <textarea> 한 개."""
    name:       str
    field_type: str            # text / password / hidden / textarea …
    value:      str = ""
    options:    list[str] = field(default_factory=list)   # <select> 옵션


@dataclass
class FormDef:
    """HTML <form> 한 개."""
    action:   str
    method:   Method
    fields:   list[FieldDef]
    found_on: str = ""         # 폼이 발견된 원본 페이지 URL


@dataclass
class CrawledPage:
    """WebCrawler 가 반환하는 페이지 단위."""
    url:          str
    query_params: dict[str, str]        = field(default_factory=dict)
    forms:        list[FormDef]         = field(default_factory=list)
    headers:      dict[str, str]        = field(default_factory=dict)
    cookies:      dict[str, str]        = field(default_factory=dict)


# ══════════════════════════════════════════════
# 분석기 → 엔진 구간 모델  (engine.py 가 소비)
# ══════════════════════════════════════════════

@dataclass
class ScanTarget:
    """
    Analyzer 가 엔진으로 넘기는 주입 단위.

    필드 대응 (구 이름 → 현재):
      ScanTarget.name      → param    (주입 대상 파라미터 이름)
      ScanTarget.base_data → extra    (요청 재현용 나머지 파라미터 전체 dict)
      TargetParam.original → extra[param] 으로 접근 가능 (별도 필드 불필요)
    """
    url:      str
    method:   Method
    position: Position
    param:    str                                          # 주입 대상 파라미터 이름
    extra:    dict[str, Any] = field(default_factory=dict) # 나머지 파라미터 원본값 포함
    found_on: str            = ""                          # 리포트용 출처 URL

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