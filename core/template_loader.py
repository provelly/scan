"""
core/template_loader.py

/templates/<category>/<name>.yaml 구조를 재귀 탐색해
ScanTemplate 목록으로 파싱한다.

디렉터리 구조 예시:
  templates/
    sqli/
      error-based.yaml
      time-based.yaml
    xss/
      reflected.yaml
      stored.yaml
    traversal/
      unix.yaml
      windows.yaml
    ssrf/
      basic.yaml
"""

from __future__ import annotations

import re
import yaml
from dataclasses import dataclass, field
from pathlib import Path
from typing import Literal

from core.models import Method, Position


# ──────────────────────────────────────────────
# 템플릿 데이터 클래스
# ──────────────────────────────────────────────

@dataclass
class MatcherDef:
    """YAML matchers[] 항목 하나를 그대로 보관."""
    type:    str                          # word / time / status / regex / size
    data:    dict                         # type 에 따라 내용이 다름
    # 공통 옵션
    condition: Literal["or", "and"] = "or"   # 항목 내부 복수 값 처리
    negate:    bool                 = False


@dataclass
class ScanTemplate:
    id:                  str
    name:                str
    severity:            str
    description:         str
    category:            str                    # 디렉터리명 (sqli / xss / ...)
    source_path:         Path

    allowed_methods:     list[Method]
    allowed_positions:   list[Position]

    payloads:            list[str]
    matchers:            list[MatcherDef]
    matchers_condition:  Literal["or", "and"]   # 매처 간 조합 방식

    # 요청 커스터마이즈 (템플릿 선택 사항)
    headers:             dict[str, str]  = field(default_factory=dict)
    follow_redirects:    bool            = True
    max_redirects:       int             = 5


# ──────────────────────────────────────────────
# 파서
# ──────────────────────────────────────────────

def _parse_matcher(raw: dict) -> MatcherDef:
    return MatcherDef(
        type      = raw["type"],
        data      = {k: v for k, v in raw.items()
                    if k not in ("type", "condition", "negate")},
        condition = raw.get("condition", "or"),
        negate    = raw.get("negate", False),
    )


def _parse_template(path: Path, category: str) -> ScanTemplate:
    with open(path, encoding="utf-8") as f:
        raw = yaml.safe_load(f)

    info = raw.get("info", {})
    defn = raw.get("definition", {})

    return ScanTemplate(
        id                 = raw.get("id", path.stem),
        name               = info.get("name", path.stem),
        severity           = info.get("severity", "info"),
        description        = info.get("description", ""),
        category           = category,
        source_path        = path,

        allowed_methods    = [m.upper() for m in defn.get("method", ["GET", "POST"])],
        allowed_positions  = defn.get("position", ["query", "body"]),

        payloads           = raw.get("payloads", []),
        matchers           = [_parse_matcher(m) for m in raw.get("matchers", [])],
        matchers_condition = raw.get("matchers-condition", "or").lower(),

        headers            = raw.get("headers", {}),
        follow_redirects   = raw.get("follow-redirects", True),
        max_redirects      = raw.get("max-redirects", 5),
    )


# ──────────────────────────────────────────────
# 공개 API
# ──────────────────────────────────────────────

def load_templates(
    templates_root: str | Path = "templates",
    categories:     list[str] | None = None,   # None 이면 전체 로드
    template_ids:   list[str] | None = None,   # 특정 ID만 필터
) -> list[ScanTemplate]:
    """
    templates_root 하위를 재귀 탐색해 ScanTemplate 리스트 반환.

    Parameters
    ----------
    templates_root : 템플릿 루트 디렉터리 (기본값 "templates/")
    categories     : ['sqli', 'xss'] 처럼 대분류 지정. None 이면 전체.
    template_ids   : ['sqli-error-based'] 처럼 특정 템플릿 ID만 로드.
    """
    root     = Path(templates_root)
    result   : list[ScanTemplate] = []
    errors   : list[str]          = []

    if not root.exists():
        raise FileNotFoundError(f"Templates root not found: {root}")

    for category_dir in sorted(root.iterdir()):
        if not category_dir.is_dir():
            continue

        cat = category_dir.name
        if categories and cat not in categories:
            continue

        for yaml_file in sorted(category_dir.glob("**/*.yaml")):
            try:
                tmpl = _parse_template(yaml_file, cat)
                if template_ids and tmpl.id not in template_ids:
                    continue
                result.append(tmpl)
            except Exception as exc:
                errors.append(f"[WARN] Failed to load {yaml_file}: {exc}")

    for e in errors:
        print(e)

    print(f"[TemplateLoader] Loaded {len(result)} template(s) "
          f"from {root} "
          f"(categories={categories or 'all'}, ids={template_ids or 'all'})")
    return result