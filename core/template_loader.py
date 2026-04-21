"""
core/template_loader.py

/templates/<category>/<name>.yaml 구조를 재귀 탐색해
ScanTemplate 목록으로 파싱한다.
"""

from __future__ import annotations

import yaml
from dataclasses import dataclass, field
from pathlib import Path
from typing import Literal

from core.models import Method, Position


@dataclass
class MatcherDef:
    type:    str
    data:    dict
    condition: Literal["or", "and"] = "or"
    negate:    bool                 = False


@dataclass
class ScanTemplate:
    id:                  str
    name:                str
    severity:            str
    description:         str
    category:            str
    source_path:         Path

    allowed_methods:     list[Method]
    allowed_positions:   list[Position]

    payloads:            list[str]
    matchers:            list[MatcherDef]
    matchers_condition:  Literal["or", "and"]

    headers:             dict[str, str]  = field(default_factory=dict)
    follow_redirects:    bool            = True
    max_redirects:       int             = 5


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

        # 방어 코드 추가: 값이 None일 경우 빈 리스트로 초기화
        payloads           = raw.get("payloads") or [],
        matchers           = [_parse_matcher(m) for m in (raw.get("matchers") or [])],
        matchers_condition = raw.get("matchers-condition", "or").lower(),

        headers            = raw.get("headers", {}),
        follow_redirects   = raw.get("follow-redirects", True),
        max_redirects      = raw.get("max-redirects", 5),
    )


def load_templates(
    templates_root: str | Path = "templates",
    categories:     list[str] | None = None,
    template_ids:   list[str] | None = None,
) -> list[ScanTemplate]:
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

        # .yaml 파일로 통일된 형식 탐색
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