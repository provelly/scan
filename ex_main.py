"""
ex_main.py  ─  파이프라인 통합 예시

세 가지 입력 방식을 모두 시연:
  방식 1: Analyzer.parse_request()  — raw dict
  방식 2: Analyzer.build_targets()  — CrawledPage 수동 구성
  방식 3: WebCrawler → Analyzer.build_targets()  — 실제 크롤링 (비동기)
"""

import asyncio

from analyzer    import Analyzer
from engine      import ScanEngine
from crawler     import WebCrawler
from core.models import CrawledPage, FormDef, FieldDef

analyzer = Analyzer()
engine   = ScanEngine(
    templates_root  = "templates/",
    categories      = ["xss", "sqli"],
    request_timeout = 10.0,
)

# ══════════════════════════════════════════════
# 방식 1: raw dict (parse_request)
# ══════════════════════════════════════════════

crawl_data_list = [
    {
        "url":    "https://example.com/search?q=hello&page=1",
        "method": "GET",
        "headers": {"User-Agent": "Mozilla/5.0"},
    },
    {
        "url":    "https://example.com/login",
        "method": "POST",
        "headers": {"Content-Type": "application/x-www-form-urlencoded"},
        "body":   "username=admin&password=secret",
    },
    {
        "url":    "https://example.com/api/data",
        "method": "POST",
        "headers": {"Content-Type": "application/json"},
        "body":   '{"user_id": "1", "action": "view"}',
    },
]

targets_from_dict = []
for cd in crawl_data_list:
    targets_from_dict.extend(analyzer.parse_request(cd))

print(f"[방식1] 추출된 ScanTarget: {len(targets_from_dict)}개")

# ══════════════════════════════════════════════
# 방식 2: CrawledPage 목록 수동 구성 (build_targets)
# ══════════════════════════════════════════════

pages = [
    CrawledPage(
        url          = "https://example.com/board?category=notice&page=2",
        query_params = {"category": "notice", "page": "2"},
        forms        = [
            FormDef(
                action   = "https://example.com/comment",
                method   = "POST",
                found_on = "https://example.com/board",
                fields   = [
                    FieldDef(name="content",  field_type="textarea", value=""),
                    FieldDef(name="author",   field_type="text",     value=""),
                    FieldDef(name="_csrf",    field_type="hidden",   value="abc123"),
                    FieldDef(name="submit",   field_type="submit",   value="등록"),  # 주입 제외
                ],
            )
        ],
    ),
]

targets_from_pages = analyzer.build_targets(pages)
print(f"[방식2] 추출된 ScanTarget: {len(targets_from_pages)}개")

# ══════════════════════════════════════════════
# 방식 3: 실제 WebCrawler 크롤링 (비동기)
# 실제 URL 로 테스트할 때 주석 해제
# ══════════════════════════════════════════════

async def crawl_and_scan(start_url: str) -> list:
    """크롤러 → 분석기 → 엔진 전체 파이프라인"""
    crawler = WebCrawler(
        start_url     = start_url,
        max_depth     = 2,
        max_pages     = 50,
        concurrency   = 5,
        request_delay = 0.3,
    )
    pages   = await crawler.crawl()
    targets = analyzer.build_targets(pages)
    print(f"[방식3] 크롤링 페이지: {len(pages)}개 → ScanTarget: {len(targets)}개")
    return engine.run(targets, stop_on_first_hit=True)

# 실제 크롤링 실행 예시 (주석 해제 후 사용):
# results_from_crawl = asyncio.run(crawl_and_scan("https://testphp.vulnweb.com"))

# ══════════════════════════════════════════════
# 엔진 실행 (방식 1 + 2 결과 합산)
# ══════════════════════════════════════════════

all_targets = targets_from_dict + targets_from_pages
results     = engine.run(all_targets, stop_on_first_hit=True)

# ── 결과 요약 ───────────────────────────────────────────
vulns = [r for r in results if r.matched]
print(f"\n{'='*55}")
print(f"Total scanned    : {len(results)}")
print(f"Vulnerabilities  : {len(vulns)}")
for v in vulns:
    hits = [mr.mtype for mr in v.match_results if mr.hit]
    print(
        f"  [{v.severity.upper():8}] {v.template_id:25} | "
        f"{v.target.url} | param={v.target.param} | "
        f"payload={v.payload!r} | match={hits}"
    )
