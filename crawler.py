"""
crawler.py — 비동기 웹 크롤러
"""

from __future__ import annotations

import asyncio
import logging
from typing import Optional
from urllib.parse import urljoin, urlparse, parse_qs

import aiohttp
from bs4 import BeautifulSoup

from core.models import FieldDef, FormDef, CrawledPage

class LinkExtractor:
    LINK_ATTRS = {
        "a":      "href",
        "link":   "href",
        "script": "src",
        "img":    "src",
        "iframe": "src",
        "form":   "action",
    }

    def extract(self, html: str, base_url: str) -> list[str]:
        soup  = BeautifulSoup(html, "html.parser")
        links: list[str] = []
        for tag, attr in self.LINK_ATTRS.items():
            for el in soup.find_all(tag):
                href = el.get(attr)
                if not href:
                    continue
                absolute = urljoin(base_url, href.strip())
                if absolute.startswith(("http://", "https://")):
                    links.append(absolute)
        return list(set(links))


class FormExtractor:
    def extract(self, html: str, base_url: str) -> list[FormDef]:
        soup  = BeautifulSoup(html, "html.parser")
        forms: list[FormDef] = []
        for form_tag in soup.find_all("form"):
            action     = form_tag.get("action", "")
            abs_action = urljoin(base_url, action) if action else base_url
            method     = (form_tag.get("method") or "get").upper()
            fields     = self._extract_fields(form_tag)
            forms.append(FormDef(
                action   = abs_action,
                method   = method,
                fields   = fields,
                found_on = base_url,
            ))
        return forms

    def _extract_fields(self, form_tag) -> list[FieldDef]:
        fields: list[FieldDef] = []
        for inp in form_tag.find_all("input"):
            name = inp.get("name", "")
            if name:
                fields.append(FieldDef(
                    name       = name,
                    field_type = (inp.get("type") or "text").lower(),
                    value      = inp.get("value", ""),
                ))
        for ta in form_tag.find_all("textarea"):
            name = ta.get("name", "")
            if name:
                fields.append(FieldDef(
                    name       = name,
                    field_type = "textarea",
                    value      = ta.get_text(),
                ))
        for sel in form_tag.find_all("select"):
            name = sel.get("name", "")
            if name:
                opts = [o.get("value", o.get_text()) for o in sel.find_all("option")]
                fields.append(FieldDef(
                    name       = name,
                    field_type = "select",
                    options    = opts,
                ))
        return fields


class WebCrawler:
    DEFAULT_HEADERS = {
        "User-Agent":      "Mozilla/5.0 (compatible; VulnScanner/2.0)",
        "Accept":          "text/html,application/xhtml+xml,*/*;q=0.8",
        "Accept-Language": "en-US,en;q=0.9",
    }

    def __init__(
        self,
        start_url:     str,
        max_depth:     int   = 3,
        max_pages:     int   = 100,
        concurrency:   int   = 5,
        request_delay: float = 0.5,
        timeout:       int   = 10,
    ):
        self.start_url     = start_url
        self.max_depth     = max_depth
        self.max_pages     = max_pages
        self.concurrency   = concurrency
        self.request_delay = request_delay
        self.timeout       = aiohttp.ClientTimeout(total=timeout)
        self.target_domain = urlparse(start_url).netloc
        
        self.link_ex       = LinkExtractor()
        self.form_ex       = FormExtractor()
        self.results: list[CrawledPage] = []
        self._visited: set[str]         = set()
        self.logger        = logging.getLogger("WebCrawler")

    async def crawl(self) -> list[CrawledPage]:
        # 워커 패턴용 큐 도입
        self.queue = asyncio.Queue()
        self._enqueue(self.start_url, 0)

        connector = aiohttp.TCPConnector(ssl=False)
        async with aiohttp.ClientSession(
            headers   = self.DEFAULT_HEADERS,
            connector = connector,
            timeout   = self.timeout,
        ) as session:
            
            workers = [
                asyncio.create_task(self._worker(session))
                for _ in range(self.concurrency)
            ]
            
            await self.queue.join()

            for w in workers:
                w.cancel()

        self.logger.info(
            "크롤링 완료 — 페이지 %d개 / 방문 URL %d개",
            len(self.results), len(self._visited)
        )
        return self.results

    def _enqueue(self, url: str, depth: int):
        normalized = url.split("#")[0].rstrip("/")
        if (
            normalized not in self._visited
            and urlparse(normalized).netloc == self.target_domain
            and depth <= self.max_depth
        ):
            self._visited.add(normalized)
            self.queue.put_nowait((normalized, depth))

    async def _worker(self, session: aiohttp.ClientSession):
        while True:
            url, depth = await self.queue.get()
            
            if len(self.results) >= self.max_pages:
                self.queue.task_done()
                continue
                
            try:
                self.logger.info("[depth=%d] %s", depth, url)
                async with session.get(url, allow_redirects=True) as resp:
                    await self._process_response(resp, url, depth)
            except (aiohttp.ClientError, asyncio.TimeoutError) as e:
                self.logger.warning("실패 (%s): %s", url, e)
            finally:
                self.queue.task_done()
                if self.request_delay > 0:
                    await asyncio.sleep(self.request_delay)

    async def _process_response(
        self,
        response: aiohttp.ClientResponse,
        url:      str,
        depth:    int,
    ) -> None:
        content_type = response.headers.get("Content-Type", "")
        links: list[str]     = []
        forms: list[FormDef] = []

        if "text/html" in content_type:
            html  = await response.text(errors="replace")
            links = self.link_ex.extract(html, url)
            forms = self.form_ex.extract(html, url)
            for link in links:
                self._enqueue(link, depth + 1)

        query_params: dict[str, str] = {
            k: (v[0] if v else "")
            for k, v in parse_qs(urlparse(url).query).items()
        }

        self.results.append(CrawledPage(
            url              = url,
            query_params     = query_params,
            forms            = forms,
            response_headers = dict(response.headers),
            status_code      = response.status,
            content_type     = content_type,
            links            = links,
            depth            = depth,
        ))

        if forms:
            self.logger.info("  └─ 폼 %d개 (action=%s)", len(forms), forms[0].action)
        if query_params:
            self.logger.info("  └─ 쿼리 파라미터: %s", list(query_params.keys()))