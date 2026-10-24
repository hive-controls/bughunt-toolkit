"""List the form fields and query parameters on a page, without sending a modified request.

A local file stays local. A URL is fetched with one ordinary GET, and only when it is in scope.
--save writes raw requests that repeater can replay.
"""

from __future__ import annotations

import argparse
import re
from collections.abc import Callable, Hashable, Iterable, Iterator
from dataclasses import dataclass, field
from html.parser import HTMLParser
from itertools import count, islice
from pathlib import Path
from urllib.parse import (
    SplitResult,
    parse_qsl,
    urlencode,
    urljoin,
    urlsplit,
    urlunsplit,
)

import httpx

from bughunt import VERSION
from bughunt.core import pagefetch
from bughunt.core.pagefetch import (
    FetchError,
    Halt,
    ScopeError,
    is_web_url,
    report_error,
    report_note,
)
from bughunt.core.workspace import (
    allowed,
    authority,
    explain_target,
    live_lines,
    requests_dir,
    save_request,
    scope_is_active,
)

_SNIFF_CHARS = 8_000
_DOCUMENT_CHARS = 1_000_000
_FIELDS_PER_FORM = 40
_LINKS_CONSIDERED = 200
_FINDING_CAP = 200
_SAVE_CAP = 40
_FORM_VERBS = frozenset({"GET", "POST", "PUT", "PATCH"})
_HTML_MARKERS = ("<form", "<input", "<html", "<a ", "<a>", "<base")
_TABLE_HEADER = ("method", "url", "name", "source", "note")

_REVIEW_NAME_GROUPS = (
    "id uid user userid username email account",
    "search q query sort order orderby filter",
    "category cat item product report",
    "page offset limit column table field where",
)
_REVIEW_NAMES = frozenset(
    word for group in _REVIEW_NAME_GROUPS for word in group.split()
)
_ID_SUFFIXES = ("_id", "-id")

# (label, needles): groups are consulted in order, needles inside a group in order.
_ERROR_SIGNATURES = (
    ("MySQL syntax error", ("you have an error in your sql syntax",)),
    ("MySQL warning", ("warning: mysql",)),
    ("MySQL error", ("mysql_fetch", "mysqli_")),
    ("PostgreSQL error", ("pg_query()", "psqlexception")),
    ("SQLite error", ("sqlite3.operationalerror",)),
    ("SQL Server error", ("unclosed quotation mark after the character string",)),
    ("ODBC error", ("microsoft ole db provider for odbc drivers",)),
    ("Oracle error", ("ora-00933", "ora-01756")),
    ("SQLSTATE error", ("sqlstate[",)),
)

_AttrList = list[tuple[str, str | None]]


@dataclass
class _Endpoint:
    method: str
    url: str


@dataclass
class Finding(_Endpoint):
    name: str
    source: str
    note: str


@dataclass
class Draft(_Endpoint):
    body: str


@dataclass
class Page:
    findings: list[Finding] = field(default_factory=list)
    drafts: list[Draft] = field(default_factory=list)
    unresolved: int = 0
    db_note: str = ""


_OPTIONS = (
    (
        ("inputs",),
        {"nargs": "*", "help": "Local HTML file, or a file of http(s) URLs."},
    ),
    (
        ("--url",),
        {
            "action": "append",
            "default": [],
            "help": "Fetch this in-scope page with a normal GET.",
        },
    ),
    (("--base",), {"help": "Page URL used to resolve relative links in a local file."}),
    (
        ("--save",),
        {
            "dest": "save_requests",
            "action": "store_true",
            "help": "Write an in-scope raw request for each form and link under .bughunt/requests/.",
        },
    ),
    (
        ("--no-workspace",),
        {
            "action": "store_true",
            "help": "List every parsed URL and do not apply the scope filter.",
        },
    ),
    (
        ("--limit",),
        {"type": int, "default": 20, "help": "Maximum pages to fetch. Default 20."},
    ),
    (
        ("--timeout",),
        {"type": float, "default": 10, "help": "Seconds to wait for each page."},
    ),
    (
        ("--cookie",),
        {"help": "Cookie for this run. Replaces the saved session cookie."},
    ),
    (
        ("--authorization",),
        {"help": "Authorization for this run. Replaces the saved session value."},
    ),
)


def build_parser() -> argparse.ArgumentParser:
    cli = argparse.ArgumentParser(
        prog="bughunt forms",
        description="List form fields and query parameters. Does not send a modified request.",
    )
    for flags, settings in _OPTIONS:
        cli.add_argument(*flags, **settings)
    return cli


def _distinct(items: Iterable, key: Callable[[object], Hashable]) -> Iterator:
    """The items in order, keeping only the first with each key."""
    seen: set[Hashable] = set()
    for item in items:
        marker = key(item)
        if marker not in seen:
            seen.add(marker)
            yield item


# --- reading a page ---------------------------------------------------------------------------------------


@dataclass
class _Control:
    name: str
    kind: str
    value: str
    disabled: bool


@dataclass
class _FormDraft:
    action: str
    method: str
    controls: list[_Control] = field(default_factory=list)


@dataclass
class _Pending:
    """A select or textarea that has been opened but not yet closed."""

    name: str
    kind: str
    disabled: bool
    value: str = ""
    chosen: bool = False


@dataclass
class _Scanned:
    base_href: str = ""
    forms: list[_FormDraft] = field(default_factory=list)
    hrefs: list[str] = field(default_factory=list)


def _name_of(attrs: dict[str, str]) -> str:
    return attrs.get("name", "").strip()


class _Scanner(HTMLParser):
    """Collects forms, the first non-empty <base href>, and links worth a second look."""

    def __init__(self) -> None:
        super().__init__()
        self.found = _Scanned()
        self._form: _FormDraft | None = None
        self._pending: dict[str, _Pending] = {}
        self._openers = {
            "base": self._on_base,
            "form": self._on_form,
            "a": self._on_anchor,
            "area": self._on_embedded,
            "iframe": self._on_embedded,
            "input": self._on_input,
            "button": self._on_button,
            "textarea": self._on_textarea,
            "select": self._on_select,
            "option": self._on_option,
        }
        self._closers = {
            "form": self._on_form_end,
            "textarea": self._on_pending_end,
            "select": self._on_pending_end,
        }

    def handle_starttag(self, tag: str, attrs: _AttrList) -> None:
        opener = self._openers.get(tag)
        if opener is not None:
            opener({key: value or "" for key, value in attrs})

    def handle_endtag(self, tag: str) -> None:
        closer = self._closers.get(tag)
        if closer is not None:
            closer(tag)

    def handle_data(self, data: str) -> None:
        text_box = self._pending.get("textarea")
        if text_box is not None:
            text_box.value += data

    def finish(self) -> None:
        self.close()
        self._close_form()

    def _close_form(self) -> None:
        form, self._form = self._form, None
        if form is not None:
            self.found.forms.append(form)

    def _add(self, control: _Control) -> None:
        if self._form:
            self._form.controls.append(control)

    def _on_base(self, attrs: dict[str, str]) -> None:
        if not self.found.base_href:
            self.found.base_href = attrs.get("href", "").strip()

    def _on_form(self, attrs: dict[str, str]) -> None:
        self._on_form_end("form")
        verb = (attrs.get("method") or "GET").strip().upper() or "GET"
        self._form = _FormDraft(attrs.get("action", "").strip(), verb)

    def _on_form_end(self, _tag: str) -> None:
        self._close_form()
        self._pending.clear()

    def _on_anchor(self, attrs: dict[str, str]) -> None:
        href = attrs.get("href", "").strip()
        if href:
            self.found.hrefs.append(href)

    def _on_embedded(self, attrs: dict[str, str]) -> None:
        target = (attrs.get("href") or attrs.get("src") or "").strip()
        if "?" in target:
            self.found.hrefs.append(target)

    def _add_named(self, attrs: dict[str, str], kind: str) -> None:
        name = _name_of(attrs)
        if name:
            self._add(_Control(name, kind, attrs.get("value", ""), "disabled" in attrs))

    def _on_input(self, attrs: dict[str, str]) -> None:
        self._add_named(attrs, (attrs.get("type") or "text").strip().lower() or "text")

    def _on_button(self, attrs: dict[str, str]) -> None:
        self._add_named(attrs, "button")

    def _open_pending(self, attrs: dict[str, str], kind: str, disabled: bool) -> None:
        name = _name_of(attrs)
        if name and self._form is not None:
            self._pending[kind] = _Pending(name, kind, disabled)

    def _on_textarea(self, attrs: dict[str, str]) -> None:
        self._open_pending(attrs, "textarea", "disabled" in attrs)

    def _on_select(self, attrs: dict[str, str]) -> None:
        self._open_pending(attrs, "select", False)

    def _on_option(self, attrs: dict[str, str]) -> None:
        menu = self._pending.get("select")
        if menu is not None:
            picked = "selected" in attrs
            if picked or not menu.chosen:
                menu.value = attrs.get("value", "")
            menu.chosen = True

    def _on_pending_end(self, tag: str) -> None:
        finished = self._pending.pop(tag, None)
        if finished is not None:
            self._add(
                _Control(
                    finished.name, finished.kind, finished.value, finished.disabled
                )
            )


def _scan(text: str) -> _Scanned:
    scanner = _Scanner()
    scanner.feed(text)
    scanner.finish()
    return scanner.found


def _is_inert(reference: str) -> bool:
    """True for references that point nowhere a request could go: empty, fragments, other schemes."""
    if not reference or reference.startswith("#"):
        return True
    scheme = re.match(r"([A-Za-z][A-Za-z0-9+.-]*):", reference)
    return bool(scheme and scheme[1].lower() not in pagefetch.WEB_SCHEMES)


def _resolve(reference: str, base: str | None) -> str | None:
    """Absolute URL for a reference; "" means ignore it silently, None means it needs a base."""
    text = reference.strip()
    if _is_inert(text):
        return ""
    candidate = text if is_web_url(text) else (urljoin(base, text) if base else None)
    return candidate if candidate and is_web_url(candidate) else None


class _Resolver:
    """Makes references absolute against one base and counts those that needed a base they lack."""

    def __init__(self, base: str | None) -> None:
        self.base = base
        self.missing = 0

    def absolute(self, reference: str) -> str:
        """The absolute URL, or "" when the reference is to be skipped (counted if it lacked a base)."""
        outcome = _resolve(reference, self.base)
        if outcome is None:
            self.missing += 1
        return outcome or ""

    def page_itself(self) -> str:
        if self.base is None:
            self.missing += 1
        return self.base or ""

    def rebase(self, declared: str) -> None:
        if declared:
            self.base = self.absolute(declared) or self.base


def _is_review_name(name: str) -> bool:
    lowered = name.strip().lower()
    return lowered in _REVIEW_NAMES or lowered.endswith(_ID_SUFFIXES)


_NOTE_RULES: tuple[tuple[str, Callable[[_Control], bool]], ...] = (
    ("hidden", lambda control: control.kind == "hidden"),
    ("password", lambda control: control.kind == "password"),
    ("disabled", lambda control: control.disabled),
    ("review", lambda control: _is_review_name(control.name)),
)


def _control_note(control: _Control) -> str:
    return ", ".join(label for label, applies in _NOTE_RULES if applies(control))


def database_note(text: str) -> str:
    haystack = text.lower()
    matching = (
        label
        for label, needles in _ERROR_SIGNATURES
        if any(needle in haystack for needle in needles)
    )
    return next(matching, "")


def _encode_request(
    action: str, method: str, controls: list[_Control]
) -> tuple[str, str]:
    pairs = [
        (c.name, "" if c.kind == "password" else c.value)
        for c in controls
        if not c.disabled
    ]
    if method != "GET":
        return action, urlencode(pairs)
    split = urlsplit(action)
    query = urlencode(
        parse_qsl(split.query, keep_blank_values=True) + pairs, doseq=True
    )
    return urlunsplit((split.scheme, split.netloc, split.path or "/", query, "")), ""


Entries = tuple[list[Finding], list[Draft]]


def _form_entries(form: _FormDraft, resolver: _Resolver) -> Entries:
    target = resolver.absolute(form.action) if form.action else resolver.page_itself()
    controls = form.controls[:_FIELDS_PER_FORM]
    if not target or not controls:
        return [], []
    verb = form.method if form.method in _FORM_VERBS else "GET"
    findings = [
        Finding(verb, target, c.name, "form", _control_note(c)) for c in controls
    ]
    return findings, [Draft(verb, *_encode_request(target, verb, controls))]


def _query_names(url: str) -> list[str]:
    pairs = parse_qsl(urlsplit(url).query, keep_blank_values=True)
    return list(dict.fromkeys(name for name, _value in pairs if name))


def _link_entries(hrefs: list[str], resolver: _Resolver) -> Entries:
    findings: list[Finding] = []
    drafts: list[Draft] = []
    listed: set[str] = set()
    for href in (h for h in hrefs if "?" in h):
        target = resolver.absolute(href)
        names = _query_names(target) if target and target not in listed else []
        if names:
            listed.add(target)
            findings += [
                Finding(
                    "GET",
                    target,
                    name,
                    "link",
                    "review" if _is_review_name(name) else "",
                )
                for name in names
            ]
            drafts.append(Draft("GET", target, ""))
    return findings, drafts


def parse_document(text: str, base: str | None, *, page_url: str) -> Page:
    scanned = _scan(text)
    resolver = _Resolver(base or None)
    resolver.rebase(scanned.base_href)
    db_note = database_note(text)
    findings = [Finding("NOTE", page_url, "-", "database", db_note)] if db_note else []
    drafts: list[Draft] = []
    sections = [_form_entries(form, resolver) for form in scanned.forms]
    sections.append(_link_entries(scanned.hrefs[:_LINKS_CONSIDERED], resolver))
    for section_findings, section_drafts in sections:
        findings += section_findings
        drafts += section_drafts
    return Page(findings, drafts, resolver.missing, db_note)


# --- raw requests -----------------------------------------------------------------------------------------


def _host_header(split: SplitResult) -> str:
    return authority(split.hostname or "", split.port)


def _request_target(split: SplitResult) -> str:
    return (split.path or "/") + (f"?{split.query}" if split.query else "")


def render_request(draft: Draft) -> bytes:
    split = urlsplit(draft.url)
    verb = draft.method.upper()
    payload = b"" if verb == "GET" else draft.body.encode("utf-8")
    head = [
        f"{verb} {_request_target(split)} HTTP/1.1",
        f"Host: {_host_header(split)}",
        f"User-Agent: Bughunt/{VERSION}",
    ]
    if verb != "GET":
        head += [
            "Content-Type: application/x-www-form-urlencoded",
            f"Content-Length: {len(payload)}",
        ]
    return "\r\n".join((*head, "", "")).encode("latin-1", errors="replace") + payload


# --- fetching ---------------------------------------------------------------------------------------------


def fetch_document(client: httpx.Client, url: str) -> tuple[str, str]:
    return pagefetch.fetch_document(client, url)


# --- command ----------------------------------------------------------------------------------------------


@dataclass
class _Inputs:
    pages: list[str] = field(default_factory=list)
    documents: list[tuple[Path, str]] = field(default_factory=list)


@dataclass
class _Haul(Page):
    """Everything gathered from every page so far, plus how many entries the scope filter removed."""

    dropped: int = 0

    def take(self, page: Page, dropped: int) -> None:
        self.findings += page.findings
        self.drafts += page.drafts
        self.unresolved += page.unresolved
        self.dropped += dropped


_NUMERIC_RULES: tuple[tuple[Callable[[argparse.Namespace], bool], str], ...] = (
    (lambda options: options.limit < 1, "Limit has to be at least 1."),
    (lambda options: options.timeout <= 0, "Timeout has to be greater than 0."),
)


def _screen_arguments(options: argparse.Namespace) -> tuple[str, bool]:
    for violated, message in _NUMERIC_RULES:
        if violated(options):
            raise Halt(2, report_error, message)
    base = (options.base or "").strip()
    if base and not is_web_url(base):
        raise Halt(
            2,
            report_error,
            "Base needs an http or https URL, such as https://app.internal/app.",
        )
    scoped = scope_is_active() and not options.no_workspace
    if base and scoped and not allowed(base):
        raise Halt(2, report_note, explain_target(base))
    if options.save_requests and not scope_is_active():
        raise Halt(2, report_error, "No scope workspace yet. Run: bughunt scope init")
    return base, scoped


def _read_text(path: Path) -> str:
    try:
        return path.read_text(encoding="utf-8", errors="replace")
    except OSError as problem:
        raise Halt(1, report_error, f"Could not read {path}: {problem}") from problem


def _url_lines(label: str, body: str) -> list[str]:
    entries = live_lines(body)
    if not entries or not all(is_web_url(entry) for entry in entries):
        raise Halt(
            2, report_error, f"{label} is not HTML and is not a list of http(s) URLs."
        )
    return entries


def _sort_file(label: str, source: Path, inputs: _Inputs) -> None:
    body = _read_text(source)
    if any(marker in body[:_SNIFF_CHARS].lower() for marker in _HTML_MARKERS):
        inputs.documents.append((source, body))
    else:
        inputs.pages.extend(_url_lines(label, body))


def _sort_positional(item: str, inputs: _Inputs) -> None:
    label = item.strip()
    if is_web_url(label):
        inputs.pages.append(label)
        return
    source = Path(label)
    if source.is_file():
        _sort_file(label, source, inputs)
    else:
        raise Halt(2, report_error, f"No file named {label}.")


def _collect_inputs(options: argparse.Namespace) -> _Inputs:
    inputs = _Inputs(pages=[url.strip() for url in options.url if url.strip()])
    for item in options.inputs or []:
        _sort_positional(item, inputs)
    if not inputs.pages and not inputs.documents:
        raise Halt(2, report_error, "Give a local HTML file, a file of URLs, or --url.")
    return inputs


def _split_by_scope(urls: list[str]) -> tuple[list[str], list[str]]:
    verdicts = {url: allowed(url) for url in dict.fromkeys(urls)}
    return (
        [url for url, ok in verdicts.items() if ok],
        [url for url, ok in verdicts.items() if not ok],
    )


def _within_scope(page: Page, scoped: bool) -> tuple[Page, int]:
    permit = allowed if scoped else (lambda _url: True)
    findings = [
        item for item in page.findings if item.method == "NOTE" or permit(item.url)
    ]
    drafts = [item for item in page.drafts if permit(item.url)]
    removed = (len(page.findings) - len(findings)) + (len(page.drafts) - len(drafts))
    return Page(findings, drafts, page.unresolved, page.db_note), removed


def _visit_pages(
    options: argparse.Namespace,
    urls: list[str],
    haul: _Haul,
    scoped: bool,
    *,
    report: bool = True,
) -> None:
    try:
        with pagefetch.crawl_client(
            "manual",
            options.timeout,
            cookie=options.cookie,
            authorization=options.authorization,
        ) as http:
            for url in islice(urls, options.limit):
                text, final = fetch_document(http, url)
                haul.take(
                    *_within_scope(parse_document(text, final, page_url=final), scoped)
                )
            if report and len(urls) > options.limit:
                report_note(f"Stopped after {options.limit} page(s).")
    except (ScopeError, FetchError) as problem:
        raise pagefetch.halt_for(problem) from problem


def _finding_key(item: Finding) -> tuple[str, str, str, str]:
    return item.method, item.url, item.name, item.source


def _draft_key(item: Draft) -> tuple[str, str, str]:
    return item.method, item.url, item.body


def _flatten(cell: str) -> str:
    return " ".join(cell.replace("\t", " ").splitlines()).strip()


def _table_text(findings: list[Finding]) -> str:
    rows = [
        _TABLE_HEADER,
        *((i.method, i.url, i.name, i.source, i.note) for i in findings),
    ]
    return "\n".join("\t".join(_flatten(cell) for cell in row) for row in rows)


def _savable(drafts: list[Draft], *, report: bool = True) -> list[Draft]:
    usable = []
    for draft in drafts:
        try:
            split = pagefetch.web_parts(draft.url)
            if split is not None and allowed(draft.url):
                _ = split.port
                usable.append(draft)
        except ValueError:
            if report:
                report_note(f"Skipped an invalid request draft: {draft.url}")
    return list(islice(_distinct(usable, _draft_key), _SAVE_CAP))


def save_drafts(drafts: list[Draft], *, report: bool = True) -> list[str]:
    chosen = _savable(drafts, report=report)
    payloads = [render_request(draft) for draft in chosen]
    taken = {path.name for path in requests_dir().glob("form-*.http")}
    free_names = (
        name
        for name in (f"form-{number:04d}.http" for number in count(1))
        if name not in taken
    )
    saved = []
    for payload, name in zip(payloads, free_names):
        save_request(name, payload)
        saved.append(name)
        if report:
            report_note(f"saved {name}")
    if report and len(drafts) > len(chosen) and len(chosen) >= _SAVE_CAP:
        report_note(f"Stopped after {_SAVE_CAP} saved requests.")
    return saved


def _write_requests(drafts: list[Draft]) -> int:
    return len(save_drafts(drafts))


def _summary_line(shown: int, haul: _Haul, blocked: int, saved: int) -> str:
    counted = (
        (haul.unresolved, "relative link(s) need --base"),
        (haul.dropped, "outside scope"),
        (blocked, "page(s) outside scope"),
        (saved, "request(s) saved"),
    )
    return "  ".join(
        [
            f"{shown} field(s)",
            *(f"{amount} {label}" for amount, label in counted if amount),
        ]
    )


def _report(
    options: argparse.Namespace, haul: _Haul, inputs: _Inputs, blocked: list[str]
) -> int:
    findings = list(_distinct(haul.findings, _finding_key))
    if len(findings) > _FINDING_CAP:
        del findings[_FINDING_CAP:]
        report_note(f"Stopped after {_FINDING_CAP} fields.")
    if findings:
        print(_table_text(findings))
    try:
        saved = _write_requests(haul.drafts) if options.save_requests else 0
    except ValueError as problem:
        report_error(str(problem))
        return 2
    report_note(_summary_line(len(findings), haul, len(blocked), saved))
    nothing_reachable = (
        bool(inputs.pages) and not findings and bool(blocked) and not inputs.documents
    )
    return 2 if nothing_reachable else 0


def collect(
    options: argparse.Namespace, *, report: bool = True
) -> tuple[_Haul, _Inputs, list[str]]:
    base, scoped = _screen_arguments(options)
    inputs = _collect_inputs(options)
    reachable, blocked = _split_by_scope(inputs.pages)
    if inputs.pages and not reachable and not inputs.documents:
        raise Halt(2, report_note, explain_target(blocked[0]))
    haul = _Haul()
    for source, text in inputs.documents:
        page = parse_document(
            text[:_DOCUMENT_CHARS], base or None, page_url=base or source.name
        )
        haul.take(*_within_scope(page, scoped))
    if reachable:
        _visit_pages(options, reachable, haul, scoped, report=report)
    return haul, inputs, blocked


def _run(options: argparse.Namespace) -> int:
    haul, inputs, blocked = collect(options)
    return _report(options, haul, inputs, blocked)


def main(argv: list[str] | None = None) -> int:
    options = build_parser().parse_args(argv)
    return pagefetch.run_halting(_run, options)
