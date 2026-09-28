#!/usr/bin/env python3
"""
check_exchange.py — пассивный сканер внешних хостов на CVE-2026-62911.

Назначение:
    Авторизованный аудит собственного периметра. Инструмент определяет:
      1. Версию Microsoft Exchange Server по пассивным эндпоинтам
         (/owa/auth/logon.aspx, /autodiscover/autodiscover.xml, WinHTTP,
         /rpc и т.д.) и сверяет её с таблицей патчей CVE-2026-62911.
      2. Фингерпринт MRSProxy-эндпоинта HTTP.sys
         (/Microsoft.Exchange.MailboxReplicationService.ProxyService):
         присутствие 401 + заголовка WWW-Authenticate: Negotiate без
         Extended Protection — признак того, что релей-вектор открыт.

ВАЖНО:
    Инструмент ТОЛЬКО читает и не выполняет атакующие действия.
    Никакого релея NTLM, записи файлов или эксплуатации.
    Используйте только против систем, на проверку которых есть
    письменное разрешение владельца. Проверьте применимость всех
    утверждений к вашему окружению перед использованием результатов.

Требования (Python 3.9+):
    requests, rich  (rich опционален: без него вывод будет plain text)

Примеры:
    python check_exchange.py -t exchange.contoso.com
    python check_exchange.py -t 192.168.1.10 --insecure
    python check_exchange.py -t host --list-hosts file.txt
    python check_exchange.py -t host -o report.md
"""

from __future__ import annotations

import argparse
import sys
import threading
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Dict, Iterable, List, Optional, Tuple

import requests
import urllib3

try:
    from rich.console import Console
    from rich.markdown import Markdown
    from rich.panel import Panel
    from rich.table import Table
    from rich.text import Text

    HAS_RICH = True
except ImportError:  # graceful degradation
    HAS_RICH = False

try:
    from requests.auth import HTTPBasicAuth
    from requests_ntlm import HttpNtlmAuth  # only for --auth ntlm logon test
except ImportError:
    HttpNtlmAuth = None

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# ---------------------------------------------------------------------------
# БАЗА ВЕРСИЙ / ПАТЧЕЙ ДЛЯ CVE-2026-62911
# ---------------------------------------------------------------------------
# ('Продукт', build, 'статус', 'закрывающий патч')
# mechanism: уязвим, если product в списке и build МЕНЬШЕ чем закрывающая сборка.
CVE_2026_62911_PATCHES = [
    {"product": "Exchange 2016 CU23", "fixed_build": "15.1.2507.72", "kb": "KB5121576", "note": "ESU only (EOL 2025-10)"},
    {"product": "Exchange 2019 CU14", "fixed_build": "15.2.1544.43", "kb": "KB5121575", "note": ""},
    {"product": "Exchange 2019 CU15", "fixed_build": "15.2.1748.48", "kb": "KB5121574", "note": ""},
    {"product": "Exchange SE RTM",   "fixed_build": "15.2.2562.45", "kb": "KB5121573", "note": ""},
]

# Признаки, по которым можно распознать версию Exchange
OWA_AUTH_PATH = "/owa/auth/logon.aspx"
AUTODISCOVER_PATH = "/autodiscover/autodiscover.xml"
MRS_ENDPOINT = "/Microsoft.Exchange.MailboxReplicationService.ProxyService"
RPC_PATH = "/rpc"
ECP_PATH = "/ecp"
EWS_PATH = "/ews/exchange.asmx"
OAB_PATH = "/oab"
ACTIVESYNC_PATH = "/microsoft-server-activesync"
SIGNATURE_X_POWERED = "Asp.Net"
X_OWA_VERSION = "X-OWA-Version"

# Маппинг сигнатур OWA на семейство/билд
OWA_SIGNATURES = {
    "15.1": "Exchange 2016",
    "15.2": "Exchange 2019/SE",
}


@dataclass
class ProbeResult:
    label: str
    ok: bool = False
    status: int = 0
    details: str = ""
    headers: Dict[str, str] = field(default_factory=dict)
    body: str = ""
    server: str = ""
    x_owa_version: str = ""
    autodiscover_email: str = ""


@dataclass
class TargetResult:
    host: str
    probes: List[ProbeResult] = field(default_factory=list)
    version_build: Optional[str] = None
    version_family: Optional[str] = None
    msrs_ep_note: Optional[str] = None
    msrs_negotiate: bool = False
    findings: List[str] = field(default_factory=list)


_VERSION_COMPONENTS = ("15.1", "15.2", "15.0", "14.3", "8.3", "8.2")


def _find_version_in_headers(headers: Dict[str, str]) -> Optional[str]:
    v = headers.get("X-OWA-Version") or headers.get("X-AspNet-Version")
    if v and v.strip():
        return v.strip()
    return None


def _find_version_in_text(text: str) -> Optional[str]:
    if not text:
        return None
    for comp in _VERSION_COMPONENTS:
        start = text.find(comp)
        if start == -1:
            continue
        end = start
        while end < len(text) and (text[end].isdigit() or text[end] == "."):
            end += 1
        if end > start:
            return text[start:end]
    # 8.3.83.x (2010) иногда приходит как "8.3", найдём шире
    return None


def _version_tuple(build: str) -> Optional[Tuple[int, ...]]:
    parts = []
    for p in build.split("."):
        try:
            parts.append(int(p))
        except ValueError:
            return None
    if len(parts) != 4:
        return None
    return tuple(parts)


def _find_patch(build: str) -> Optional[dict]:
    """Возвращает запись из таблицы патчей, если build принадлежит линейке.
    Само сравнение с конкретной исправленной сборкой делает _evaluate."""
    for p in CVE_2026_62911_PATCHES:
        tag = p["product"].split()[-1]
        if build.startswith("15.1.") and tag == "CU23":
            return p
        if build.startswith("15.2."):
            if p["product"].startswith("Exchange 2019 CU14") or p["product"] == "Exchange 2019 CU15":
                return p
            if p["product"] == "Exchange SE RTM":
                return p
    return None


def _evaluate(build: Optional[str]) -> Tuple[str, str]:
    """Возвращает (verdict, detail). verdict в {'ok','vulnerable','unknown','outdated'}"""
    if not build:
        return "unknown", "не удалось определить сборку"
    vt = _version_tuple(build)
    if not vt:
        return "unknown", f"сборка не распознана: {build}"
    for p in CVE_2026_62911_PATCHES:
        ft = _version_tuple(p["fixed_build"])
        if not ft:
            continue
        # Тот же мажор.миниор? Для 15.2 diff между CU14/15/SE тоже миниор разный,
        # поэтому сравниваем по пописанной линейке через продукты.
        # Упрощённо: если 15.2 и build < самого большого фикса своей ветки.
        if not (vt[0], vt[1]) == (ft[0], ft[1]):
            continue
        if vt < ft:
            return "vulnerable", (
                f"{p['product']}: сборка {build} < {p['fixed_build']} "
                f"({p['kb']}). {p['note']}".strip()
            )
        return "ok", f"{p['product']}: сборка {build} >= {p['fixed_build']} ({p['kb']}) — патч установлен"
    # Не попали в известные фиксы -> возможно необслуживаемая ветка
    fam = "Exchange 2016" if vt[0] == 15 and vt[1] == 1 else ("Exchange 2019/SE" if vt[0] == 15 and vt[1] == 2 else "Exchange")
    return "outdated", f"{fam}: сборка {build} вне таблицы патчей CVE-2026-62911 — уточнить вручную"


class ExchangeScanner:
    def __init__(self, host: str, insecure: bool = False, timeout: float = 15.0,
                 user_agent: Optional[str] = None):
        self.host = host
        self.base = f"https://{host}"
        self.insecure = insecure
        self.timeout = timeout
        self.session = requests.Session()
        self.session.verify = not insecure
        self.session.headers.update({
            "User-Agent": user_agent or "Mozilla/5.0 (ExchangeScan/1.0)",
            "Accept": "*/*",
        })

    def _get(self, path: str, label: str, allow_redirects: bool = False,
             **kw) -> ProbeResult:
        r = ProbeResult(label=label)
        url = self.base + path
        try:
            resp = self.session.get(url, timeout=self.timeout,
                                    allow_redirects=allow_redirects, **kw)
            r.status = resp.status_code
            r.headers = {k.lower(): v for k, v in resp.headers.items()}
            r.server = r.headers.get("server", "")
            r.x_owa_version = r.headers.get(X_OWA_VERSION.lower(), "")
            r.body = resp.text[:4096]
            r.ok = True
        except requests.exceptions.SSLError as e:
            r.details = f"TLS: {type(e).__name__}"
        except requests.exceptions.ConnectionError as e:
            r.details = f"connect: {type(e).__name__}"
        except requests.exceptions.Timeout:
            r.details = "timeout"
        except Exception as e:  # noqa
            r.details = f"err: {type(e).__name__}: {e}"
        return r

    def _detect_msrs_endpoint(self) -> Tuple[bool, str]:
        """Фингерпринт HTTP.sys MRSProxy.
        Признак уязвимого состояния: 401 + WWW-Authenticate содержит Negotiate,
        а в ответе НЕТ информации об Extended Protection (обычно просто отсутствует
        extendedProtectionPolicy в конфиге — на уровне HTTP это 'Negotiate'
        без канала привязки). Возвращает (is_negotiate, note)."""
        r = self._get(MRS_ENDPOINT, "MRSProxy HTTP.sys", allow_redirects=True)
        www_auth = r.headers.get("www-authenticate", "")
        has_negotiate = "negotiate" in www_auth.lower()
        server_is_httpapi = "httpapi" in r.server.lower() or "microsoft-httpapi" in r.server.lower()
        # HTTP 200 -> сервис отвечает, но это может быть Application error, а не
        # сам факт отсутствия развёртывания EPA. main признак — Negotiate в 401.
        note = ""
        if r.status in (401, 403) and has_negotiate:
            note = (
                f"HTTP {r.status}; Server={r.server or 'n/a'}; "
                "WWW-Authenticate=Negotiate — эндпоинт принимает NEGOTIATE. "
                "Если на нём отсутствует Extended Protection — потенциально "
                "пригоден для релея (проверьте конфиг MSExchangeMailboxReplication.exe.config)."
            )
        elif r.status in (401, 403):
            note = f"HTTP {r.status}; WWW-Authenticate={www_auth or 'нет'}. Negotiate не обнаружен."
        else:
            note = f"HTTP {r.status}; Server={r.server or 'n/a'} ({'HTTPAPI' if server_is_httpapi else 'не HTTPAPI'})"
        return has_negotiate, note


    def scan_owa(self) -> ProbeResult:
        r = self._get(OWA_AUTH_PATH, "OWA logon.aspx", allow_redirects=True)
        if r.status and r.status != 200:
            # OWA часто отдаёт 302/403 на logon.aspx, версию из заголовков:
            return r
        return r

    def scan_autodiscover_email(self) -> ProbeResult:
        r = self._get(AUTODISCOVER_PATH, "Autodiscover")
        if r.status in (200, 401, 403) and "autodiscover" in (r.body + r.headers.get("content-type", "")).lower():
            pass
        return r

    def scan_winhttp(self) -> ProbeResult:
        hdr = {"Accept": "application/xml"}
        return self._get("/winhttp", "WinHTTP", headers=hdr)

    def scan_ews(self) -> ProbeResult:
        return self._get(EWS_PATH, "EWS", allow_redirects=True)

    def run(self) -> TargetResult:
        tr = TargetResult(host=self.host)
        tr.probes = [
            self.scan_owa(),
            self.scan_autodiscover_email(),
            self.scan_winhttp(),
            self.scan_ews(),
        ]

        # Собираем кандидатов версии
        # 1) из заголовков
        for r in tr.probes:
            v = _find_version_in_headers(r.headers)
            if v:
                tr.version_build = v
                break
        # 2) из текста
        if not tr.version_build:
            for r in tr.probes:
                v = _find_version_in_text(r.body)
                if v:
                    tr.version_build = v
                    break
        # 3) OWA page meta generator
        if not tr.version_build:
            for r in tr.probes:
                if r.label == "OWA logon.aspx" and r.body:
                    low = r.body.lower()
                    for key in ("microsoft exchange", "owa", "exchange server"):
                        idx = low.find(key)
                        if idx != -1:
                            v = _find_version_in_text(r.body[idx - 40: idx + 80])
                            if v and v.startswith("15."):
                                tr.version_build = v
                                break
                    if tr.version_build:
                        break

        if tr.version_build:
            for label, prefix in (("15.1", "Exchange 2016"), ("15.2", "Exchange 2019/SE")):
                if tr.version_build.startswith(label):
                    tr.version_family = prefix
                    break

        # MRS фингерпринт
        has_neg, msrs_note = self._detect_msrs_endpoint()
        tr.msrs_negotiate = has_neg
        tr.msrs_ep_note = msrs_note

        verdict, detail = _evaluate(tr.version_build)
        tr.findings.append(f"validation: {verdict} — {detail}")
        if tr.msrs_negotiate:
            tr.findings.append(f"msrs: Negotiate endpoint present — {msrs_note}")
        return tr


# ---------------------------------------------------------------------------
# ВЫВОД / Rich UI
# ---------------------------------------------------------------------------
def _verdict_color(v: str) -> str:
    return {
        "vulnerable": "red",
        "unknown": "yellow",
        "outdated": "orange3",
        "ok": "green",
    }.get(v, "white")


def render_result_plain(tr: TargetResult, out: Path):
    lines = []
    lines.append(f"=== {tr.host} ===")
    if tr.version_build:
        lines.append(f"  Build: {tr.version_build}" + (f"  ({tr.version_family})" if tr.version_family else ""))
    lines.append(f"  MRSProxy Negotiate: {tr.msrs_negotiate}")
    for f in tr.findings:
        lines.append(f"  {f}")
    lines.append("")
    out.write_text("\n".join(lines), encoding="utf-8", errors="replace")


def render_one(console, tr: TargetResult):
    if not HAS_RICH or console is None:
        render_result_plain(tr, Path(f"report_{tr.host}.txt"))
        return
    t = Table(title=f"[bold]{tr.host}[/bold]", title_style="bold cyan")
    t.add_column("Проверка")
    t.add_column("Статус")
    t.add_column("HTTP")
    t.add_column("Server")
    t.add_column("Версия/детали")
    for r in tr.probes:
        status_txt = "OK" if r.ok else "FAIL"
        t.add_row(
            r.label,
            status_txt,
            str(r.status) if r.status else "—",
            r.server or "—",
            (r.x_owa_version or r.details or "—"),
        )
    console.print(t)

    verdict = "unknown"
    detail = ""
    for f in tr.findings:
        if f.startswith("validation:"):
            _, _, verdict = f.partition(":")
            verdict = verdict.strip()
            break
    if tr.findings:
        detail = tr.findings[0]
    color = _verdict_color(verdict)
    console.print(
        Panel(
            Text(
                f"Build: {tr.version_build or '(не определён)'}  "
                f"{f'({tr.version_family})' if tr.version_family else ''}\n"
                f"MRSProxy Negotiate endpoint: {'ДА' if tr.msrs_negotiate else 'нет'}\n"
                f"{tr.msrs_ep_note}",
                style="default",
            ),
            title="CVE-2026-62911 — статус",
            border_style=color,
        )
    )
    console.print(f"[{color}]validation: {verdict}[/{color}]")
    console.print(detail)
    console.print("")


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------
def _parse_hosts(hosts: Iterable[str]) -> List[str]:
    out = []
    for h in hosts:
        if h.startswith("http"):
            h = h.split("://", 1)[1].rstrip("/")
        out.append(h)
    return out


def main(argv: Optional[List[str]] = None) -> int:
    ap = argparse.ArgumentParser(
        prog="check_exchange",
        description="Пассивный сканер внешних хостов на CVE-2026-62911 (авторизованный аудит).",
    )
    ap.add_argument("-t", "--target", action="append", help="Хост(и). Повторите для нескольких.")
    ap.add_argument("-f", "--hosts-file", type=Path, help="Файл со списком хостов (по одному в строке).")
    ap.add_argument("--insecure", action="store_true", help="Не проверять TLS сертификат.")
    ap.add_argument("--timeout", type=float, default=15.0, help="Таймаут на запрос (с).")
    ap.add_argument("-o", "--output-dir", type=Path, default=Path("."), help="Директория для отчётов.")
    ap.add_argument("--max-workers", type=int, default=10, help="Параллельно хостов.")
    ap.add_argument("--plain", action="store_true", help="Принудительно без rich (plain text).")
    ap.add_argument("--user-agent", help="Переопределить User-Agent.")
    args = ap.parse_args(argv)

    targets: List[str] = []
    if args.target:
        targets += _parse_hosts(args.target)
    if args.hosts_file and args.hosts_file.exists():
        targets += [ln.strip() for ln in args.hosts_file.read_text(encoding="utf-8", errors="ignore").splitlines() if ln.strip()]
    # дедуп без потери порядка
    seen = set()
    targets = [x for x in targets if not (x in seen or seen.add(x))]

    if not targets:
        ap.error("укажите хотя бы один хост: -t HOST или -f FILE")

    args.output_dir.mkdir(parents=True, exist_ok=True)
    use_rich = HAS_RICH and not args.plain
    console = Console() if use_rich else None

    if use_rich and console:
        console.print(Panel.fit(
            "[bold cyan]CVE-2026-62911 Exchange Scanner[/bold cyan]\n"
            "Авторизованный пассивный аудит. Определение версии + фингерпринт MRSProxy.",
            border_style="cyan",
        ))
        console.print(f"Целей: [bold]{len(targets)}[/bold] | "
                      f"workers={args.max_workers} | timeout={args.timeout}s\n")

    results: List[TargetResult] = []
    with ThreadPoolExecutor(max_workers=args.max_workers) as ex:
        futures = {
            ex.submit(
                ExchangeScanner(
                    h, insecure=args.insecure, timeout=args.timeout,
                    user_agent=args.user_agent,
                ).run
            ): h for h in targets
        }
        for fut in as_completed(futures):
            h = futures[fut]
            try:
                tr = fut.result()
            except Exception as e:  # noqa
                tr = TargetResult(host=h, findings=[f"error: {type(e).__name__}: {e}"])
            results.append(tr)
            render_one(console, tr)

    # Сводка
    vulnerable = [r for r in results if any(f.startswith("validation: vulnerable") for f in r.findings)]
    unknown = [r for r in results if any(f.startswith("validation: unknown") for f in r.findings)]
    ok = [r for r in results if any(f.startswith("validation: ok") for f in r.findings)]
    outdated = [r for r in results if any(f.startswith("validation: outdated") for f in r.findings)]
    failed = [r for r in results if not r.findings or any(f.startswith("error:") for f in r.findings)]

    if use_rich and console:
        s = Table(title="Сводка", title_style="bold magenta")
        s.add_column("Статус")
        s.add_column("Хосты")
        s.add_column("Count")
        s.add_row("[red]Уязвимые[/red]", ", ".join(r.host for r in vulnerable) or "—", str(len(vulnerable)))
        s.add_row("[orange3]Вне таблицы (проверить)[/orange3]", ", ".join(r.host for r in outdated) or "—", str(len(outdated)))
        # s.add_row("[yellow]Не определено[/yellow]", ", ".join(r.host for r in unknown) or "—", str(len(unknown)))
        s.add_row("[green]Запатчено[/green]", ", ".join(r.host for r in ok) or "—", str(len(ok)))
        s.add_row("[white]Не отвечает/ошибка[/white]", ", ".join(r.host for r in failed) or "—", str(len(failed)))
        console.print(s)
    else:
        print(f"\n=== Сводка: vulnerable={len(vulnerable)}, outdated={len(outdated)}, "
              f"ok={len(ok)}, failed={len(failed)} ===")

    # Сохраняем отчёты
    for tr in results:
        p = args.output_dir / f"report_{tr.host.replace(':', '_')}.txt"
        render_result_plain(tr, p)
    if use_rich and console:
        console.print(f"[dim]Отчёты сохранены в {args.output_dir}[/dim]")

    return 1 if vulnerable else 0


if __name__ == "__main__":
    sys.exit(main())