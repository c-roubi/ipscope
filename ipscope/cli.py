"""Command-line interface."""

from __future__ import annotations

import asyncio
import os
import sys
from datetime import datetime
from pathlib import Path
from typing import List, Optional

import typer
from rich.console import Console
from rich.progress import BarColumn, MofNCompleteColumn, Progress, TextColumn, TimeElapsedColumn
from rich.table import Table

from ipscope import __version__
from ipscope.engine import AllSourcesDisabled, ScanOptions, Scanner
from ipscope.export import export_scan
from ipscope.inputs import expand_targets
from ipscope.keys import KeyStore, mask
from ipscope.models import IPResult, Status
from ipscope.paths import db_path
from ipscope.sources import ACTIVE_SOURCES, DEFAULT_TLS_PORTS, PRESETS, REGISTRY, default_sources, preset_sources
from ipscope.storage import Store

app = typer.Typer(add_completion=False, help="IPScope - multi-source reverse IP lookup.")
keys_app = typer.Typer(help="Manage API keys (stored in the OS keyring).")
cache_app = typer.Typer(help="Inspect or clear the lookup cache.")
app.add_typer(keys_app, name="keys")
app.add_typer(cache_app, name="cache")
index_app = typer.Typer(help="Build and query your own offline IP -> domain index.")
app.add_typer(index_app, name="index")

console = Console(stderr=True)
out = Console()

STATUS_STYLE = {
    Status.ACTIVE: "green", Status.HISTORICAL: "yellow",
    Status.DEAD: "red", Status.UNKNOWN: "dim",
}


def _version(value: bool):
    if value:
        out.print(f"ipscope {__version__}")
        raise typer.Exit()


@app.callback()
def main(
    version: bool = typer.Option(False, "--version", callback=_version, is_eager=True,
                                 help="Show version and exit."),
    home: Optional[Path] = typer.Option(None, "--home", envvar="IPSCOPE_HOME",
                                        help="Data folder (default ~/.ipscope)."),
):
    if home:
        os.environ["IPSCOPE_HOME"] = str(home)


def _store() -> Store:
    return Store(db_path())


# ---------------------------------------------------------------- scanning

SMALL_IPS = 50       # per-IP summary table up to this many IPs
SMALL_ROWS = 3000    # print domain tables up to this many rows


def _execute(store: Store, scan_id: int, ips: list[str], opts: ScanOptions, quiet: bool) -> bool:
    """Run a scan, saving each IP as it finishes. Returns True if it was interrupted."""
    keys = KeyStore().resolve_all(REGISTRY)
    if not quiet:
        console.print(f"[dim]scan #{scan_id} | {len(ips):,} IP(s) | sources: {', '.join(opts.sources)}[/]")

    progress = Progress(
        TextColumn("[bold blue]Scanning"), BarColumn(), MofNCompleteColumn(),
        TextColumn("{task.fields[found]} domains"), TimeElapsedColumn(),
        console=console, disable=quiet, transient=True,
    )
    interrupted = False
    from ipscope.results_log import ResultsLog
    rlog = ResultsLog(not os.environ.get("IPSCOPE_NO_RESULTS_TXT"))
    with progress:
        task = progress.add_task("scan", total=len(ips), found=0)
        found = 0

        def on_result(r: IPResult):
            nonlocal found
            store.save_result(scan_id, r)
            rlog.add(r.domains)
            found += len(r.domains)
            progress.update(task, advance=1, found=found)

        def on_event(level: str, msg: str):
            console.print(f"[{'yellow' if level == 'warn' else 'red'}]![/] {msg}")

        scanner = Scanner(opts, on_result=on_result, keys=keys, store=store, on_event=on_event)
        try:
            asyncio.run(scanner.run(ips, collect=False))
            store.set_status(scan_id, "done")
        except KeyboardInterrupt:
            interrupted = True
            store.set_status(scan_id, "interrupted")
        except AllSourcesDisabled as e:
            interrupted = True
            store.set_status(scan_id, "interrupted")
            console.print(f"[red]Stopped:[/] {e}")
        finally:
            rlog.close()

    st = scanner.stats
    if st.skipped_sources:
        console.print(f"[yellow]![/] skipped (not set up): {', '.join(st.skipped_sources)} "
                      f"- add a key with `ipscope keys set NAME`, or build the index with `ipscope index build FILE`")
    if not quiet:
        console.print(f"[dim]requests: {st.requests:,} | cache hits: {st.cache_hits:,} | errors: {st.errors:,}[/]")
    if interrupted:
        console.print(f"[yellow]Paused.[/] Progress saved - continue with: [bold]ipscope resume {scan_id}[/]")
    return interrupted


def _report(store: Store, scan_id: int, validate, only_active, output, quiet, roots=False, probe=False):
    status = "active" if only_active else None
    if output:
        n = export_scan(store, scan_id, output, only_active=only_active, roots_only=roots)
        console.print(f"[green]Saved {n:,} row(s) to[/] {output}")
    if quiet:
        names = store.domain_names(scan_id, status=status, roots=roots)
        if names:
            sys.stdout.write("\n".join(names) + "\n")
            sys.stdout.flush()
        return

    summ = store.summary(scan_id)
    small = summ["ips"] <= SMALL_IPS and summ["rows"] <= SMALL_ROWS
    results = store.results(scan_id) if small else None
    if summ["ips"] <= SMALL_IPS:
        _print_summary(results if results is not None else store.results(scan_id), validate)
    else:
        _print_big_summary(store, scan_id, summ, validate)
    if summ["cdn_ips"]:
        console.print(
            f"[yellow]![/] {summ['cdn_ips']:,} IP(s) belong to a CDN ({', '.join(summ['cdn_providers']) or 'CDN'}). "
            "Thousands of unrelated sites share CDN edge IPs, so those results say little about any one owner; "
            "the real origin server is hidden behind the CDN."
        )
    if output:
        return
    if not small:
        console.print(f"[dim]{summ['rows']:,} domain rows - too many to print. Save them with -o, e.g.[/] "
                      f"ipscope show {scan_id} -o results.csv")
        return
    if roots:
        _print_roots(results, only_active)
    else:
        _print_domains(results, validate, only_active, probe)


@app.command()
def scan(
    targets: Optional[List[str]] = typer.Argument(None, help="IPs, CIDRs, ASNs (AS13335), domains or URLs."),
    file: Optional[Path] = typer.Option(None, "-f", "--file", help="File with one target per line."),
    sources: Optional[str] = typer.Option(None, "-s", "--sources",
                                          help="Comma-separated sources (default: free ones + any with a key)."),
    preset: Optional[str] = typer.Option(None, "-p", "--preset",
                                         help="Source set: " + ", ".join(f"{k} ({v['help']})" for k, v in PRESETS.items())),
    active: bool = typer.Option(False, "--active",
                                help="Also contact the target: TLS certificates on many ports + direct HTTP(S)."),
    tls_ports: str = typer.Option(",".join(map(str, DEFAULT_TLS_PORTS)), "--tls-ports",
                                  help="Ports for the tls source (25/587 use SMTP STARTTLS)."),
    validate: bool = typer.Option(False, "-V", "--validate",
                                  help="Resolve every domain to check it still points at the IP."),
    only_active: bool = typer.Option(False, "--only-active",
                                     help="Keep only domains still on the IP (implies --validate)."),
    output: Optional[Path] = typer.Option(None, "-o", "--output", help="Save to .txt, .csv or .json."),
    concurrency: int = typer.Option(10, "-c", "--concurrency", min=1, max=500,
                                    help="IPs scanned in parallel."),
    timeout: float = typer.Option(15.0, "--timeout", min=1, help="Per-request timeout (s)."),
    no_cache: bool = typer.Option(False, "--no-cache", help="Ignore cached results."),
    cache_ttl: float = typer.Option(24, "--cache-ttl", min=0, help="Cache lifetime in hours."),
    probe: bool = typer.Option(False, "--probe",
                               help="Fetch each site: status, title, server, technologies (contacts the sites)."),
    probe_limit: int = typer.Option(200, "--probe-limit", min=1, help="Max domains probed per IP."),
    no_ip_info: bool = typer.Option(False, "--no-ip-info", help="Skip ASN / provider / CDN lookup."),
    roots: bool = typer.Option(False, "--roots", help="Show/export root domains only (example.co.uk)."),
    roots_only: bool = typer.Option(False, "--roots-only", help="Save one entry per root domain, not every subdomain."),
    local_first: bool = typer.Option(True, "--local-first/--no-local-first", help="Answer from your local index first; ask online sources only for IPs it does not know."),
    first_hit: bool = typer.Option(False, "--first-hit", help="Stop at the first source that finds domains (faster)."),
    skip_scanned: bool = typer.Option(False, "--skip-scanned", help="Skip IPs already scanned in earlier scans."),
    label: Optional[str] = typer.Option(None, "--label", help="Name for this scan in history."),
    allow_private: bool = typer.Option(False, "--allow-private", help="Allow private/reserved IPs."),
    max_hosts: int = typer.Option(65536, "--max-hosts", help="Largest CIDR size accepted."),
    quiet: bool = typer.Option(False, "-q", "--quiet", help="Print only domains."),
):
    """Find domains hosted on the given IP addresses. Ctrl+C pauses; `resume` continues."""
    items = list(targets or [])
    if file:
        if not file.exists():
            console.print(f"[red]File not found:[/] {file}")
            raise typer.Exit(2)
        items += file.read_text(encoding="utf-8", errors="ignore").splitlines()
    if not items and not sys.stdin.isatty():
        items += sys.stdin.read().splitlines()
    if not items:
        console.print("[red]No targets given.[/] Example: ipscope scan 8.8.8.8")
        raise typer.Exit(2)

    keys_now = KeyStore().resolve_all(REGISTRY)
    if preset and preset not in PRESETS:
        console.print(f"[red]Unknown preset:[/] {preset} (choose: {', '.join(PRESETS)})")
        raise typer.Exit(2)
    if sources:
        if preset:
            console.print("[yellow]![/] --sources given, ignoring --preset")
        src_list = [s.strip() for s in sources.split(",") if s.strip()]
    elif preset:
        src_list, preset_active = preset_sources(preset, keys_now)
        active = active or preset_active
        if not src_list:
            console.print(f"[red]Preset '{preset}' has no usable sources yet[/] "
                          "(offline needs `ipscope index build FILE`).")
            raise typer.Exit(2)
    else:
        src_list = default_sources(keys_now)
    if active:
        src_list += [s for s in ACTIVE_SOURCES if s not in src_list]
    unknown = [s for s in src_list if s not in REGISTRY]
    if unknown:
        console.print(f"[red]Unknown source(s):[/] {', '.join(unknown)} (see `ipscope sources`)")
        raise typer.Exit(2)
    try:
        ports = [int(p) for p in tls_ports.split(",") if p.strip()]
    except ValueError:
        console.print("[red]--tls-ports must be numbers, e.g. 443,8443[/]")
        raise typer.Exit(2)
    if only_active:
        validate = True

    opts = ScanOptions(sources=src_list, concurrency=concurrency, validate=validate,
                       timeout=timeout, tls_ports=ports, use_cache=not no_cache,
                       cache_ttl=cache_ttl * 3600, ip_info=not no_ip_info,
                       probe=probe, probe_limit=probe_limit, roots_only=roots_only, first_hit=first_hit,
                       local_first=local_first)

    ips, warnings = asyncio.run(expand_targets(items, allow_private=allow_private, max_hosts=max_hosts))
    for w in warnings:
        console.print(f"[yellow]![/] {w}")
    if not ips:
        console.print("[red]Nothing to scan.[/]")
        raise typer.Exit(1)

    with _store() as store:
        if skip_scanned:
            seen = store.scanned_ips()
            before = len(ips)
            ips = [ip for ip in ips if ip not in seen]
            if before - len(ips):
                console.print(f"[yellow]![/] skipped {before - len(ips):,} IP(s) already scanned before")
            if not ips:
                console.print("Every IP was already scanned. See `ipscope history`.")
                raise typer.Exit(0)
        scan_id = store.create_scan(ips, opts.to_dict(), label)
        try:
            interrupted = _execute(store, scan_id, ips, opts, quiet)
        except ValueError as e:
            store.set_status(scan_id, "interrupted")
            console.print(f"[red]{e}[/]")
            raise typer.Exit(2)
        _report(store, scan_id, validate, only_active, output, quiet, roots, probe)
    if interrupted:
        raise typer.Exit(130)


@app.command()
def resume(
    scan_id: Optional[int] = typer.Argument(None, help="Scan ID (default: latest unfinished)."),
    output: Optional[Path] = typer.Option(None, "-o", "--output"),
    only_active: bool = typer.Option(False, "--only-active"),
    roots: bool = typer.Option(False, "--roots"),
    quiet: bool = typer.Option(False, "-q", "--quiet"),
):
    """Continue a paused or crashed scan."""
    with _store() as store:
        scan_id = scan_id or store.latest_resumable()
        info = store.get_scan(scan_id) if scan_id else None
        if not info:
            console.print("[red]No scan to resume.[/] See `ipscope history`.")
            raise typer.Exit(1)
        opts = ScanOptions.from_dict(info["options"])
        pending = store.pending_ips(scan_id)
        interrupted = False
        if not pending:
            store.set_status(scan_id, "done")
            console.print(f"[green]Scan #{scan_id} is already complete.[/]")
        else:
            console.print(f"[dim]resuming scan #{scan_id}: {info['done']}/{info['total']} done[/]")
            store.set_status(scan_id, "running")
            try:
                interrupted = _execute(store, scan_id, pending, opts, quiet)
            except ValueError as e:
                store.set_status(scan_id, "interrupted")
                console.print(f"[red]{e}[/]")
                raise typer.Exit(2)
        _report(store, scan_id, opts.validate, only_active, output, quiet, roots, opts.probe)
    if interrupted:
        raise typer.Exit(130)


@app.command()
def history(limit: int = typer.Option(20, "-n", "--limit")):
    """List previous scans."""
    with _store() as store:
        rows = store.list_scans(limit)
    if not rows:
        console.print("No scans yet.")
        return
    t = Table(header_style="bold")
    for col in ("ID", "Date", "Status", "Progress", "Label"):
        t.add_column(col)
    style = {"done": "green", "interrupted": "yellow", "running": "cyan"}
    for r in rows:
        t.add_row(
            str(r["id"]),
            datetime.fromtimestamp(r["created_at"]).strftime("%Y-%m-%d %H:%M"),
            f"[{style.get(r['status'], 'white')}]{r['status']}[/]",
            f"{r['done']}/{r['total']}",
            r["label"] or "",
        )
    out.print(t)


@app.command()
def show(
    scan_id: int = typer.Argument(..., help="Scan ID from `ipscope history`."),
    output: Optional[Path] = typer.Option(None, "-o", "--output"),
    only_active: bool = typer.Option(False, "--only-active"),
    roots: bool = typer.Option(False, "--roots"),
    quiet: bool = typer.Option(False, "-q", "--quiet"),
):
    """Show or export the results of a saved scan."""
    with _store() as store:
        info = store.get_scan(scan_id)
        if not info:
            console.print(f"[red]Scan #{scan_id} not found.[/]")
            raise typer.Exit(1)
        validate = bool(info["options"].get("validate"))
        if only_active and not validate:
            console.print("[yellow]![/] this scan was run without --validate, so no domain is marked active")
        _report(store, scan_id, validate, only_active, output, quiet, roots, bool(info["options"].get("probe")))


@app.command()
def top(
    scan_id: Optional[int] = typer.Argument(None, help="Scan ID (default: all scans)."),
    n: int = typer.Option(100, "-n", "--count", min=1, help="How many IPs."),
    min_domains: int = typer.Option(50, "--min-domains", help="Only IPs with at least this many domains."),
    include_cdn: bool = typer.Option(False, "--include-cdn", help="Keep CDN edge IPs (unrelated sites)."),
    output: Optional[Path] = typer.Option(None, "-o", "--output", help="Save the IP list to a file."),
    quiet: bool = typer.Option(False, "-q", "--quiet", help="Print only IPs."),
):
    """IPs hosting the most domains - e.g. to pick busy shared-hosting servers."""
    with _store() as store:
        rows = store.top_ips(scan_id, n, min_domains, exclude_cdn=not include_cdn)
    if not rows:
        console.print(f"No IPs with {min_domains}+ domains yet. Run a scan first, or lower --min-domains.")
        raise typer.Exit(1)
    if output:
        output.write_text("\n".join(r["ip"] for r in rows) + "\n", encoding="utf-8")
        console.print(f"[green]Saved {len(rows)} IP(s) to[/] {output}")
    if quiet:
        sys.stdout.write("\n".join(r["ip"] for r in rows) + "\n")
        return
    t = Table(header_style="bold", title=f"Top {len(rows)} IPs by domains")
    for col in ("IP", "Provider", "Hosting", "Domains"):
        t.add_column(col, justify="right" if col == "Domains" else "left")
    for r in rows:
        t.add_row(r["ip"], _provider({"provider": r["provider"], "asn": r["asn"]}), r["hosting"] or "",
                  f"{r['n_domains']:,}")
    out.print(t)


@app.command()
def delete(scan_id: int = typer.Argument(...)):
    """Delete a saved scan."""
    with _store() as store:
        ok = store.delete_scan(scan_id)
    console.print(f"[green]Deleted scan #{scan_id}[/]" if ok else f"[red]Scan #{scan_id} not found[/]")


# ---------------------------------------------------------------- output tables

def _provider(info: dict) -> str:
    if not info:
        return ""
    name = info.get("provider") or ""
    asn = f"AS{info['asn']}" if info.get("asn") else ""
    return " ".join(x for x in (name, f"({asn})" if asn and name else asn) if x)


def _print_summary(results: list[IPResult], validate: bool):
    t = Table(title="Summary", header_style="bold")
    t.add_column("IP")
    t.add_column("Provider")
    t.add_column("Hosting")
    t.add_column("Domains", justify="right")
    if validate:
        t.add_column("Active", justify="right", style="green")
    t.add_column("Errors", style="red")
    for r in results:
        hosting = r.info.get("hosting", "")
        if hosting == "cdn-edge":
            hosting = "[yellow]cdn-edge[/]"
        row = [r.ip, _provider(r.info), hosting, str(len(r.domains))]
        if validate:
            row.append(str(r.count(Status.ACTIVE)))
        row.append("; ".join(f"{k}: {v}" for k, v in r.errors.items()))
        t.add_row(*row)
    console.print(t)


def _print_big_summary(store: Store, scan_id: int, summ: dict, validate: bool):
    t = Table(title="Summary", header_style="bold", show_header=False)
    t.add_column(style="dim")
    t.add_column(justify="right")
    t.add_row("IPs scanned", f"{summ['ips']:,}")
    t.add_row("IPs with domains", f"{summ['ips_with_domains']:,}")
    t.add_row("Domain rows", f"{summ['rows']:,}")
    t.add_row("Unique domains", f"{summ['domains']:,}")
    t.add_row("Root domains", f"{summ['roots']:,}")
    if validate:
        t.add_row("Active", f"[green]{summ['active']:,}[/]")
    t.add_row("CDN IPs", f"{summ['cdn_ips']:,}")
    console.print(t)

    top, _ = store.list_ips(scan_id, order="domains", limit=15)
    if top and top[0]["n_domains"]:
        tt = Table(title="Top IPs by domains", header_style="bold")
        tt.add_column("IP")
        tt.add_column("Provider")
        tt.add_column("Hosting")
        tt.add_column("Domains", justify="right")
        for r in top:
            if not r["n_domains"]:
                break
            prov = _provider({"provider": r["provider"], "asn": r["asn"]})
            tt.add_row(r["ip"], prov, r["hosting"] or "", f"{r['n_domains']:,}")
        console.print(tt)

    errors = store.error_summary(scan_id)
    if errors:
        console.print("[red]Errors per source:[/] " + ", ".join(f"{k}: {v:,} IPs" for k, v in sorted(errors.items())))


def _print_domains(results: list[IPResult], validate: bool, only_active: bool, probe: bool = False):
    for r in results:
        rows = [d for d in r.sorted_domains() if not only_active or d.status == Status.ACTIVE]
        if not rows:
            continue
        t = Table(title=f"{r.ip}  {_provider(r.info)}", header_style="bold", title_justify="left")
        t.add_column("Domain")
        if validate:
            t.add_column("Status")
        t.add_column("Conf", justify="right")
        if probe:
            t.add_column("HTTP", justify="right")
            t.add_column("Title", max_width=40, overflow="ellipsis", no_wrap=True)
            t.add_column("Tech", style="cyan", max_width=40)
        t.add_column("Sources", style="dim")
        for d in rows:
            row = [d.domain]
            if validate:
                row.append(f"[{STATUS_STYLE[d.status]}]{d.status.value}[/]")
            c = d.confidence
            row.append(f"[{'green' if c >= 70 else 'yellow' if c >= 40 else 'red'}]{c}[/]")
            if probe:
                h = d.http or {}
                if h.get("error"):
                    row += ["[red]err[/]", f"[dim]{h['error'][:40]}[/]", ""]
                elif h:
                    st = h.get("status") or ""
                    color = "green" if st and st < 400 else "red"
                    row += [f"[{color}]{st}[/]", h.get("title") or "", ", ".join(h.get("tech") or [])]
                else:
                    row += ["", "", ""]
            row.append(", ".join(sorted(d.sources)))
            t.add_row(*row)
        out.print(t)


def _print_roots(results: list[IPResult], only_active: bool):
    for r in results:
        groups: dict[str, list[str]] = {}
        for d in r.sorted_domains():
            if only_active and d.status != Status.ACTIVE:
                continue
            groups.setdefault(d.root or d.domain, []).append(d.domain)
        if not groups:
            continue
        t = Table(title=f"{r.ip}  {_provider(r.info)}", header_style="bold", title_justify="left")
        t.add_column("Root domain")
        t.add_column("Names", justify="right")
        t.add_column("Examples", style="dim", max_width=60)
        for root in sorted(groups, key=lambda k: (-len(groups[k]), k)):
            names = groups[root]
            t.add_row(root, str(len(names)), ", ".join(names[:3]) + (" …" if len(names) > 3 else ""))
        out.print(t)


# ---------------------------------------------------------------- sources

@app.command("sources")
def list_sources():
    """List available data sources."""
    keys = KeyStore().resolve_all(REGISTRY)
    defaults = default_sources(keys)
    t = Table(header_style="bold")
    for col in ("Name", "Default", "Type", "Key", "Description"):
        t.add_column(col)
    for name, cls in REGISTRY.items():
        if name == "local":
            key = "[green]index ready[/]" if name in defaults else "[dim]no index yet[/]"
        elif not cls.key_env:
            key = "-"
        elif keys.get(name):
            key = f"[green]{len(keys[name])} set[/]"
        else:
            key = "[red]required[/]" if cls.requires_key else "optional"
        t.add_row(name, "yes" if name in defaults else "",
                  "active" if cls.active else "passive", key, cls.description)
    out.print(t)


# ---------------------------------------------------------------- keys

def _keyed_source(name: str):
    cls = REGISTRY.get(name)
    if not cls or not cls.key_env:
        valid = ", ".join(n for n, c in REGISTRY.items() if c.key_env)
        console.print(f"[red]'{name}' doesn't use an API key.[/] Valid: {valid}")
        raise typer.Exit(2)
    return cls


@keys_app.command("set")
def keys_set(
    name: str = typer.Argument(..., help="Source name, e.g. virustotal."),
    key: Optional[str] = typer.Argument(None, help="The key (omit to type it hidden)."),
    add: bool = typer.Option(False, "--add", help="Add as an extra key for rotation."),
):
    """Save an API key."""
    _keyed_source(name)
    if not key:
        key = typer.prompt(f"{name} API key", hide_input=True)
    key = key.strip()
    if not key:
        raise typer.Exit(2)
    ks = KeyStore()
    if add:
        n = ks.add(name, key)
        console.print(f"[green]Added.[/] {name} now has {n} key(s) [dim]({ks.backend})[/]")
    else:
        ks.set(name, [key])
        console.print(f"[green]Saved[/] {name} key [dim]({ks.backend})[/]")


@keys_app.command("list")
def keys_list():
    """Show which sources have keys (masked)."""
    ks = KeyStore()
    t = Table(header_style="bold", caption=f"storage: {ks.backend}")
    for col in ("Source", "Keys", "From", "Env var"):
        t.add_column(col)
    for name, cls in REGISTRY.items():
        if not cls.key_env:
            continue
        keys, where = ks.resolve(name, cls.key_env)
        t.add_row(name, ", ".join(mask(k) for k in keys) or "[dim]none[/]", where or "-", cls.key_env)
    out.print(t)


@keys_app.command("delete")
def keys_delete(name: str = typer.Argument(...)):
    """Remove stored key(s) for a source."""
    _keyed_source(name)
    ok = KeyStore().delete(name)
    console.print(f"[green]Deleted {name} key(s).[/]" if ok else f"No stored key for {name}.")


# ---------------------------------------------------------------- subdomains

@app.command()
def subdomains(
    domains: Optional[List[str]] = typer.Argument(None, help="Domains, e.g. example.com"),
    file: Optional[Path] = typer.Option(None, "-f", "--file", help="File with one domain per line."),
    sources: Optional[str] = typer.Option(None, "-s", "--sources",
                                          help="Comma-separated: local, dnsrift, thc, otx, crtsh, rapiddns."),
    validate: bool = typer.Option(False, "-V", "--validate", help="Resolve each subdomain (live + IPs)."),
    output: Optional[Path] = typer.Option(None, "-o", "--output", help="Save to .txt, .csv or .json."),
    quiet: bool = typer.Option(False, "-q", "--quiet", help="Print only subdomains."),
):
    """Find known subdomains of a domain (passive: nothing is sent to the target)."""
    import csv as _csv
    import json as _json
    from ipscope.subdomains import DEFAULT_SUB_SOURCES, SUB_REGISTRY, find_subdomains

    items = list(domains or [])
    if file:
        items += [x for x in file.read_text(encoding="utf-8", errors="ignore").splitlines() if x.strip()]
    if not items:
        console.print("[red]No domains given.[/] Example: ipscope subdomains example.com")
        raise typer.Exit(2)
    src = [x.strip() for x in sources.split(",")] if sources else DEFAULT_SUB_SOURCES
    bad = [x for x in src if x not in SUB_REGISTRY]
    if bad:
        console.print(f"[red]Unknown source(s):[/] {', '.join(bad)} (choose: {', '.join(SUB_REGISTRY)})")
        raise typer.Exit(2)

    with console.status("Looking up subdomains...", spinner="dots") if not quiet else _nullctx():
        results, skipped = asyncio.run(find_subdomains(items, src, KeyStore().resolve_all(REGISTRY), validate))
    if skipped and not quiet:
        console.print(f"[dim]skipped (not set up): {', '.join(skipped)}[/]")

    rows = []
    for r in results:
        for name in sorted(r.names):
            ips = r.resolved.get(name) if validate else None
            rows.append({"domain": r.domain, "subdomain": name, "sources": sorted(r.names[name]),
                         "live": (bool(ips) if ips is not None else None) if validate else None,
                         "ips": ips or []})
    if output:
        ext = output.suffix.lower()
        output.parent.mkdir(parents=True, exist_ok=True)
        if ext == ".csv":
            with output.open("w", newline="", encoding="utf-8-sig") as f:
                w = _csv.writer(f)
                w.writerow(["domain", "subdomain", "sources", "live", "ips"])
                for x in rows:
                    w.writerow([x["domain"], x["subdomain"], ";".join(x["sources"]),
                                "" if x["live"] is None else ("yes" if x["live"] else "no"), ";".join(x["ips"])])
        elif ext == ".json":
            output.write_text(_json.dumps(rows, indent=2), encoding="utf-8")
        else:
            output.write_text("\n".join(sorted({x["subdomain"] for x in rows})) + "\n", encoding="utf-8")
        console.print(f"[green]Saved {len(rows):,} subdomain(s) to[/] {output}")
    if quiet:
        if rows:
            sys.stdout.write("\n".join(sorted({x["subdomain"] for x in rows})) + "\n")
        return
    for r in results:
        errs = "; ".join(f"{k}: {v}" for k, v in r.errors.items())
        console.print(f"[bold]{r.domain}[/]: {len(r.names):,} subdomains" + (f"  [red]{errs}[/]" if errs else ""))
        if output or not r.names:
            continue
        if len(r.names) > SMALL_ROWS:
            console.print(f"[dim]too many to print - save them with -o[/]")
            continue
        t = Table(header_style="bold")
        t.add_column("Subdomain")
        if validate:
            t.add_column("IPs")
        t.add_column("Sources", style="dim")
        for name in sorted(r.names):
            row = [name]
            if validate:
                ips = r.resolved.get(name)
                row.append(", ".join(ips[:3]) if ips else ("[red]no address[/]" if ips == [] else "[dim]?[/]"))
            row.append(", ".join(sorted(r.names[name])))
            t.add_row(*row)
        out.print(t)
    if results and any(r.names for r in results) and not output:
        console.print("[dim]Tip: reverse-scan the hosts' IPs to see what else runs on the same servers: "
                      "ipscope subdomains example.com -V -q | ipscope scan[/]")


class _nullctx:
    def __enter__(self):
        return self

    def __exit__(self, *a):
        return False


# ---------------------------------------------------------------- local index

def _fmt_bytes(n: int) -> str:
    for unit in ("B", "KB", "MB", "GB", "TB"):
        if n < 1024 or unit == "TB":
            return f"{n:,.0f} {unit}" if unit == "B" else f"{n:,.1f} {unit}"
        n /= 1024


def _index_add(files: list[Path], only: list[str] | None = None) -> None:
    from ipscope.index import LocalIndex
    try:
        import ipaddress
        for x in only or []:
            ipaddress.ip_network(x, strict=False)
    except ValueError as e:
        console.print(f"[red]--only:[/] {e}")
        raise typer.Exit(2)
    with LocalIndex() as idx:
        for f in files:
            if not f.exists():
                console.print(f"[red]File not found:[/] {f}")
                raise typer.Exit(2)
            with Progress(TextColumn("[bold blue]Importing[/] " + f.name), TextColumn("{task.fields[lines]} lines"),
                          TimeElapsedColumn(), console=console, transient=True) as pr:
                task = pr.add_task("import", lines="0")
                res = idx.import_file(f, on_progress=lambda n: pr.update(task, lines=f"{n:,}"), only=only)
            what = f"{res['records']:,} resolved records" if res["format"] == "fdns" else f"{res['names']:,} new names"
            console.print(f"[green]Imported[/] {f.name} ({res['format']}, {res['lines']:,} lines): {what}")


def _index_resolve(concurrency: int, retry_failed: bool, refresh_days, limit) -> None:
    from ipscope.index import LocalIndex
    with LocalIndex() as idx:
        total = idx.pending_count(retry_failed, refresh_days)
        if limit:
            total = min(total, limit)
        if not total:
            console.print("Nothing to resolve.")
            return
        console.print(f"[dim]resolving {total:,} names, {concurrency} at a time (Ctrl+C to pause, run again to continue)[/]")
        with Progress(TextColumn("[bold blue]Resolving"), BarColumn(), MofNCompleteColumn(),
                      TextColumn("{task.fields[ok]} with IPs"), TimeElapsedColumn(), console=console) as pr:
            task = pr.add_task("resolve", total=total, ok="0")
            try:
                st = asyncio.run(idx.resolve(
                    concurrency=concurrency, retry_failed=retry_failed, refresh_days=refresh_days, limit=limit,
                    on_progress=lambda s: pr.update(task, completed=s["done"], ok=f"{s['ok']:,}"),
                ))
            except KeyboardInterrupt:
                console.print("[yellow]Paused.[/] Run `ipscope index resolve` again to continue.")
                return
        console.print(f"[green]Done:[/] {st['ok']:,} resolved ({st['records']:,} IP records), "
                      f"{st['nx']:,} without address, {st['failed']:,} failed"
                      + (" - retry them with --retry-failed" if st["failed"] else ""))


@index_app.command("add")
def index_add(
    files: List[Path] = typer.Argument(..., help="Domain lists, zone files or Rapid7 FDNS json(.gz)."),
    only: Optional[List[str]] = typer.Option(None, "--only", help="FDNS: keep only records in these CIDRs (repeatable)."),
):
    """Import domains (or already-resolved FDNS records) into the index."""
    _index_add(files, only)


@index_app.command("resolve")
def index_resolve(
    concurrency: int = typer.Option(500, "-c", "--concurrency", min=1, max=5000, help="Parallel DNS queries."),
    retry_failed: bool = typer.Option(False, "--retry-failed", help="Also retry names whose lookup failed."),
    refresh_days: Optional[float] = typer.Option(None, "--refresh-days", help="Re-resolve names older than N days."),
    limit: Optional[int] = typer.Option(None, "--limit", help="Resolve at most N names this run."),
):
    """Resolve pending names (resumable)."""
    _index_resolve(concurrency, retry_failed, refresh_days, limit)


@index_app.command("build")
def index_build(
    files: List[Path] = typer.Argument(..., help="Domain lists, zone files or Rapid7 FDNS json(.gz)."),
    concurrency: int = typer.Option(500, "-c", "--concurrency", min=1, max=5000),
    only: Optional[List[str]] = typer.Option(None, "--only", help="FDNS: keep only records in these CIDRs (repeatable)."),
):
    """Import files and resolve everything in one go."""
    _index_add(files, only)
    _index_resolve(concurrency, False, None, None)


@index_app.command("stats")
def index_stats():
    """Show index size and progress."""
    from ipscope.index import LocalIndex
    with LocalIndex() as idx:
        s = idx.stats()
    t = Table(show_header=False, caption=s["path"])
    t.add_column(style="dim")
    t.add_column(justify="right")
    t.add_row("Names", f"{s['names']:,}")
    t.add_row("Resolved", f"[green]{s['resolved']:,}[/]")
    t.add_row("No address", f"{s['nxdomain']:,}")
    t.add_row("Failed", f"{s['failed']:,}")
    t.add_row("Pending", f"[yellow]{s['pending']:,}[/]")
    t.add_row("IP -> domain records", f"{s['records']:,}")
    t.add_row("Size on disk", _fmt_bytes(s["size_bytes"]))
    out.print(t)


@index_app.command("lookup")
def index_lookup(ip: str = typer.Argument(...)):
    """Look up one IP in the index."""
    from ipscope.index import LocalIndex
    with LocalIndex() as idx:
        rows = idx.lookup(ip)
    if not rows:
        console.print(f"No domains for {ip} in the index.")
        raise typer.Exit(1)
    for name, _ in rows:
        out.print(name, highlight=False)


@index_app.command("top")
def index_top(
    n: int = typer.Option(50, "-n", help="How many IPs to show."),
    min_domains: int = typer.Option(1, "--min-domains", help="Skip IPs with fewer domains."),
    output: Optional[Path] = typer.Option(None, "-o", "--output", help="Write the IPs to a file (one per line)."),
):
    """IPs with the most domains in your index - paste them into a scan."""
    from ipscope.index import LocalIndex
    with LocalIndex() as idx:
        rows = idx.top_ips(n, min_domains)
    if not rows:
        console.print("No IPs in the index yet. Run `index add` and `index resolve` first.")
        raise typer.Exit(1)
    if output:
        output.write_text("\n".join(ip for ip, _ in rows) + "\n", encoding="utf-8")
        console.print(f"{len(rows)} IPs -> {output} ({sum(c for _, c in rows):,} domains in total)")
        return
    t = Table(header_style="bold")
    t.add_column("IP")
    t.add_column("Domains", justify="right")
    for ip, c in rows:
        t.add_row(ip, f"{c:,}")
    out.print(t)
    console.print(f"{sum(c for _, c in rows):,} domains across these {len(rows)} IPs")


# ---------------------------------------------------------------- desktop app

@app.command()
def gui():
    """Open the desktop app."""
    from ipscope.gui.app import main as gui_main
    gui_main()


# ---------------------------------------------------------------- cache

@cache_app.command("stats")
def cache_stats():
    """Cached lookups per source."""
    with _store() as store:
        rows = store.cache_stats()
    t = Table(header_style="bold", caption=str(db_path()))
    t.add_column("Source")
    t.add_column("Cached IPs", justify="right")
    for name, n in rows:
        t.add_row(name, str(n))
    out.print(t)


@cache_app.command("clear")
def cache_clear(older_than: Optional[float] = typer.Option(None, "--older-than", help="Hours.")):
    """Delete cached lookups."""
    with _store() as store:
        n = store.cache_clear(older_than * 3600 if older_than is not None else None)
    console.print(f"[green]Removed {n} cached entr{'y' if n == 1 else 'ies'}.[/]")


if __name__ == "__main__":
    app()
