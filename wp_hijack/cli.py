"""
wp-Hijack CLI — entry point.
Commands: scan, update-db, show-config
"""



from __future__ import annotations









import sys as _sys



if _sys.platform == "win32":



    for _s in (_sys.stdout, _sys.stderr):



        if hasattr(_s, "reconfigure"):



            try:



                _s.reconfigure(encoding="utf-8", errors="replace")



            except Exception:



                pass







import asyncio



import json



import pathlib



import sys



from typing import Optional







import typer



from rich.panel import Panel



from rich.text import Text



from rich import print as rprint







from . import __version__, __author__, __github__



from .config  import load_config, is_pdf_enabled



from .scanner import Scanner



from .ui      import print_banner, console



from .ui.theme import BRAND_GREEN, ACCENT_BLUE, BRAND_ORANGE



from .reporting import (



    write_json_report, write_html_report, write_pdf_report, write_markdown_report,



    print_findings_summary, print_finding_detail, print_summary,



    print_users, print_exposed_files,



)







app = typer.Typer(



    name="wp-hijack",



    help="[bold #FF6B35]wp-Hijack[/] — WordPress Vulnerability Scanner & Exploitation Framework",



    rich_markup_mode="rich",



    add_completion=False,



    pretty_exceptions_show_locals=False,



)











def _version_callback(value: bool) -> None:



    if value:



        typer.echo(f"wp-hijack v{__version__}")



        raise typer.Exit()











@app.callback(invoke_without_command=True)



def _main(



    ctx: typer.Context,



    version: Optional[bool] = typer.Option(



        None, "--version", "-v",



        callback=_version_callback,



        is_eager=True,



        help="Show version and exit.",



    ),



) -> None:



    if ctx.invoked_subcommand is None and not version:



        typer.echo(ctx.get_help())











@app.command(name="vi", hidden=True)

def _vi_alias(ctx: typer.Context) -> None:

    """Alias: show the wp-Hijack banner and command overview."""

    from . import __version__

    print_banner(__version__)

    typer.echo(ctx.parent.get_help() if ctx.parent else "")





def _resolve_output(base: str, suffix: str, target: str) -> pathlib.Path:



    """Build a default output path from target hostname."""



    import re



    host = re.sub(r"https?://", "", target).split("/")[0].replace(".", "_")



    return pathlib.Path(base) / f"wp_hijack_{host}{suffix}"











def _apply_cfg_overrides(



    cfg: dict,



    *,



    no_ai: bool,



    no_confirm: bool,



    cautious: bool,



    model: Optional[str],



    provider: Optional[str],



) -> None:



    """Apply CLI flag overrides to the loaded config dict (in-place)."""



    _OLLAMA_PREFIXES = (



        "llama", "mistral", "gemma", "phi", "qwen", "deepseek", "codellama",



        "dolphin", "vicuna", "orca", "tinyllama", "wizardlm",



        "nvidia/", "meta/", "mistralai/", "deepseek-ai/", "minimaxai/",



        "moonshotai/", "z-ai/", "google/", "anthropic/", "cohere/",



    )



    if no_ai:



        cfg.setdefault("ai", {})["enabled"] = False



    if no_confirm:



        cfg.setdefault("confirmation", {})["run_confirmations"] = False



    if cautious:



        cfg.setdefault("confirmation", {})["allow_cautious_tests"] = True



    if model:



        cfg.setdefault("ai", {})["model"] = model



        if provider is None and ("/" in model or ":" in model or model.startswith(_OLLAMA_PREFIXES)):



            ai_cfg = cfg.setdefault("ai", {})



            if ai_cfg.get("provider", "openai") not in ("ollama", "openai-compat"):



                ai_cfg["provider"] = "ollama"



                ollama_url = cfg.get("ollama", {}).get("base_url", "http://localhost:11434")



                ai_cfg["base_url"] = ollama_url.rstrip("/") + "/v1"



                ai_cfg["api_key"] = "ollama"



    if provider:



        cfg.setdefault("ai", {})["provider"] = provider



        if provider == "ollama":



            ollama_url = cfg.get("ollama", {}).get("base_url", "http://localhost:11434")



            cfg["ai"]["base_url"] = ollama_url.rstrip("/") + "/v1"



            cfg["ai"].setdefault("api_key", "ollama")











def _write_all_reports(



    results: dict,



    target: str,



    output_dir: str,



    cfg: dict,



    *,



    markdown: bool = False,



) -> dict[str, pathlib.Path]:



    """Write JSON + HTML + PDF reports. Return paths dict."""



    from .ui.status import phase_header







    outdir    = pathlib.Path(output_dir)



    json_path = _resolve_output(str(outdir), ".json", target)



    html_path = _resolve_output(str(outdir), ".html", target)



    pdf_path  = _resolve_output(str(outdir), ".pdf",  target)







    confirmed = results["confirmed"]



    users     = results["users"]



    exposed   = results["exposed"]









    recon = results.get("recon")



    write_json_report(



        json_path,



        target=target,



        scan_meta={



            "wp_version": results["cms_info"].version if results["cms_info"] else None,



            "recon": {



                "ip":          recon.ip          if recon else None,



                "reverse_dns": recon.reverse_dns if recon else None,



                "country":     recon.country     if recon else None,



                "region":      recon.region      if recon else None,



                "city":        recon.city        if recon else None,



                "org":         recon.org         if recon else None,



                "server":      recon.server      if recon else None,



                "powered_by":  recon.powered_by  if recon else None,



                "page_title":  recon.page_title  if recon else None,



                "tech_stack":  recon.tech_stack  if recon else [],



                "ssl_issuer":  recon.ssl_issuer  if recon else None,



                "ssl_expiry":  recon.ssl_expiry  if recon else None,



                "ssl_valid":   recon.ssl_valid   if recon else None,



            },



        },



        confirmed_findings=confirmed,



        users=users,



        exposed_files=exposed,



        xmlrpc=results["xmlrpc"],



        rest_api=results["rest_api"],



        login_sec=results["login_sec"],



        waf=results["waf"],



        cms_info=results["cms_info"],



        ai_summary=results.get("ai_summary"),



        risk_score=results.get("risk_score"),



    )



    console.print(f"[scan.done]  ✔ JSON report:[/] [white]{json_path}[/]")









    try:



        write_html_report(



            html_path,



            target=target,



            confirmed_findings=confirmed,



            users=users,



            exposed_files=exposed,



            cms_info=results["cms_info"],



            waf=results["waf"],



            elapsed=results["elapsed"],



            ai_summary=results.get("ai_summary"),



            risk_score=results.get("risk_score"),



        )



        console.print(f"[scan.done]  ✔ HTML report:[/] [white]{html_path}[/]")



    except Exception as exc:



        console.print(f"[scan.warn]  ⚠ HTML report failed: {exc}[/]")



        html_path = None









    if html_path and html_path.exists():



        try:



            write_pdf_report(pdf_path, html_path=html_path, scan_results=results)



            console.print(f"[scan.done]  ✔ PDF  report:[/] [white]{pdf_path}[/]")



        except Exception as exc:



            console.print(f"[scan.warn]  ⚠ PDF generation failed: {exc}[/]")



            pdf_path = None









    if markdown or cfg.get("reporting", {}).get("markdown_enabled", False):



        md_path = _resolve_output(str(outdir), ".md", target)



        try:



            write_markdown_report(



                md_path,



                target=target,



                scan_meta={"wp_version": results["cms_info"].version if results["cms_info"] else None},



                confirmed_findings=confirmed,



                users=users,



                exposed_files=exposed,



                xmlrpc=results["xmlrpc"],



                rest_api=results["rest_api"],



                login_sec=results["login_sec"],



                waf=results["waf"],



                cms_info=results["cms_info"],



                ai_summary=results.get("ai_summary"),



                risk_score=results.get("risk_score"),



                attack_chain=results.get("attack_chain"),



                elapsed=results["elapsed"],



            )



            console.print(f"[scan.done]  ✔ MD   report:[/] [white]{md_path}[/]")



        except Exception as exc:



            console.print(f"[scan.warn]  ⚠ Markdown report failed: {exc}[/]")







    return {"json": json_path, "html": html_path, "pdf": pdf_path}











def _ai_analyze_prompt(results: dict, cfg: dict) -> None:



    """Ask user interactively if they want AI analysis. Run it if yes."""



    import asyncio as _asyncio







    ai_cfg = cfg.get("ai", {})



    if not ai_cfg.get("enabled", True):



        return







    console.print()



    try:



        ans = console.input(



            f"[bold #FFD700]  AI se analyze karwana hai? (Results ka AI analysis chahiye?) [Y/n] ›[/] "



        ).strip().lower()



    except (EOFError, KeyboardInterrupt):



        return







    if ans in ("n", "no", "nahi", "nhi", "nope"):



        console.print("[dim]  AI analysis skipped.[/]")



        return









    console.print(f"\n[scan.phase]  Generating AI analysis...[/]")



    from .ai import generate_summary, score_risk, generate_attack_chain







    confirmed = results.get("confirmed", [])



    target    = results.get("target", "")







    ai_results: dict = {"summary": None, "risk": None, "chain": None}







    async def _run_ai() -> None:



        scan_ctx = {



            "target": target,



            "confirmed_count": sum(1 for c in confirmed if getattr(c, "status", None) and c.status.value == "CONFIRMED"),



            "potential_count": sum(1 for c in confirmed if getattr(c, "status", None) and c.status.value == "POTENTIAL"),



            "critical_count":  sum(1 for c in confirmed if getattr(c, "severity", "").upper() == "CRITICAL"),



            "findings": confirmed,



        }



        try:



            ai_results["summary"] = await generate_summary(scan_ctx, ai_cfg)



        except Exception as exc:



            _exc_str = str(exc)



            if "connection" in _exc_str.lower() or "refused" in _exc_str.lower() or "connect" in _exc_str.lower():



                _base_url = ai_cfg.get("base_url", "http://localhost:11434")



                ai_results["summary"] = f"Ollama is not reachable at {_base_url}. Make sure Ollama is running (`ollama serve`)."



            else:



                ai_results["summary"] = f"(AI summary failed: {_exc_str})"



        try:



            if confirmed:



                _findings_list = [c.finding if hasattr(c, "finding") else c for c in confirmed]



                ai_results["risk"] = await score_risk(_findings_list, target, ai_cfg)



        except Exception:



            pass



        try:



            if confirmed:



                _findings_list = [c.finding if hasattr(c, "finding") else c for c in confirmed]



                waf_name = results.get("waf") and results["waf"].detected and results["waf"].name or None



                ai_results["chain"] = await generate_attack_chain(_findings_list, target, waf_name, ai_cfg)



        except Exception:



            pass







    _asyncio.run(_run_ai())









    results["ai_summary"]   = ai_results["summary"]



    results["risk_score"]   = ai_results["risk"]



    results["attack_chain"] = ai_results["chain"]







    if ai_results["summary"]:



        from rich.panel import Panel as _Panel



        console.print(_Panel(



            ai_results["summary"],



            title=f"[bold #FFD700]AI Security Analysis[/]",



            border_style=ACCENT_BLUE,



            padding=(1, 2),



        ))







    if ai_results["risk"]:



        score = ai_results["risk"].get("score", "?") if isinstance(ai_results["risk"], dict) else "?"



        console.print(f"  [scan.done]Risk Score:[/] [bold white]{score}/10[/]")







    console.print()











def _do_single_scan(



    target: str,



    cfg: dict,



    output_dir: str,



    *,



    verbose: bool = False,



    chat: bool = False,



    markdown: bool = False,



    ask_ai: bool = True,



) -> dict:



    """
    Run one target scan end-to-end.
    Returns a summary dict for bulk reporting.
    """



    from .ui.status import phase_header







    if not target.startswith(("http://", "https://")):



        target = "https://" + target









    from urllib.parse import urlparse as _urlparse



    _parsed_target = _urlparse(target)



    _hostname = _parsed_target.hostname or ""



    if not _hostname or "." not in _hostname or len(_hostname.split(".")[-1]) < 2:



        _tld = _hostname.split(".")[-1] if "." in _hostname else _hostname



        console.print(f"\n[scan.error]  Invalid target URL: [bold white]{target}[/]")



        if len(_tld) < 2:



            console.print(



                f"[scan.warn]   TLD [bold white].{_tld}[/] looks like a typo — "



                f"did you mean a different extension? (e.g. [bold white].co.kr[/], [bold white].com[/])"



            )



        console.print("[scan.warn]   Aborting scan.\n")



        return {"target": target, "status": "INVALID_URL", "confirmed": 0, "potential": 0, "elapsed": 0.0}







    console.print(f"[scan.target]  Target:[/] [bold white]{target}[/]")



    console.print()







    scanner = Scanner.__new__(Scanner)
    scanner.cfg = cfg
    scanner._target = ""
    scanner._results = {}
    scanner._notifier = None

    # Wire Telegram notifier from config
    _tg_cfg = cfg.get("telegram", {})
    if _tg_cfg.get("enabled"):
        try:
            from .telegram.notifier import TelegramNotifier as _TGN
            scanner._notifier = _TGN(_tg_cfg)
        except Exception as _tg_err:
            console.print(f"[dim]  Telegram notifier init failed: {_tg_err}[/]")







    try:



        results = asyncio.run(scanner.scan(target))



    except KeyboardInterrupt:



        console.print("\n[scan.error]  Scan interrupted by user.[/]")



        raise typer.Exit(1)



    except Exception as exc:



        console.print(f"\n[scan.error]  Scan failed: {exc}[/]")



        if verbose:



            import traceback; traceback.print_exc()



        return {"target": target, "status": "ERROR", "error": str(exc),



                "confirmed": 0, "potential": 0, "elapsed": 0.0}









    phase_header("Results")







    confirmed = results["confirmed"]



    users     = results["users"]



    exposed   = results["exposed"]







    print_findings_summary(confirmed)







    if verbose:



        for cf in confirmed:



            print_finding_detail(cf)







    print_users(users)



    print_exposed_files(exposed)







    c_count = sum(1 for cf in confirmed if cf.status.value == "CONFIRMED")



    p_count = sum(1 for cf in confirmed if cf.status.value == "POTENTIAL")







    print_summary(



        target=target,



        total_checks=len(confirmed) + len(exposed),



        confirmed=c_count,



        potential=p_count,



        elapsed=results["elapsed"],



    )









    if ask_ai:



        _ai_analyze_prompt(results, cfg)









    report_paths = _write_all_reports(results, target, output_dir, cfg, markdown=markdown)



    console.print()

    # Telegram: send the final report PDF/HTML
    if getattr(scanner, "_notifier", None):
        _html_p = report_paths.get("html")
        _pdf_p  = report_paths.get("pdf")
        if _html_p and pathlib.Path(str(_html_p)).exists():
            try:
                asyncio.run(scanner._notifier.send_report(_html_p, _pdf_p))
            except Exception as _tg_send_err:
                console.print(f"[dim]  Telegram report send failed: {_tg_send_err}[/]")









    if chat and cfg.get("ai", {}).get("enabled", True):



        _run_chat_session(results, cfg)









    sev_order = {"CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "LOW": 1, "INFO": 0}



    top_sev = "CLEAN"



    for cf in confirmed:



        sev = getattr(cf, "severity", "INFO").upper()



        if sev_order.get(sev, 0) > sev_order.get(top_sev, -1):



            top_sev = sev







    recon = results.get("recon")



    return {



        "target":    target,



        "status":    "OK",



        "ip":        recon.ip if recon else "",



        "cms":       results["cms_info"].cms.value if results.get("cms_info") else "?",



        "waf":       (results["waf"].name or "Yes") if results.get("waf") and results["waf"].detected else "—",



        "confirmed": c_count,



        "potential": p_count,



        "top_sev":   top_sev,



        "elapsed":   results["elapsed"],



        "json":      report_paths.get("json"),



        "html":      report_paths.get("html"),



        "pdf":       report_paths.get("pdf"),



    }













@app.command()



def scan(



    target: Optional[str] = typer.Argument(None, help="Target URL (e.g. https://example.com)"),



    file: Optional[str]   = typer.Option(None, "--file", "-f",



                                         help="Text file with one URL per line for bulk scanning"),



    config: Optional[str] = typer.Option(None, "--config", "-c", help="Path to config.json"),



    output_dir: str        = typer.Option("./reports", "--output", "-o", help="Output directory for reports"),



    no_ai: bool            = typer.Option(False, "--no-ai", help="Disable AI features for this run"),



    no_confirm: bool       = typer.Option(False, "--no-confirm", help="Skip active confirmation tests"),



    cautious: bool         = typer.Option(False, "--cautious", help="Enable CAUTIOUS-level confirmation tests"),



    markdown: bool         = typer.Option(False, "--markdown", "-m", help="Write Markdown report"),



    chat: bool             = typer.Option(False, "--chat", help="Interactive AI chat after scan"),



    model: Optional[str]   = typer.Option(None, "--model", help="Override AI model for this run"),



    provider: Optional[str]= typer.Option(None, "--provider", help="Override AI provider"),



    verbose: bool          = typer.Option(False, "--verbose", help="Print detailed finding cards"),



    yes_ai: bool           = typer.Option(False, "--yes-ai", "-y", help="Auto-yes AI analysis (skip prompt)"),



    no_ai_prompt: bool     = typer.Option(False, "--no-ai-prompt", help="Skip AI analysis prompt"),



) -> None:



    """Scan a WordPress target (or bulk scan from --file site.txt)."""









    if not target and not file:



        console.print("[scan.error]  Provide a target URL or --file with a list of URLs.[/]")



        console.print("  Example: [bold white]wp-hijack scan https://example.com[/]")



        console.print("  Example: [bold white]wp-hijack scan --file targets.txt[/]")



        raise typer.Exit(1)







    print_banner(__version__)







    cfg = load_config(config)



    _apply_cfg_overrides(cfg, no_ai=no_ai, no_confirm=no_confirm, cautious=cautious,



                         model=model, provider=provider)









    targets: list[str] = []



    if file:



        fpath = pathlib.Path(file)



        if not fpath.exists():



            console.print(f"[scan.error]  File not found: {fpath}[/]")



            raise typer.Exit(1)



        lines = fpath.read_text(encoding="utf-8", errors="ignore").splitlines()



        for ln in lines:



            ln = ln.strip()



            if ln and not ln.startswith("#"):



                targets.append(ln)



        console.print(f"[scan.phase]  Bulk mode — [bold white]{len(targets)}[/] targets from [white]{fpath}[/]\n")



    if target:



        targets.insert(0, target)







    if not targets:



        console.print("[scan.error]  No valid targets found.[/]")



        raise typer.Exit(1)







    bulk_results: list[dict] = []



    _is_bulk = len(targets) > 1









    for idx, tgt in enumerate(targets, 1):



        if _is_bulk:



            console.rule(f"[bold {BRAND_ORANGE}]  [{idx}/{len(targets)}]  {tgt}  [/]")



            console.print()









        _ask_ai = False if no_ai_prompt else (True if yes_ai else (not _is_bulk))



        if yes_ai:





            _ask_ai = False



            cfg.setdefault("ai", {})["enabled"] = True







        summary = _do_single_scan(



            tgt,



            cfg,



            output_dir,



            verbose=verbose,



            chat=chat and not _is_bulk,



            markdown=markdown,



            ask_ai=_ask_ai,



        )



        bulk_results.append(summary)









    if _is_bulk:



        from rich.table import Table as _Table



        from rich.text  import Text  as _Text







        _SEV_COLOR = {



            "CRITICAL": "#E74C3C", "HIGH": "#E67E22", "MEDIUM": "#F39C12",



            "LOW": "#2ECC71", "INFO": "#3498DB", "CLEAN": "#00FF41",



        }







        console.rule()



        tbl = _Table(



            title=f"[bold {BRAND_GREEN}]Bulk Scan Summary — {len(targets)} targets[/]",



            border_style=ACCENT_BLUE,



            header_style=f"bold {BRAND_ORANGE}",



            show_lines=True,



        )



        tbl.add_column("#",         width=4,  justify="right", style="dim")



        tbl.add_column("Target",    min_width=28)



        tbl.add_column("IP",        width=18, style="dim white")



        tbl.add_column("CMS",       width=12)



        tbl.add_column("WAF",       width=14)



        tbl.add_column("Confirmed", width=10, justify="center")



        tbl.add_column("Potential", width=10, justify="center")



        tbl.add_column("Top Sev",   width=10, justify="center")



        tbl.add_column("Time",      width=8,  justify="right", style="dim")



        tbl.add_column("Reports",   min_width=6, justify="center")







        total_c = total_p = 0



        for i, r in enumerate(bulk_results, 1):



            sev   = r.get("top_sev", "CLEAN")



            color = _SEV_COLOR.get(sev, "white")



            c_val = str(r["confirmed"]) if r["status"] == "OK" else "ERR"



            p_val = str(r["potential"]) if r["status"] == "OK" else "ERR"



            total_c += r.get("confirmed", 0)



            total_p += r.get("potential", 0)



            reps = []



            if r.get("json"): reps.append("JSON")



            if r.get("html"): reps.append("HTML")



            if r.get("pdf"):  reps.append("PDF")



            tbl.add_row(



                str(i),



                r["target"],



                r.get("ip", ""),



                r.get("cms", "?"),



                r.get("waf", "—"),



                f"[bold {'#E74C3C' if r['confirmed'] else '#00FF41'}]{c_val}[/]",



                f"[bold {'#FFD700' if r['potential'] else 'dim'}]{p_val}[/]",



                f"[bold {color}]{sev}[/]",



                f"{r.get('elapsed', 0):.1f}s",



                " ".join(reps),



            )







        console.print(tbl)



        console.print(



            f"\n  [bold {BRAND_GREEN}]Total:[/]  "



            f"Confirmed: [bold {'#E74C3C' if total_c else '#00FF41'}]{total_c}[/]  "



            f"Potential: [bold {'#FFD700' if total_p else 'dim'}]{total_p}[/]  "



            f"Reports in: [white]{output_dir}[/]\n"



        )













@app.command(name="update-db")



def update_db(



    years: Optional[str] = typer.Option(None, "--years", help="Comma-separated years, e.g. 2023,2024,2025"),



    config: Optional[str] = typer.Option(None, "--config", "-c"),



) -> None:



    """Download NVD bulk feeds and update the local vulnerability database."""



    print_banner(__version__)



    console.print("[scan.phase]  Updating vulnerability database from NVD...[/]\n")







    from .vulndb import update_vulndb



    year_list = None



    if years:



        year_list = [int(y.strip()) for y in years.split(",") if y.strip().isdigit()]







    try:



        summary = asyncio.run(update_vulndb(years=year_list))



        console.print(f"[scan.done]  ✔ Bundled entries:   {summary['bundled']}[/]")



        console.print(f"[scan.done]  ✔ NVD new entries:   {summary['nvd_new']}[/]")



        console.print(f"[scan.done]  ✔ Years processed:   {summary['years']}[/]")



    except Exception as exc:



        console.print(f"[scan.error]  Update failed: {exc}[/]")



        raise typer.Exit(1)













@app.command(name="model-list")



def model_list(



    config: Optional[str] = typer.Option(None, "--config", "-c"),



    url: Optional[str] = typer.Option(None, "--url", "-u", help="Ollama base URL (e.g. http://localhost:11434)"),



) -> None:



    """List all models available on the local Ollama server."""



    from rich.table import Table



    from .ai.ollama_models import fetch_ollama_models, format_size, get_ollama_base_url







    print_banner(__version__)







    cfg = load_config(config)



    base_url = url or get_ollama_base_url(cfg)







    console.print(f"[scan.phase]  Querying Ollama at:[/] [bold white]{base_url}[/]\n")







    try:



        models = asyncio.run(fetch_ollama_models(base_url))



    except ConnectionError as exc:



        console.print(f"[scan.error]  {exc}[/]")



        raise typer.Exit(1)







    if not models:



        console.print("[scan.warn]  No models found. Pull one with: [bold white]ollama pull llama3.2[/]")



        raise typer.Exit(0)







    tbl = Table(



        title=f"[bold {BRAND_GREEN}]Ollama Models — {base_url}[/]",



        border_style=ACCENT_BLUE,



        header_style=f"bold {BRAND_ORANGE}",



        show_lines=False,



    )



    tbl.add_column("#",         style="dim", width=4, justify="right")



    tbl.add_column("Model Name", style=f"bold white", min_width=28)



    tbl.add_column("Size",       style=f"bold {ACCENT_BLUE}", justify="right", width=10)



    tbl.add_column("Family",     style="cyan",   width=14)



    tbl.add_column("Params",     style="magenta", width=10)



    tbl.add_column("Quant",      style="yellow",  width=10)



    tbl.add_column("Modified",   style="dim",     width=20)







    current_model = cfg.get("ai", {}).get("model", "")







    for idx, m in enumerate(models, 1):



        name     = m.get("name", "unknown")



        size     = format_size(m.get("size", 0))



        details  = m.get("details", {})



        family   = details.get("family", "")



        params   = details.get("parameter_size", "")



        quant    = details.get("quantization_level", "")



        modified = (m.get("modified_at") or "")[:10]



        marker   = f"[bold {BRAND_GREEN}]✔ {name}[/]" if name == current_model or name.split(":")[0] == current_model else name



        tbl.add_row(str(idx), marker, size, family, params, quant, modified)







    console.print(tbl)



    console.print(f"\n[dim]Currently active model in config: [bold white]{current_model or '(not set)'}[/][/]")



    console.print(f"[dim]To select a model run: [bold white]wp-hijack model-select[/][/]")



    console.print()













@app.command(name="model-select")



def model_select(



    config: Optional[str] = typer.Option(None, "--config", "-c"),



    url: Optional[str] = typer.Option(None, "--url", "-u", help="Ollama base URL"),



    name: Optional[str] = typer.Option(None, "--name", "-n", help="Model name to select without interactive prompt"),



) -> None:



    """Interactively select an Ollama model and save it to config.json."""



    import re



    from .ai.ollama_models import fetch_ollama_models, format_size, get_ollama_base_url







    print_banner(__version__)







    from .config import _find_config



    if config:



        cfg_path = pathlib.Path(config)



    else:



        found = _find_config()



        cfg_path = found if found else (pathlib.Path.cwd() / "config.json")



    cfg = load_config(str(cfg_path)) if cfg_path.exists() else load_config()



    base_url = url or get_ollama_base_url(cfg)







    console.print(f"[scan.phase]  Querying Ollama at:[/] [bold white]{base_url}[/]\n")







    try:



        models = asyncio.run(fetch_ollama_models(base_url))



    except ConnectionError as exc:



        console.print(f"[scan.error]  {exc}[/]")



        raise typer.Exit(1)







    if not models:



        console.print("[scan.warn]  No models found. Pull one first: [bold white]ollama pull llama3.2[/]")



        raise typer.Exit(0)







    model_names = [m.get("name", "") for m in models]









    if name:



        chosen = name if name in model_names else None





        if not chosen:



            chosen = next((n for n in model_names if n.split(":")[0] == name.split(":")[0]), None)



        if not chosen:



            console.print(f"[scan.error]  Model [bold]{name}[/] not found. Available: {', '.join(model_names)}[/]")



            raise typer.Exit(1)



    else:





        console.print(f"[bold {BRAND_GREEN}]Available Ollama models:[/]\n")



        for i, m in enumerate(models, 1):



            details = m.get("details", {})



            params  = details.get("parameter_size", "")



            quant   = details.get("quantization_level", "")



            tag     = f"  [dim]{params} · {quant}[/]" if params else ""



            console.print(f"  [bold {ACCENT_BLUE}]{i:>3}.[/]  [bold white]{m['name']}[/]{tag}")







        console.print()



        while True:



            raw = console.input(f"[bold {BRAND_GREEN}]Select model (number or name) ›[/] ").strip()



            if not raw:



                continue



            if raw.isdigit():



                idx = int(raw) - 1



                if 0 <= idx < len(models):



                    chosen = models[idx]["name"]



                    break



                console.print(f"[scan.warn]  Enter a number between 1 and {len(models)}[/]")



            elif raw in model_names:



                chosen = raw



                break



            else:





                match = next((n for n in model_names if n.split(":")[0] == raw.split(":")[0]), None)



                if match:



                    chosen = match



                    break



                console.print(f"[scan.warn]  Model [bold]{raw}[/] not found. Try again.[/]")









    cfg["ai"]["model"]    = chosen



    cfg["ai"]["provider"] = "ollama"



    cfg["ai"]["base_url"] = base_url.rstrip("/") + "/v1"



    cfg["ai"].setdefault("api_key", "ollama")



    cfg.setdefault("ollama", {})["default_model"] = chosen



    cfg["ollama"]["base_url"] = base_url







    cfg_path.write_text(json.dumps(cfg, indent=2), encoding="utf-8")







    console.print(f"\n[scan.done]  ✔ Model set to:[/] [bold white]{chosen}[/]")



    console.print(f"[scan.done]  ✔ Provider:    [/] [bold white]ollama[/]")



    console.print(f"[scan.done]  ✔ Ollama URL:  [/] [bold white]{base_url}[/]")



    console.print(f"[scan.done]  ✔ Config saved:[/] [white]{cfg_path}[/]")



    console.print()













@app.command(name="show-config")



def show_config(



    config: Optional[str] = typer.Option(None, "--config", "-c"),



) -> None:



    """Display the current configuration (with API keys masked)."""



    cfg = load_config(config)





    ai = cfg.get("ai", {})



    if ai.get("api_key") and not ai["api_key"].startswith("sk-YOUR"):



        masked = ai["api_key"][:8] + "****" + ai["api_key"][-4:]



        cfg["ai"]["api_key"] = masked







    print_banner(__version__)



    console.print(Panel(



        json.dumps(cfg, indent=2),



        title=f"[bold {BRAND_ORANGE}]wp-Hijack Configuration[/]",



        border_style=ACCENT_BLUE,



    ))











def _run_chat_session(results: dict, cfg: dict) -> None:



    """Launch an interactive streaming AI chat about scan results."""



    import asyncio as _asyncio



    from .ai import ScanChat



    from rich.panel    import Panel    as _Panel



    from rich.text     import Text     as _Text



    from rich.markdown import Markdown as _MD



    from rich.live     import Live     as _Live







    ai_cfg = cfg.get("ai", {})



    session = ScanChat(results, ai_cfg)







    console.print()



    console.print(_Panel(



        _Text.from_markup(



            "[bold #00FF41]AI Security Analyst[/] — Interactive Chat\n"



            "[dim]Ask anything about this scan. Type [bold white]exit[/] or [bold white]quit[/] to stop.[/]"



        ),



        border_style=ACCENT_BLUE,



        expand=False,



    ))



    console.print()







    async def _chat_loop() -> None:

        """Single event loop that runs the entire interactive chat session.

        Keeping everything inside one asyncio.run() call prevents the
        'Event loop is closed' RuntimeError that occurs when httpx background
        cleanup tasks are scheduled after asyncio.run() has already torn down
        the loop (the old per-question asyncio.run() pattern).
        """

        while True:

                                                                            

                                                                             

            try:

                question = await _asyncio.to_thread(

                    lambda: console.input(f"[bold {BRAND_GREEN}]You ›[/] ").strip()

                )

            except (EOFError, KeyboardInterrupt):

                break



            if not question:

                continue



            if question.lower() in ("exit", "quit", "q"):

                console.print("[dim]Chat ended.[/]")

                break



            buf = ""



            with _Live(

                _Text.from_markup(

                    f"[bold {ACCENT_BLUE}]AI › [/][dim]thinking…[/]"

                ),

                console=console,

                refresh_per_second=12,

                transient=True,

            ) as live:

                async for chunk in session.ask_stream(question):

                    buf += chunk

                    preview = buf.replace("\n", " ")[-120:]

                    live.update(

                        _Text.from_markup(

                            f"[bold {ACCENT_BLUE}]AI › [/][dim]{preview}…[/]"

                        )

                    )



            console.print(

                _Panel(

                    _MD(buf),

                    border_style=ACCENT_BLUE,

                    title=f"[bold {ACCENT_BLUE}]AI Security Analyst[/]",

                    title_align="left",

                    padding=(1, 2),

                )

            )

            console.print()







    _asyncio.run(_chat_loop())













@app.command()



def chat_report(



    report: str = typer.Argument(..., help="Path to a wp-Hijack JSON report file"),



    config: Optional[str] = typer.Option(None, "--config", "-c", help="Path to config.json"),



) -> None:



    """Load a saved scan report and start an interactive AI chat session about it."""



    import json as _json







    print_banner(__version__)



    cfg = load_config(config)







    report_path = pathlib.Path(report)



    if not report_path.exists():



        console.print(f"[scan.error]  Report not found: {report_path}[/]")



        raise typer.Exit(1)







    with open(report_path, encoding="utf-8") as fh:



        raw = _json.load(fh)









    scan_results = {



        "target":    raw.get("target", "unknown"),



        "cms_info":  _DictProxy(raw.get("cms", {})),



        "waf":       _DictProxy(raw.get("waf", {})),



        "confirmed": [],



        "users":     raw.get("users", []),



        "exposed":   raw.get("exposed_files", []),



        "ai_summary": raw.get("ai_summary"),



        "risk_score": raw.get("risk_score"),



    }





    for v in raw.get("vulnerabilities", []):



        scan_results["confirmed"].append(_DictProxy(v))







    _run_chat_session(scan_results, cfg)





                                                                               



@app.command()



def pwn(



    target: str = typer.Argument(..., help="Target URL or IP (e.g. http://target.com)"),



    config: Optional[str] = typer.Option(None, "--config", "-c", help="Path to config.json"),



    max_steps: Optional[int] = typer.Option(None, "--max-steps", "-n",



                                             help="Optional step cap (default: unlimited — agent runs until target is compromised)"),



    output: Optional[str] = typer.Option(None, "--output", "-o",



                                          help="Directory to save agent report JSON"),



    model: Optional[str] = typer.Option(None, "--model", "-m",



                                         help="AI model override"),



    no_ai: bool = typer.Option(False, "--no-ai", help="Disable AI (dry-run tool check only)"),



) -> None:



    """

    [bold #FF6B35]AUTONOMOUS AI PENTESTING AGENT.[/]

    The agent runs nmap, whatweb, nikto, gobuster, wpscan, sqlmap and more —

    reads the output, decides next steps, writes and executes Python exploits,

    then produces a full findings report. No human prompts needed.

    """



    import asyncio as _asyncio



    import json as _json



    import pathlib as _pathlib







    print_banner(__version__)



    cfg = load_config(config)







                          



    if model:



        cfg["ai"]["model"] = model



    if no_ai:



        cfg["ai"]["enabled"] = False



        console.print("[yellow]AI disabled — showing available tools only.[/yellow]")







                              



    agent_cfg: dict = cfg.get("agent", {})



    if max_steps is not None:



        agent_cfg["max_steps"] = max_steps







    if no_ai:



        from .agent.tools import check_available, available_tools_block



        allowed = agent_cfg.get(



            "allowed_tools",



            ["nmap", "whatweb", "nikto", "gobuster", "ffuf", "wpscan", "curl", "sqlmap", "hydra"],



        )



        avail = check_available(allowed)



        console.print(



            Panel(



                available_tools_block(allowed),



                title="Tool Availability",



                border_style="cyan",



            )



        )



        return







    from .agent import AutonomousAgent







    async def _run_agent() -> None:



        agent = AutonomousAgent(



            target=target,



            ai_cfg=cfg["ai"],



            agent_cfg=agent_cfg,



        )



        session = await agent.run()







                     



        out_dir = _pathlib.Path(output or "reports")



        out_dir.mkdir(parents=True, exist_ok=True)



        import re as _re



        host = _re.sub(r"https?://", "", target).split("/")[0].replace(".", "_")



        report_path = out_dir / f"agent_{host}.json"



        report_path.write_text(session.to_json(), encoding="utf-8")



        console.print(



            Panel(



                f"Report saved: [bold]{report_path}[/]\n"



                f"Total steps: [bold]{len(session.steps)}[/]\n"



                f"Findings: [bold]{len(session.findings)}[/]",



                title="[bold green]Agent Complete[/]",



                border_style="green",



            )



        )



        # ── Auto-launch post-pwn interactive chat ──────────────────────────

        from .agent.post_chat import AgentPostChat

        post_chat = AgentPostChat(

            session=session,

            memory=agent.memory,

            ai_cfg=cfg["ai"],

        )

        await post_chat.run()



    _asyncio.run(_run_agent())







class _DictProxy:



    """Lightweight proxy that exposes dict keys as attributes (for chat context)."""



    def __init__(self, d: dict) -> None:



        self.__dict__.update(d)







    def __getattr__(self, item: str) -> None:



        return None












@app.command(name="bot")
def bot_command(
    config: str = typer.Option(None, "--config", "-c", help="Path to config.json"),
) -> None:
    """Start the Telegram bot controller — listen for /scan, /agent, /status commands."""
    import asyncio as _asyncio

    from .config import load_config as _load_config

    cfg = _load_config(config)
    tg_cfg = cfg.get("telegram", {})

    if not tg_cfg.get("enabled"):
        console.print(
            "[bold yellow]  Telegram is disabled.[/]\n"
            "  Set [bold white]telegram.enabled = true[/] and [bold white]telegram.bot_token[/] in config.json first."
        )
        raise typer.Exit(1)

    if not tg_cfg.get("bot_token") or tg_cfg.get("bot_token") == "YOUR_BOT_TOKEN_HERE":
        console.print(
            "[bold red]  No bot_token set in config.json![/]\n"
            "  Create a bot via @BotFather on Telegram, copy the token, and set it in config.json."
        )
        raise typer.Exit(1)

    print_banner(__version__)
    console.print("[bold #FF6B35]  Telegram Bot Controller starting...[/]")
    console.print(f"  Bot token: [dim]{tg_cfg['bot_token'][:10]}...[/]")
    chat_ids = tg_cfg.get("allowed_chat_ids", [])
    if chat_ids:
        console.print(f"  Allowed chat IDs: [bold white]{chat_ids}[/]")
    else:
        console.print("[bold yellow]  WARNING: No allowed_chat_ids set — bot accepts commands from anyone![/]")
    console.print()
    console.print("  Send [bold white]/help[/] to your bot on Telegram to get started.")
    console.print("  Press [bold white]Ctrl+C[/] to stop.\n")

    from .telegram.controller import BotController
    ctrl = BotController(tg_cfg=tg_cfg, full_cfg=cfg)
    try:
        _asyncio.run(ctrl.run_forever())
    except KeyboardInterrupt:
        console.print("\n[dim]  Bot controller stopped.[/]")


def main() -> None:



    app()











if __name__ == "__main__":



    main()


