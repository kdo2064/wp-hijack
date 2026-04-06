"""PDF report generator using reportlab (pure-Python, no native deps)."""



from __future__ import annotations



import pathlib



import datetime



from typing import Any











def write_pdf_report(



    output_path: pathlib.Path,



    html_path: pathlib.Path | None = None,



    html_content: str | None = None,



    scan_results: dict | None = None,



) -> pathlib.Path:



    """
    Generate a structured PDF security report using reportlab.
    Accepts either a pre-built HTML file (html_path), raw HTML string
    (html_content), or the raw scan results dict (scan_results).
    Supply at least one of the three.
    """



    try:



        from reportlab.lib.pagesizes import A4



        from reportlab.lib import colors



        from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle



        from reportlab.lib.units import mm



        from reportlab.platypus import (



            SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle,



            HRFlowable, KeepTogether,



        )



        from reportlab.lib.enums import TA_LEFT, TA_CENTER, TA_RIGHT



    except ImportError:



        raise RuntimeError(



            "reportlab is not installed. Run: pip install reportlab"



        )







    output_path = pathlib.Path(output_path)



    output_path.parent.mkdir(parents=True, exist_ok=True)









    if scan_results is None:



        scan_results = {}







    target      = scan_results.get("target", "Unknown Target")



    elapsed     = scan_results.get("elapsed", 0.0)



    cms_info    = scan_results.get("cms_info")



    waf_info    = scan_results.get("waf")



    confirmed   = scan_results.get("confirmed", [])



    plugins     = scan_results.get("plugins", [])



    themes      = scan_results.get("themes", [])



    users       = scan_results.get("users", [])



    exposed     = scan_results.get("exposed", [])



    ai_summary  = scan_results.get("ai_summary", "")



    risk_score  = scan_results.get("risk_score")



    attack_chain = scan_results.get("attack_chain", "")



    scan_time   = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S UTC")









    C_BG        = colors.HexColor("#0d1117")



    C_ACCENT    = colors.HexColor("#00FF41")



    C_DANGER    = colors.HexColor("#FF4444")



    C_WARN      = colors.HexColor("#FFA500")



    C_INFO      = colors.HexColor("#4FC3F7")



    C_MUTED     = colors.HexColor("#8B949E")



    C_WHITE     = colors.HexColor("#E6EDF3")



    C_HEADER_BG = colors.HexColor("#161B22")



    C_ROW_ALT   = colors.HexColor("#1C2128")







    SEV_COLOUR = {



        "CRITICAL": colors.HexColor("#FF4444"),



        "HIGH":     colors.HexColor("#FF8C00"),



        "MEDIUM":   colors.HexColor("#FFA500"),



        "LOW":      colors.HexColor("#4FC3F7"),



        "INFO":     colors.HexColor("#8B949E"),



    }









    styles = getSampleStyleSheet()







    def _style(name, **kw):



        return ParagraphStyle(name, parent=styles["Normal"], **kw)







    s_title   = _style("Title",   fontSize=22, textColor=C_ACCENT,  fontName="Helvetica-Bold",  alignment=TA_LEFT)



    s_sub     = _style("Sub",     fontSize=11, textColor=C_MUTED,   fontName="Helvetica",       alignment=TA_LEFT)



    s_h2      = _style("H2",      fontSize=13, textColor=C_ACCENT,  fontName="Helvetica-Bold",  spaceBefore=8)



    s_h3      = _style("H3",      fontSize=11, textColor=C_WHITE,   fontName="Helvetica-Bold",  spaceBefore=4)



    s_body    = _style("Body",    fontSize=9,  textColor=C_WHITE,   fontName="Helvetica",       leading=14)



    s_muted   = _style("Muted",   fontSize=8,  textColor=C_MUTED,   fontName="Helvetica")



    s_code    = _style("Code",    fontSize=8,  textColor=C_ACCENT,  fontName="Courier",         leading=12)



    s_danger  = _style("Danger",  fontSize=9,  textColor=C_DANGER,  fontName="Helvetica-Bold")



    s_warn    = _style("Warn",    fontSize=9,  textColor=C_WARN,    fontName="Helvetica-Bold")



    s_info    = _style("InfoP",   fontSize=9,  textColor=C_INFO,    fontName="Helvetica-Bold")







    def _hr():



        return HRFlowable(width="100%", thickness=0.5, color=C_MUTED, spaceAfter=4, spaceBefore=4)







    def _sp(h=4):



        return Spacer(1, h)









    doc = SimpleDocTemplate(



        str(output_path),



        pagesize=A4,



        leftMargin=18*mm, rightMargin=18*mm,



        topMargin=18*mm,  bottomMargin=18*mm,



        title=f"WP-Hijack Security Report – {target}",



    )







    story: list = []









    story += [



        Paragraph("WP-HIJACK", s_title),



        Paragraph("WordPress Security Assessment Report", s_sub),



        _sp(2),



        Paragraph(f"<font color='#8B949E'>Target:</font> <b>{target}</b>", s_body),



        Paragraph(f"<font color='#8B949E'>Generated:</font> {scan_time}", s_muted),



        Paragraph(f"<font color='#8B949E'>Scan duration:</font> {elapsed:.1f}s", s_muted),



        _hr(),



        _sp(4),



    ]









    total_conf  = len(confirmed)



    severity_counts = {}



    for cf in confirmed:



        sev = getattr(getattr(cf, "finding", cf), "severity", "INFO") or "INFO"



        severity_counts[sev] = severity_counts.get(sev, 0) + 1







    story.append(Paragraph("Executive Summary", s_h2))



    story.append(_sp(2))







    summary_data = [



        ["Metric", "Value"],



        ["Target", target],



        ["Total Findings", str(total_conf)],



        ["Critical", str(severity_counts.get("CRITICAL", 0))],



        ["High", str(severity_counts.get("HIGH", 0))],



        ["Medium", str(severity_counts.get("MEDIUM", 0))],



        ["Low", str(severity_counts.get("LOW", 0))],



        ["Plugins Detected", str(len(plugins))],



        ["Themes Detected", str(len(themes))],



        ["Users Exposed", str(len(users))],



        ["Sensitive Files", str(len(exposed))],



    ]







    if risk_score is not None:



        summary_data.append(["Risk Score", str(risk_score)])







    if cms_info:



        cms_name = getattr(cms_info, "cms", None)



        cms_ver  = getattr(cms_info, "version", "unknown") or "unknown"



        if cms_name:



            summary_data.append(["CMS", f"{getattr(cms_name, 'value', cms_name)} {cms_ver}"])







    if waf_info and getattr(waf_info, "detected", False):



        summary_data.append(["WAF", f"{waf_info.name} ({waf_info.confidence}%)"])







    w = doc.width



    t = Table(summary_data, colWidths=[w * 0.4, w * 0.6])



    t.setStyle(TableStyle([



        ("BACKGROUND",  (0, 0), (-1, 0),  C_HEADER_BG),



        ("TEXTCOLOR",   (0, 0), (-1, 0),  C_ACCENT),



        ("FONTNAME",    (0, 0), (-1, 0),  "Helvetica-Bold"),



        ("FONTSIZE",    (0, 0), (-1, 0),  9),



        ("ROWBACKGROUNDS", (0, 1), (-1, -1), [C_BG, C_ROW_ALT]),



        ("TEXTCOLOR",   (0, 1), (-1, -1), C_WHITE),



        ("FONTSIZE",    (0, 1), (-1, -1), 9),



        ("FONTNAME",    (0, 1), (-1, -1), "Helvetica"),



        ("GRID",        (0, 0), (-1, -1), 0.3, C_MUTED),



        ("LEFTPADDING", (0, 0), (-1, -1), 6),



        ("TOPPADDING",  (0, 0), (-1, -1), 4),



        ("BOTTOMPADDING", (0, 0), (-1, -1), 4),



    ]))



    story += [t, _sp(6)]







    if ai_summary:



        story += [



            Paragraph("AI Assessment", s_h3),



            Paragraph(str(ai_summary).replace("\n", "<br/>"), s_body),



            _sp(4),



        ]









    if confirmed:



        story += [_hr(), Paragraph("Vulnerability Findings", s_h2), _sp(2)]







        for idx, cf in enumerate(confirmed, 1):



            finding = getattr(cf, "finding", cf)



            sev     = getattr(finding, "severity", "INFO") or "INFO"



            cve     = getattr(finding, "cve", "N/A") or "N/A"



            title   = getattr(finding, "title", "Unknown") or "Unknown"



            comp    = getattr(finding, "component", "") or ""



            ver     = getattr(finding, "installed_version", "") or ""



            fixed   = getattr(finding, "fixed_version", "") or ""



            desc    = getattr(finding, "description", "") or ""



            remed   = getattr(finding, "remediation", "") or ""



            cvss    = getattr(finding, "cvss", None)







            sev_col = SEV_COLOUR.get(sev, C_MUTED)







            rows = [



                [f"#{idx}  {cve}  —  {title}", ""],



                ["Severity", sev],



            ]



            if comp:   rows.append(["Component", f"{comp} {ver}".strip()])



            if fixed:  rows.append(["Fix Version", fixed])



            if cvss:   rows.append(["CVSS", f"{cvss:.1f}"])



            if desc:   rows.append(["Description", desc[:300]])



            if remed:  rows.append(["Remediation", remed[:200]])







            exploit = getattr(cf, "exploit", None)



            if exploit:



                poc = getattr(exploit, "poc_code", "") or ""



                if poc:



                    rows.append(["PoC", poc[:300]])







            t2 = Table(rows, colWidths=[w * 0.22, w * 0.78])



            ts_cmds = [



                ("BACKGROUND",    (0, 0), (-1, 0),  C_HEADER_BG),



                ("SPAN",          (0, 0), (-1, 0)),



                ("TEXTCOLOR",     (0, 0), (-1, 0),  sev_col),



                ("FONTNAME",      (0, 0), (-1, 0),  "Helvetica-Bold"),



                ("FONTSIZE",      (0, 0), (-1, 0),  9),



                ("ROWBACKGROUNDS",(0, 1), (-1, -1),  [C_BG, C_ROW_ALT]),



                ("TEXTCOLOR",     (0, 1), (0, -1),  C_MUTED),



                ("FONTNAME",      (0, 1), (0, -1),  "Helvetica-Bold"),



                ("TEXTCOLOR",     (1, 1), (-1, -1), C_WHITE),



                ("FONTNAME",      (1, 1), (-1, -1), "Helvetica"),



                ("FONTSIZE",      (1, 0), (-1, -1), 8),



                ("GRID",          (0, 0), (-1, -1), 0.3, C_MUTED),



                ("LEFTPADDING",   (0, 0), (-1, -1), 5),



                ("TOPPADDING",    (0, 0), (-1, -1), 3),



                ("BOTTOMPADDING", (0, 0), (-1, -1), 3),



                ("ROWBACKGROUNDS", (1, 1), (0, 1),  [sev_col]),



                ("TEXTCOLOR",      (1, 1), (1, 1),  colors.white),



                ("FONTNAME",       (1, 1), (1, 1),  "Helvetica-Bold"),



            ]



            t2.setStyle(TableStyle(ts_cmds))



            story += [KeepTogether([t2, _sp(4)])]









    if attack_chain:



        story += [



            _hr(),



            Paragraph("AI Attack Chain Analysis", s_h2),



            _sp(2),



            Paragraph(str(attack_chain).replace("\n", "<br/>"), s_body),



            _sp(4),



        ]









    if plugins or themes or users:



        story += [_hr(), Paragraph("Enumeration Details", s_h2), _sp(2)]







        if plugins:



            story.append(Paragraph(f"Plugins ({len(plugins)})", s_h3))



            rows = [["Slug", "Version", "Status"]]



            for p in plugins[:50]:



                rows.append([



                    getattr(p, "slug", str(p)),



                    getattr(p, "version", "?") or "?",



                    getattr(p, "status", "") or "",



                ])



            tp = Table(rows, colWidths=[w*0.5, w*0.2, w*0.3])



            tp.setStyle(TableStyle([



                ("BACKGROUND", (0,0),(-1,0), C_HEADER_BG),



                ("TEXTCOLOR",  (0,0),(-1,0), C_ACCENT),



                ("FONTNAME",   (0,0),(-1,0), "Helvetica-Bold"),



                ("ROWBACKGROUNDS",(0,1),(-1,-1),[C_BG, C_ROW_ALT]),



                ("TEXTCOLOR",  (0,1),(-1,-1), C_WHITE),



                ("FONTSIZE",   (0,0),(-1,-1), 8),



                ("GRID",       (0,0),(-1,-1), 0.3, C_MUTED),



                ("LEFTPADDING",(0,0),(-1,-1), 4),



                ("TOPPADDING", (0,0),(-1,-1), 3),



                ("BOTTOMPADDING",(0,0),(-1,-1), 3),



            ]))



            story += [tp, _sp(4)]







        if users:



            story.append(Paragraph(f"Exposed Users ({len(users)})", s_h3))



            rows = [["Username", "ID", "Display Name"]]



            for u in users[:30]:



                rows.append([



                    getattr(u, "username", str(u)),



                    str(getattr(u, "user_id", "")),



                    getattr(u, "display_name", "") or "",



                ])



            tu = Table(rows, colWidths=[w*0.35, w*0.15, w*0.5])



            tu.setStyle(TableStyle([



                ("BACKGROUND", (0,0),(-1,0), C_HEADER_BG),



                ("TEXTCOLOR",  (0,0),(-1,0), C_ACCENT),



                ("FONTNAME",   (0,0),(-1,0), "Helvetica-Bold"),



                ("ROWBACKGROUNDS",(0,1),(-1,-1),[C_BG, C_ROW_ALT]),



                ("TEXTCOLOR",  (0,1),(-1,-1), C_WHITE),



                ("FONTSIZE",   (0,0),(-1,-1), 8),



                ("GRID",       (0,0),(-1,-1), 0.3, C_MUTED),



                ("LEFTPADDING",(0,0),(-1,-1), 4),



                ("TOPPADDING", (0,0),(-1,-1), 3),



                ("BOTTOMPADDING",(0,0),(-1,-1), 3),



            ]))



            story += [tu, _sp(4)]









    story += [



        _hr(),



        Paragraph(



            f"Generated by WP-Hijack · {scan_time} · For authorized security testing only.",



            s_muted,



        ),



    ]









    def _on_page(canvas, document):



        canvas.saveState()



        canvas.setFillColor(C_BG)



        canvas.rect(0, 0, A4[0], A4[1], fill=1, stroke=0)



        canvas.restoreState()







    doc.build(story, onFirstPage=_on_page, onLaterPages=_on_page)



    return output_path



