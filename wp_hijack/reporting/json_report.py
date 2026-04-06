"""JSON report writer."""



from __future__ import annotations



import json



import pathlib



import datetime



from typing import Any











def write_json_report(



    output_path: pathlib.Path,



    *,



    target: str,



    scan_meta: dict[str, Any],



    confirmed_findings: list[Any],



    users: list[Any],



    exposed_files: list[Any],



    xmlrpc: Any,



    rest_api: Any,



    login_sec: Any,



    waf: Any,



    cms_info: Any,



    ai_summary: str | None = None,



    risk_score: dict | None = None,



) -> pathlib.Path:



    report = {



        "tool":    "wp-Hijack",



        "version": "1.0.0",



        "author":  "KDO || Xpert Exploit",



        "github":  "github.com/kdo2064/wp-Hijack",



        "generated_at": datetime.datetime.utcnow().isoformat() + "Z",



        "target":  target,



        "meta":    scan_meta,



        "cms": {



            "type":       cms_info.cms.value if cms_info else None,



            "version":    cms_info.version if cms_info else None,



            "confidence": cms_info.confidence if cms_info else 0,



            "signals":    cms_info.signals if cms_info else [],



        },



        "waf": {



            "detected":   waf.detected if waf else False,



            "name":       waf.name if waf else None,



            "confidence": waf.confidence if waf else 0,



        },



        "vulnerabilities": [cf.to_dict() for cf in confirmed_findings],



        "users": [



            {"id": u.id, "login": u.login, "display_name": u.display_name, "source": u.source}



            for u in users



        ],



        "exposed_files": [



            {"path": f.path, "status": f.status_code, "severity": f.severity}



            for f in exposed_files



        ],



        "xmlrpc": {



            "enabled":    xmlrpc.enabled if xmlrpc else False,



            "methods":    xmlrpc.methods if xmlrpc else [],



            "multicall":  xmlrpc.multicall_allowed if xmlrpc else False,



            "pingback":   xmlrpc.pingback_enabled if xmlrpc else False,



        },



        "rest_api": {



            "reachable":          rest_api.reachable if rest_api else False,



            "users_exposed":      rest_api.users_exposed if rest_api else False,



            "woocommerce":        rest_api.woocommerce_exposed if rest_api else False,



            "namespaces":         rest_api.namespaces if rest_api else [],



        },



        "login_security": {



            "accessible":         login_sec.login_accessible if login_sec else False,



            "username_oracle":    login_sec.username_oracle if login_sec else False,



            "no_rate_limit":      login_sec.no_rate_limit if login_sec else False,



            "open_registration":  login_sec.open_registration if login_sec else False,



        },



        "ai_summary": ai_summary,



        "risk_score": risk_score,



    }



    output_path.parent.mkdir(parents=True, exist_ok=True)



    output_path.write_text(json.dumps(report, indent=2, default=str), encoding="utf-8")



    return output_path



