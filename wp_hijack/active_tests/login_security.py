"""Login security checks — user oracle, rate-limit absent, open registration."""

from __future__ import annotations

import asyncio

from dataclasses import dataclass, field





@dataclass

class LoginSecurityResult:

    login_accessible: bool = False

    username_oracle: bool = False

    no_rate_limit: bool = False

    open_registration: bool = False

    wp_admin_accessible: bool = False

    details: list[str] = field(default_factory=list)





async def test_login_security(http, base_url: str) -> LoginSecurityResult:

    base = base_url.rstrip("/")

    result = LoginSecurityResult()

    login_ep = f"{base}/wp-login.php"




    try:

        r = await http.get(login_ep, timeout=8)

        if r.status_code == 200:

            result.login_accessible = True

    except Exception:

        return result




    async def _oracle(username: str) -> str:

        try:

            r = await http.post(

                login_ep,

                data={"log": username, "pwd": "INVALID_PW_xXxHijack123", "wp-submit": "Log In"},

                timeout=8,

            )

            return r.text.lower()

        except Exception:

            return ""



    admin_resp, noexist_resp = await asyncio.gather(

        _oracle("admin"),

        _oracle("noexistuserxyz9876"),

    )

    if admin_resp and noexist_resp:

        if ("incorrect password" in admin_resp or "the password you entered" in admin_resp):

            result.username_oracle = True

            result.details.append("Login page leaks valid usernames via error message difference")




    if result.login_accessible:

        try:

            responses = await asyncio.gather(

                *[

                    http.post(

                        login_ep,

                        data={"log": "admin", "pwd": f"fail{i}", "wp-submit": "Log In"},

                        timeout=6,

                    )

                    for i in range(3)

                ]

            )

            codes = [r.status_code for r in responses if hasattr(r, "status_code")]


            if all(c == 200 for c in codes):

                result.no_rate_limit = True

                result.details.append("No login rate limiting detected after 3 rapid attempts")

        except Exception:

            pass




    try:

        r = await http.get(f"{base}/wp-login.php?action=register", timeout=8)

        body = r.text.lower()

        if r.status_code == 200 and "register" in body and "username" in body:

            result.open_registration = True

            result.details.append("Open user registration is enabled")

    except Exception:

        pass




    try:

        r = await http.get(f"{base}/wp-admin/", timeout=8)

        if r.status_code == 200 and "dashboard" in r.text.lower():

            result.wp_admin_accessible = True

            result.details.append("wp-admin/ accessible without authentication!")

    except Exception:

        pass



    return result

