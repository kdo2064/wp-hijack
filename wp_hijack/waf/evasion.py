"""WAF evasion helpers — header injection, UA tricks, rate limiting."""

from __future__ import annotations

import random

import string

from dataclasses import dataclass, field





@dataclass

class EvasionConfig:

    randomize_xff: bool = True

    add_fake_referer: bool = True

    case_rotate_payloads: bool = True

    chunk_requests: bool = False





def apply_evasion(headers: dict[str, str], cfg: EvasionConfig) -> dict[str, str]:

    """Return enhanced headers dict with evasion fields applied."""

    h = dict(headers)

    if cfg.randomize_xff:

        ip = ".".join(str(random.randint(1, 254)) for _ in range(4))

        h["X-Forwarded-For"] = ip

        h["X-Real-IP"] = ip

        h["X-Originating-IP"] = ip

        h["X-Remote-IP"] = ip

        h["X-Client-IP"] = ip



    if cfg.add_fake_referer:

        h["Referer"] = "https://www.google.com/search?q=site%3Awp-target"



    return h





def rotate_case(payload: str) -> str:

    """Randomly toggles case of alphabetic chars to bypass naive keyword filters."""

    return "".join(

        c.upper() if random.random() > 0.5 else c.lower()

        for c in payload

    )

