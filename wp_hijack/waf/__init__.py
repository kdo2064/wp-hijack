from .detector import detect_waf, WAFResult
from .evasion  import EvasionConfig, apply_evasion

__all__ = ["detect_waf", "WAFResult", "EvasionConfig", "apply_evasion"]
