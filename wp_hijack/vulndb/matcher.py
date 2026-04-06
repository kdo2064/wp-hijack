"""Version-range matching using packaging.version."""



from __future__ import annotations



import json



import re



from packaging.version import Version, InvalidVersion











def _parse(ver_str: str) -> Version | None:



    try:



        return Version(ver_str.strip())



    except InvalidVersion:





        cleaned = re.sub(r'\.(\d+)$', r'.post\1', ver_str.strip())



        try:



            return Version(cleaned)



        except InvalidVersion:



            return None











def is_version_affected(



    installed_version: str,



    affected_versions: list[str] | str,



) -> bool:



    """
    Check if installed_version falls within any affected range.

    Range formats supported:
    - "<= 6.3.2"
    - "< 6.4"
    - ">= 1.0, < 2.0"
    - "== 1.5.3"
    - "1.0 - 1.5"  (inclusive range)
    - "1.5.3"      (exact)
    """



    if isinstance(affected_versions, str):



        try:



            affected_versions = json.loads(affected_versions)



        except Exception:



            affected_versions = [affected_versions]







    installed = _parse(installed_version)



    if installed is None:



        return False







    for spec in affected_versions:



        spec = spec.strip()



        if not spec:



            continue









        if " - " in spec:



            parts = spec.split(" - ", 1)



            lo = _parse(parts[0])



            hi = _parse(parts[1])



            if lo and hi and lo <= installed <= hi:



                return True



            continue









        if "," in spec:



            sub_specs = [s.strip() for s in spec.split(",")]



            if all(_single_match(installed, s) for s in sub_specs):



                return True



            continue







        if _single_match(installed, spec):



            return True







    return False











def _single_match(installed: Version, spec: str) -> bool:



    spec = spec.strip()



    for op, rest in [("<=", spec[2:]), ("<", spec[1:]), (">=", spec[2:]), (">", spec[1:]), ("==", spec[2:])]:



        if spec.startswith(op):



            other = _parse(rest.strip())



            if other is None:



                return False



            if op == "<="  : return installed <= other



            if op == "<"   : return installed <  other



            if op == ">="  : return installed >= other



            if op == ">"   : return installed >  other



            if op == "=="  : return installed == other





    other = _parse(spec)



    return other is not None and installed == other



