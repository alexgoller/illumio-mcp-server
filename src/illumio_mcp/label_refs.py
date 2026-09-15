"""One way to name a label, shared by every tool that takes one.

Tools had drifted into three conventions: traffic accepted `key=value` or an
HREF, get-workloads accepted only an HREF, and create-ringfence accepted only
bare `app_name`/`env_name` strings. Same concept, three spellings, and the
failure mode for guessing wrong was a PCE 406 with no hint -- so callers had to
learn each tool's dialect by trial and error.

Accepted everywhere now:

    "app=ordering"                      key=value shorthand
    "/orgs/1/labels/42"                 bare HREF
    {"key": "app", "value": "ordering"} explicit mapping
    {"href": "/orgs/1/labels/42"}       explicit HREF

Resolution is exact on both key and value: the PCE matches `?key=` as a
substring, so asking for role would otherwise also match servicerole.
"""
from __future__ import annotations

import json
import logging

logger = logging.getLogger(__name__)


def _label_index(pce) -> dict:
    """Map (key, value) -> href for the org's labels."""
    return {(l.key, l.value): l.href
            for l in pce.labels.get(params={'max_results': 10000})}


def resolve_label_refs(pce, refs) -> tuple[list[str], list[str]]:
    """Resolve label references to HREFs.

    Returns (hrefs, unresolved). Unresolved references are returned rather than
    raised so callers can fail with a useful message naming the valid values --
    silently dropping one would widen the caller's filter, which for a policy
    or traffic query means quietly answering a different question.
    """
    if refs is None:
        return [], []
    if isinstance(refs, (str, dict)):
        refs = [refs]

    hrefs: list[str] = []
    unresolved: list[str] = []
    index: dict | None = None

    for ref in refs:
        if isinstance(ref, dict):
            if ref.get('href'):
                hrefs.append(str(ref['href']))
                continue
            if ref.get('key') and ref.get('value') is not None:
                pair = (str(ref['key']), str(ref['value']))
            else:
                unresolved.append(json.dumps(ref, sort_keys=True))
                continue
        else:
            text = str(ref).strip()
            if text.startswith('/'):           # already an HREF
                hrefs.append(text)
                continue
            if '=' not in text:
                unresolved.append(text)
                continue
            key, _, value = text.partition('=')
            pair = (key.strip(), value.strip())

        if index is None:
            index = _label_index(pce)
        href = index.get(pair)
        if href:
            hrefs.append(href)
        else:
            unresolved.append(f"{pair[0]}={pair[1]}")

    return hrefs, unresolved


def encode_label_filter(hrefs) -> str:
    """Encode HREFs as the PCE's `labels` query parameter.

    The parameter is a JSON string of nested lists where the OUTER list is
    OR'd and each INNER list is AND'd. One inner list therefore means "has
    all of these labels", which is what a caller filtering on app=x AND env=y
    means. Getting this inverted returns a superset that looks plausible --
    138 workloads instead of 23 -- so it is worth stating explicitly.
    """
    return json.dumps([list(hrefs)]) if hrefs else json.dumps([])


def unresolved_label_error(unresolved, pce, *, keys=()) -> dict:
    """Build a fail-fast error naming what was not found, and what is valid."""
    valid: dict = {}
    for key in keys or sorted({u.split('=')[0] for u in unresolved if '=' in u}):
        try:
            values = sorted({l.value for l in pce.labels.get(
                params={'key': key, 'max_results': 100}) if l.value and l.key == key})
            if values:
                valid[key] = values[:50]
        except Exception as e:
            logger.debug("could not list values for label key %s: %s", key, e)
    return {
        "error": "unresolved_label_filter",
        "unresolved": unresolved,
        "hint": ("Use key=value (e.g. app=ordering) or a label HREF. "
                 "Call get-labels for the exact values."),
        "valid_values": valid,
    }


def normalise_label_value(pce, ref, key: str) -> str:
    """Reduce any accepted label reference to its plain value for `key`.

    For tools whose contract is a bare value (create-ringfence's app_name), so
    they accept `app=ordering` and a label HREF too without changing what they
    pass downstream. An unrecognised form is returned unchanged -- the caller
    already handles "label not found" and reports it better than we could here.
    """
    if not isinstance(ref, str) or not ref.strip():
        return ref
    text = ref.strip()
    if text.startswith('/'):
        for label in pce.labels.get(params={'max_results': 10000}):
            if label.href == text:
                return label.value
        return text
    if '=' in text:
        prefix, _, value = text.partition('=')
        # Only strip the prefix when it names this dimension; a value that
        # legitimately contains '=' must survive intact.
        if prefix.strip() == key:
            return value.strip()
    return text
