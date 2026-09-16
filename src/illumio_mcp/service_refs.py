"""Resolving service references, shared by every tool that takes a service.

Two shapes, both of which the PCE accepts inside `ingress_services`:

    {"port": 443, "proto": "tcp"}   an inline port/protocol
    {"href": "/orgs/1/sec_policy/draft/services/42"}   a service object

Callers may also write `{"service": "All Services"}` and have the name resolved
here, because an href is not something a human or a model knows offhand.

Why this module exists rather than a few lines in each handler: the rule tools
used to rebuild each entry as `{"port": ..., "proto": ...}`, which silently
DISCARDED an `href` the caller had supplied. The call succeeded, the PCE stored
`0/tcp`, and the policy that came back was not the policy that was asked for.
Silently writing the wrong rule is worse than refusing the call, so unknown and
conflicting keys are hard errors here and nothing is sent to the PCE until every
entry has resolved.
"""
from __future__ import annotations

import logging

logger = logging.getLogger(__name__)

# The PCE takes protocol numbers. The rule tools have always accepted the names
# as well, so keep doing that everywhere rather than making callers remember
# which field wants which form.
PROTO_NAMES = {"tcp": 6, "udp": 17, "icmp": 1, "icmpv6": 58, "ipv6-icmp": 58}
PROTO_NUMBERS = {6: "tcp", 17: "udp", 1: "icmp", 58: "icmpv6"}

ALL_SERVICES = "All Services"

_INLINE_KEYS = {"port", "to_port", "proto"}

# The PCE is asymmetric between the two Windows qualifier lists, verified
# against a live PCE rather than assumed:
#
#   windows_services         port, to_port, proto, process_name, service_name
#   windows_egress_services  process_name, service_name ONLY
#
# Sending port/proto in an egress entry is refused with
#   input_validation_error: ... contains additional properties ["port", "proto"]
#   outside of the schema when none are allowed
#
# so "chrome.exe on 443" is expressed as service_ports 443 PLUS an egress entry
# naming the process -- the port lives on the service, the process qualifies who
# may use it. Enforced here so the caller gets that instruction instead of a
# schema dump from the PCE.
_WINDOWS_KEYS = {"port", "to_port", "proto", "process_name", "service_name"}
_WINDOWS_EGRESS_KEYS = {"process_name", "service_name"}

# href -> name, per PCE. Service objects are immutable enough for a session and
# `All Services` is looked up on nearly every rule call.
_name_cache: dict[str, dict] = {}


class ServiceRefError(ValueError):
    """A service reference that cannot be resolved. Message is user-facing."""


def _org_key(pce) -> str:
    return f"{getattr(pce, '_hostname', '')}:{getattr(pce, 'org_id', '')}"


def coerce_proto(value, *, where: str = "proto") -> int:
    """Protocol name or number -> number. Raises ServiceRefError on junk."""
    if isinstance(value, bool):
        raise ServiceRefError(f"{where}: expected a protocol, got {value!r}")
    if isinstance(value, int):
        return value
    if isinstance(value, str):
        text = value.strip().lower()
        if text in PROTO_NAMES:
            return PROTO_NAMES[text]
        if text.isdigit():
            return int(text)
    raise ServiceRefError(
        f"{where}: unknown protocol {value!r}; use tcp, udp, icmp or a number"
    )


def lookup_service_by_name(pce, name: str) -> str:
    """Exact-name lookup returning an href.

    The PCE matches ?name= as a SUBSTRING -- asking for 'S-HTTP' on a real org
    comes back with ['S-HTTPS', 'S-HTTPS-UDP', 'S-HTTP'] -- so the server-side
    filter only narrows the fetch and the exact match is made here. Ambiguity is
    an error listing the candidates rather than a guess, because picking the
    wrong service writes a rule that looks right and is not.
    """
    if not isinstance(name, str) or not name.strip():
        raise ServiceRefError("service: expected a non-empty service name")
    wanted = name.strip()

    cache = _name_cache.setdefault(_org_key(pce), {})
    if wanted in cache:
        return cache[wanted]

    try:
        resp = pce.get("/sec_policy/draft/services",
                       params={"name": wanted}, include_org=True)
        resp.raise_for_status()
        candidates = resp.json()
    except ServiceRefError:
        raise
    except Exception as e:
        raise ServiceRefError(f"service {wanted!r}: lookup failed: {e}") from e

    exact = [s for s in candidates if s.get("name") == wanted]
    if len(exact) == 1:
        href = exact[0]["href"]
        cache[wanted] = href
        return href
    if not exact:
        near = sorted({s.get("name") for s in candidates if s.get("name")})
        hint = f"; similar names: {near}" if near else ""
        raise ServiceRefError(f"service {wanted!r} not found{hint}")
    raise ServiceRefError(
        f"service {wanted!r} is ambiguous, {len(exact)} objects share that "
        f"exact name: {[s.get('href') for s in exact]}"
    )


def all_services_href(pce) -> str:
    """Href of the org's built-in All Services object.

    Never hardcoded: the id differs on every PCE.
    """
    return lookup_service_by_name(pce, ALL_SERVICES)


def service_name_for_href(pce, href: str) -> str | None:
    """Best-effort reverse lookup, for echoing a readable name in responses.

    Failure is not an error: the rule is still valid, the caller just sees the
    href alone.
    """
    cache = _name_cache.setdefault(_org_key(pce), {})
    for name, known in cache.items():
        if known == href:
            return name
    try:
        resp = pce.get(href)
        resp.raise_for_status()
        name = resp.json().get("name")
        if name:
            cache[name] = href
        return name
    except Exception as e:
        logger.debug("could not resolve service name for %s: %s", href, e)
        return None


def _classify(entry: dict, index: int) -> str:
    """Which of the three forms this entry is, or raise explaining why not."""
    where = f"ingress_services[{index}]"
    if not isinstance(entry, dict):
        raise ServiceRefError(f"{where}: expected an object, got {type(entry).__name__}")

    keys = set(entry)
    unknown = keys - _INLINE_KEYS - {"href", "service"}
    if unknown:
        raise ServiceRefError(
            f"{where}: unknown field(s) {sorted(unknown)}. Use {{port, proto, to_port}}, "
            f"{{href}} or {{service}}."
        )

    has_href = "href" in keys
    has_name = "service" in keys
    has_inline = bool(keys & _INLINE_KEYS)

    # Conflicts are refused rather than resolved by precedence. The old code
    # took `port`/`proto` and dropped `href`, so a caller who supplied both got
    # a rule for port 0 and no indication anything had been ignored.
    chosen = [k for k, present in
              (("href", has_href), ("service", has_name), ("port/proto", has_inline))
              if present]
    if len(chosen) > 1:
        raise ServiceRefError(
            f"{where}: conflicting fields {chosen}. A service reference is either "
            f"an inline port/proto, an href, or a service name -- not a mixture. "
            f"Nothing was written."
        )
    if not chosen:
        raise ServiceRefError(
            f"{where}: empty. Give {{port, proto}}, {{href}} or {{service}}."
        )
    return chosen[0]


def resolve_ingress_services(pce, entries) -> tuple[list, list]:
    """Resolve a mixed ingress_services list.

    Returns (payload, display):
      payload  exactly what the PCE is sent
      display  the same entries annotated with resolved_name, for the response

    Raises ServiceRefError on the first unresolvable entry, before anything is
    sent. A partially applied rule set is worse than no rule at all.
    """
    if entries is None:
        raise ServiceRefError("ingress_services is required")
    # A bare string is a service name. Callers with a scalar default -- the
    # ringfence deny service is "All Services" -- would otherwise have to wrap
    # it, and forgetting to turned every selective ringfence into an error.
    if isinstance(entries, str):
        entries = [{"service": entries}]
    if isinstance(entries, dict):
        entries = [entries]
    if not isinstance(entries, list) or not entries:
        # The PCE answers an empty list with 406 ingress_services_cannot_be_empty,
        # which tells the caller nothing about how to fix it.
        raise ServiceRefError(
            "ingress_services must contain at least one entry. For 'any service', "
            f"use [{{\"service\": \"{ALL_SERVICES}\"}}] -- the PCE rejects an empty "
            "list, and {port: 0} does not mean all ports."
        )

    payload, display = [], []
    for index, entry in enumerate(entries):
        kind = _classify(entry, index)
        where = f"ingress_services[{index}]"

        if kind == "href":
            href = entry["href"]
            if not isinstance(href, str) or not href.strip():
                raise ServiceRefError(f"{where}: href must be a non-empty string")
            payload.append({"href": href})
            display.append({"href": href,
                            "resolved_name": service_name_for_href(pce, href)})

        elif kind == "service":
            href = lookup_service_by_name(pce, entry["service"])
            payload.append({"href": href})
            display.append({"href": href, "resolved_name": entry["service"].strip()})

        else:
            if "port" not in entry:
                raise ServiceRefError(
                    f"{where}: an inline service needs a port (with to_port for a range)"
                )
            item = {"port": entry["port"]}
            if "proto" in entry:
                item["proto"] = coerce_proto(entry["proto"], where=f"{where}.proto")
            if entry.get("to_port") is not None:
                item["to_port"] = entry["to_port"]
            payload.append(item)
            display.append(dict(item))

    return payload, display


def normalise_windows_services(entries, field: str) -> list:
    """Validate and coerce windows_services / windows_egress_services.

    Each entry needs at least one of port, process_name or service_name. The PCE
    enforces that too, but its error does not say which entry was wrong.

    process_name is passed through EXACTLY as given -- no case folding, no slash
    normalisation. Windows paths are matched literally by the VEN, so 'fixing'
    them here would quietly change which binary a rule matches.
    """
    if entries is None:
        return []
    if isinstance(entries, dict):
        entries = [entries]
    if not isinstance(entries, list):
        raise ServiceRefError(f"{field}: expected a list of objects")

    out = []
    for index, entry in enumerate(entries):
        where = f"{field}[{index}]"
        if not isinstance(entry, dict):
            raise ServiceRefError(f"{where}: expected an object")

        allowed = (_WINDOWS_EGRESS_KEYS if field == "windows_egress_services"
                   else _WINDOWS_KEYS)
        unknown = set(entry) - allowed

        port_like = unknown & _INLINE_KEYS
        if port_like and field == "windows_egress_services":
            raise ServiceRefError(
                f"{where}: the PCE does not accept {sorted(port_like)} inside "
                f"windows_egress_services -- it takes process_name/service_name "
                f"only. Put the ports in service_ports on the same service: "
                f'{{"service_ports": [{{"port": 443, "proto": 6}}], '
                f'"windows_egress_services": [{{"process_name": "..."}}]}}'
            )
        if unknown:
            raise ServiceRefError(
                f"{where}: unknown field(s) {sorted(unknown)}. Allowed: {sorted(allowed)}"
            )
        if not any(entry.get(k) not in (None, "") for k in
                   ("port", "process_name", "service_name")):
            raise ServiceRefError(
                f"{where}: needs at least one of "
                + ("process_name or service_name" if field == "windows_egress_services"
                   else "port, process_name or service_name")
            )

        item = {}
        for key in ("process_name", "service_name"):
            if entry.get(key):
                item[key] = entry[key]          # verbatim, deliberately
        if entry.get("port") is not None:
            item["port"] = entry["port"]
        if entry.get("to_port") is not None:
            item["to_port"] = entry["to_port"]
        if entry.get("proto") is not None:
            item["proto"] = coerce_proto(entry["proto"], where=f"{where}.proto")
        out.append(item)
    return out


def windows_qualified_services(pce, payload_entries) -> list[str]:
    """Names of referenced service objects that carry Windows process qualifiers.

    Deny rules cannot use them: the PCE evaluates a deny on the consumer side
    without the process context, so a process-qualified service in a deny reads
    as its ports alone -- silently broader than intended. The supported shape is
    a qualified ALLOW above a broad deny, which is why this is reported as an
    error rather than quietly accepted.
    """
    flagged = []
    for entry in payload_entries or []:
        href = entry.get("href")
        if not href:
            continue
        try:
            resp = pce.get(href)
            resp.raise_for_status()
            body = resp.json()
        except Exception as e:
            logger.debug("could not inspect service %s: %s", href, e)
            continue
        if body.get("windows_services") or body.get("windows_egress_services"):
            flagged.append(body.get("name") or href)
    return flagged


def _service_has_egress_qualifier(pce, payload_entries) -> list[str]:
    """Names of referenced services that carry windows_egress_services."""
    names = []
    for entry in payload_entries or []:
        href = entry.get("href")
        if not href:
            continue
        try:
            resp = pce.get(href)
            resp.raise_for_status()
            body = resp.json()
        except Exception as e:
            logger.debug("could not inspect service %s: %s", href, e)
            continue
        if body.get("windows_egress_services"):
            names.append(body.get("name") or href)
    return names


def consumer_os_warning(pce, payload_entries, consumer_refs) -> dict | None:
    """Warn when an egress-process rule has consumers that cannot honour it.

    `windows_egress_services` matches the process on the CONSUMER side and needs
    a Windows VEN there. A Linux consumer ignores the process qualifier and
    matches on port alone, so the rule is silently WIDER than it reads -- a
    "chrome.exe only" rule becomes "any process on 443" for those workloads.

    Returns None when there is nothing to say, so the check costs one extra API
    call only on the rare rule that references such a service.
    """
    qualified = _service_has_egress_qualifier(pce, payload_entries)
    if not qualified:
        return None

    from .label_refs import resolve_label_refs, encode_label_filter

    label_refs = [r for r in (consumer_refs or [])
                  if isinstance(r, str) and r != "ams" and not r.startswith("iplist:")]
    includes_ams = any(r == "ams" for r in (consumer_refs or []))

    try:
        params = {"max_results": 1000}
        if label_refs and not includes_ams:
            hrefs, unresolved = resolve_label_refs(pce, label_refs)
            if unresolved or not hrefs:
                return None          # cannot tell; say nothing rather than guess
            params["labels"] = encode_label_filter(hrefs)
        resp = pce.get("/workloads", params=params, include_org=True)
        resp.raise_for_status()
        workloads = resp.json()
    except Exception as e:
        logger.debug("could not check consumer OS mix: %s", e)
        return None

    non_windows = [w.get("hostname") or w.get("href") for w in workloads
                   if not str(w.get("os_id") or "").lower().startswith("win")]
    if not non_windows:
        return None

    return {
        "warning": "process_qualifier_ignored_on_non_windows",
        "services": qualified,
        "non_windows_consumer_count": len(non_windows),
        "examples": sorted(x for x in non_windows if x)[:5],
        "message": (
            f"{len(non_windows)} consumer workload(s) in scope are not Windows. "
            f"They ignore the process qualifier in {qualified} and match on port "
            f"alone, so this rule is wider than it reads for those workloads."
        ),
    }


def reject_egress_service_in_ingress(pce, payload_entries) -> str | None:
    """Error message if an ingress list references a Windows-egress service.

    The PCE answers such a rule with

        ingress_service_cannot_be_windows_egress_service

    which does not say where the service should go instead. It belongs in the
    rule's `egress_services`, a separate field that qualifies the CONSUMER's
    process while `ingress_services` stays the provider-side port. The two
    together are what expresses "this binary, to that port".
    """
    for entry in payload_entries or []:
        href = entry.get("href")
        if not href:
            continue
        try:
            resp = pce.get(href)
            resp.raise_for_status()
            body = resp.json()
        except Exception as e:
            logger.debug("could not inspect service %s: %s", href, e)
            continue
        if body.get("windows_egress_services"):
            name = body.get("name") or href
            return (
                f"{name!r} is a Windows egress service and cannot be used in "
                f"ingress_services -- the PCE refuses that combination. Put it in "
                f"`egress_services` instead, which qualifies the consumer's "
                f"process, and keep the provider-side port in ingress_services: "
                f'ingress_services=[{{"port": 443, "proto": "tcp"}}], '
                f'egress_services=[{{"service": "{name}"}}]'
            )
    return None
