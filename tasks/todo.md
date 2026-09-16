# Process-based egress services + service references in rules

Spec: process-qualified services and service-object references, to unblock the
Shadow AI demo ("browser only into payment").

## Plan

- [x] A1. `service_refs.py` — shared resolver (mirrors `label_refs.py`)
      - ingress_services union: inline {port,proto,to_port} | {href} | {service}
      - exact-name resolution (PCE ?name= is substring: S-HTTP -> 3 matches)
      - All Services href cached per org
      - unknown/mixed keys = hard error, never strip
      - windows_services / windows_egress_services validation + proto coercion
- [x] A2. create-service / update-service accept windows_(egress_)services
      - drop service_ports required; require >=1 of the three
- [x] A3. get-services returns windows_egress_services + egress_process_name filter
- [x] B.  ingress_services union in create-deny-rule, update-deny-rule, create-ruleset
- [x] C.  new update-sec-rule + delete-sec-rule
- [x] D.  create-ringfence deny_service (default "All Services")
- [x] E.  output hygiene: echo resolved form with resolved_name; fail before PCE call
- [x] F.  Windows-VEN warning when egress-process service meets non-Windows consumers
- [x] G.  schemas in server.py + registry + docs + CHANGELOG entry
- [x] H.  tests (unit, no PCE) + live verification of all 7 acceptance criteria

## Verified against live PCE (org 5636114) before coding

- All Services href = /orgs/5636114/sec_policy/draft/services/24206847997119298
- GET services?name=S-HTTP -> ['S-HTTPS','S-HTTPS-UDP','S-HTTP']  (substring)
- SDK Service already has windows_egress_services; Rule.build takes dicts,
  so hrefs can flow through the allow path without bypassing the SDK.

## Review

### Three places the spec did not match the PCE

Found by probing before and during implementation, not by reasoning about it.
Each would have shipped a broken demo if implemented as written.

1. `windows_egress_services` does NOT take port/to_port/proto. The PCE answers
   `input_validation_error ... additional properties ["port","proto"] ... none
   are allowed`. The spec's worked example carries both and is rejected.

2. The three qualifier lists are MUTUALLY EXCLUSIVE -- a service carries an OS
   type. Sending service_ports with windows_egress_services returns 201 while
   silently storing service_ports: null. Editing one into the other answers
   `cannot change OS type of service`. So "chrome.exe on 443" is not one
   service object, which the spec assumed it was.

3. A Windows egress service cannot be used in a rule's `ingress_services` at
   all (`ingress_service_cannot_be_windows_egress_service`). It belongs in
   `egress_services`, a rule field the Illumio SDK's Rule dataclass does not
   model -- which is presumably why the spec routed it through
   ingress_services. Found by diffing raw rule JSON against the SDK fields.

The pattern that actually works, verified end to end:
    service: windows_egress_services = [{process_name: chrome.exe}]
    rule:    ingress_services = [{port: 443}]   (provider side)
             egress_services  = [{service: "S-VDI-chrome-egress"}]  (consumer)

### Bug I introduced and caught before shipping

`deny_service` defaults to the string "All Services", but the resolver only
accepted lists/dicts -- so every selective ringfence would have failed with
invalid_deny_service. The resolver now accepts a scalar name. Covered by a
regression test naming the consequence.

### Acceptance criteria

1. egress-only service + egress_process_name lookup    PASS
2. deny with {"service": "All Services"} -> All Svcs href  PASS
3. conflicting port+href rejected, nothing written      PASS (deny count 1 -> 1)
4. {"service": "S-HTTP"} exact, not S-HTTPS             PASS
5. update-sec-rule swaps services in place             PASS
6. full demo sequence with no UI step                  PASS up to provision,
   which was deliberately NOT run -- provisioning stays the user's click.
7. inline {port, proto} callers unchanged              PASS (stored 443/6)

All test objects created on demo100 were deleted; draft policy is back to its
prior state.
