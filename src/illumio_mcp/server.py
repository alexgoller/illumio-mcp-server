import asyncio
import contextvars
import os
import json
import logging
import time
import mcp.types as types
from mcp.server.models import InitializationOptions
from mcp.server import NotificationOptions, Server
import mcp.server.stdio
import dotenv
from pathlib import Path

from .context import ToolContext
from .pce import get_pce_from_env
from .tools import TOOL_REGISTRY
from .auth.audit import AuditEntry, NullAuditLog


def setup_logging():
    """Configure logging based on environment"""
    logger = logging.getLogger('illumio_mcp')
    logger.setLevel(logging.DEBUG)
    
    # Create formatter
    formatter = logging.Formatter(
        '%(asctime)s - %(name)s - %(levelname)s - %(message)s'
    )
    
    # Determine log path based on environment
    if os.environ.get('DOCKER_CONTAINER'):
        log_path = Path('/var/log/illumio-mcp/illumio-mcp.log')
    else:
        # Use home directory for local logging
        log_path = './illumio-mcp.log'
    
    file_handler = logging.FileHandler(str(log_path))
    file_handler.setFormatter(formatter)
    file_handler.setLevel(logging.DEBUG)
    logger.addHandler(file_handler)
    
    # Prevent logs from propagating to root logger
    logger.propagate = False
    
    return logger


# Initialize logging
logger = setup_logging()
logger.debug("Loading environment variables")

dotenv.load_dotenv()


def _build_stdio_context() -> ToolContext:
    """Build the single ToolContext used for the lifetime of the stdio process.

    Stdio mode has one user (the operator who launched the process) and one PCE
    (built from PCE_* env vars). The ToolContext is created lazily on first use
    so that test setups can override env before the PCE is constructed.

    Stdio gets user_role="admin" and a NullAuditLog so the dispatcher can apply
    uniform role + audit logic without special-casing the transport.
    """
    return ToolContext(
        pce=get_pce_from_env(),
        is_stdio=True,
        user_role="admin",
        audit_log=NullAuditLog(),
    )


_stdio_ctx: ToolContext | None = None


def _get_stdio_context() -> ToolContext:
    global _stdio_ctx
    if _stdio_ctx is None:
        _stdio_ctx = _build_stdio_context()
    return _stdio_ctx


_http_context: contextvars.ContextVar["ToolContext | None"] = contextvars.ContextVar(
    "_http_context", default=None
)


def get_active_context() -> ToolContext:
    """Return the ToolContext for the current call.

    HTTP requests set the ContextVar before invoking the dispatcher; stdio
    falls through to the singleton.
    """
    http_ctx = _http_context.get()
    if http_ctx is not None:
        return http_ctx
    return _get_stdio_context()


def set_http_context(ctx: ToolContext) -> contextvars.Token:
    """HTTP middleware sets the per-request context. Returned token is used to
    reset() after the request completes."""
    return _http_context.set(ctx)


def reset_http_context(token: contextvars.Token) -> None:
    _http_context.reset(token)


def build_http_context_for(
    user_sub: str | None,
    user_iss: str | None,
    keystore: object | None,
    user_role: str | None,
    audit_log: object | None,
    request_id: str | None,
) -> ToolContext:
    """Build a ToolContext for one HTTP request.

    Looks up the user's stored PCE credentials in the keystore. If found, builds
    a fresh PCE client from them. If not found, returns a context with pce=None
    and lets the dispatcher decide what to allow.
    """
    pce = None
    if keystore is not None and user_sub and user_iss:
        try:
            from .pce import build_pce_for
            creds = keystore.get(sub=user_sub, iss=user_iss)
            if creds is not None:
                pce = build_pce_for(creds)
        except Exception:
            logger.exception("Failed to load PCE credentials for user %s", user_sub)
    return ToolContext(
        pce=pce,
        is_stdio=False,
        user_sub=user_sub,
        user_iss=user_iss,
        keystore=keystore,
        user_role=user_role,
        audit_log=audit_log,
        request_id=request_id,
    )


server = Server("illumio-mcp")
logging.debug("Server initialized")

# ---------------------------------------------------------------------------
# Illumio Knowledge Base — MCP Resources
# ---------------------------------------------------------------------------
# These resources provide persistent domain knowledge to the LLM so it
# understands Illumio concepts without relying solely on tool descriptions.

ILLUMIO_RESOURCES = {
    "illumio://concepts/rule-processing": {
        "name": "Illumio Rule Processing Order",
        "description": "How Illumio processes rules — essential for understanding policy behavior",
        "content": """# Illumio Rule Processing Order

Rules in Illumio are processed in strict priority order. Understanding this is CRITICAL for correct policy design.

## Processing Order (highest to lowest priority)

1. **Essential rules** — Built-in rules that cannot be modified. Always processed first.

2. **Override Deny rules** — BLOCK traffic, overriding ALL allow rules below them.
   - Created via the deny_rules API with `"override": true`
   - These deny traffic regardless of any allow rules — "this must not happen under any circumstances"
   - Use cases:
     - Emergency isolation of compromised systems
     - Hard compliance blocks (e.g., PCI zones that must never reach the internet)
     - Blocking an active attack vector
     - Any scenario where no allow rule should ever override the block
   - NEVER use override deny for normal segmentation or ringfencing — use regular deny rules instead
   - Example: "Block ALL traffic to app X immediately" or "PCI zone must never reach external networks"

3. **Allow rules** — Normal rules in rulesets that permit specific traffic.
   - This is where ringfence rules live (both intra-scope and extra-scope)
   - Processed AFTER override deny, so override deny wins if both match

4. **Deny rules** — Block specific traffic (regular deny, NOT override).
   - Created via the deny_rules API with `"override": false`
   - Processed AFTER allow rules, so allow rules take precedence
   - Used in selective enforcement ringfencing to block unknown inbound traffic
   - Known remote apps get allow rules (step 3) which are processed before this deny (step 4)

5. **Default action** — What happens when no rule matches:
   - **Selective enforcement mode**: default = ALLOW ALL (deny rules are actively enforced, everything else passes)
   - **Full enforcement mode**: default = DENY ALL (only explicitly allowed traffic passes)

## Key Implications

- Override Deny > Allow > Deny > Default
- In selective mode, you NEED a deny rule to block anything (default is allow-all)
- In full enforcement, you NEED allow rules to permit anything (default is deny-all)
- Override deny should NEVER be used for routine segmentation — it's for emergencies only
- Ringfencing uses regular deny rules (step 4) + allow rules (step 3), never override deny (step 2)
"""
    },
    "illumio://concepts/enforcement-modes": {
        "name": "Illumio Enforcement Modes",
        "description": "Enforcement modes control how policy rules affect workload traffic",
        "content": """# Illumio Enforcement Modes

Each workload has an enforcement mode that determines how policy affects its traffic.

## Modes (from least to most restrictive)

### Idle
- No policy enforcement at all
- VEN is installed but not actively managing firewall rules
- Used during initial deployment or troubleshooting

### Visibility Only
- VEN reports traffic flows but does NOT enforce any rules
- All traffic is allowed regardless of policy
- Used for traffic discovery and policy modeling before enforcement

### Selective Enforcement
- Default action is **ALLOW ALL**
- Only **deny rules** are actively enforced
- Allow rules exist for documentation/visibility but don't change traffic behavior
- Use case: "I want to block specific things but allow everything else"
- Ringfencing in selective mode requires a deny rule to be effective
- Good stepping stone between visibility and full enforcement

### Full Enforcement
- Default action is **DENY ALL**
- Only traffic explicitly permitted by allow rules can pass
- Most restrictive and most secure mode
- Use case: "Only explicitly allowed traffic should flow"
- Requires comprehensive policy before enabling — missing rules will break connectivity

## Recommended Rollout Order

1. **Visibility Only** — discover traffic patterns, build policy
2. **Selective Enforcement** — enforce deny rules, validate allow rules don't break anything
3. **Full Enforcement** — flip to deny-all default once policy is comprehensive

## Mixed Enforcement Warning
Having workloads in the same app with different enforcement modes is a common issue during rollouts. Use `get-workload-enforcement-status` to detect this.
"""
    },
    "illumio://concepts/segmentation": {
        "name": "Illumio Segmentation & Ringfencing",
        "description": "Core concepts for application segmentation and ringfencing",
        "content": """# Illumio Segmentation Concepts

## Labels
Illumio uses a label system (not traditional network zones) to identify workloads:
- **Role** — what the workload does (web, db, app-server)
- **Application** — which application it belongs to (CRM, Ordering, ELK)
- **Environment** — deployment environment (Production, Staging, Development)
- **Location** — physical or logical location (US-East, Cloud, DC1)

An application is uniquely identified by its **app + env** label combination.

## Rulesets and Scopes
- A **ruleset** contains rules and has one or more **scopes**
- A scope defines which workloads the ruleset applies to (e.g., app=CRM, env=Production)
- Rules within a ruleset are either:
  - **Intra-scope** — traffic between workloads inside the scope (unscoped_consumers=false)
  - **Extra-scope** — traffic from outside the scope into it (unscoped_consumers=true)

## Ringfencing
Ringfencing = coarse-grained app-to-app segmentation on All Services:

### Standard Ringfence
1. Create a ruleset scoped to [app, env]
2. Add an intra-scope allow rule: All Workloads -> All Workloads on All Services
3. For each remote app that needs access, add an extra-scope allow rule

### Selective Ringfence
Same as standard, plus:
4. Add a **deny rule** (regular, NOT override deny) blocking all inbound
5. The deny rule (step 4 in processing) catches unknown traffic
6. Allow rules for known remote apps (step 3 in processing) are processed first, so they pass through

### Override Deny is NOT for Ringfencing
Override deny blocks traffic above ALL allow rules. If you use it for ringfencing, your allow rules for known remote apps won't work because override deny is processed first. Override deny means "this traffic must not happen under any circumstances" — use it for emergency isolation, hard compliance blocks, or active attack response. Never for routine segmentation.

## Deny Consumer Flavors
Controls where the deny rule is enforced (Illumio writes deny rules to the consumer/source side):
- **`any`** — Consumer = IP list "Any (0.0.0.0/0)". Deny only at destination workloads. Safest.
- **`ams`** — Consumer = All Workloads. Deny pushed to every managed source workload. Broader.
- **`ams_and_any`** — Both. Maximum coverage.

## Policy Coverage
Traffic flows have a `policy_decision`:
- **allowed** — covered by active allow rules
- **potentially_blocked** — would be blocked if draft policy were provisioned
- **blocked** — currently blocked by active policy

When creating ringfence rules, remote apps are tagged:
- **already_allowed** — all flows already covered by existing policy (rule created for documentation)
- **newly_allowed** — at least one flow would be blocked without the new rule (filling a gap)

## Infrastructure Services
Infrastructure services (DNS, AD, monitoring) should be policy'd FIRST because many apps depend on them. Use `identify-infrastructure-services` to find them. If you ringfence an app before allowing its infrastructure dependencies, you break it.
"""
    },
    "illumio://concepts/draft-active-policy": {
        "name": "Illumio Draft vs Active Policy",
        "description": "Understanding draft and active policy states and provisioning",
        "content": """# Draft vs Active Policy

Illumio uses a two-stage policy model:

## Draft Policy
- All mutations (create, update, delete) go to `/sec_policy/draft/`
- Draft changes are NOT enforced — they're a staging area
- Multiple changes can be accumulated before provisioning
- Draft policy can be simulated: traffic flows show `potentially_blocked` for flows that WOULD be blocked if the draft were provisioned

## Active Policy
- Currently enforced policy at `/sec_policy/active/`
- Read-only — cannot be modified directly
- Only changes when draft policy is provisioned

## Provisioning
- Moves draft changes to active state
- Use `provision-policy` tool to provision
- Use `compare-draft-active` to preview what would change
- Always review draft changes before provisioning
- Provisioning is atomic — all changes go live at once

## Policy Simulation
The `policy_decision` field on traffic flows is extremely powerful:
- Shows what would happen if current draft policy were active
- `potentially_blocked` = "this traffic would break if you provision"
- Use this to validate policy BEFORE enforcing it
- The `enforcement-readiness` tool uses this to assess readiness
"""
    },
    "illumio://compliance/pci-dss": {
        "name": "PCI-DSS Segmentation & Visibility Requirements",
        "description": "PCI-DSS v4.0 requirements mapped to Illumio segmentation and visibility controls",
        "content": """# PCI-DSS v4.0 — Segmentation & Visibility with Illumio

## Overview
PCI-DSS requires organizations that handle cardholder data to implement strict network segmentation
and access controls. Illumio provides micro-segmentation that directly maps to PCI requirements.

## Key Concept: Cardholder Data Environment (CDE)
The CDE includes all systems that store, process, or transmit cardholder data, plus any systems
directly connected to or supporting those systems. Proper segmentation REDUCES PCI scope by
isolating the CDE from the rest of the network.

## Requirement Mapping

### Requirement 1: Install and Maintain Network Security Controls
- **1.2.1** — Network security controls (NSCs) must restrict traffic between CDE and untrusted networks
  - Illumio: Ringfence CDE apps with `create-ringfence` using `selective=true`
  - Override deny for absolute blocks: CDE must NEVER reach certain external networks
- **1.2.5** — All services, protocols, and ports allowed must be documented and authorized
  - Illumio: `get-traffic-flows-summary` shows all observed services with policy decisions
  - `get-policy-coverage-report` identifies gaps between observed traffic and policy
- **1.3.1** — Inbound traffic to the CDE must be restricted to only necessary traffic
  - Illumio: Extra-scope allow rules in ringfence rulesets explicitly permit inbound sources
  - All other inbound is blocked by deny rule (selective) or default deny (full enforcement)
- **1.3.2** — Outbound traffic from the CDE must be restricted to only necessary traffic
  - Illumio: Create outbound rulesets scoped to CDE apps with explicit allow rules
- **1.4.1** — NSCs between trusted and untrusted networks must be implemented
  - Illumio: Enforcement mode must be `selective` or `full` for CDE workloads
  - `get-workload-enforcement-status` verifies all CDE workloads are enforced

### Requirement 2: Apply Secure Configurations
- **2.2.4** — Only necessary services, protocols, daemons, and functions are enabled
  - Illumio: `find-unmanaged-traffic` detects unauthorized services
  - Traffic flow analysis shows unnecessary port exposure

### Requirement 6: Develop and Maintain Secure Systems
- **6.4.1** — Public-facing web applications must be protected
  - Illumio: Identify internet-facing workloads via traffic flows from unmanaged IPs
  - Ringfence public-facing apps separately from internal CDE systems

### Requirement 7: Restrict Access to System Components
- **7.2.1** — Access control systems must restrict access based on business need
  - Illumio: Label-based policy ensures only authorized apps reach CDE
  - `compliance-check framework=pci-dss` validates rule coverage
- **7.2.5** — All application and system accounts are assigned least privilege
  - Illumio: Granular rules per port/protocol instead of "All Services" for CDE

### Requirement 10: Log and Monitor All Access
- **10.2.1** — Audit logs capture all access to cardholder data
  - Illumio: `get-events` provides PCE audit trail
  - Traffic flows serve as network-level access logs
- **10.4.1** — Audit logs are reviewed to identify anomalies
  - Illumio: `detect-lateral-movement-paths` identifies unexpected connectivity

### Requirement 11: Test Security Systems and Processes
- **11.4.1** — Penetration testing validates segmentation controls
  - Illumio: `enforcement-readiness` assesses policy completeness
  - `compare-draft-active` ensures no policy drift

## PCI-Specific High-Risk Ports
These ports require explicit allow rules and should NEVER be open to/from CDE without justification:
- **3389** (RDP) — Remote Desktop, primary attack vector
- **22** (SSH) — Secure Shell, limit to jump hosts only
- **23** (Telnet) — MUST be blocked, unencrypted protocol
- **445** (SMB) — Windows file sharing, lateral movement vector
- **1433** (MSSQL), **3306** (MySQL), **5432** (PostgreSQL), **1521** (Oracle) — Database ports, CDE core
- **27017** (MongoDB), **6379** (Redis) — NoSQL databases
- **135/139** (NetBIOS/RPC) — Windows infrastructure, restrict within CDE only

## Segmentation Validation Strategy
1. Use `identify-infrastructure-services` to find shared services CDE depends on
2. Ringfence CDE apps with `create-ringfence` (selective mode for gradual rollout)
3. Use `enforcement-readiness` to assess each CDE app before moving to full enforcement
4. Run `compliance-check framework=pci-dss` to validate against requirements
5. Use `get-policy-coverage-report` to prove all CDE traffic is policy-covered
6. Document with `get-traffic-flows-summary` showing only authorized flows remain
"""
    },
    "illumio://compliance/dora": {
        "name": "DORA (Digital Operational Resilience Act) Requirements",
        "description": "EU DORA regulation mapped to Illumio segmentation and operational resilience controls",
        "content": """# DORA — Digital Operational Resilience Act with Illumio

## Overview
DORA (EU Regulation 2022/2554) requires financial entities to ensure digital operational resilience
through ICT risk management, incident reporting, resilience testing, and third-party risk management.
Effective January 17, 2025.

## Who Must Comply
Banks, insurance companies, investment firms, payment institutions, crypto-asset service providers,
and critical ICT third-party service providers operating in the EU.

## Requirement Mapping

### Chapter II: ICT Risk Management Framework (Articles 5-16)

#### Article 6: ICT Risk Management Framework
- **6.8** — Identify, classify, and document all ICT assets and dependencies
  - Illumio: `get-workloads` with label filtering provides complete asset inventory
  - `identify-infrastructure-services` maps critical ICT dependencies
  - Labels (app, env, role, loc) classify assets by function and criticality

#### Article 7: ICT Systems, Protocols, and Tools
- **7.1** — Use resilient, reliable ICT systems with sufficient capacity
  - Illumio: `get-workload-enforcement-status` ensures protection is active
  - Monitor enforcement mode consistency across critical systems

#### Article 8: Identification
- **8.1** — Identify and document all ICT-supported business functions and assets
  - Illumio: Traffic flow analysis reveals actual application dependencies
  - `get-traffic-flows-summary` documents communication patterns
  - `find-unmanaged-traffic` identifies undocumented ICT assets

#### Article 9: Protection and Prevention
- **9.1** — Continuously monitor and control ICT system security
  - Illumio: Micro-segmentation prevents lateral movement between systems
  - `detect-lateral-movement-paths` identifies potential propagation paths
- **9.2** — Implement policies to restrict network access
  - Illumio: `create-ringfence` enforces app-level segmentation
  - Enforcement modes control traffic at the workload level
- **9.3** — Design network connectivity to allow immediate severing/isolation
  - Illumio: Override deny rules can instantly isolate compromised systems
  - `emergency-isolate-application` prompt provides guided isolation workflow
  - Isolation is immediate — no firewall change requests needed

#### Article 10: Detection
- **10.1** — Detect anomalous activities, network performance issues, ICT incidents
  - Illumio: `get-events` monitors PCE events with severity filtering
  - Traffic flow analysis detects unauthorized communication patterns
  - `find-unmanaged-traffic` surfaces unknown connections

#### Article 11: Response and Recovery
- **11.1** — ICT business continuity policy with response and recovery plans
  - Illumio: Segmentation limits blast radius of incidents
  - Override deny enables immediate containment
  - `compare-draft-active` ensures recovery policy is ready to provision
- **11.3** — Activate response plans upon ICT-related incidents
  - Illumio: `emergency-isolate-application` provides one-click isolation
  - `provision-policy` can rapidly deploy pre-staged containment rules

### Chapter III: ICT-Related Incident Management (Articles 17-23)

#### Article 17: ICT-Related Incident Management Process
- **17.1** — Classify and report ICT incidents by impact and severity
  - Illumio: `get-events` with severity filters supports incident classification
  - Traffic flows provide forensic evidence of incident scope

#### Article 18: Classification of ICT-Related Incidents
- Map incident severity to segmentation response:
  - **Critical**: Override deny — immediate isolation
  - **Major**: Selective enforcement — restrict to known-good traffic
  - **Minor**: Monitor via visibility mode, draft new rules as needed

### Chapter IV: Digital Operational Resilience Testing (Articles 24-27)

#### Article 25: Testing ICT Tools and Systems
- **25.1** — Perform vulnerability assessments, network security assessments
  - Illumio: `compliance-check` validates segmentation policy
  - `enforcement-readiness` assesses enforcement completeness
  - `get-policy-coverage-report` measures policy coverage

#### Article 26: Advanced Testing (TLPT)
- **26.1** — Threat-led penetration testing for significant financial entities
  - Illumio: `detect-lateral-movement-paths` maps potential attack paths
  - Segmentation effectiveness can be validated without disruption using visibility mode

### Chapter V: Third-Party Risk Management (Articles 28-44)

#### Article 28: ICT Third-Party Risk
- **28.1** — Manage risks from ICT third-party service providers
  - Illumio: `find-unmanaged-traffic` reveals third-party connections
  - Ringfence third-party integration points
  - Monitor third-party traffic patterns for anomalies

## DORA-Specific Segmentation Strategy
1. **Identify**: Use `identify-infrastructure-services` + `get-workloads` to map all ICT assets
2. **Classify**: Label workloads by criticality and business function
3. **Protect**: Ringfence critical financial services, enforce segmentation
4. **Detect**: Monitor traffic flows for anomalous patterns
5. **Respond**: Pre-stage override deny rules for critical systems, test isolation procedures
6. **Recover**: Use `compare-draft-active` to manage recovery policy, provision when ready

## Key DORA Principle: Immediate Isolation Capability
DORA Article 9.3 specifically requires the ability to immediately sever/isolate affected systems.
Illumio's override deny rules provide this — they block traffic instantly, overriding any allow rules.
This maps directly to DORA's requirement for rapid containment during ICT incidents.
"""
    },
    "illumio://compliance/nist-800-53": {
        "name": "NIST 800-53 Security Controls",
        "description": "NIST 800-53 Rev 5 controls mapped to Illumio segmentation capabilities",
        "content": """# NIST 800-53 Rev 5 — Security Controls with Illumio

## Overview
NIST 800-53 provides a catalog of security and privacy controls for federal information systems.
Many private sector organizations adopt it as a comprehensive security framework.

## Control Family Mapping

### AC — Access Control

#### AC-3: Access Enforcement
- Enforce approved authorizations for logical access to information and system resources
- Illumio: Label-based policy enforces access at the workload level
- Rulesets define exactly which apps can communicate with which
- `get-policy-coverage-report` validates enforcement completeness

#### AC-4: Information Flow Enforcement
- Enforce approved authorizations for controlling the flow of information within the system
  and between connected systems
- Illumio: Micro-segmentation controls east-west traffic flows
- Ringfencing enforces app-to-app communication policies
- Policy decisions (allowed/blocked/potentially_blocked) show flow enforcement status
- **AC-4(21)** Physical/logical separation of information flows
  - Illumio: Labels create logical separation without physical network changes

#### AC-17: Remote Access
- Establish usage restrictions and implementation guidance for remote access
- Illumio: Control which systems remote access (RDP 3389, SSH 22, VNC 5900) can reach
- High-risk ports must have explicit allow rules only to authorized destinations

### AU — Audit and Accountability

#### AU-2: Event Logging
- Identify events that the system must log
- Illumio: `get-events` provides comprehensive PCE event logging
- Traffic flows serve as network-level audit trail

#### AU-6: Audit Record Review, Analysis, and Reporting
- Review and analyze audit records for indications of inappropriate or unusual activity
- Illumio: `detect-lateral-movement-paths` analyzes traffic for unusual patterns
- `find-unmanaged-traffic` identifies unauthorized connections

### CA — Assessment, Authorization, and Monitoring

#### CA-7: Continuous Monitoring
- Develop a continuous monitoring strategy and implement a program
- Illumio: Continuous traffic flow visibility across all workloads
- `enforcement-readiness` provides ongoing readiness assessment
- `compliance-check` can be run periodically for compliance validation

### CM — Configuration Management

#### CM-7: Least Functionality
- Configure the system to provide only essential capabilities
- Restrict the use of unnecessary ports, protocols, functions, and services
- Illumio: Traffic analysis reveals unnecessary services
- `find-unmanaged-traffic` identifies services outside policy
- Ringfencing limits each app to only its required connectivity

### IA — Identification and Authentication

#### IA-3: Device Identification and Authentication
- Uniquely identify and authenticate devices before establishing connections
- Illumio: VEN agents on workloads provide device-level identification
- Labels provide logical identity for policy decisions

### IR — Incident Response

#### IR-4: Incident Handling
- Implement an incident handling capability including preparation, detection, containment
- Illumio: Override deny rules provide immediate containment
- `emergency-isolate-application` enables rapid incident response
- Segmentation limits blast radius during incidents

#### IR-6: Incident Reporting
- Report incidents to appropriate authorities and organizational entities
- Illumio: `get-events` provides incident evidence and audit trail
- Traffic flow data supports forensic analysis

### SC — System and Communications Protection

#### SC-7: Boundary Protection
- Monitor and control communications at external managed interfaces and key internal boundaries
- Illumio: Micro-segmentation creates boundaries at every workload
- `create-ringfence` establishes application-level boundaries
- `get-workload-enforcement-status` verifies boundary enforcement
- **SC-7(5)** Deny by default / allow by exception
  - Illumio: Full enforcement mode = deny-all default, only explicitly allowed traffic passes
  - Selective enforcement = allow-all default with explicit deny rules

#### SC-28: Protection of Information at Rest
- Protect the confidentiality and integrity of information at rest
- Illumio: Segment database systems containing sensitive data
- Override deny blocks ensure critical data stores are never exposed

### SI — System and Information Integrity

#### SI-4: System Monitoring
- Monitor the system to detect attacks, unauthorized connections, and anomalies
- Illumio: Traffic flow analysis detects unauthorized network activity
- `detect-lateral-movement-paths` identifies potential attack paths
- `find-unmanaged-traffic` surfaces unknown connections

## NIST High-Risk Ports
Ports requiring explicit authorization under NIST controls:
- **22** (SSH), **23** (Telnet), **3389** (RDP) — Remote access
- **135/139** (NetBIOS/RPC), **445** (SMB) — Windows services
- **1433** (MSSQL), **3306** (MySQL), **5432** (PostgreSQL) — Databases
- **80/443** (HTTP/HTTPS) — Web services (restrict from internal systems to CDE)
"""
    },
    "illumio://compliance/iso-27001": {
        "name": "ISO 27001:2022 Controls",
        "description": "ISO 27001:2022 Annex A controls mapped to Illumio segmentation capabilities",
        "content": """# ISO 27001:2022 — Information Security Controls with Illumio

## Overview
ISO 27001:2022 is the international standard for information security management systems (ISMS).
Annex A contains 93 controls organized into 4 themes. Network segmentation maps to multiple controls.

## Annex A Control Mapping

### A.5 — Organizational Controls

#### A.5.9: Inventory of Information and Other Associated Assets
- Maintain an inventory of information and associated assets
- Illumio: `get-workloads` provides workload inventory with labels
- Labels classify assets by app, env, role, and location
- `identify-infrastructure-services` maps critical dependencies

#### A.5.23: Information Security for Use of Cloud Services
- Establish processes for acquisition, use, management, and exit of cloud services
- Illumio: Segment cloud workloads with same label-based policy as on-premises
- `find-unmanaged-traffic` identifies cloud service dependencies

#### A.5.25: Assessment and Decision on Information Security Events
- Assess information security events and decide if they are incidents
- Illumio: `get-events` provides security event visibility
- Traffic flows provide evidence for event assessment

### A.8 — Technological Controls

#### A.8.20: Networks Security
- Secure networks and network services, including mechanisms for filtering traffic
- Illumio: Micro-segmentation provides workload-level traffic filtering
- `create-ringfence` establishes network security boundaries
- `get-workload-enforcement-status` validates security is active

#### A.8.21: Security of Network Services
- Identify and implement security mechanisms, service levels, and requirements
- Illumio: Policy-driven segmentation ensures consistent network security
- `compliance-check` validates control effectiveness

#### A.8.22: Segregation of Networks
- Groups of information services, users, and information systems shall be segregated
- Illumio: Label-based segmentation segregates by application, environment, and role
- Ringfencing provides coarse-grained segregation
- Fine-grained rules provide per-port/protocol controls within segments
- `detect-lateral-movement-paths` validates segregation effectiveness

#### A.8.23: Web Filtering
- Access to external websites shall be managed to reduce exposure to malicious content
- Illumio: Outbound traffic rules control which systems can reach external services
- `find-unmanaged-traffic` direction=outbound identifies uncontrolled outbound connections

#### A.8.26: Application Security Requirements
- Information security requirements shall be identified and specified when developing/acquiring applications
- Illumio: `enforcement-readiness` validates security completeness per application
- `get-policy-coverage-report` measures policy coverage

## ISO 27001 Segmentation Best Practices
1. **Classify** assets using Illumio labels (app, env, role, loc)
2. **Segregate** using ringfencing between applications and environments
3. **Enforce** with progressive enforcement (visibility → selective → full)
4. **Monitor** with continuous traffic flow analysis
5. **Audit** with compliance checks and event monitoring
6. **Improve** using enforcement readiness scores to track progress
"""
    },
    "illumio://compliance/swift-csp": {
        "name": "SWIFT Customer Security Programme (CSP)",
        "description": "SWIFT CSP controls mapped to Illumio segmentation for financial messaging security",
        "content": """# SWIFT CSP — Customer Security Programme with Illumio

## Overview
SWIFT's Customer Security Programme (CSP) establishes mandatory security controls for all
organizations connected to the SWIFT network. The secure zone containing SWIFT infrastructure
must be strictly segmented from the rest of the enterprise network.

## Key Concept: SWIFT Secure Zone
The SWIFT secure zone contains all SWIFT-related components:
- SWIFT messaging interfaces (Alliance Lite2, Alliance Access, Alliance Gateway)
- SWIFT communication interfaces
- Operator PCs used to access SWIFT
- Any system that directly connects to SWIFT infrastructure

This zone MUST be isolated from the general enterprise network.

## Mandatory Control Mapping

### 1. Restrict Internet Access & Protect Critical Systems

#### 1.1: SWIFT Environment Protection
- Ensure the protection of the SWIFT infrastructure from the general IT environment
- Illumio: Ringfence SWIFT zone apps with `create-ringfence selective=true`
- Override deny to block SWIFT zone from internet access entirely
- Only explicitly authorized systems can reach SWIFT components

#### 1.2: Operating System Privileged Account Control
- Restrict and control privileged OS account usage within the SWIFT secure zone
- Illumio: Limit SSH (22) and RDP (3389) access to SWIFT systems to jump hosts only
- Explicit allow rules only for authorized admin connections

#### 1.4: Restriction of Internet Access
- SWIFT-connected systems must not have direct internet access
- Illumio: **Override deny rule** blocking all traffic from SWIFT zone to internet IPs
- This is a "must not happen under any circumstances" scenario — override deny is correct here
- `find-unmanaged-traffic` validates no unauthorized internet connections exist

### 2. Reduce Attack Surface and Vulnerabilities

#### 2.1: Internal Data Flow Security
- Ensure confidentiality, integrity, and authentication of data flows between SWIFT components
- Illumio: Intra-scope rules control traffic within SWIFT zone
- Enforce specific port/protocol rules (not All Services) between SWIFT components

#### 2.6: Operator Session Confidentiality and Integrity
- Protect operator sessions to SWIFT-related applications
- Illumio: Allow only encrypted protocols (SSH, HTTPS) from operator PCs to SWIFT systems
- Block unencrypted protocols (Telnet 23, HTTP 80, FTP 21)

### 3. Physically Secure the Environment
(Physical controls — Illumio supports with logical segmentation of location-labeled workloads)

### 4. Prevent Compromise of Credentials

#### 4.1: Password Policy
- Enforce strong password policies for SWIFT system accounts
- Illumio: Complements by ensuring only authorized systems can attempt authentication

### 5. Manage Identities and Segregate Privileges

#### 5.1: Logical Access Control
- Enforce least-privilege access to SWIFT systems
- Illumio: Fine-grained rules restrict SWIFT zone access to specific source apps/roles
- `get-policy-coverage-report` validates all SWIFT traffic is explicitly authorized

### 6. Detect Anomalous Activity

#### 6.1: Malware Protection
- Detect and prevent malware in the SWIFT secure zone
- Illumio: Segmentation prevents malware lateral movement into/within SWIFT zone
- `detect-lateral-movement-paths` identifies potential propagation vectors

#### 6.4: Logging and Monitoring
- Record and monitor security events in the SWIFT secure zone
- Illumio: `get-events` monitors SWIFT-related policy events
- Traffic flows provide network-level audit trail for SWIFT zone

## SWIFT-Specific High-Risk Ports
Ports requiring strict control in the SWIFT secure zone:
- **3389** (RDP), **22** (SSH) — Admin access, restrict to jump hosts
- **23** (Telnet), **21** (FTP) — MUST be blocked (unencrypted)
- **80** (HTTP) — Block in favor of HTTPS only
- **1433/3306/5432** — Database access, restrict to SWIFT application servers
- **445** (SMB), **135/139** (NetBIOS) — Block within SWIFT zone

## SWIFT Segmentation Strategy
1. Label all SWIFT components with dedicated app label (e.g., app=SWIFT)
2. Create SWIFT secure zone ringfence with `create-ringfence selective=true`
3. Add **override deny** blocking SWIFT zone → internet (must never happen)
4. Add explicit allow rules for authorized connections only
5. Validate with `compliance-check` and `get-policy-coverage-report`
6. Move to full enforcement after validation
"""
    },
    "illumio://compliance/cis-controls": {
        "name": "CIS Controls v8",
        "description": "CIS Critical Security Controls v8 mapped to Illumio segmentation capabilities",
        "content": """# CIS Controls v8 — Critical Security Controls with Illumio

## Overview
The CIS Critical Security Controls (formerly SANS Top 20) are a prioritized set of actions
to protect organizations from known cyber-attack vectors. Illumio maps to several controls
in the network and data protection domains.

## Control Mapping

### CIS Control 1: Inventory and Control of Enterprise Assets
- Actively manage all enterprise assets connected to the network
- Illumio: `get-workloads` provides managed asset inventory
- `find-unmanaged-traffic` reveals assets not yet under management
- Labels provide classification (app, env, role, location)

### CIS Control 2: Inventory and Control of Software Assets
- Actively manage all software on the network
- Illumio: Traffic flow analysis reveals which services/ports are in use
- Unexpected services indicate unauthorized software

### CIS Control 3: Data Protection
- Develop processes and controls to identify, classify, securely handle data
- Illumio: Segment systems handling sensitive data with ringfencing
- Override deny for systems that must never expose data externally

### CIS Control 4: Secure Configuration of Enterprise Assets and Software
- Establish and maintain secure configurations
- Illumio: `compliance-check` validates segmentation configuration
- `get-workload-enforcement-status` verifies enforcement is properly configured

### CIS Control 6: Access Control Management
- Use processes and tools to create, assign, manage, and revoke access credentials
- Illumio: Label-based policy controls network-level access
- Rules define exactly which applications can communicate

### CIS Control 7: Continuous Vulnerability Management
- Develop a plan to continuously assess and remediate vulnerabilities
- Illumio: `enforcement-readiness` provides ongoing security posture assessment
- `detect-lateral-movement-paths` identifies vulnerability propagation paths

### CIS Control 8: Audit Log Management
- Collect, alert, review, and retain audit logs of events
- Illumio: `get-events` provides audit log access
- Traffic flows provide network-level audit data

### CIS Control 9: Email and Web Browser Protections
- Improve protections and detections of threats from email and web vectors
- Illumio: Control which systems can reach web/email ports (80, 443, 25, 587)

### CIS Control 12: Network Infrastructure Management
- **12.2** — Establish and maintain a secure network architecture
  - Illumio: Micro-segmentation creates a secure architecture without network redesign
  - `create-ringfence` establishes app-level security boundaries
- **12.3** — Securely manage network infrastructure
  - Illumio: `get-workload-enforcement-status` monitors enforcement health
- **12.8** — Establish and maintain dedicated computing resources for admin work
  - Illumio: Segment admin jump hosts, restrict RDP/SSH to these only

### CIS Control 13: Network Monitoring and Defense
- **13.1** — Centralize security event alerting
  - Illumio: `get-events` provides centralized security events
- **13.3** — Deploy a network intrusion detection solution
  - Illumio: Traffic flow visibility serves as behavior-based detection
  - `detect-lateral-movement-paths` identifies suspicious connectivity
- **13.4** — Perform traffic filtering between network segments
  - Illumio: Core capability — micro-segmentation is traffic filtering
  - `get-policy-coverage-report` validates filtering completeness
- **13.5** — Manage access control for remote assets
  - Illumio: VPN/remote access segmentation via label-based policy

### CIS Control 17: Incident Response Management
- **17.1** — Designate personnel to manage incident handling
- **17.3** — Establish and maintain an incident response plan
  - Illumio: Override deny rules enable immediate containment
  - `emergency-isolate-application` provides guided incident response
  - Pre-stage containment rules in draft policy for rapid deployment

## CIS High-Risk Ports
- **3389** (RDP), **22** (SSH), **23** (Telnet) — Remote access
- **445** (SMB), **135/139** (NetBIOS/RPC) — File sharing / Windows
- **21** (FTP), **69** (TFTP) — File transfer (unencrypted)
- **25/587** (SMTP) — Email servers
"""
    },
    "illumio://compliance/hipaa": {
        "name": "HIPAA Security Rule",
        "description": "HIPAA Security Rule requirements mapped to Illumio segmentation for healthcare data protection",
        "content": """# HIPAA Security Rule — Healthcare Segmentation with Illumio

## Overview
The HIPAA Security Rule requires covered entities and business associates to implement
safeguards to protect electronic Protected Health Information (ePHI). Network segmentation
is a key technical safeguard.

## Key Concept: ePHI Environment
Systems that create, receive, maintain, or transmit ePHI must be identified and protected.
Segmenting ePHI systems reduces the scope of HIPAA compliance requirements.

## Safeguard Mapping

### Administrative Safeguards (§164.308)

#### §164.308(a)(1) — Security Management Process
- Implement policies and procedures to prevent, detect, contain, and correct security violations
- Illumio: Micro-segmentation prevents lateral movement to ePHI systems
- `detect-lateral-movement-paths` identifies potential violation paths
- Override deny enables immediate containment of active violations

#### §164.308(a)(7) — Contingency Plan
- Establish policies for responding to emergencies that damage ePHI systems
- Illumio: `emergency-isolate-application` provides rapid containment
- Pre-staged draft policies enable quick recovery

### Physical Safeguards (§164.310)

#### §164.310(b) — Workstation Use
- Implement policies specifying proper functions and manner of use for workstations
- Illumio: Segment workstations by role, restrict ePHI access to authorized roles

### Technical Safeguards (§164.312)

#### §164.312(a)(1) — Access Control
- Implement technical policies to allow access only to authorized persons/software
- Illumio: Label-based policy restricts ePHI system access to authorized applications
- `create-ringfence` isolates ePHI systems from general network
- `get-policy-coverage-report` validates access control completeness

#### §164.312(b) — Audit Controls
- Implement mechanisms to record and examine activity in systems containing ePHI
- Illumio: Traffic flows provide network-level audit trail
- `get-events` provides system-level audit records

#### §164.312(c)(1) — Integrity
- Protect ePHI from improper alteration or destruction
- Illumio: Segment database systems containing ePHI
- Restrict database port access to authorized application servers only

#### §164.312(d) — Person or Entity Authentication
- Verify identity of persons/entities seeking access to ePHI
- Illumio: Network-level authentication via workload identity (VEN + labels)
- Only authenticated, labeled workloads can reach ePHI systems

#### §164.312(e)(1) — Transmission Security
- Implement technical measures to guard against unauthorized access to ePHI during transmission
- Illumio: Block unencrypted protocols (Telnet, FTP, HTTP) to/from ePHI systems
- Allow only encrypted protocols (SSH, HTTPS, TLS-wrapped database connections)

## HIPAA Segmentation Strategy
1. Label all ePHI systems (app=EMR, app=PACS, app=PatientDB, etc.)
2. Identify ePHI dependencies with `identify-infrastructure-services`
3. Ringfence each ePHI application with strict inbound/outbound controls
4. Block unencrypted protocols to ePHI zone via deny rules
5. Validate with `compliance-check` and `enforcement-readiness`
6. Monitor with continuous traffic flow analysis
"""
    },
    "illumio://compliance/segmentation-methodology": {
        "name": "Segmentation Methodology & Best Practices",
        "description": "General methodology for implementing micro-segmentation with Illumio across any compliance framework",
        "content": """# Segmentation Methodology — Framework-Agnostic Best Practices

## The Segmentation Journey

### Phase 1: Discovery & Visibility
**Goal**: Understand what you have and how it communicates.

1. **Asset Discovery**
   - Deploy VEN agents on all workloads
   - `get-workloads` to inventory managed systems
   - Assign labels: app, env, role, location

2. **Traffic Discovery**
   - Set enforcement mode to `visibility_only`
   - Collect traffic flows for 30-90 days
   - `get-traffic-flows-summary` to understand communication patterns
   - `find-unmanaged-traffic` to identify blind spots

3. **Dependency Mapping**
   - `identify-infrastructure-services` to find critical shared services
   - Map app-to-app dependencies from traffic flows
   - Identify internet-facing vs internal-only applications
   - `detect-lateral-movement-paths` to understand risk exposure

### Phase 2: Policy Design
**Goal**: Design segmentation policy before enforcing it.

1. **Infrastructure First**
   - Policy infrastructure services first (DNS, AD, monitoring, backup)
   - These are consumed by many apps — if you ringfence apps without allowing infra, you break things
   - Use `identify-infrastructure-services` to prioritize

2. **Application Ringfencing**
   - `create-ringfence` for each application (dry_run=true first)
   - Review discovered remote apps and validate they should have access
   - Use `skip_allowed=true` for minimal rulesets or `false` for self-documenting ones

3. **Compliance Zone Isolation**
   - CDE (PCI), SWIFT zone, ePHI systems get additional restrictions
   - Override deny for hard blocks (e.g., "CDE must never reach internet")
   - Fine-grained rules within compliance zones (not just All Services)

4. **Policy Validation**
   - `enforcement-readiness` to assess each app
   - `get-policy-coverage-report` to measure coverage
   - `compare-draft-active` to review pending changes
   - `compliance-check` against relevant framework

### Phase 3: Enforcement Rollout
**Goal**: Progressively enforce policy with minimal disruption.

1. **Selective Enforcement First**
   - Move workloads from `visibility_only` to `selective`
   - Selective mode: default=allow, deny rules are actively enforced
   - This catches gross violations without breaking everything
   - `get-workload-enforcement-status` to track rollout progress

2. **Monitor and Adjust**
   - Watch for `blocked` traffic in flows — is it intentional or a missing rule?
   - `get-policy-coverage-report` shows gaps
   - Add rules for legitimate traffic before moving to full enforcement

3. **Full Enforcement**
   - Move workloads to `full` enforcement
   - Default=deny: only explicitly allowed traffic flows
   - Start with less critical apps, build confidence
   - Critical systems last (after thorough validation)

### Phase 4: Continuous Operations
**Goal**: Maintain and improve segmentation over time.

1. **Ongoing Monitoring**
   - Regular `compliance-check` runs
   - `find-unmanaged-traffic` to catch new unauthorized connections
   - `get-events` for security event monitoring

2. **Policy Drift Detection**
   - `compare-draft-active` to detect uncommitted changes
   - `enforcement-readiness` scores should trend upward

3. **Incident Response**
   - Override deny for emergency isolation
   - `emergency-isolate-application` for guided incident response
   - Pre-stage containment rules in draft policy

## Common Pitfalls
- **Ringfencing without allowing infrastructure** — breaks DNS, AD, monitoring. Always identify infra first.
- **Using override deny for ringfencing** — override deny blocks above allow rules. Your app-level allow rules won't work. Use regular deny.
- **All Services rules everywhere** — coarse for ringfencing, but compliance zones need per-port/protocol rules.
- **Skipping selective enforcement** — going straight to full enforcement breaks things. Use selective as a stepping stone.
- **Not validating with traffic flows** — policy looks good on paper but real traffic patterns may differ. Always verify with actual flow data.
- **Mixed enforcement modes** — inconsistent enforcement within an app creates security gaps. Use `get-workload-enforcement-status` to detect.

## Compliance Framework Quick Reference

| Framework | Focus Area | Key Illumio Tools |
|-----------|-----------|-------------------|
| PCI-DSS | CDE isolation | ringfence, override deny, compliance-check pci-dss |
| DORA | Operational resilience, incident response | ringfence, emergency isolation, enforcement-readiness |
| NIST 800-53 | Comprehensive security controls | all tools |
| ISO 27001 | ISMS, network segregation | ringfence, compliance-check, enforcement-readiness |
| SWIFT CSP | SWIFT secure zone | ringfence, override deny, find-unmanaged-traffic |
| HIPAA | ePHI protection | ringfence, policy-coverage-report, compliance-check |
| CIS Controls | Prioritized cyber defense | identify-infra, ringfence, detect-lateral-movement |
"""
    },
    "illumio://architecture/pce-ven": {
        "name": "PCE & VEN Architecture",
        "description": "Illumio platform architecture — PCE (Policy Compute Engine) and VEN (Virtual Enforcement Node) components, deployment models, and scaling",
        "content": """# Illumio Architecture — PCE & VEN

## Two Core Components

### Policy Compute Engine (PCE)
The PCE is the central brain of Illumio. It:
- Stores all data (workloads, labels, rules, traffic flows)
- Calculates security policy and distributes it to VENs
- Provides the management UI and API
- Can scale to support hundreds of thousands of workloads

### Virtual Enforcement Node (VEN)
The VEN runs on each managed workload. It:
- Reports traffic flows and workload state back to the PCE
- Implements security policy by managing the local host firewall (iptables/Windows Firewall)
- Available for Linux, Windows, Solaris, and AIX
- Lightweight — minimal CPU, RAM, and disk usage
- Upgrades can be pushed centrally from the PCE

## PCE Deployment Options

### Cloud Service (SaaS)
- Managed by Illumio's operations team
- Quick start, no hardware required
- SOC 2-compliant, highly resilient
- Recommended for 0–10,000 workloads or organizations without deep Linux expertise

### On-Premises
- Full control over all PCE operations
- Recommended for 0–250,000 workloads
- Required for strict data residency or custodianship requirements
- Needs Linux servers with specific OS and storage requirements
- Minimum 4 servers per cluster (supports up to 10,000 workloads)
- Larger footprints support up to 25,000 workloads per cluster

### Supercluster (Large Scale)
- Federated set of clusters with near-real-time replication
- For organizations with 25,000+ managed workloads
- Single-pane-of-glass visibility across all clusters
- Each cluster can operate independently during outages
- Common pattern: regional PCE clusters (e.g., Americas, EMEA, APAC)

## Redundancy & High Availability

### Split-Cluster (Metro-Area HA)
- PCE nodes split between two data centers
- Hot-hot deployment — survives total failure of one data center
- Specific latency requirements between the two sites

### Cold-Standby (DR)
- No specific latency requirements
- Can be combined with split-cluster for full DR capability

### VEN Connectivity
- No specific latency requirement between PCE and VEN
- Global deployments work fine (e.g., PCE in North America, VENs in Asia)
- VENs continue enforcing last-known policy if PCE connectivity is lost

## PCE Hardening
- On-premises PCEs need hardening per Illumio's published hardening guide
- Protect against malicious connections and data integrity threats
- Illumio provides tools to implement recommended controls
"""
    },
    "illumio://concepts/workloads": {
        "name": "Workload Types & VEN Deployment",
        "description": "Managed vs unmanaged workloads, VEN deployment strategies, and workload lifecycle",
        "content": """# Illumio Workloads

## What Is a Workload?
A workload is any endpoint on your network:
- Physical or virtual server
- Public cloud instance (AWS EC2, Azure VM, GCP)
- Container
- Storage appliance
- VIP on a load balancer or proxy device
- Any device with an IP address

## Two Types of Workloads

### Managed Workloads
- Have the VEN software installed and activated
- Under full management by Illumio
- VEN provides traffic visibility AND policy enforcement
- VEN reports workload state, open ports, running processes
- Can be in any enforcement mode: idle, visibility_only, selective, full

### Unmanaged Workloads
- Represented in the PCE but do NOT have VEN installed
- Important for modeling — they appear in dependency maps
- Typical for network appliances, legacy systems, or devices that can't run VEN
- Can have labels assigned for policy purposes
- Traffic TO them from managed workloads is visible
- Traffic FROM them is NOT visible (no VEN to report it)
- Use `find-unmanaged-traffic` to identify traffic involving unmanaged workloads

## VEN Deployment Strategy

### Distribution Methods
- **Automation tools**: Chef, Puppet, Ansible for Linux/Windows
- **SCCM**: Push to Windows workloads via Microsoft SCCM
- **Golden image**: Pre-install VEN in your base image, activates on deployment
- **Custom scripting**: SSH to each workload and pull the VEN package

### Deployment Order (recommended)
1. Start small — pilot with a limited set of workloads
2. Deploy to infrastructure/core services first (DNS, AD, backup)
3. Expand to business applications by criticality
4. Create unmanaged workloads for devices that can't run VEN
5. Full coverage is the goal — gaps in VEN deployment = gaps in visibility

### VEN Behavior on Activation
- Immediately establishes communication with the PCE
- Reports local network state (interfaces, open ports, processes)
- Begins providing traffic visibility
- Starts enforcing policy based on its configured enforcement mode

## Enforcement Modes per Workload
Each workload has its own enforcement mode:
- **Idle**: VEN installed but not active
- **Visibility Only**: Reports traffic, no enforcement
- **Selective**: Enforces deny rules only, default=allow
- **Full**: Enforces all rules, default=deny

**Important**: Enforcement mode is set per-workload, not globally. You can have different
modes within the same application during rollout. Use `get-workload-enforcement-status`
to detect mixed enforcement within an app (a common issue during rollouts).

## Workloads and Deny Rules
The design guide predates deny rule features. Key additions:
- **Deny rules** (regular): Written to the consumer (source) workload's firewall
- **Override deny rules**: Block traffic above all allow rules — for emergencies only
- Deny rules only apply to **managed workloads** (unmanaged workloads have no VEN to enforce them)
- The `deny_consumer` parameter controls which workloads receive the deny rule:
  - `any`: Only destination workloads get the deny rule (safest)
  - `ams`: All managed workloads get the deny rule (broader enforcement)
  - `ams_and_any`: Both (maximum coverage)
"""
    },
    "illumio://architecture/labels": {
        "name": "Label Design (R+A+E+L)",
        "description": "Illumio's four-dimensional label model — Role, Application, Environment, Location — design principles, data quality, and governance",
        "content": """# Illumio Label Design — R+A+E+L

## The Four Dimensions

Each workload is identified by up to four labels:

| Dimension | Purpose | Examples |
|-----------|---------|----------|
| **R**ole | Function the workload performs | Web Server, Database, App Server, Load Balancer |
| **A**pplication | Application the workload belongs to | Payroll, CRM, ELK, SAP, Oracle EBS |
| **E**nvironment | Deployment stage | Production, Staging, QA, Development, DR |
| **L**ocation | Physical or logical location | US-East, Cloud-AWS, DC1, London, EMEA |

## Key Design Principles

### Labels Are NOT Groups
Each label dimension is **independent**. Labels combine to form a unique set of security
properties for each workload. A production HR webserver in London inherits policies from:
- All London servers
- All HR servers
- All production webservers
This intersection-based model is what makes Illumio's policy scalable.

### Consistency Within Dimensions
Each dimension should ALWAYS refer to the same logical concept:
- If Role holds application tiers (web, app, db), always use it for tiers
- Don't mix concepts (e.g., don't put sensitivity classifications in the Role dimension)
- Consistent usage enables predictable policy behavior

### Security Policies Use Labels, Not IPs
Policies are written as label-to-label rules:
- "Web servers in Production can connect to Database servers in Production on port 3306"
- NOT "10.0.1.5 can connect to 10.0.2.10 on port 3306"
- When workloads change (scale up/down, IP changes), policy automatically adapts

### Unique Application Identity
An application is identified by **App + Env** label combination:
- App=CRM, Env=Production → one application instance
- App=CRM, Env=Staging → different application instance
- Ringfencing scopes to this combination

## Data Sources for Labels

### Where to Get Label Data
- **CMDB** (ServiceNow, BMC, etc.) — most comprehensive source
- **Cloud metadata** — AWS tags, Azure tags, GCP labels
- **Hostname conventions** — parse app/env/role from naming patterns
- **API integration** — sync labels automatically from external sources
- **Manual entry** — smallest deployments or one-off systems

### Label Data Quality
- Most organizations start with 50-80% accuracy for environment labels
- Other dimensions (app, role) are often lower
- **This is OK** — Illumio is designed to work with incomplete data
- Traffic flow visibility helps you discover and correct labels
- The process of adopting Illumio improves your metadata quality

### Data Governance
- Consider appointing a **data guardian** for label quality
- Automate label sync from authoritative sources via API
- Refresh labels regularly (daily or real-time as changes occur)
- Updates to labels automatically trigger policy recalculation

## Label Design Anti-Patterns
- **Too few labels**: Everything labeled as "App=Server" — no meaningful segmentation
- **Too many roles**: Hundreds of unique roles — policy becomes unmanageable
- **Inconsistent dimensions**: Location sometimes means physical DC, sometimes means region
- **Missing labels**: Workloads without labels can't be targeted by policy
- **Stale labels**: Workload moved to production but still labeled Development

## Labels and Policy Rules
When writing rules, labels define the scope:
- **Ruleset scope**: App=CRM, Env=Production applies rules to all CRM Production workloads
- **Intra-scope rules**: Traffic between workloads in the same scope
- **Extra-scope rules**: Traffic from outside the scope into it
- **Deny rules**: Can target any label combination (but deny rules are NOT in the design guide — they were added later)
"""
    },
    "illumio://methodology/first-principles": {
        "name": "FIRST Principles of Security Segmentation",
        "description": "Illumio's FIRST methodology — Find, Identify, Reach out, Start, Target — the recommended approach to deploying segmentation",
        "content": """# Illumio's FIRST Principles of Security Segmentation

The FIRST Principles provide a structured methodology for deploying micro-segmentation.
Follow these in order for the highest chance of success.

## F — Find Metadata Sources

**Goal**: Know where your workload data lives before you start.

- Identify your CMDB, cloud metadata, hostname conventions, spreadsheets
- Determine which sources can provide which label dimensions (R, A, E, L)
- Assess data quality — 50-80% accuracy for environment labels is typical to start
- Plan how to sync this data to the PCE (API, manual, or hybrid)

**Illumio Tools**: `get-workloads` to see current inventory, labels reveal data gaps

## I — Identify a Label Design

**Goal**: Design your R+A+E+L label model before applying it.

- Role: what does the workload do? (web, db, app-server)
- Application: which application? (CRM, Payroll, SAP)
- Environment: what stage? (Production, Staging, Dev)
- Location: where is it? (physical DC, cloud region, regulatory jurisdiction)
- Keep each dimension consistent — same concept always
- Labels are NOT groups — they combine for unique identity

**Illumio Tools**: `get-label-dimensions` to see current label schema

## R — Reach Out to Service Owners Early

**Goal**: Engage stakeholders before enforcement begins.

- Service owners know their applications' expected traffic patterns
- They can validate dependency maps against expected behavior
- Early engagement prevents surprises when enforcement starts
- Common stakeholders:
  - Application owners (validate app-to-app communication)
  - Network team (understand existing firewall rules)
  - Security team (define compliance requirements)
  - Operations team (identify maintenance and backup traffic)

**Illumio Tools**: `get-traffic-flows-summary` produces dependency reports service owners can review

## S — Start with Core Services

**Goal**: Policy infrastructure services first — they affect everything else.

Core services are consumed by most/all workloads:
- Active Directory / LDAP
- DNS
- NTP
- Backup (NetBackup, Veeam, Commvault)
- Monitoring (Splunk, Datadog, Zabbix, Nagios)
- Patching / SCCM / WSUS
- Anti-virus / EDR management servers

**Why first?**
- Core services represent a large percentage of total traffic
- Rules for them de-clutter the dependency map
- If you ringfence an app without allowing its core service dependencies, you break it
- Core service rules are consistent across workloads — write once, apply broadly

**Illumio Tools**: `identify-infrastructure-services` uses traffic graph analysis to automatically
find core services based on connection patterns (high fan-in = provider infra, high fan-out = consumer infra)

## T — Target Ringfencing for Business Applications

**Goal**: After core services are handled, ringfence your business applications.

Ringfencing = coarse-grained segmentation at the app level:
1. Each app gets a virtual perimeter (ruleset scoped to app+env)
2. Internal communication within the app is allowed (intra-scope rule)
3. Known remote apps get explicit allow rules (extra-scope rules)
4. Unknown traffic is blocked (via deny rules in selective mode, or default-deny in full mode)

**Progressive approach**:
- Start with `dry_run=true` to preview what rules would be created
- Use `skip_allowed=false` to create rules for ALL observed traffic (self-documenting)
- Validate with `enforcement-readiness` before enforcing
- Start with selective enforcement (deny rules block, default=allow)
- Graduate to full enforcement (default=deny) after validation

**Illumio Tools**: `create-ringfence`, `enforcement-readiness`, `get-policy-coverage-report`

## Putting FIRST Together

```
Find metadata  →  Get label data into the PCE
     ↓
Identify labels  →  Design R+A+E+L model
     ↓
Reach out  →  Engage service owners, validate dependency maps
     ↓
Start with core  →  Policy DNS, AD, backup, monitoring first
     ↓
Target ringfencing  →  Ringfence business apps, progressive enforcement
```

Each step builds on the previous one. Skipping steps leads to broken connectivity,
missing policies, and frustrated stakeholders.
"""
    },
    "illumio://methodology/core-services": {
        "name": "Core Services Strategy",
        "description": "Why infrastructure services must be policy'd first — identification, types, and strategy for core service segmentation",
        "content": """# Core Services — Policy Infrastructure First

## What Are Core Services?

Core services are infrastructure services consumed by most or all workloads in your environment.
They provide platform or operating system-level functionality.

**Examples:**
| Service | Protocol/Port | Direction | Why It's Core |
|---------|--------------|-----------|---------------|
| Active Directory / LDAP | 389/636, 88 (Kerberos) | Provider (inbound) | Authentication for all Windows workloads |
| DNS | 53 UDP/TCP | Provider (inbound) | Name resolution for everything |
| NTP | 123 UDP | Provider (inbound) | Time sync, affects logging and auth |
| NetBackup / Veeam | Various | Consumer (outbound) | Backup agents connect to all workloads |
| Splunk / SIEM | 514, 8089, 9997 | Consumer (outbound) | Log collection from all workloads |
| SCCM / WSUS / Patching | 8530, 443 | Provider (inbound) | OS patching for managed workloads |
| Monitoring (Nagios, Zabbix) | Various | Consumer (outbound) | Health checks on all systems |
| Anti-virus mgmt (SEP, CrowdStrike) | Various | Both | Agent management and updates |
| DHCP | 67/68 UDP | Provider | IP assignment |
| Proxy / Web Gateway | 8080, 3128 | Provider (inbound) | Internet access for workloads |

## Why Policy Core Services First?

### 1. They Are a Large Percentage of Traffic
Core service connections often represent 40-60% of total observed traffic.
Policy'ing them first dramatically simplifies the dependency map for application owners.

### 2. They De-Clutter the Dependency Map
Once core service rules exist, application dependency maps show only
application-specific traffic — which is what app owners need to validate.

### 3. Ringfencing Without Core Services Breaks Things
If you ringfence an application but haven't allowed DNS, AD, or monitoring:
- DNS lookups fail → app can't resolve hostnames
- AD auth fails → users can't log in
- Monitoring breaks → false alerts, SLA violations
- Backup stops → data loss risk

**Always** create core service rules before ringfencing business apps.

### 4. Core Service Rules Are Broadly Applicable
A rule like "All workloads can reach DNS on port 53" applies everywhere.
Write it once, and it covers every app you ringfence later.

## Identifying Core Services

### Automatic Detection
Use `identify-infrastructure-services` to find core services automatically.
It analyzes the app-to-app communication graph and scores services:

**Provider Infrastructure** (consumed by many apps):
- High in-degree centrality (many apps connect TO it)
- Low out-degree (doesn't initiate connections to many apps)
- Examples: DNS, AD, NTP, SCCM

**Consumer Infrastructure** (connects out to many apps):
- High out-degree centrality (connects TO many apps)
- Low in-degree (few apps connect to it)
- Examples: Monitoring, backup, log shipping, vulnerability scanners

**Scoring:**
- Provider score: 40% in-degree + 30% consumer ratio + 25% betweenness + 5% volume
- Consumer score: 40% out-degree + 30% producer ratio + 25% betweenness + 5% volume
- Mixed-traffic dampening reduces scores for bidirectional apps (those are business apps, not infra)
- Classification: Core Infrastructure (≥75), Shared Service (≥50), Standard Application (<50)

### Manual Identification
Ask your infrastructure team: "Which services do ALL servers need?"
The answer is your core services list.

## Core Service Policy Strategy

### Step 1: Identify
```
identify-infrastructure-services --env Production --min_flows 100
```

### Step 2: Label
Ensure all core service workloads have correct labels:
- Role: DNS, ActiveDirectory, Backup, Monitoring, etc.
- App: Infrastructure or the specific product name
- Env: Production (core services are almost always production)

### Step 3: Write Allow Rules
Create rulesets with broad scopes that allow core service traffic:
- "All Workloads → DNS on port 53"
- "All Workloads → AD on ports 389, 636, 88"
- "Backup servers → All Workloads on backup agent ports"

### Step 4: Validate
- `get-traffic-flows-summary` confirms traffic is policy-covered
- `get-policy-coverage-report` shows any remaining gaps

### Step 5: Then Ringfence Apps
Now that core services have rules, ringfencing business apps won't break infrastructure dependencies.

## Core Services and Deny Rules
The design guide predates deny/override deny rules. Important additions:

- **DO NOT** ringfence core services with deny rules in most cases
  - Core services need broad accessibility — deny rules restrict that
  - Exception: restrict management ports (SSH/RDP) on core service servers to jump hosts

- **Override deny** may apply to core services in emergency scenarios:
  - Compromised AD server → override deny to isolate it immediately
  - Core service with active vulnerability → override deny to block exploitation
  - These are emergency actions, not normal policy
"""
    },
    "illumio://methodology/ringfencing-patterns": {
        "name": "Ringfencing Patterns & Granularity Levels",
        "description": "Three levels of application segmentation — App Group Level, Role Level All Services, Role Level Specified Services — with deny rule integration",
        "content": """# Ringfencing Patterns — Progressive Granularity

Illumio supports multiple levels of segmentation granularity. You can mix and match
based on each application's security requirements.

## Pattern 1: App Group Level (Application Ringfencing)

**The most common pattern.** A virtual perimeter around the entire application.

```
┌─────────────────────────────────────────┐
│  App=CRM, Env=Production                │
│                                          │
│  ┌─────┐   ┌─────┐   ┌─────┐           │
│  │ Web │←→│ App │←→│ DB  │           │
│  └─────┘   └─────┘   └─────┘           │
│     ↕ All workloads communicate freely   │
└─────────────────────────────────────────┘
     ↑ Only authorized external apps can enter
```

**Rules:**
- Intra-scope: All Workloads → All Workloads on All Services (free internal comms)
- Extra-scope: Specific remote apps → All Workloads on All Services
- In selective mode: Add deny rule blocking all other inbound

**Characteristics:**
- Simple to implement and maintain
- Prevents lateral movement BETWEEN applications
- Does NOT restrict lateral movement WITHIN the application
- Best balance of security vs complexity for most apps
- Most Illumio customers use this as their baseline

## Pattern 2: Role Level — All Services

**Adds role-based restrictions within the application perimeter.**

```
┌──────────────────────────────────────────┐
│  App=CRM, Env=Production                 │
│                                           │
│  ┌─────┐   ┌─────┐   ┌─────┐            │
│  │ Web │──→│ App │──→│ DB  │            │
│  └─────┘   └─────┘   └─────┘            │
│     Web cannot directly reach DB          │
└──────────────────────────────────────────┘
```

**Rules:**
- Role-to-role allow rules: Web → App on All Services, App → DB on All Services
- No direct Web → DB rule (so Web can't reach the database)
- Extra-scope: External apps → specific roles only

**Characteristics:**
- More restrictive than App Group Level
- Prevents lateral movement between tiers within the app
- Still uses All Services — any port is allowed between authorized roles
- Requires knowledge of which roles talk to which

## Pattern 3: Role Level — Specified Services

**The most granular level. Role-to-role, port-by-port.**

```
┌──────────────────────────────────────────┐
│  App=CRM, Env=Production                 │
│                                           │
│  ┌─────┐ 8443  ┌─────┐ 3306  ┌─────┐   │
│  │ Web │──────→│ App │──────→│ DB  │   │
│  └─────┘       └─────┘       └─────┘   │
│     Only specified ports allowed          │
└──────────────────────────────────────────┘
```

**Rules:**
- Web → App on TCP 8443 only
- App → DB on TCP 3306 only
- No other connections allowed within the app

**Characteristics:**
- Highest security — prevents lateral movement even within an app
- Requires detailed knowledge of exact ports/protocols per role
- More maintenance as applications change over time
- Recommended for **Digital Crown Jewels** (sensitive apps)

## Choosing the Right Pattern

| Factor | App Group | Role All Services | Role Specified |
|--------|-----------|-------------------|----------------|
| Security level | Good | Better | Best |
| Complexity | Low | Medium | High |
| Maintenance | Low | Medium | Higher |
| Knowledge needed | App boundaries | Role-to-role flow | Exact ports |
| Best for | Most apps | Important apps | Crown jewels |

**Recommended approach:**
- App Group Level for 80% of applications (baseline protection)
- Role Level All Services for important business apps
- Role Level Specified Services for digital crown jewels (PCI CDE, SWIFT zone, ePHI)
- You can upgrade an app's pattern anytime without changing other apps

## Deny Rules and Ringfencing (Not in Original Design Guide)

The design guide predates Illumio's deny rule feature. Here's how deny rules integrate:

### Standard Ringfencing (Full Enforcement)
- No deny rules needed — full enforcement default is DENY ALL
- Allow rules are sufficient: anything not explicitly allowed is blocked

### Selective Ringfencing (Selective Enforcement)
- Selective mode default is ALLOW ALL — deny rules are required to block traffic
- Add a **regular deny rule** (`override: false`) blocking inbound to the app scope
- Known remote apps get **allow rules** which are processed BEFORE the deny rule
- Processing order: Allow (step 3) → Deny (step 4) → Default allow

### Override Deny — NOT for Ringfencing
Override deny is processed BEFORE allow rules (step 2). If you use it for ringfencing:
- Your extra-scope allow rules for known remote apps will be OVERRIDDEN
- Nothing can get through, including legitimate traffic
- Override deny means "this must not happen under any circumstances"
- Use cases: emergency isolation, hard compliance blocks, active attack response
- NEVER use override deny for routine segmentation

### Deny Consumer Options
When adding deny rules for ringfencing:
- `any` (default): Deny rule enforced only at destination workloads. Safest.
- `ams`: Deny rule pushed to ALL managed workloads. Broader but wider blast radius.
- `ams_and_any`: Both. Maximum enforcement but highest impact.
"""
    },
    "illumio://methodology/crown-jewels": {
        "name": "Digital Crown Jewels",
        "description": "Identifying and protecting your most sensitive applications with the highest level of segmentation control",
        "content": """# Digital Crown Jewels — Maximum Protection

## What Are Digital Crown Jewels?

Crown jewels are applications that store or process your most sensitive data:
- **Payment/financial data** — PCI cardholder data, banking systems, trading platforms
- **Personal information** — PII, PHI (health records), employee data
- **Trade secrets** — intellectual property, source code repositories, R&D systems
- **Critical infrastructure** — industrial control systems, SCADA
- **Regulatory data** — SWIFT messaging systems, SOX financial reporting
- **Authentication systems** — Active Directory, certificate authorities, identity providers

## Why Crown Jewels Need Special Treatment

Most applications can be adequately protected with **App Group Level ringfencing** —
a coarse-grained perimeter around the entire application.

Crown jewels need **Role Level Specified Services** — the most granular pattern:
- Port-by-port, protocol-by-protocol control
- Web → App on TCP 8443 ONLY, App → DB on TCP 3306 ONLY
- No "All Services" rules within the crown jewel perimeter
- This prevents lateral movement WITHIN the application

## Identifying Crown Jewels

### Ask These Questions
1. What data, if breached, would make headlines?
2. What systems, if compromised, would halt business operations?
3. What regulatory frameworks apply, and which systems are in scope?
4. What applications have the highest data sensitivity classification?

### Common Crown Jewels by Industry
| Industry | Crown Jewels |
|----------|-------------|
| Financial Services | Trading platforms, payment processing, SWIFT, core banking |
| Healthcare | EMR/EHR systems, PACS imaging, patient databases |
| Retail | POS systems, payment processing, customer databases |
| Manufacturing | SCADA/ICS, R&D systems, patent databases |
| Technology | Source code repos, CI/CD pipelines, secrets management |
| Government | Classified systems, citizen data, critical infrastructure |

## Crown Jewel Protection Strategy

### Step 1: Identify and Label
- Label crown jewel workloads with specific app and role labels
- Example: App=PaymentGateway, Role=PaymentDB, Env=Production
- Ensure 100% label accuracy — no room for error on critical systems

### Step 2: Map Dependencies
```
get-traffic-flows-summary --app PaymentGateway --env Production
identify-infrastructure-services --app PaymentGateway --env Production
```
- Document every connection, every port, every protocol
- Validate with application owners — "is this expected traffic?"
- Flag any unexpected connections for investigation

### Step 3: Write Granular Rules (Role Level Specified Services)
Instead of "All Workloads → All Workloads on All Services":
- Payment Web → Payment App on TCP 8443
- Payment App → Payment DB on TCP 3306
- Payment App → Payment Cache on TCP 6379
- Monitoring → All Roles on TCP 9100 (metrics)
- Nothing else is allowed within the perimeter

### Step 4: Add Compliance-Specific Controls
For PCI crown jewels:
- Block high-risk ports (RDP, Telnet, FTP) with deny rules
- Override deny for hard compliance blocks ("CDE must never reach internet")
- Encrypt all data-in-transit (block HTTP, require HTTPS)

For SWIFT crown jewels:
- Override deny blocking SWIFT zone → internet
- Restrict admin access (SSH/RDP) to jump hosts only
- Block all unencrypted protocols

### Step 5: Enforce Progressively
1. Visibility Only → collect traffic flows, validate rules
2. Selective → deny rules active, verify no breakage
3. Full enforcement → default=deny, only explicitly allowed traffic flows

### Step 6: Monitor Continuously
```
compliance-check --framework pci-dss --app PaymentGateway --env Production
detect-lateral-movement-paths --app PaymentGateway --env Production
enforcement-readiness --app PaymentGateway --env Production
```

## Crown Jewels and Deny/Override Deny Rules

### Regular Deny Rules for Selective Mode
- Crown jewels in selective mode NEED deny rules for ringfencing
- Block ALL inbound except explicitly allowed sources
- Use the most restrictive deny_consumer option appropriate

### Override Deny for Hard Compliance Blocks
Override deny is appropriate for crown jewels in specific scenarios:
- "PCI CDE must NEVER reach the internet" → override deny
- "SWIFT zone must NEVER have direct internet access" → override deny
- "ePHI database must NEVER be accessible from development" → override deny
- These are absolute blocks that no allow rule should ever bypass

### Override Deny is NOT for Day-to-Day Segmentation
Even for crown jewels, normal segmentation uses regular deny rules + allow rules.
Override deny is the nuclear option — use it only for compliance-mandated hard blocks
and emergency isolation scenarios.

## Maintenance Considerations
Crown jewel protection at Role Level Specified Services requires more maintenance:
- Application changes (new microservice, port change) require rule updates
- Regular reviews with application owners
- `compare-draft-active` to detect policy drift
- Automated compliance checks on a schedule
- The maintenance cost is justified by the data sensitivity
"""
    },
    "illumio://operations/logging-monitoring": {
        "name": "Logging, Monitoring & SIEM Integration",
        "description": "PCE logging types, SIEM integration, traffic data records, auditable events, and alerting strategies",
        "content": """# Logging, Monitoring, and Alerting with Illumio

## Three Types of PCE Log Data

### 1. PCE Internal Messages
- Unstructured log records about PCE component operations
- For support and troubleshooting only
- Managed automatically — log rotation, disk space management
- Stored in PCE log directory (on-premises)
- Not typically exported to SIEM

### 2. Auditable Events
Structured messages about significant security events:
- Agent activated / deactivated
- User password changed
- Security policy modified or provisioned
- Label created / modified / deleted
- Workload paired / unpaired
- Enforcement mode changed

**Properties:**
- Well-defined data fields (structured, parseable)
- Comply with Common Criteria Class FAU Security Audit standard
- Stored in PCE database, queryable via web UI and API
- Can be published to SIEM via syslog or Fluentd
- Available in JSON, CEF, or LEEF formats

**Illumio Tool**: `get-events` provides access to auditable events with severity filtering

### 3. Traffic Data Records
Periodic summaries of connections observed on managed workloads:
- Source and destination (IP, hostname, workload)
- Labels for source and destination (when available)
- Port, protocol, and process information
- Policy decision: **allowed**, **blocked**, or **potentially_blocked**
- Timestamp and volume data

**Traffic record types:**
- **Accepted**: Connections allowed by policy or default action
- **Blocked**: Connections denied by policy enforcement
- **Potentially Blocked**: Connections on non-enforcing workloads that WOULD be blocked if enforced

**Volume warning:** Traffic data can be very high-volume. Ensure your SIEM has sufficient capacity.

## SIEM Integration

### Supported SIEM Products
- **Splunk**: Illumio App for Splunk available on Splunkbase (turnkey integration)
- **HPE ArcSight**: CEF format output
- **IBM QRadar**: LEEF format output
- **Any syslog-compatible SIEM**: JSON, CEF, or LEEF via syslog
- **Fluentd-compatible systems**: Native Fluentd output

### Integration Architecture
```
PCE → syslog/Fluentd → SIEM
  ├── Auditable events (structured)
  └── Traffic data records (high volume)
```

### What to Send to Your SIEM
| Data Type | Volume | Value | Recommended |
|-----------|--------|-------|-------------|
| Auditable events | Low | High | Always export |
| Accepted traffic | High | Medium | Export if capacity allows |
| Blocked traffic | Medium | Very High | Always export |
| Potentially blocked | Medium | High | Export during rollout |

## Alerting Strategies

### Individual Event Alerts
High-priority events to alert on immediately:
- **agent.tampering** — VEN detected unauthorized changes to local firewall rules
- **enforcement_mode_changed** — workload enforcement mode was modified
- **policy_provisioned** — security policy was pushed to active
- **workload.unpaired** — VEN was removed from a managed workload

### Aggregate/Trend Alerts
Monitor totals and trends:
- Total messages per day by type — sudden spikes indicate issues
- Blocked traffic volume increase — may indicate attack or misconfiguration
- New "potentially blocked" flows appearing — policy gaps
- Workload count changes — track VEN deployment progress

### Traffic-Based Alerting
Use traffic data records for security monitoring:
- **Cross-environment traffic**: Production ↔ Development connections (label-enriched flows make this easy)
- **Unexpected protocol usage**: Telnet, FTP on production systems
- **Lateral movement indicators**: New connections between previously unrelated apps
- **Volume anomalies**: Sudden increase in traffic to a specific workload

**Illumio Tools:**
- `detect-lateral-movement-paths` — identifies potential lateral movement vectors
- `find-unmanaged-traffic` — surfaces unknown connections
- `get-traffic-flows-summary` — comprehensive traffic analysis

## Operational Monitoring

### PCE Health (On-Premises)
- Monitor PCE component health via internal messages
- Track PCE cluster state (primary/secondary, replication lag)
- Disk space monitoring for log and database storage

### VEN Health
- Track VEN connectivity status via PCE
- Alert on VEN tamper events
- Monitor VEN version distribution for upgrade tracking

### Policy Health
- `compare-draft-active` — detect uncommitted draft changes
- `enforcement-readiness` — track enforcement rollout progress
- `compliance-check` — periodic compliance validation
- `get-policy-coverage-report` — measure policy completeness

## Traffic Data for Forensics
Traffic data records are invaluable for incident investigation:
- "Which workloads communicated with the compromised server in the last 7 days?"
- "What ports were used for connections crossing from dev to prod?"
- "When did the first unauthorized connection to the database appear?"
- Labels enrich raw flow data with business context — you don't just see IPs, you see applications
"""
    },
}

@server.list_resources()
async def handle_list_resources() -> list[types.Resource]:
    """List Illumio knowledge base resources."""
    resources = []
    for uri, info in ILLUMIO_RESOURCES.items():
        resources.append(types.Resource(
            uri=uri,
            name=info["name"],
            description=info["description"],
            mimeType="text/plain"
        ))
    return resources

@server.read_resource()
async def handle_read_resource(uri) -> str:
    """Read an Illumio knowledge base resource."""
    uri_str = str(uri)
    if uri_str in ILLUMIO_RESOURCES:
        return ILLUMIO_RESOURCES[uri_str]["content"]
    raise ValueError(f"Unknown resource: {uri_str}")

@server.list_prompts()
async def handle_list_prompts() -> list[types.Prompt]:
    """
    List available prompts.
        Each prompt can have optional arguments to customize its behavior.
    """
    return [
        types.Prompt(
            name="ringfence-application",
            description="Ringfence an application by deploying rulesets to limit the inbound and outbound traffic",
            arguments=[
                types.PromptArgument(
                    name="application_name",
                    description="Name of the application to ringfence",
                    required=True,
                ),
                types.PromptArgument(
                    name="application_environment",
                    description="Environment of the application to ringfence",
                    required=True,
                )
            ],
        ),
        types.Prompt(
            name="analyze-application-traffic",
            description="Analyze the traffic flows for an application and environment",
            arguments=[
                types.PromptArgument(
                    name="application_name",
                    description="Name of the application to analyze",
                    required=True,
                ),
                types.PromptArgument(
                    name="application_environment",
                    description="Environment of the application to analyze",
                    required=True,
                )
            ]
        ),
        types.Prompt(
            name="emergency-isolate-application",
            description="Emergency isolation of an application using override deny rules — blocks ALL traffic to/from the app immediately, overriding any existing allow rules. Use only for security incidents.",
            arguments=[
                types.PromptArgument(
                    name="application_name",
                    description="Name of the application to isolate",
                    required=True,
                ),
                types.PromptArgument(
                    name="application_environment",
                    description="Environment of the application to isolate",
                    required=True,
                )
            ]
        )
    ]

@server.get_prompt()
async def handle_get_prompt(
    name: str, arguments: dict[str, str] | None
) -> types.GetPromptResult:
    """
    Generate a prompt by combining arguments with server state.
    The prompt includes all current notes and can be customized via arguments.
    """
    if name == "ringfence-application":
        return types.GetPromptResult(
            description="Ringfence an application by deploying rulesets to limit the inbound and outbound traffic",
            messages=[
                types.PromptMessage(
                    role="user",
                    content=types.TextContent(
                        type="text",
                        text=f"""
Ringfence the application {arguments['application_name']} in the environment {arguments['application_environment']}.
Always reference labels as hrefs like /orgs/1/labels/57 or similar.
Consumers means the source of the traffic, providers means the destination of the traffic.

1. First, get all the labels to have them available for later use.
2. Retrieve all the traffic flows inside the application and environment. 
   Only fetch potentially blocked or blocked traffic.Analyze the connections.
3. Then retrieve all the traffic flows inbound to the application and environment.
4. Inside the app, please be sure to have rules for each role or app tier to connect to the other tiers. 
5. Prefer the traffic summary over the traffic flow tool.

Always use traffic flows to find out what other applications and environemnts need to connect into {arguments['application_name']}, 
and then deploy rulesets to limit the inbound traffic to those applications and environments. 
For traffic that is required to connect outbound from {arguments['application_name']}, deploy rulesets to limit the 
outbound traffic to those applications and environments. If a consumer is coming from the same app and env, please use 
all workloads for the rules inside the scope (intra-scope). If it comes from the outside, please use app, env and if possible role

If a remote app is connected as destination, a new ruleset needs to be created that has the name of the remote app and env,
all incoming connections need to be added as extra-scope rules in that ruleset.
Always use hrefs for labels and workloads.
The logic in illumio is the following:

If a scope exists. Rules define connections within the scope if unscoped consumers is not set to true. Unscoped consumers define inbound traffic from things outside the scope. The unscoped consumer is a set of labels being the source of inbound traffic. Provider is the destination. For the provider a value of AMS (short for all workloads) means that a connection is allowed for all workloads inside the scope. So for example if the source is role=monitoring, app=nagios, env=prod, then the rule for the app=ordering, env=prod application would be:

  consumer: role=monitoring,app=nagios,env=prod 
  provider: role=All workloads
  service: 5666/tcp

  If a rule is setting unscoped consumers to "false", this means that the rule is intra scope. Repeating any label that is in the scope does not make sense for this. Instead use role or whatever specific label to characterize the thing in the scope.

e.g. for the loadbalancer to connect to the web-tier in ordering, prod the rule is:

scope: app=ordering, env=prod
consumers: role=loadbalancer
providers: role=web
service: 8080/tcp
unscoped consumers: false

This is a intra-scope rule allowing the role=loadbalancer,app=ordering,env=prod workloads to connect to the role=web,app=ordering,env=prod workloads on port 8080/tcp. 

For traffic that goes from the {arguments['application_name']} app to the outside, please create a ruleset with the name {arguments['application_name']}-outbound and make it scopeless.
Add all the outbound traffic to that ruleset using roles, applications and environments as labels.
                        """
                    )
                )
            ]
        )
    elif name == "analyze-application-traffic":
        return types.GetPromptResult(
            description="Analyze the traffic flows for an application and environment",
            messages=[
                types.PromptMessage(
                    role="user",
                    content=types.TextContent(
                        type="text",
                        text=f"""
                            Please provide the traffic flows for {arguments['application_name']} in the environment {arguments['application_environment']}.
                            Order by inbound and outbound traffic and app/env/role tupels.
                            Find other label types that are of interest and show them. Display your results in a react component. Show protocol, port and try to
                            understand the traffic flows (e.g. 5666/tcp likely could be nagios).
                            Categorize traffic into infrastructure and application traffic.
                            Find out if the application is internet facing or not.
                            Show illumio role labels, as well as application and environment labels in the output.
                        """
                    )
                )
            ]
        )

    elif name == "emergency-isolate-application":
        return types.GetPromptResult(
            description="Emergency isolation of an application using override deny rules",
            messages=[
                types.PromptMessage(
                    role="user",
                    content=types.TextContent(
                        type="text",
                        text=f"""
EMERGENCY ISOLATION: Immediately isolate application {arguments['application_name']} in environment {arguments['application_environment']}.

This is a security incident response action. You MUST use OVERRIDE DENY rules — these are the highest priority deny rules
in Illumio that block traffic even when allow rules exist. This is the correct and ONLY use case for override deny.

IMPORTANT CONTEXT — Illumio Rule Processing Order:
1. Essential rules (built-in)
2. **Override Deny rules** — THIS IS WHAT WE USE HERE. Blocks traffic above ALL allow rules.
3. Allow rules — these CANNOT override our override deny
4. Regular deny rules — NOT sufficient for emergency isolation (allow rules are processed first)
5. Default action

Steps:
1. First, get the labels for app={arguments['application_name']} and env={arguments['application_environment']} to get their hrefs.
2. Find or create a ruleset scoped to this app+env (name it "EMERGENCY-ISOLATE-{arguments['application_name']}-{arguments['application_environment']}").
3. Create an OVERRIDE DENY rule (override_deny=true) that blocks ALL inbound traffic:
   - providers: All Workloads (ams)
   - consumers: All Workloads (ams) AND IP list Any (0.0.0.0/0)
   - ingress_services: All Services
   - unscoped_consumers: true
   - override_deny: true  ← CRITICAL: this makes it override deny, not regular deny
4. Optionally create a second override deny rule for outbound if full isolation is needed.
5. PROVISION the policy immediately using provision-policy so it takes effect.
6. Report what was created and confirm the application is now isolated.

WARNING: Override deny rules override ALL allow rules. This WILL break all connectivity to/from this application.
Only use this for genuine security incidents. To undo, delete the override deny rules and re-provision.
                        """
                    )
                )
            ]
        )

    else:
        raise ValueError(f"Unknown prompt: {name}")

@server.list_tools()
async def handle_list_tools() -> list[types.Tool]:
    """
    List available tools.
    Each tool specifies its arguments using JSON Schema validation.
    """
    return [
        types.Tool(
            name="get-workloads",
            description="Get workloads from the PCE. Use detail_level to control breadth vs depth: 'compact' (default) for tabular overviews of thousands of workloads, 'full' for complete data on specific workloads, 'labels_only' for maximum breadth with just identity and labels.",
            inputSchema={
                "type": "object",
                "properties": {
                    "name": {"type": "string", "description": "Filter by workload name (supports partial matches)"},
                    "hostname": {"type": "string", "description": "Filter by hostname (supports partial matches)"},
                    "ip_address": {"type": "string", "description": "Filter by IP address (supports partial matches)"},
                    "description": {"type": "string", "description": "Filter by description (supports partial matches)"},
                    "managed": {"type": "boolean", "description": "Filter managed (true) or unmanaged (false) workloads"},
                    "online": {"type": "boolean", "description": "Filter online (true) or offline (false) workloads"},
                    "enforcement_mode": {
                        "type": "string",
                        "enum": ["visibility_only", "full", "idle", "selective"],
                        "description": "Filter by enforcement mode"
                    },
                    "labels": {"type": "string", "description": "JSON-encoded list of label URIs to filter by"},
                    "max_results": {"type": "integer", "description": "Maximum number of workloads to return (default 10000)"},
                    "detail_level": {
                        "type": "string",
                        "enum": ["compact", "full", "labels_only"],
                        "description": "Level of detail. 'compact' (default): tabular summary with key fields and labels. 'full': complete workload data including services, VEN agent, interfaces. 'labels_only': minimal table of href, name, hostname, and labels.",
                        "default": "compact"
                    },
                },
            },
        ),
        types.Tool(
            name="update-workload",
            description="Update a workload in the PCE. Identify by href (preferred) or name. Provide only fields you want to change.",
            inputSchema={
                "type": "object",
                "properties": {
                    "href": {"type": "string", "description": "Workload href (e.g., /orgs/1/workloads/xxxx). Preferred identifier."},
                    "name": {"type": "string", "description": "Workload name to find (alternative to href). If updating, this finds the workload."},
                    "new_name": {"type": "string", "description": "New name for the workload"},
                    "description": {"type": "string", "description": "New description for the workload"},
                    "hostname": {"type": "string", "description": "New hostname for the workload"},
                    "enforcement_mode": {
                        "type": "string",
                        "enum": ["visibility_only", "full", "idle", "selective"],
                        "description": "Enforcement mode to set"
                    },
                    "ip_addresses": {"type": "array", "items": {"type": "string"}, "description": "New IP addresses (replaces existing interfaces)"},
                    "labels": {
                        "type": "array",
                        "items": {"type": "object", "properties": {"key": {"type": "string"}, "value": {"type": "string"}}},
                        "description": "Labels to assign (replaces existing labels). Each item has 'key' and 'value'."
                    },
                },
            }
        ),
        types.Tool(
            name="get-labels",
            description="Get labels from the PCE with optional filtering",
            inputSchema={
                "type": "object",
                "properties": {
                    "key": {"type": "string", "description": "Filter by label key/type (e.g., 'role', 'app', 'env', 'loc')"},
                    "value": {"type": "string", "description": "Filter by label value (supports partial matches)"},
                    "max_results": {"type": "integer", "description": "Maximum number of labels to return"},
                    "include_deleted": {"type": "boolean", "description": "Include deleted labels"},
                    "usage": {"type": "boolean", "description": "Include label usage flags"},
                },
            }
        ),
        types.Tool(
            name="create-workload",
            description="Create a Illumio Core unmanaged workload in the PCE",
            inputSchema={
                "type": "object",
                "properties": {
                    "name": {"type": "string"},
                    "ip_addresses": {"type": "array", "items": {"type": "string"}},
                    "labels": {"type": "array", "items":
                               {"type": "object", "properties": {"key": {"type": "string"}, "value": {"type": "string"}}}
                    },
                },
                "required": ["name", "ip_addresses"],
            }
        ),
        types.Tool(
            name="create-label",
            description="Create a label of a specific type and the value in the PCE",
            inputSchema={
                "type": "object",
                "properties": {
                    "key": {"type": "string"},
                    "value": {"type": "string"},
                },
                "required": ["key", "value"]
            }
        ),
        types.Tool(
            name="delete-label",
            description="Delete a label in the PCE",
            inputSchema={
                "type": "object",
                "properties": {
                    "key": {"type": "string"},
                    "value": {"type": "string"},
                },
                "required": ["key", "value"]
            }
        ),
        types.Tool(
            name="delete-workload",
            description="Delete a workload from the PCE. Identify by href (preferred) or name.",
            inputSchema={
                "type": "object",
                "properties": {
                    "href": {"type": "string", "description": "Workload href (e.g., /orgs/1/workloads/xxxx)"},
                    "name": {"type": "string", "description": "Workload name (alternative to href)"},
                },
            }
        ),
        types.Tool(
            name="get-traffic-flows",
            description="Get traffic flows from the PCE with comprehensive filtering options",
            inputSchema={
                "type": "object",
                "properties": {
                    "start_date": {"type": "string", "description": "Starting datetime (YYYY-MM-DD or timestamp)"},
                    "end_date": {"type": "string", "description": "Ending datetime (YYYY-MM-DD or timestamp)"},
                    "include_sources": {
                        "type": "array",
                        "items": {"type": "string"},
                        "description": "Sources to include (label/IP list/workload HREFs, FQDNs, IPs)"
                    },
                    "exclude_sources": {
                        "type": "array",
                        "items": {"type": "string"},
                        "description": "Sources to exclude (label/IP list/workload HREFs, FQDNs, IPs)"
                    },
                    "include_destinations": {
                        "type": "array",
                        "items": {"type": "string"},
                        "description": "Destinations to include (label/IP list/workload HREFs, FQDNs, IPs)"
                    },
                    "exclude_destinations": {
                        "type": "array",
                        "items": {"type": "string"},
                        "description": "Destinations to exclude (label/IP list/workload HREFs, FQDNs, IPs)"
                    },
                    "include_services": {
                        "type": "array",
                        "items": {
                            "type": "object",
                            "properties": {
                                "port": {"type": "integer"},
                                "proto": {"type": "string"}
                            }
                        }
                    },
                    "exclude_services": {
                        "type": "array",
                        "items": {
                            "type": "object",
                            "properties": {
                                "port": {"type": "integer"},
                                "proto": {"type": "string"}
                            }
                        }
                    },
                    "policy_decisions": {
                        "type": "array",
                        "items": {
                            "type": "string",
                            "enum": ["allowed", "blocked", "potentially_blocked", "unknown"]
                        }
                    },
                    "exclude_workloads_from_ip_list_query": {"type": "boolean"},
                    "max_results": {"type": "integer"},
                    "query_name": {"type": "string"}
                },
                "required": ["start_date", "end_date"]
            }
        ),
        types.Tool(
            name="get-traffic-flows-summary",
            description="Get traffic flows from the PCE in a summarized text format, this is a text format that is not a dataframe, it also is not json, the form is: 'From <source> to <destination> on <port> <proto>: <number of connections>'",
            inputSchema={
                "type": "object",
                "properties": {
                    "start_date": {"type": "string", "description": "Starting datetime (YYYY-MM-DD or timestamp)"},
                    "end_date": {"type": "string", "description": "Ending datetime (YYYY-MM-DD or timestamp)"},
                    "include_sources": {
                        "type": "array",
                        "items": {"type": "string"},
                        "description": "Sources to include (label/IP list/workload HREFs, FQDNs, IPs). Best case these are hrefs like /orgs/1/labels/57 or similar. Other way is app=env as an example (label key and value)"
                    },
                    "exclude_sources": {
                        "type": "array",
                        "items": {"type": "string"},
                        "description": "Sources to exclude (label/IP list/workload HREFs, FQDNs, IPs). Best case these are hrefs like /orgs/1/labels/57 or similar. Other way is app=env as an example (label key and value)"
                    },
                    "include_destinations": {
                        "type": "array",
                        "items": {"type": "string"},
                        "description": "Destinations to include (label/IP list/workload HREFs, FQDNs, IPs). Best case these are hrefs like /orgs/1/labels/57 or similar. Other way is app=env as an example (label key and value)"
                    },
                    "exclude_destinations": {
                        "type": "array",
                        "items": {"type": "string"},
                        "description": "Destinations to exclude (label/IP list/workload HREFs, FQDNs, IPs). Best case these are hrefs like /orgs/1/labels/57 or similar. Other way is app=env as an example (label key and value)"
                    },
                    "include_services": {
                        "type": "array",
                        "items": {
                            "type": "object",
                            "properties": {
                                "port": {"type": "integer"},
                                "proto": {"type": "string"}
                            }
                        }
                    },
                    "exclude_services": {
                        "type": "array",
                        "items": {
                            "type": "object",
                            "properties": {
                                "port": {"type": "integer"},
                                "proto": {"type": "string"}
                            }
                        }
                    },
                    "policy_decisions": {
                        "type": "array",
                        "items": {
                            "type": "string",
                            "enum": ["allowed", "potentially_blocked", "blocked", "unknown"]
                        }
                    },
                    "exclude_workloads_from_ip_list_query": {"type": "boolean"},
                    "max_results": {"type": "integer"},
                    "query_name": {"type": "string"}
                },
                "required": ["start_date", "end_date"]
            }
        ),
        types.Tool(
            name="check-pce-connection",
            description="Are my credentials and the connection to the PCE working?",
            inputSchema={
                "type": "object",
                "properties": {}
            }
        ),
        types.Tool(
            name="get-rulesets",
            description="Get rulesets from the PCE with optional filtering",
            inputSchema={
                "type": "object",
                "properties": {
                    "name": {"type": "string", "description": "Filter rulesets by name (supports partial matches)"},
                    "description": {"type": "string", "description": "Filter rulesets by description (supports partial matches)"},
                    "enabled": {"type": "boolean", "description": "Filter by enabled/disabled status"},
                    "labels": {"type": "string", "description": "JSON-encoded list of label URIs to filter by scope"},
                    "max_results": {"type": "integer", "description": "Maximum number of rulesets to return"},
                }
            }
        ),
        types.Tool(
            name="get-iplists",
            description="Get IP lists from the PCE with optional filtering",
            inputSchema={
                "type": "object",
                "properties": {
                    "name": {"type": "string", "description": "Filter IP lists by name (supports partial matches)"},
                    "description": {"type": "string", "description": "Filter by description (supports partial matches)"},
                    "fqdn": {"type": "string", "description": "Filter by FQDN (supports partial matches)"},
                    "ip_address": {"type": "string", "description": "Filter by IP address (supports partial matches)"},
                    "max_results": {"type": "integer", "description": "Maximum number of IP lists to return"},
                }
            }
        ),
        types.Tool(
            name="get-events",
            description="Get events from the PCE with optional filtering",
            inputSchema={
                "type": "object",
                "properties": {
                    "event_type": {"type": "string", "description": "Filter by event type (e.g., 'system_task.expire_service_account_api_keys')"},
                    "severity": {
                        "type": "string",
                        "enum": ["emerg", "alert", "crit", "err", "warning", "notice", "info", "debug"],
                        "description": "Filter by event severity"
                    },
                    "status": {
                        "type": "string",
                        "enum": ["success", "failure"],
                        "description": "Filter by event status"
                    },
                    "created_by": {"type": "string", "description": "Filter by creator (user, agent, or system)"},
                    "timestamp_gte": {"type": "string", "description": "Earliest event timestamp (RFC 3339 format)"},
                    "timestamp_lte": {"type": "string", "description": "Latest event timestamp (RFC 3339 format)"},
                    "max_results": {"type": "integer", "description": "Maximum number of events to return", "default": 100},
                }
            }
        ),
        types.Tool(
            name="create-ruleset",
            description="Create a ruleset in the PCE with support for ring-fencing patterns",
            inputSchema={
                "type": "object",
                "properties": {
                    "name": {"type": "string", "description": "Name of the ruleset (e.g., 'RS-ELK'). Must be unique in the PCE."},
                    "description": {"type": "string", "description": "Description of the ruleset (optional)"},
                    "scopes": {
                        "type": "array",
                        "items": {
                            "type": "array",
                            "items": {"type": "string"}
                        },
                        "description": "List of label combinations that define scopes. Each scope is an array of label values. This need to be label references like /orgs/1/labels/57 or similar. Get the label href from the get-labels tool."
                    },
                    "rules": {
                        "type": "array",
                        "items": {
                            "type": "object",
                            "properties": {
                                "providers": {
                                    "type": "array",
                                    "items": {"type": "string"},
                                    "description": "Array of provider labels, 'ams' for all workloads, or IP list references (e.g., 'iplist:Any (0.0.0.0/0)')"
                                },
                                "consumers": {
                                    "type": "array",
                                    "items": {"type": "string"},
                                    "description": "Array of consumer labels, 'ams' for all workloads, or IP list references (e.g., 'iplist:Any (0.0.0.0/0)')"
                                },
                                "ingress_services": {
                                    "type": "array",
                                    "items": {
                                        "type": "object",
                                        "properties": {
                                            "port": {"type": "integer"},
                                            "proto": {"type": "string"}
                                        },
                                        "required": ["port", "proto"]
                                    }
                                },
                                "unscoped_consumers": {
                                    "type": "boolean",
                                    "description": "Whether to allow unscoped consumers (extra-scope rule)",
                                    "default": False
                                },
                                "rule_type": {
                                    "type": "string",
                                    "enum": ["allow", "deny", "override_deny"],
                                    "description": "Type of rule: 'allow' (default), 'deny' to block specific traffic, or 'override_deny' to block traffic overriding ALL allow rules (emergency use only — highest priority deny)",
                                    "default": "allow"
                                }
                            },
                            "required": ["providers", "consumers", "ingress_services"]
                        }
                    }
                },
                "required": ["name", "scopes"]
            }
        ),
        types.Tool(
            name="create-deny-rule",
            description="Create a deny rule in an existing ruleset. Deny rules block specific traffic (processed after allow rules). Override deny rules (override_deny=true) are the HIGHEST priority — they block traffic even when allow rules exist, meaning 'this must not happen under any circumstances.' Use override deny for emergency isolation, hard compliance blocks, or active attack response — NOT for normal segmentation or ringfencing. Rule processing order: 1) Essential rules, 2) Override Deny (blocks above all), 3) Allow rules, 4) Deny rules, 5) Default action.",
            inputSchema={
                "type": "object",
                "properties": {
                    "ruleset_href": {
                        "type": "string",
                        "description": "Href of the ruleset to add the deny rule to (e.g., /orgs/1/sec_policy/draft/rule_sets/123)"
                    },
                    "ruleset_name": {
                        "type": "string",
                        "description": "Name of the ruleset to add the deny rule to (alternative to ruleset_href)"
                    },
                    "providers": {
                        "type": "array",
                        "items": {"type": "string"},
                        "description": "Array of provider (destination) references: 'ams' for all workloads, label hrefs, key=value pairs, or 'iplist:<name>'"
                    },
                    "consumers": {
                        "type": "array",
                        "items": {"type": "string"},
                        "description": "Array of consumer (source) references: 'ams' for all workloads, label hrefs, key=value pairs, or 'iplist:<name>'"
                    },
                    "ingress_services": {
                        "type": "array",
                        "items": {
                            "type": "object",
                            "properties": {
                                "port": {"type": "integer"},
                                "proto": {"type": "string"}
                            },
                            "required": ["port", "proto"]
                        },
                        "description": "Services to deny (e.g., [{'port': 3389, 'proto': 'tcp'}])"
                    },
                    "override_deny": {
                        "type": "boolean",
                        "description": "If true, creates an override deny rule — the highest priority deny that blocks traffic even if allow rules exist. Means 'this must not happen under any circumstances.' Use for emergency isolation, hard compliance blocks (e.g., PCI zones), or active attack response. If false (default), creates a regular deny rule (processed after allow rules).",
                        "default": False
                    },
                    "unscoped_consumers": {
                        "type": "boolean",
                        "description": "Whether to allow unscoped consumers (extra-scope rule)",
                        "default": False
                    }
                },
                "required": ["providers", "consumers", "ingress_services"]
            }
        ),
        types.Tool(
            name="get-services",
            description="Get services from the PCE with optional filtering",
            inputSchema={
                "type": "object",
                "properties": {
                    "name": {"type": "string", "description": "Filter services by name (supports partial matches)"},
                    "description": {"type": "string", "description": "Filter services by description (supports partial matches)"},
                    "port": {"type": "integer", "description": "Filter services by port number"},
                    "proto": {"type": "string", "description": "Filter services by protocol (e.g., tcp, udp)"},
                    "process_name": {"type": "string", "description": "Filter services by process name"},
                    "max_results": {"type": "integer", "description": "Maximum number of services to return"},
                }
            }
        ),
        types.Tool(
            name="create-service",
            description="Create a new service definition in the PCE",
            inputSchema={
                "type": "object",
                "properties": {
                    "name": {"type": "string", "description": "Name of the service"},
                    "description": {"type": "string", "description": "Description of the service"},
                    "service_ports": {
                        "type": "array",
                        "items": {
                            "type": "object",
                            "properties": {
                                "port": {"type": "integer", "description": "Port number (-1 for all ports)"},
                                "to_port": {"type": "integer", "description": "End port for a port range (optional)"},
                                "proto": {"type": "integer", "description": "Protocol number (6=TCP, 17=UDP, 1=ICMP)"}
                            },
                            "required": ["proto"]
                        },
                        "description": "Array of port/protocol definitions"
                    },
                },
                "required": ["name", "service_ports"]
            }
        ),
        types.Tool(
            name="update-service",
            description="Update an existing service in the PCE. Identify by href (preferred) or name.",
            inputSchema={
                "type": "object",
                "properties": {
                    "href": {"type": "string", "description": "Service href (e.g., /orgs/1/sec_policy/draft/services/123)"},
                    "name": {"type": "string", "description": "Service name to find (alternative to href)"},
                    "new_name": {"type": "string", "description": "New name for the service"},
                    "description": {"type": "string", "description": "New description"},
                    "service_ports": {
                        "type": "array",
                        "items": {
                            "type": "object",
                            "properties": {
                                "port": {"type": "integer"},
                                "to_port": {"type": "integer"},
                                "proto": {"type": "integer"}
                            },
                            "required": ["proto"]
                        },
                        "description": "New port/protocol definitions (replaces existing)"
                    },
                },
            }
        ),
        types.Tool(
            name="delete-service",
            description="Delete a service from the PCE. Identify by href (preferred) or name.",
            inputSchema={
                "type": "object",
                "properties": {
                    "href": {"type": "string", "description": "Service href (e.g., /orgs/1/sec_policy/draft/services/123)"},
                    "name": {"type": "string", "description": "Service name (alternative to href)"},
                },
            }
        ),
        types.Tool(
            name="update-deny-rule",
            description="Update an existing deny rule in a ruleset. Identify the rule by its href.",
            inputSchema={
                "type": "object",
                "properties": {
                    "href": {"type": "string", "description": "Deny rule href (e.g., /orgs/1/sec_policy/draft/rule_sets/123/deny_rules/456)"},
                    "enabled": {"type": "boolean", "description": "Enable or disable the deny rule"},
                    "providers": {
                        "type": "array", "items": {"type": "string"},
                        "description": "Updated provider references: 'ams', label hrefs, key=value pairs, or 'iplist:<name>'"
                    },
                    "consumers": {
                        "type": "array", "items": {"type": "string"},
                        "description": "Updated consumer references: 'ams', label hrefs, key=value pairs, or 'iplist:<name>'"
                    },
                    "ingress_services": {
                        "type": "array",
                        "items": {
                            "type": "object",
                            "properties": {"port": {"type": "integer"}, "proto": {"type": "string"}},
                            "required": ["port", "proto"]
                        },
                        "description": "Updated services"
                    },
                },
                "required": ["href"]
            }
        ),
        types.Tool(
            name="delete-deny-rule",
            description="Delete a deny rule from a ruleset by its href",
            inputSchema={
                "type": "object",
                "properties": {
                    "href": {"type": "string", "description": "Deny rule href (e.g., /orgs/1/sec_policy/draft/rule_sets/123/deny_rules/456)"},
                },
                "required": ["href"]
            }
        ),
        types.Tool(
            name="update-label",
            description="Update an existing label in the PCE. Provide either: 1) href + new_value (optionally with key), or 2) key + value + new_value to identify and update the label.",
            inputSchema={
                "type": "object",
                "properties": {
                    "href": {
                        "type": "string",
                        "description": "Label href (e.g., /orgs/1/labels/42). Use this to directly identify the label."
                    },
                    "key": {
                        "type": "string",
                        "description": "Label type (e.g., role, app, env, loc). Required when using value to identify label, or when using href."
                    },
                    "value": {
                        "type": "string",
                        "description": "Current value of the label. Used with key to identify the label when href is not provided."
                    },
                    "new_value": {
                        "type": "string",
                        "description": "New value for the label. Always required."
                    }
                }
            }
        ),
        types.Tool(
            name="create-iplist",
            description="Create a new IP List in the PCE",
            inputSchema={
                "type": "object",
                "properties": {
                    "name": {
                        "type": "string",
                        "description": "Name of the IP List"
                    },
                    "description": {
                        "type": "string",
                        "description": "Description of the IP List"
                    },
                    "ip_ranges": {
                        "type": "array",
                        "description": "List of IP ranges to include",
                        "items": {
                            "type": "object",
                            "properties": {
                                "from_ip": {
                                    "type": "string",
                                    "description": "Starting IP address (IPv4 or IPv6)"
                                },
                                "to_ip": {
                                    "type": "string",
                                    "description": "Ending IP address (optional, for ranges)"
                                },
                                "description": {
                                    "type": "string",
                                    "description": "Description of this IP range (optional)"
                                },
                                "exclusion": {
                                    "type": "boolean",
                                    "description": "Whether this is an exclusion range",
                                    "default": False
                                }
                            },
                            "required": ["from_ip"]
                        }
                    },
                    "fqdn": {
                        "type": "string",
                        "description": "Fully Qualified Domain Name (optional)"
                    }
                },
                "required": ["name", "ip_ranges"]
            }
        ),
        types.Tool(
            name="update-iplist",
            description="Update an existing IP List in the PCE. Provide either 'href' or 'name' (but not both) to identify the IP List.",
            inputSchema={
                "type": "object",
                "properties": {
                    "href": {
                        "type": "string",
                        "description": "Href of the IP List to update (e.g., /orgs/1/sec_policy/draft/ip_lists/123)"
                    },
                    "name": {
                        "type": "string",
                        "description": "Name of the IP List to update (alternative to href)"
                    },
                    "description": {
                        "type": "string",
                        "description": "New description for the IP List (optional)"
                    },
                    "ip_ranges": {
                        "type": "array",
                        "description": "New list of IP ranges",
                        "items": {
                            "type": "object",
                            "properties": {
                                "from_ip": {
                                    "type": "string",
                                    "description": "Starting IP address (IPv4 or IPv6)"
                                },
                                "to_ip": {
                                    "type": "string",
                                    "description": "Ending IP address (optional, for ranges)"
                                },
                                "description": {
                                    "type": "string",
                                    "description": "Description of this IP range (optional)"
                                },
                                "exclusion": {
                                    "type": "boolean",
                                    "description": "Whether this is an exclusion range",
                                    "default": False
                                }
                            },
                            "required": ["from_ip"]
                        }
                    },
                    "fqdn": {
                        "type": "string",
                        "description": "New Fully Qualified Domain Name (optional)"
                    }
                }
            }
        ),
        types.Tool(
            name="delete-iplist",
            description="Delete an IP List from the PCE. Provide either 'href' or 'name' (but not both) to identify the IP List.",
            inputSchema={
                "type": "object",
                "properties": {
                    "href": {
                        "type": "string",
                        "description": "Href of the IP List to delete (e.g., /orgs/1/sec_policy/draft/ip_lists/123)"
                    },
                    "name": {
                        "type": "string",
                        "description": "Name of the IP List to delete (alternative to href)"
                    }
                }
            }
        ),
        types.Tool(
            name="update-ruleset",
            description="Update an existing ruleset in the PCE. Provide either 'href' or 'name' (but not both) to identify the ruleset.",
            inputSchema={
                "type": "object",
                "properties": {
                    "href": {
                        "type": "string",
                        "description": "Href of the ruleset to update (e.g., /orgs/1/sec_policy/active/rule_sets/123)"
                    },
                    "name": {
                        "type": "string",
                        "description": "Name of the ruleset to update (alternative to href)"
                    },
                    "description": {
                        "type": "string",
                        "description": "New description for the ruleset"
                    },
                    "enabled": {
                        "type": "boolean",
                        "description": "Whether the ruleset is enabled"
                    },
                    "scopes": {
                        "type": "array",
                        "description": "New scopes for the ruleset. Each scope is an array of label identifiers (either href strings like '/orgs/1/labels/42', or key=value strings like 'role=web', or objects with href property).",
                        "items": {
                            "type": "array",
                            "items": {
                                "description": "Label identifier - can be a string (href or key=value) or an object with href property"
                            }
                        }
                    }
                }
            }
        ),
        types.Tool(
            name="delete-ruleset",
            description="Delete a ruleset from the PCE by its href",
            inputSchema={
                "type": "object",
                "properties": {
                    "href": {
                        "type": "string",
                        "description": "Href of the ruleset to delete (e.g., /orgs/1/sec_policy/draft/rule_sets/123)"
                    }
                },
                "required": ["href"]
            }
        ),
        types.Tool(
            name="create-ringfence",
            description="""Create a ringfencing policy for an application. This analyzes traffic flows to discover
which other apps communicate with this app, then creates a ruleset with:
1) An intra-scope rule allowing all workloads within the app to communicate on All Services
2) Extra-scope rules for each remote app+env discovered in traffic, allowing them in on All Services
The result is a coarse-grained segmentation that controls which apps can talk to each other,
reducing risk without requiring per-port policies.""",
            inputSchema={
                "type": "object",
                "properties": {
                    "app_name": {
                        "type": "string",
                        "description": "Application label value (e.g., 'CRM', 'Ordering', 'ELK')"
                    },
                    "env_name": {
                        "type": "string",
                        "description": "Environment label value (e.g., 'Production', 'Staging', 'Development')"
                    },
                    "lookback_days": {
                        "type": "integer",
                        "description": "Number of days to look back for traffic flows (default: 30)",
                        "default": 30
                    },
                    "ruleset_name": {
                        "type": "string",
                        "description": "Custom name for the ringfence ruleset (default: 'RF-<app_name>-<env_name>')"
                    },
                    "dry_run": {
                        "type": "boolean",
                        "description": "If true, analyze traffic and report what would be created without actually creating anything (default: false)",
                        "default": False
                    },
                    "selective": {
                        "type": "boolean",
                        "description": "If true, adds a deny rule blocking all inbound traffic to the app. "
                            "In selective enforcement mode the default action is allow-all, so without "
                            "this deny rule the ringfence has no teeth. Allow rules for known remote apps "
                            "are processed before the deny rule (rule order: override_deny > allow > deny > default), "
                            "so known apps pass through and everything else hits the deny. "
                            "This gets you to enforcement faster than full enforcement mode.",
                        "default": False
                    },
                    "skip_allowed": {
                        "type": "boolean",
                        "description": "If true, skip creating rules for remote apps whose traffic is already "
                            "fully allowed by existing policy. Default is false, meaning rules are created "
                            "for all observed traffic regardless of policy decision. This makes the ringfence "
                            "ruleset self-documenting — it shows the complete picture of app connectivity. "
                            "Set to true for minimal rulesets that only fill policy gaps.",
                        "default": False
                    },
                    "deny_consumer": {
                        "type": "string",
                        "enum": ["any", "ams", "ams_and_any"],
                        "description": "Controls which consumers the deny rule targets (only used with selective=true). "
                            "Illumio pushes deny rules to the source workload, so this choice matters: "
                            "'any' (default) = IP list Any (0.0.0.0/0) as consumer, deny rule only written to "
                            "destination workloads inside the scope. Safest, no impact on remote workloads. "
                            "'ams' = All Workloads as consumer, deny rule pushed to every managed workload "
                            "outside the scope. Broader enforcement but wider blast radius. "
                            "'ams_and_any' = both All Workloads and Any IP list, maximum coverage for "
                            "managed and unmanaged sources.",
                        "default": "any"
                    }
                },
                "required": ["app_name", "env_name"]
            }
        ),
        types.Tool(
            name="identify-infrastructure-services",
            description="""Analyze traffic flows to identify infrastructure services in your environment.
Builds an app-to-app communication graph and computes centrality metrics to rank apps by how
'infrastructure-like' they are. Infrastructure services (DNS, AD, logging, monitoring platforms,
shared databases) are consumed by many apps and should be policy'd first during segmentation
rollouts. Returns a ranked list with scores, classification tiers, and connectivity details.""",
            inputSchema={
                "type": "object",
                "properties": {
                    "lookback_days": {
                        "type": "integer",
                        "description": "Number of days to look back for traffic flows (default: 90)",
                        "default": 90
                    },
                    "min_connections": {
                        "type": "integer",
                        "description": "Minimum total connections for an edge to be included — filters noise (default: 1)",
                        "default": 1
                    },
                    "top_n": {
                        "type": "integer",
                        "description": "Number of top results to return (default: 20)",
                        "default": 20
                    }
                },
                "required": []
            }
        ),
        types.Tool(
            name="provision-policy",
            description="Provision pending draft policy changes in the PCE. This moves draft rulesets, rules, IP lists, services, and label groups from draft to active state. You can provision all pending changes or specific items by href.",
            inputSchema={
                "type": "object",
                "properties": {
                    "hrefs": {
                        "type": "array",
                        "items": {"type": "string"},
                        "description": "List of specific draft hrefs to provision (e.g., ['/orgs/1/sec_policy/draft/rule_sets/123']). If omitted, provisions ALL pending changes."
                    },
                    "change_description": {
                        "type": "string",
                        "description": "Description of the provisioning change (for audit trail)"
                    }
                },
            }
        ),
        types.Tool(
            name="compare-draft-active",
            description="Compare draft vs active policy to see what would change on provisioning. Shows new, modified, and deleted rulesets, rules, IP lists, and services.",
            inputSchema={
                "type": "object",
                "properties": {
                    "resource_type": {
                        "type": "string",
                        "enum": ["rule_sets", "ip_lists", "services", "all"],
                        "description": "Type of resource to compare (default: all)",
                        "default": "all"
                    }
                },
            }
        ),
        types.Tool(
            name="enforcement-readiness",
            description="Assess whether an application is ready for enforcement by analyzing its traffic flows, existing policy coverage, and identifying potential gaps. Provides a readiness score and actionable recommendations.",
            inputSchema={
                "type": "object",
                "properties": {
                    "app_name": {
                        "type": "string",
                        "description": "Application label value (e.g., 'CRM', 'Ordering')"
                    },
                    "env_name": {
                        "type": "string",
                        "description": "Environment label value (e.g., 'Production', 'Staging')"
                    },
                    "lookback_days": {
                        "type": "integer",
                        "description": "Number of days to look back for traffic flows (default: 30)",
                        "default": 30
                    }
                },
                "required": ["app_name", "env_name"]
            }
        ),
        types.Tool(
            name="ringfence-batch",
            description="Create ringfence policies for multiple applications at once. Optionally auto-discovers infrastructure services and ringfences them first, then standard apps. Uses the same logic as create-ringfence for each app.",
            inputSchema={
                "type": "object",
                "properties": {
                    "apps": {
                        "type": "array",
                        "items": {
                            "type": "object",
                            "properties": {
                                "app_name": {"type": "string"},
                                "env_name": {"type": "string"},
                                "selective": {"type": "boolean", "default": False}
                            },
                            "required": ["app_name", "env_name"]
                        },
                        "description": "List of applications to ringfence"
                    },
                    "auto_order": {
                        "type": "boolean",
                        "description": "If true, uses identify-infrastructure-services to order apps by infrastructure score (infra first). Default: false",
                        "default": False
                    },
                    "dry_run": {
                        "type": "boolean",
                        "description": "If true, preview what would be created without making changes",
                        "default": False
                    },
                    "lookback_days": {
                        "type": "integer",
                        "description": "Number of days to look back for traffic flows (default: 30)",
                        "default": 30
                    }
                },
                "required": ["apps"]
            }
        ),
        types.Tool(
            name="get-workload-enforcement-status",
            description="Get enforcement mode status across all workloads, grouped by application and environment. Shows counts per enforcement mode and identifies apps with mixed enforcement states.",
            inputSchema={
                "type": "object",
                "properties": {
                    "app_name": {
                        "type": "string",
                        "description": "Filter by application name (optional)"
                    },
                    "env_name": {
                        "type": "string",
                        "description": "Filter by environment name (optional)"
                    }
                },
            }
        ),
        types.Tool(
            name="get-policy-coverage-report",
            description="Generate a policy coverage report for an app, showing what traffic is covered by existing rules vs what would be blocked. Helps understand how much of an app's traffic is already policy'd.",
            inputSchema={
                "type": "object",
                "properties": {
                    "app_name": {
                        "type": "string",
                        "description": "Application label value"
                    },
                    "env_name": {
                        "type": "string",
                        "description": "Environment label value"
                    },
                    "lookback_days": {
                        "type": "integer",
                        "description": "Number of days to look back for traffic flows (default: 30)",
                        "default": 30
                    }
                },
                "required": ["app_name", "env_name"]
            }
        ),
        types.Tool(
            name="find-unmanaged-traffic",
            description="Find traffic involving unmanaged (unlabeled) workloads or IP addresses. These are sources or destinations without app/env labels, representing potential policy blind spots.",
            inputSchema={
                "type": "object",
                "properties": {
                    "lookback_days": {
                        "type": "integer",
                        "description": "Number of days to look back (default: 30)",
                        "default": 30
                    },
                    "direction": {
                        "type": "string",
                        "enum": ["inbound", "outbound", "both"],
                        "description": "Filter by traffic direction relative to managed workloads (default: both)",
                        "default": "both"
                    },
                    "min_connections": {
                        "type": "integer",
                        "description": "Minimum connections to include (filters noise, default: 1)",
                        "default": 1
                    },
                    "top_n": {
                        "type": "integer",
                        "description": "Number of top results to return (default: 50)",
                        "default": 50
                    }
                },
            }
        ),
        types.Tool(
            name="detect-lateral-movement-paths",
            description="Analyze traffic patterns to detect potential lateral movement paths — chains of connections that could allow an attacker to pivot between applications. Identifies apps that serve as bridges between otherwise disconnected app groups.",
            inputSchema={
                "type": "object",
                "properties": {
                    "app_name": {
                        "type": "string",
                        "description": "Starting application to analyze paths from (optional — if omitted, analyzes all apps)"
                    },
                    "env_name": {
                        "type": "string",
                        "description": "Environment to focus on (optional)"
                    },
                    "lookback_days": {
                        "type": "integer",
                        "description": "Number of days to look back (default: 30)",
                        "default": 30
                    },
                    "max_hops": {
                        "type": "integer",
                        "description": "Maximum number of hops to trace (default: 4)",
                        "default": 4
                    }
                },
            }
        ),
        types.Tool(
            name="compliance-check",
            description="Check policy compliance against common frameworks (PCI-DSS, NIST, CIS). Identifies workloads in specific compliance scopes and verifies that segmentation policies meet framework requirements.",
            inputSchema={
                "type": "object",
                "properties": {
                    "framework": {
                        "type": "string",
                        "enum": ["pci-dss", "dora", "nist", "cis", "iso-27001", "swift-csp", "hipaa", "general"],
                        "description": "Compliance framework to check against (default: general). Read the corresponding illumio://compliance/* resource for detailed framework guidance.",
                        "default": "general"
                    },
                    "app_name": {
                        "type": "string",
                        "description": "Application to check (optional — if omitted, checks all apps)"
                    },
                    "env_name": {
                        "type": "string",
                        "description": "Environment to check (optional)"
                    },
                    "lookback_days": {
                        "type": "integer",
                        "description": "Number of days to look back for traffic analysis (default: 30)",
                        "default": 30
                    }
                },
            }
        ),
        types.Tool(
            name="get-container-workload-profiles",
            description="Get Container Workload Profiles for a container cluster. These profiles control how Kubernetes pods are managed by Illumio — mapping K8s namespaces to Illumio labels and enforcement modes.",
            inputSchema={
                "type": "object",
                "properties": {
                    "cluster_href": {"type": "string", "description": "Container cluster href (e.g., /orgs/1/container_clusters/uuid). If omitted, lists all container clusters first."},
                    "namespace": {"type": "string", "description": "Filter by Kubernetes namespace name"},
                    "managed": {"type": "boolean", "description": "Filter by managed (true) or unmanaged (false) profiles"},
                },
            }
        ),
        types.Tool(
            name="update-container-workload-profile",
            description="Update a Container Workload Profile to manage Kubernetes pods in Illumio. Set managed=true and assign labels to start managing pods in a namespace.",
            inputSchema={
                "type": "object",
                "properties": {
                    "profile_href": {"type": "string", "description": "Full href of the container workload profile (e.g., /orgs/1/container_clusters/uuid/container_workload_profiles/uuid)"},
                    "managed": {"type": "boolean", "description": "Set to true to manage pods in this namespace"},
                    "enforcement_mode": {
                        "type": "string",
                        "enum": ["visibility_only", "full", "idle", "selective"],
                        "description": "Enforcement mode for managed pods"
                    },
                    "assign_labels": {
                        "type": "array",
                        "items": {"type": "object", "properties": {"href": {"type": "string"}}, "required": ["href"]},
                        "description": "Illumio labels to assign to pods (e.g., [{'href': '/orgs/1/labels/5'}])"
                    },
                },
                "required": ["profile_href"]
            }
        ),
        types.Tool(
            name="get-kubernetes-workloads",
            description="Get Kubernetes Workloads (CLAS mode) from a container cluster. Shows Deployments, Services, and other K8s objects managed by Illumio with their labels and policy sync state.",
            inputSchema={
                "type": "object",
                "properties": {
                    "cluster_href": {"type": "string", "description": "Container cluster href (e.g., /orgs/1/container_clusters/uuid). If omitted, lists all clusters first."},
                    "namespace": {"type": "string", "description": "Filter by Kubernetes namespace"},
                    "max_results": {"type": "integer", "description": "Maximum results to return (default 500)"},
                },
            }
        ),
        types.Tool(
            name="get-container-clusters",
            description="Get container clusters (Kubernetes/OpenShift) registered in the PCE. Shows cluster name, CLAS mode, online status, kubelink version, and node count.",
            inputSchema={
                "type": "object",
                "properties": {
                    "name": {"type": "string", "description": "Filter by cluster name (partial match)"},
                    "max_results": {"type": "integer", "description": "Maximum results to return (default 50)"},
                },
            }
        ),
        types.Tool(
            name="get-pairing-profiles",
            description="Get pairing profiles from the PCE. Pairing profiles define the initial enforcement mode and labels for VENs when they pair with the PCE.",
            inputSchema={
                "type": "object",
                "properties": {
                    "name": {"type": "string", "description": "Filter by pairing profile name (partial match)"},
                    "max_results": {"type": "integer", "description": "Maximum results to return (default 50)"},
                },
            }
        ),
    ]

@server.call_tool()
async def handle_call_tool(name: str, arguments: dict) -> list[types.TextContent | types.ImageContent | types.EmbeddedResource]:
    logger.debug(f"Tool called: {name} with arguments: {arguments}")
    spec = TOOL_REGISTRY.get(name)
    if spec is None:
        raise ValueError(f"Unknown tool: {name}")
    ctx = get_active_context()
    audit = ctx.audit_log or NullAuditLog()

    def _audit(decision: str, reason: str | None) -> None:
        audit.record(AuditEntry(
            sub=ctx.user_sub,
            iss=ctx.user_iss,
            tool=name,
            decision=decision,
            reason=reason,
            role=ctx.user_role,
            request_id=ctx.request_id,
        ))

    # Role check
    if ctx.user_role is None:
        _audit("denied", "no role assigned")
        return [types.TextContent(type="text", text=json.dumps({
            "error": "forbidden_no_role",
            "message": "Your user has no role mapping configured on this server.",
        }, indent=2))]
    if ctx.user_role not in spec.roles:
        _audit("denied", f"role {ctx.user_role!r} not in {sorted(spec.roles)}")
        return [types.TextContent(type="text", text=json.dumps({
            "error": "forbidden",
            "message": f"Role {ctx.user_role!r} is not permitted to call {name!r}.",
            "allowed_roles": sorted(spec.roles),
        }, indent=2))]

    # PCE-presence check (Phase 3b)
    if spec.requires_pce and ctx.pce is None:
        _audit("denied", "no_pce_credentials")
        return [types.TextContent(
            type="text",
            text=json.dumps({
                "error": "no_pce_credentials",
                "message": (
                    "No PCE credentials registered for this user. "
                    "Call `register-pce-credentials` or open the browser setup page."
                ),
                "setup_path": "/setup",
            }, indent=2),
        )]

    try:
        t0 = time.monotonic()
        result = await asyncio.to_thread(spec.handler, ctx, arguments or {})
        elapsed = time.monotonic() - t0
        logger.info(f"Tool {name} completed in {elapsed:.2f}s")
        _audit("allowed", None)
        return result
    except Exception as e:
        error_msg = f"Tool {name} failed: {str(e)}"
        logger.error(error_msg, exc_info=True)
        _audit("error", str(e)[:200])
        return [types.TextContent(type="text", text=json.dumps({"error": error_msg}, indent=2))]

async def run_stdio() -> None:
    """Run the MCP server over stdio. This is the default entry point used by
    Claude Desktop, Cursor, and other clients that launch the server as a
    subprocess."""
    logger.debug("Starting stdio server")
    async with mcp.server.stdio.stdio_server() as (read_stream, write_stream):
        await server.run(
            read_stream,
            write_stream,
            InitializationOptions(
                server_name="illumio-mcp",
                server_version="0.1.0",
                capabilities=server.get_capabilities(
                    notification_options=NotificationOptions(),
                    experimental_capabilities={},
                ),
            ),
        )
