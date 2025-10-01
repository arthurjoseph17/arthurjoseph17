# 📡 UCaaS Managed & Deployment (Enterprise Voice/Collab Modernization)

## Executive Summary
Led a multi-phase UCaaS modernization and migration program spanning design, managed operations, upgrades, carrier/circuit turn-ups, firewall hardening, DR failover, and final cloud cutover. The work combined network/voice engineering, change management, and cross-vendor coordination to deliver a resilient, observable, and scalable communications platform.

**Project window:** Aug 18, 2023 → Sep 21, 2025  
**Phases:** Managed operations → Upgrade & demo → Carrier installs → Firewall deployments → SIP HA → DR failover/failback → Cloud migration → Closeout

---

## Timeline & Phases (Condensed)

### Project Inception
**Duration:** 766 days • **Dates:** 2023-08-18 → 2025-09-21

---

### Phase 1 — UCaaS Managed
**Duration:** 81 days • **Dates:** 2023-08-18 → 2023-11-06  
**Focus:** Secure access, jump box, monitoring/alerting, initial user enablement, runbook foundation.

**Key work items**
- Environment access and credentialing  
- Jump box build and toolset installs (incl. monitoring)  
- Advanced monitoring, alerts, and SNMP for core voice stack (call control, voicemail, gateways, contact center)  
- Target user identification & role-based access enablement  
- Client Services Playbook draft (voice diagram, failure scenarios, MACD patterns)  
- Transition to steady-state managed support

---

### Phase 2 — UCaaS Upgrade
**Duration:** 308 days • **Dates:** 2023-11-07 → 2024-09-09  
**Focus:** Discovery, capacity checks, application/OS credentials, test planning, lab/demo builds.

**Key work items**
- Discovery & application assessment (inventory, IP/DNS/NTP, host capacity/RAM checks)  
- Business acceptance test plan for CUCM/IM&P/Voicemail/Contact Center/Edge  
- Demo period:  
  - VPN tunnel for demo connectivity (temporary)  
  - Test numbers provisioned  
  - Dual-site UC clusters built in provider “PODs”  
  - Public reachability for contact center demo components  
  - User demo: softphone (IM&P) + agent desktop  
  - Tunnel toggles & site failover verification

---

### Phase 3 — Circuit Turn-Up (Data Center East)
**Duration:** 17 days • **Dates:** 2024-12-19 → 2025-01-04  
**Focus:** Carrier ring work; core UC application upgrades (major versions).

**Key work items**
- MPLS ring activities and verification  
- UC upgrades: call processing, voicemail, messaging, contact center, edge traversal, adjunct apps

---

### Phase 4 — Carrier & Cross-Connect Activities (Data Center East)
**Duration:** 52 days • **Dates:** 2024-12-25 → 2025-02-14  
**Focus:** Equipment logistics, LOA/CFA processing, cross-connects, test/activation, site verification.

**Key work items**
- Equipment receipt & staging  
- LOA/CFA processing and cross-connects  
- Last-mile signal validation & equipment test  
- Site verification, config build, circuit activation  
- Parallel activities for secondary carrier

---

### Phase 5 — DR Gap Analysis
**Duration:** 3 days • **Dates:** 2025-01-29 → 2025-01-31  
**Focus:** DR assessment between Primary Site and Recovery Site.

**Outcome**
- Finding: Primary could not fail over to Recovery in current state  
- Resolution: Add physical firewall and configuration at Recovery Site

---

### Phase 6 — Firewall Install/Test (Data Center East)
**Duration:** 39 days • **Dates:** 2025-01-29 → 2025-03-08  
**Focus:** Edge hardening, Panorama integration, policy creation, staged rollout.

**Key work items**
- Procurement, rack/stack, IP/licensing, cabling  
- Impact assessment (Edge, VPN, intersite paths, call flows, CC, softphone)  
- Panorama onboarding, tunnel/policy builds (staggered sites)  
- Validation & test execution

---

### Phase 7 — Firewall Install/Test (Data Center West)
**Duration:** 59 days • **Dates:** 2025-02-13 → 2025-04-12  
**Focus:** Mirror of East with shipping, cabling, policies, and platform upgrades.

**Key work items**
- Rack/stack + cabling; Panorama onboarding & policy builds  
- **Contact Center upgrade to ES06** (change approved/executed)  
- **SIP HA:** discovery of working config, re-implementation via carrier backbone, failover testing

---

### Phase 8 — DR Failover & Failback Exercises
**Duration:** 30 days • **Dates:** 2025-03-15 → 2025-04-13  
**Focus:** Planned failover from Primary to Recovery, validation of all UC/agent workflows, controlled failback.

**Key scenarios**
- Voice gateway and UC server shutdown at Primary → verify full service from Recovery  
- Agent workflow validation on backup internet (softphone + agent desktop)  
- Inbound/outbound, call features, cabinet tests, remote-site validation  
- SIP failover verification with carrier backbone  
- Controlled failback to Primary

---

### Phase 9 — Cloud Migration (Final Cutover)
**Duration:** 12 days • **Dates:** 2025-09-09 → 2025-09-20  
**Focus:** Prepare/approve change, end-to-end testing, migrate UC workloads to cloud, validate/rollback readiness.

**Key work items**
- Routing verification between all sites and cloud DC (VPN + carrier)  
- Business analysis and non-disruptive migration planning  
- Change document, cutover steps, test plan, rollback plan  
- Migrate: Call Control, Voicemail, IM&P, Contact Center, Reporting, Adjunct apps  
- End-to-end testing and go/no-go adherence  
- **Project Closeout & Support Transition:** 2025-09-21

---

## Responsibilities & Contributions
- Designed secure admin access (jump box) and built **observability**: SNMP + advanced alerts across call control, voicemail, gateways, CC.  
- Drove **carrier turn-ups** and **cross-connects** through to activation with site verification.  
- Implemented **edge firewalls** at both DCs with centralized management and staged cutovers.  
- Built **SIP HA** posture and performed **DR failover/failback** drills with comprehensive test plans.  
- Orchestrated **cloud UC migration** with change control, rollback readiness, and post-cutover validation.  
- Authored/maintained **runbooks and playbooks** (voice diagrams, failure scenarios, MACD flows).

## Outcomes
- **High availability** across DCs with tested failover/failback playbooks.  
- **Reduced risk** via formal change control, rollback patterns, and staged policy deployment.  
- **Improved visibility** and MTTR through proactive monitoring and alerting.  
- **Cloud-ready posture** delivering scalability and simplified lifecycle management.

## Stack & Competencies
- **UC Platforms:** Call processing, messaging/IM&P, voicemail, contact center, reporting  
- **Network/Edge:** Firewalls, VPN, inter-site routing, SIP trunking/HA  
- **Observability:** SNMP, platform health, alert routing  
- **Ops/Change:** Change requests, BIRA/impact analysis, rollback planning, DR testing  
- **Program Skills:** Vendor & carrier coordination, cutover leadership, stakeholder comms

---

## Visuals (placeholders — add screenshots as you collect them)
- `![Program Timeline](images/ucaas_timeline.png)` — high-level Gantt by phase  
- `![Voice Architecture](images/voice_architecture_after.png)` — post-migration logical diagram  
- `![Monitoring & Alerts](images/monitoring_dashboard.png)` — redacted dashboard view  
- `![DR Playbook Excerpt](images/dr_playbook.png)` — test matrix snapshot  
- `![Change Control Packet](images/change_packet.png)` — redacted headers only

---

## Appendices (Optional)
<details>
<summary><strong>Representative Work Items (by Phase)</strong></summary>

- **Phase 1 (Managed):** Access enablement, jump box, SNMP + alerting across call control/voicemail/gateway/CC, target user onboarding, MACD runbook.  
- **Phase 2 (Upgrade/Demo):** Inventory/IP/DNS/NTP, credential audits, capacity/RAM checks, BAT plan, dual-site lab builds, demo user validation.  
- **Phase 3–4 (Carriers):** LOA/CFA, cross-connects, equipment turn-up, site verification, activation.  
- **Phase 5 (DR Gap):** Primary→Recovery posture review, remediation plan.  
- **Phase 6–7 (Firewalls):** Rack/stack, Panorama, tunnels/policies, staged site activation, CC ES update, SIP HA implementation.  
- **Phase 8 (DR Exercises):** Planned failover, agent desktop validation on backup internet, call feature matrix, remote-site tests, failback.  
- **Phase 9 (Cloud):** Route checks, change/test/rollback package, migration of UC workloads, E2E verification, closeout and support transition.
</details>
