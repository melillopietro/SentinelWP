# SentinelWP — Sprint 6 Remaining Gaps & Future Enhancements
## Post-Consolidation Roadmap & Product Polish

**Sprint:** Sprint 6 — Enterprise UI/UX Consolidation  
**Target Branch:** `feat/sentinelwp-sprint6-unified-ui`  
**Base Commit:** `f8b4f99`  
**Date:** 2026-10-10  

---

### 1. Executive Summary

Sprint 6 successfully consolidated SentinelWP's user experience into 6 primary workspaces, resolved navigation fragmentation, introduced action modals, and provided full backward compatibility. 

In accordance with engineering rigor, this document provides an honest assessment of non-blocking UX refinements and candidate enhancements identified for subsequent sprints (e.g. Sprint 7+).

---

### 2. Audit of Future Enhancements

#### S6-GAP-001: Client-Side Tab State Persistence via `localStorage`
- **Current Behavior:** Active workspace tab selection is driven by the URL query parameter `?tab=<name>` and server-side Jinja rendering. When navigating away and returning via sidebar navigation, the default tab for that workspace is restored unless the user uses browser back/forward or specific deep links.
- **Impact:** Low. URL sharing and bookmarks work predictably and consistently.
- **Recommended Enhancement:** Add lightweight client-side persistence in `static/main.js` to store the last active tab per workspace in `localStorage` and optionally restore it when navigating without an explicit `?tab=` query parameter.

#### S6-GAP-002: Multi-Select Bulk Actions on Findings and Assets
- **Current Behavior:** Findings triage (status changes, risk exceptions, assignment) and asset management operations are performed individually or via targeted forms.
- **Impact:** Medium in high-volume enterprise environments with hundreds of simultaneous findings.
- **Recommended Enhancement:** Introduce checkbox table headers, a floating action bar (FAB) for bulk remediation assignment, bulk risk exception submission, and bulk tagging across the Assets and Vulnerabilities workspaces.

#### S6-GAP-003: Saved Filter Presets & Quick Search Facets
- **Current Behavior:** Filters (such as severity, status, environment, business unit) use standard GET query parameters. Users must select filters manually each session.
- **Impact:** Low to Medium.
- **Recommended Enhancement:** Implement customizable filter presets (e.g., "My High-Risk Production Assets", "Unassigned P1 Findings", "SLA Breaching Next 48h") saved to the user profile or local storage.

#### S6-GAP-004: Interactive Differential Posture Timeline
- **Current Behavior:** Differential scans and posture changes are displayed as table comparison cards in the Asset 360 "Reports & Diff" tab.
- **Impact:** Low. All differential data is fully exposed.
- **Recommended Enhancement:** Visualize consecutive scan differentials as an interactive horizontal timeline chart showing exactly when specific vulnerabilities appeared, persisted, or were resolved across historical scan cycles.

#### S6-GAP-005: Real-Time WebSocket / Server-Sent Events (SSE) for Scan Progress
- **Current Behavior:** Scan status updates in Operations & Scans rely on manual page refreshes or standard polling intervals.
- **Impact:** Low. Standard enterprise batch scanning pattern.
- **Recommended Enhancement:** Implement SSE or WebSocket listeners on `/scans` so that running scan jobs transition from "RUNNING" to "COMPLETED" in real time without page reload.

---

### 3. Release Readiness Impact

None of the above candidate enhancements represent blockers for Sprint 6 completion or production deployment. All 6 workspaces are fully functional, responsive, and backed by a comprehensive regression test suite (509 passing tests, 0 failures).
