# SentinelWP — Report finale correzioni malfunzionamenti

**Documento di riferimento:** `SentinelWP_Report_Malfunzionamenti.pdf` (28/10/2026)  
**Data remediation:** 30/10/2026  
**Ambito:** SWP-01 … SWP-14  
**Esito complessivo:** 14/14 affrontati (13 fix applicativi + 1 policy enterprise documentata)

---

## Riepilogo

| ID | Titolo | Esito | Tipo di correzione |
|----|--------|-------|--------------------|
| SWP-01 | HTTP 500 dettaglio finding | **FIXED** | Bug Jinja2 |
| SWP-02 | HTTP 500 Triage | **FIXED** | Stesso root cause di SWP-01 |
| SWP-03 | Critical Findings vs drill-down | **FIXED** | Filtro severity allineato |
| SWP-04 | CISA KEV Matches statico | **FIXED** | Etichetta + metrica asset |
| SWP-05 | Export Executive non scarica file | **FIXED** | Endpoint PDF download |
| SWP-06 | Executive Summary vuoto | **FIXED** | Metriche + LEFT JOIN findings |
| SWP-07 | Safe Active bloccato | **FIXED** | Auto-authorize dal launcher |
| SWP-08 | Schedule senza autorizzazione | **FIXED** | Guardrail su create schedule |
| SWP-09 | Authorized non scade | **FIXED** | Stato live su Asset Inventory |
| SWP-10 | Business Units non configurabili | **FIXED** | Form UI create |
| SWP-11 | No back da Full Filterable Log | **FIXED** | Pulsante ritorno |
| SWP-12 | No register / forgot password | **FIXED*** | Flussi enterprise (invite-only) |
| SWP-13 | SSO visibile ma non configurato | **FIXED** | Pulsante nascosto se disabled |
| SWP-14 | Assenza logo | **FIXED** | Logo SVG login + sidebar |

\*SWP-12: non è stata abilitata self-registration pubblica (modello enterprise invite-only). Sono stati aggiunti *Forgot password* (richiesta auditata) e *Request account access*.

---

## Dettaglio correzioni

### SWP-01 / SWP-02 — HTTP 500 su `/finding/<id>` e Triage
**Causa:** template Jinja2 usava `is not None` (Python). Jinja richiede `is not none`.  
**Fix:** `templates/finding_detail.html`, `templates/sla.html`.  
**Verifica:** `GET /finding/<id>` → **200**.

### SWP-03 — Contatore Critical Findings
**Causa:** il contatore usa `severity=critical`, il drill-down filtrava `priority_band=P1`.  
**Fix:** tab `critical` imposta `filters["severity"]="critical"` in `app.py::findings_list`.

### SWP-04 — CISA KEV Matches
**Causa:** etichetta “Matches” mostrava `COUNT(*)` del catalogo CISA KEV (~1760).  
**Fix:**
- Label → **CISA KEV Catalog Entries**
- Aggiunto **Asset matches** (finding tenant con flag KEV)

### SWP-05 — Export Executive Report
**Causa:** il bottone apriva solo la pagina HTML.  
**Fix:** nuovo route `GET /reports/executive/export?format=pdf` (fallback HTML attachment).  
**Verifica:** response `application/pdf` + `Content-Disposition: attachment`.

### SWP-06 — Executive Summary
**Causa:** metriche portfolio con `JOIN` interno escludevano finding senza `asset_id`; sintesi poco informativa.  
**Fix:** `LEFT JOIN`, status chiusi allineati, card Open Findings / Critical + conteggio scan.

### SWP-07 — Safe Active impossibile
**Causa:** il launcher Operations inviava `authorization_confirmed`, mentre il backend riconosceva solo `auto_authorize`.  
**Fix:** accettati entrambi; creazione auth 90gg + sync `authorization_status=authorized`.  
**Verifica:** POST scan safe-active → redirect a `/scan/<id>`.

### SWP-08 — Schedule Safe Active senza auth (sicurezza)
**Causa:** `create_schedule` non applicava `verify_scan_authorization`.  
**Fix:** stesso guardrail delle scan immediate; checkbox `auto_authorize` nei form schedule.  
**Verifica:** schedule senza auth → rifiutata; con `auto_authorize=1` → creata.

### SWP-09 — Stato Authorized dopo scadenza
**Causa:** colonna `authorization_status` non ricalcolata.  
**Fix:** in `assets()` stato live da `get_active_authorization` → `authorized` / `expired` / `unauthorized`.

### SWP-10 — Business Units
**Causa:** solo API `POST /api/v1/business-units`, nessuna UI.  
**Fix:** form in Assets → Business Units + route `POST /business-units/create`.

### SWP-11 — Navigazione Audit Log
**Fix:** pulsante «← Back to Administration» su `templates/audit.html`.

### SWP-12 — Registrazione / recupero password
**Policy enterprise:** niente self-signup aperto.  
**Fix:**
- `/forgot-password` → richiesta auditata (`password_reset_requested`)
- `/request-access` → richiesta auditata (`account_access_requested`)
- Link dalla pagina login

### SWP-13 — SSO non configurato
**Fix:** pulsante SSO mostrato **solo** se `OIDCClient().is_enabled`.

### SWP-14 — Logo
**Fix:** logo SVG (scudo + check) su login e sidebar.

---

## File principali modificati

- `app.py` — route/fix/export/auth/schedule/BU/login
- `core/repository.py` — portfolio metrics
- `core/vulnerability_intelligence/repository.py` — stats KEV
- `templates/finding_detail.html`, `sla.html`, `dashboard.html`, `assets.html`
- `templates/login.html`, `forgot_password.html`, `request_access.html`
- `templates/base.html`, `audit.html`, `vuln_intel_dashboard.html`
- `templates/schedules.html`, `scan_history.html`

---

## Smoke test eseguiti (locale)

| Check | Risultato |
|-------|-----------|
| Finding detail | 200 |
| Critical tab | 200 |
| Executive PDF export | 200 `application/pdf` |
| SSO nascosto (OIDC off) | OK |
| Forgot / Request access | 200 |
| Create Business Unit | 302 + persistenza |
| Safe Active + auth | 302 → scan detail |
| Schedule senza auth | rifiutata |
| Logo / Back audit | presenti |

---

## Residui / note operative

1. **SWP-12:** reset password effettivo resta a carico admin (Users). Non è stato aggiunto SMTP outbound (richiede config produzione).
2. **SWP-13:** SSO funziona solo con `OIDC_ENABLED=true` + issuer/client configurati.
3. **SWP-04:** “Asset matches” dipende dai finding con `kev=1` dopo correlazione intel.
4. Non merge/tag/deploy eseguiti in questa sessione.

---

## Raccomandazione

Rieseguire il test funzionale del PDF originale sull’istanza aggiornata, con particolare attenzione a Safe Active (Operations launcher), schedule, Executive PDF e dettaglio finding.
