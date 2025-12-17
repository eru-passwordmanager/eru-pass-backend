# Threat Model – Local Password Manager

## 1. Purpose

This document describes the **threat model** for a **local, offline-first password manager** application.  
Its goal is to systematically identify:

- protected assets,
- realistic threat actors,
- potential attack surfaces,
- implemented security controls,
- and consciously accepted risks.

The objective is **risk awareness and defense-in-depth**, not absolute security.

---

## 2. System Overview

**Application type:**
- Single-user
- Local password manager
- Offline-first

**Architecture:**
- Backend: Flask (Python)
- Frontend: Electron + React (planned)
- Database: SQLite (local file)

**Cryptography:**
- Key Derivation: `scrypt`
- Encryption: `AES-256-GCM` (authenticated encryption)

**Authentication model:**
- Master password
- In-memory unlock token

**Trust assumptions:**
- No remote server
- No cloud synchronization
- User controls the local machine

---

## 3. Protected Assets

| Asset | Description | Sensitivity |
|---|---|---|
| Master password | Root secret for the vault | Critical |
| Derived encryption key | AES-GCM key | Critical |
| Vault items | User secrets | Critical |
| Unlock token | Vault session state | High |
| Process memory (RAM) | Key resides here temporarily | High |
| SQLite database file | Encrypted storage | Medium |

---

## 4. Threat Actors

| Actor | In Scope |
|---|---|
| Local attacker with file access | ✅ |
| Malicious user-space malware | ✅ |
| Curious or careless user | ✅ |
| Remote network attacker | ❌ |
| Kernel-level malware | ❌ |
| Nation-state attacker | ❌ |

> Out-of-scope threats are **explicitly acknowledged**, not ignored.

---

## 5. Attack Surfaces

| Surface | Description |
|---|---|
| `/api/vault/unlock` | Brute-force target |
| SQLite database file | Can be copied or modified |
| Process memory (RAM) | Possible memory dump |
| Electron UI | Shoulder surfing risk |
| Unlock token | Session misuse |

---

## 6. Threats and Mitigations

### 6.1 Offline Brute-Force (Database Compromise)

**Threat:**  
An attacker obtains the SQLite database file.

**Risk:**  
Offline guessing of the master password.

**Mitigations:**
- `scrypt` key derivation (high CPU + memory cost)
- Unique random salt
- Strong master password enforced via `zxcvbn`
- AES-GCM authenticated encryption

**Residual Risk:**
- Weak master passwords are explicitly rejected.

---

### 6.2 Online Brute-Force (`/vault/unlock`)

**Threat:**  
Repeated unlock attempts using automated scripts.

**Mitigations:**
- Rate limiting
- Progressive artificial delay (exponential backoff)
- Constant delay for rate-limited responses
- Auto-lock on inactivity
- Manual lock endpoint

**Result:**  
Online brute-force becomes impractical.

---

### 6.3 Memory Disclosure (RAM Attacks)

**Threat:**  
Extraction of encryption keys from process memory.

**Mitigations:**
- Keys stored only in memory (never on disk)
- Idle-based auto-lock
- Manual lock endpoint
- Forced lock after master password change
- Best-effort memory zeroization using mutable buffers (`bytearray`)

**Residual Risk:**
- Python VM copies and garbage collection behavior (language limitation)

---

### 6.4 Database Tampering

**Threat:**  
Modification of encrypted database content.

**Mitigations:**
- AES-GCM authentication tags
- Additional authenticated data (AAD)
- Decryption failure results in operation rejection

**Result:**  
Tampered data cannot be decrypted or trusted.

---

### 6.5 Unlocked Vault / Shoulder Surfing

**Threat:**  
Secrets exposed while the vault is unlocked.

**Mitigations:**
- Idle auto-lock
- Manual lock
- Forced re-lock after master password changes

---

## 7. Explicitly Accepted Risks

| Risk | Rationale |
|---|---|
| Perfect memory wiping is impossible | Python language limitation |
| Kernel-level malware | Out of scope |
| Hardware keyloggers | OS / physical security issue |
| Physical coercion | No technical mitigation |

These risks are **understood and consciously accepted**.

---

## 8. Security Principles Applied

- Defense in depth
- Least privilege
- Fail-secure behavior
- Offline-first trust model
- Explicit risk acceptance

---

## 9. Conclusion

The system implements a **realistic, security-aware password manager design**:

- Strong cryptography
- Layered defenses against brute-force attacks
- Controlled key lifetime in memory
- Clear security boundaries and assumptions

This design aligns with real-world password manager practices while acknowledging practical limitations.

---

## 10. Future Work

- Frontend-specific threat modeling (Electron)
- Secure IPC design
- Local audit logging
- Encrypted export and backup functionality

---
## 11. Architectural Notes and Planned Refactoring

At the current stage, API endpoints are implemented directly at the route level
for clarity and rapid iteration during the security design phase.

### Current State

- Route handlers currently contain:
  - request validation
  - business logic
  - direct database access
- This approach was intentionally chosen to:
  - keep the threat model transparent,
  - make security boundaries explicit,
  - and simplify reasoning about cryptographic flows.

### Planned Refactoring

As the project matures and the frontend layer is introduced, the backend will be
refactored into a layered architecture:

- **Repository layer**
  - Low-level database access
  - No business logic
- **Service layer**
  - Business rules
  - Cryptographic operations
  - Vault lifecycle management
- **Route (controller) layer**
  - HTTP concerns only
  - Input validation
  - Error mapping

### Security Rationale

This refactoring is not expected to change the security model, but to:

- improve maintainability and testability,
- reduce the risk of logic duplication,
- enable more fine-grained security testing at the service layer,
- and keep cryptographic operations centralized and auditable.

The current threat model remains valid after refactoring, as the trust boundaries and attack surfaces remain unchanged.

**Status:** Backend security threat model (pre-frontend)  
**Scope:** Local password manager – single user
