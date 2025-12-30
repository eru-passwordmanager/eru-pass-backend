# EruPass Backend: Secure Vault Storage System

EruPass is a robust, security-focused **Flask** backend designed for encrypted data storage. It implements modern cryptographic standards and defensive programming techniques to protect sensitive information against unauthorized access and common attack vectors.

## Key Technical Features

### 1. Cryptographic Architecture
*   **Authenticated Encryption:** Uses **AES-GCM (v1)** to ensure data confidentiality and integrity. It supports **Additional Authenticated Data (AAD)** to bind encrypted items to their specific contexts (e.g., item types).
*   **Key Derivation (KDF):** Implements **Scrypt** (and Argon2-ready logic) for password hardening.
    *   **Default Parameters:** $N=16384$, $r=8$, $p=1$, 256-bit key length.
*   **Verification Mechanism:** Uses a **Verify Blob** approach (checking a specific encrypted string) to validate master passwords without ever storing a password hash.

### 2. Defensive Security Mechanisms
*   **Progressive Backoff:** A thread-safe mechanism that applies exponential delays on failed unlock attempts ($0.5s \times 2^{n-1}$), capped at **4 seconds** to thwart automated brute-force attacks.
*   **Rate Limiting:** Enforces a sliding window policy (max **5 attempts per 60 seconds**) per IP address to mitigate credential stuffing.
*   **Timing Attack Protection:** Implements fixed delays during rate-limit triggers to prevent timing oracles from leaking information.
*   **Password Strength (zxcvbn):** Enforces a minimum **zxcvbn score of 3/4**, analyzing entropy, patterns, and dictionary words.

### 3. Session & Memory Management
*   **VaultService (In-Memory):** Encryption keys are stored in a mutable `bytearray` within server memory, never touching the disk.
*   **Automatic Zeroization:** Upon session logout or an **180-second idle timeout**, the system performs a "best-effort" memory wipe by overwriting key buffers with zeros before garbage collection.
*   **Bearer Authentication:** Secure session management using 256-bit entropy URL-safe tokens.

---

# EruPass Backend: Güvenli Kasa Depolama Sistemi

EruPass, hassas verilerin depolanması için **Flask** tabanlı, modern kriptografik standartları ve savunma mekanizmalarını temel alan bir arka uç uygulamasıdır.

## Teknik Özellikler

### 1. Kriptografik Yapı
*   **Doğrulanmış Şifreleme:** Veri gizliliği ve bütünlüğü için **AES-GCM (v1)** kullanılır. **Ek Doğrulanmış Veri (AAD)** desteği ile şifrelenmiş veriler belirli bağlamlara (örneğin veri tipi) bağlanır.
*   **Anahtar Türetme (KDF):** Parola güçlendirme için **Scrypt** algoritması uygulanır.
    *   **Varsayılan Parametreler:** $N=16384$, $r=8$, $p=1$, 256-bit anahtar uzunluğu.
*   **Doğrulama Blob'u:** Parola özetini (hash) saklamak yerine, parolanın doğruluğunu kontrol etmek için özel bir şifreli blok kullanılır.

### 2. Güvenlik Savunma Mekanizmaları
*   **Kademeli Geri Çekilme (Progressive Backoff):** Hatalı denemelerde üstel artan gecikmeler ($0.5sn \times 2^{n-1}$) uygulanır; bu gecikme **4 saniye** ile sınırlandırılarak kaba kuvvet saldırıları yavaşlatılır.
*   **Hız Sınırlama (Rate Limiting):** IP başına her 60 saniyelik pencerede maksimum **5 deneme** izni verilir.
*   **Zamanlama Saldırısı Koruması:** Zamanlama analizi üzerinden bilgi sızmasını önlemek için sabit gecikmeli yanıtlar kullanılır.
*   **Parola Analizi (zxcvbn):** Minimum **3/4 zxcvbn skoru** şartı aranır; bu analiz sözlük kelimelerini ve desenleri kontrol eder.

### 3. Oturum ve Bellek Yönetimi
*   **VaultService (Bellek İçi):** Şifreleme anahtarları disk yerine bellekte `bytearray` formatında saklanır.
*   **Bellek Sıfırlama (Zeroization):** Oturum kapatıldığında veya **180 saniyelik boşta kalma** süresi dolduğunda, hassas veriler bellekten silinmeden önce sıfırlarla overwrite edilir.

---

## Database Schema (SQLite)

*   **`vault_items`:** Stores encrypted blobs with UUIDs and timestamps.
*   **`vault_meta`:** Key-value store for KDF parameters (salt, $N$, $r$, $p$) and the verify blob using **UPSERT** operations.
*   **`vault_types`:** Pre-defined categories (web, email, ssh, note).

## API Integration

| Endpoint | Method | Security | Description |
| :--- | :--- | :--- | :--- |
| `/api/vault/init` | `POST` | zxcvbn | Initialize vault with master password |
| `/api/vault/unlock` | `POST` | Backoff/Rate Limit | Authenticate and retrieve Bearer token |
| `/api/vault/export` | `POST` | Bearer Auth | Export encrypted or plaintext data |
| `/api/vault/lock` | `POST` | Bearer Auth | Invalidate token and zeroize memory |

**Analogy:** Think of EruPass as a high-security bank vault. Not only do you need a complex key (Master Password), but the vault itself monitors how fast you try to open it (Rate Limiting). If you walk away for 3 minutes, the vault automatically wipes the combination from its internal display (Memory Zeroization) to ensure no one can peek.

---

**Analoji:** Bu sistemi, dijital bir **banka kasasına** benzetebiliriz. Sadece doğru anahtara (parola) sahip olmanız yetmez; aynı zamanda kasanın güvenlik görevlisi (Rate Limiter) çok hızlı deneme yapmanızı engeller ve kasa kapağı (Memory Zeroization) siz işlem yapmayı bıraktığınızda güvenliğiniz için otomatik olarak kapanır.




