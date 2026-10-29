/* =========================================================================
 * DEPRECATED (27 Oct 2026): this X25519-pairing design was NOT shipped.
 * Shipped v4.0.0 = mutual HMAC-PSK challenge-response + per-connection
 * session key + per-frame session-MAC envelopes (see agent.c main loop and
 * bridge_mcp.py _serve_connection). Kept for reference only; not compiled in.
 * -------------------------------------------------------------------------
 * BridgeWindows v4 secure transport (replaces the static pre-shared token)
 *  - One-time pairing: X25519 key agreement (CNG) + 6-digit code compared by the
 *    owner on BOTH machines (blocks man-in-the-middle). Key stored with DPAPI.
 *  - Each session: nonces exchanged, mutual proof of key possession, then every
 *    JSON frame is [len][HMAC-SHA256 tag (32 bytes)][json] with per-direction
 *    sequence numbers (no replay, no reordering). No secret ever crosses the wire.
 *  - Binary chunk frames are refused in secure mode.
 * ========================================================================= */
#include <wincrypt.h>
#ifndef BCRYPT_ECC_CURVE_NAME
#define BCRYPT_ECC_CURVE_NAME L"ECCCurveName"
#endif
#ifndef BCRYPT_ECC_CURVE_25519
#define BCRYPT_ECC_CURVE_25519 L"curve25519"
#endif
#ifndef BCRYPT_ECDH_PUBLIC_GENERIC_MAGIC
#define BCRYPT_ECDH_PUBLIC_GENERIC_MAGIC 0x504B4345
#endif
#ifndef BCRYPT_KDF_RAW_SECRET
#define BCRYPT_KDF_RAW_SECRET L"TRUNCATE"
#endif
#define V4_VERSION "4.0.0"
/* Byte-order adapters between CNG blobs and RFC 7748 (set from the interop self-test). */
#ifndef V4_REVERSE_PUB
#define V4_REVERSE_PUB 0
#endif
#ifndef V4_REVERSE_SECRET
#define V4_REVERSE_SECRET 0
#endif

static uint8_t g_key[32];
static bool g_have_key = false;
static uint8_t g_sess[32];
static uint64_t g_seq_tx = 0, g_seq_rx = 0;
static volatile bool g_secure = false;
static bool g_pair_mode = false;

static void v4_rev(uint8_t *b, size_t n) { for (size_t i = 0; i < n / 2; i++) { uint8_t t = b[i]; b[i] = b[n - 1 - i]; b[n - 1 - i] = t; } }

static bool v4_hmac(const uint8_t *key, size_t klen, const void *d1, size_t l1, const void *d2, size_t l2,
                    const void *d3, size_t l3, const void *d4, size_t l4, uint8_t out[32]) {
    BCRYPT_ALG_HANDLE a = NULL; BCRYPT_HASH_HANDLE h = NULL; bool ok = false;
    if (!NT_SUCCESS(BCryptOpenAlgorithmProvider(&a, BCRYPT_SHA256_ALGORITHM, NULL, BCRYPT_ALG_HANDLE_HMAC_FLAG))) return false;
    if (NT_SUCCESS(BCryptCreateHash(a, &h, NULL, 0, (PUCHAR)key, (ULONG)klen, 0))
        && (!l1 || NT_SUCCESS(BCryptHashData(h, (PUCHAR)d1, (ULONG)l1, 0)))
        && (!l2 || NT_SUCCESS(BCryptHashData(h, (PUCHAR)d2, (ULONG)l2, 0)))
        && (!l3 || NT_SUCCESS(BCryptHashData(h, (PUCHAR)d3, (ULONG)l3, 0)))
        && (!l4 || NT_SUCCESS(BCryptHashData(h, (PUCHAR)d4, (ULONG)l4, 0)))
        && NT_SUCCESS(BCryptFinishHash(h, out, 32, 0))) ok = true;
    if (h) BCryptDestroyHash(h);
    BCryptCloseAlgorithmProvider(a, 0);
    return ok;
}

static bool v4_eq(const uint8_t *a, const uint8_t *b, size_t n) { uint8_t d = 0; for (size_t i = 0; i < n; i++) d |= a[i] ^ b[i]; return d == 0; }
static void v4_hex(const uint8_t *b, size_t n, char *out) { static const char *x = "0123456789abcdef"; for (size_t i = 0; i < n; i++) { out[2*i] = x[b[i] >> 4]; out[2*i+1] = x[b[i] & 15]; } out[2*n] = 0; }
static bool v4_unhex(const char *s, uint8_t *b, size_t n) {
    if (!s || strlen(s) != 2 * n) return false;
    for (size_t i = 0; i < n; i++) { unsigned v; if (sscanf(s + 2*i, "%2x", &v) != 1) return false; b[i] = (uint8_t)v; }
    return true;
}
static bool v4_random(uint8_t *b, size_t n) { return NT_SUCCESS(BCryptGenRandom(NULL, b, (ULONG)n, BCRYPT_USE_SYSTEM_PREFERRED_RNG)); }

static void v4_key_path(char *out, size_t n) {
    char exe[MAX_PATH]; GetModuleFileNameA(NULL, exe, MAX_PATH);
    char *slash = strrchr(exe, '\\'); if (slash) *(slash + 1) = 0;
    snprintf(out, n, "%sbridge_key.dat", exe);
}
static bool v4_save_key(void) {
    DATA_BLOB in = { 32, g_key }, out = { 0 };
    if (!CryptProtectData(&in, L"BridgeWindows v4 key", NULL, NULL, NULL, CRYPTPROTECT_UI_FORBIDDEN, &out)) return false;
    char p[MAX_PATH]; v4_key_path(p, sizeof(p));
    FILE *f = fopen(p, "wb"); bool ok = f && fwrite(out.pbData, 1, out.cbData, f) == out.cbData;
    if (f) fclose(f);
    LocalFree(out.pbData);
    return ok;
}
static bool v4_load_key(void) {
    char p[MAX_PATH]; v4_key_path(p, sizeof(p));
    FILE *f = fopen(p, "rb"); if (!f) return false;
    uint8_t buf[2048]; size_t n = fread(buf, 1, sizeof(buf), f); fclose(f);
    DATA_BLOB in = { (DWORD)n, buf }, out = { 0 };
    if (!CryptUnprotectData(&in, NULL, NULL, NULL, NULL, CRYPTPROTECT_UI_FORBIDDEN, &out)) return false;
    bool ok = out.cbData == 32;
    if (ok) memcpy(g_key, out.pbData, 32);
    SecureZeroMemory(out.pbData, out.cbData); LocalFree(out.pbData);
    return ok;
}

static bool v4_x25519_keypair(BCRYPT_ALG_HANDLE *pa, BCRYPT_KEY_HANDLE *pk, uint8_t pub[32]) {
    if (!NT_SUCCESS(BCryptOpenAlgorithmProvider(pa, BCRYPT_ECDH_ALGORITHM, NULL, 0))) return false;
    if (!NT_SUCCESS(BCryptSetProperty(*pa, BCRYPT_ECC_CURVE_NAME, (PUCHAR)BCRYPT_ECC_CURVE_25519,
                                      (ULONG)((wcslen(BCRYPT_ECC_CURVE_25519) + 1) * sizeof(WCHAR)), 0))) return false;
    if (!NT_SUCCESS(BCryptGenerateKeyPair(*pa, pk, 255, 0)) || !NT_SUCCESS(BCryptFinalizeKeyPair(*pk, 0))) return false;
    uint8_t blob[256]; ULONG n = 0;
    if (!NT_SUCCESS(BCryptExportKey(*pk, NULL, BCRYPT_ECCPUBLIC_BLOB, blob, sizeof(blob), &n, 0))) return false;
    BCRYPT_ECCKEY_BLOB *hdr = (BCRYPT_ECCKEY_BLOB *)blob;
    if (hdr->cbKey != 32) return false;
    memcpy(pub, blob + sizeof(*hdr), 32);
    if (V4_REVERSE_PUB) v4_rev(pub, 32);
    return true;
}
static bool v4_x25519_shared(BCRYPT_ALG_HANDLE a, BCRYPT_KEY_HANDLE k, const uint8_t peer_rfc[32], uint8_t out[32]) {
    uint8_t blob[sizeof(BCRYPT_ECCKEY_BLOB) + 64]; BCRYPT_ECCKEY_BLOB *hdr = (BCRYPT_ECCKEY_BLOB *)blob;
    hdr->dwMagic = BCRYPT_ECDH_PUBLIC_GENERIC_MAGIC; hdr->cbKey = 32;
    memcpy(blob + sizeof(*hdr), peer_rfc, 32); if (V4_REVERSE_PUB) v4_rev(blob + sizeof(*hdr), 32);
    memset(blob + sizeof(*hdr) + 32, 0, 32);
    BCRYPT_KEY_HANDLE pk = NULL; BCRYPT_SECRET_HANDLE s = NULL; ULONG n = 0; bool ok = false;
    if (NT_SUCCESS(BCryptImportKeyPair(a, NULL, BCRYPT_ECCPUBLIC_BLOB, &pk, blob, sizeof(blob), 0))
        && NT_SUCCESS(BCryptSecretAgreement(k, pk, &s, 0))
        && NT_SUCCESS(BCryptDeriveKey(s, BCRYPT_KDF_RAW_SECRET, NULL, out, 32, &n, 0)) && n == 32) ok = true;
    if (ok && V4_REVERSE_SECRET) v4_rev(out, 32);
    if (s) BCryptDestroySecret(s);
    if (pk) BCryptDestroyKey(pk);
    return ok;
}

static void v4_be64(uint64_t v, uint8_t b[8]) { for (int i = 7; i >= 0; i--) { b[i] = (uint8_t)v; v >>= 8; } }

/* Secure frame send (called with g_send_lock held by send_frame). */
static bool v4_send_tagged(SOCKET s, const char *json, uint32_t len) {
    uint8_t seq[8], tag[32]; v4_be64(g_seq_tx, seq);
    if (!v4_hmac(g_sess, 32, "A", 1, seq, 8, json, len, NULL, 0, tag)) return false;
    uint32_t net_len = htonl(len + 32);
    bool ok = send_all(s, (const char *)&net_len, 4) && send_all(s, (const char *)tag, 32) && send_all(s, json, len);
    if (ok) g_seq_tx++;
    return ok;
}
/* Verify a received secure frame in place; returns pointer to JSON (NUL-terminated) or NULL. */
static char *v4_verify(char *frame, uint32_t len) {
    if (len < 33) return NULL;
    uint8_t seq[8], tag[32]; v4_be64(g_seq_rx, seq);
    if (!v4_hmac(g_sess, 32, "M", 1, seq, 8, frame + 32, len - 32, NULL, 0, tag)) return NULL;
    if (!v4_eq(tag, (const uint8_t *)frame, 32)) return NULL;
    g_seq_r
