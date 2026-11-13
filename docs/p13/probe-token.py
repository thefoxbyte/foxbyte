# SPDX-License-Identifier: AGPL-3.0-or-later
# Throwaway probe: what the vault design assumes about a PKCS#11 token (SoftHSM2).
import os, time, PyKCS11
from PyKCS11 import LowLevel as LL
lib = PyKCS11.PyKCS11Lib(); lib.load("/usr/lib/softhsm/libsofthsm2.so")
slot = lib.getSlotList(tokenPresent=True)[0]
print("token:", lib.getTokenInfo(slot).label.strip(), "| lib:", lib.getInfo().libraryDescription.strip(), lib.getInfo().libraryVersion)
mechs = lib.getMechanismList(slot)
for m in ("CKM_AES_GCM", "CKM_SHA256_HMAC", "CKM_AES_KEY_WRAP", "CKM_AES_KEY_WRAP_PAD", "CKM_GENERIC_SECRET_KEY_GEN"):
    print(m, "supported" if m in mechs else "MISSING")
s = lib.openSession(slot, PyKCS11.CKF_SERIAL_SESSION | PyKCS11.CKF_RW_SESSION)
try:
    s.login("0000"); print("wrong PIN: ACCEPTED (bad)")
except PyKCS11.PyKCS11Error as e: print("wrong PIN refused:", e)
s.login("1234")
aes = s.generateKey([(PyKCS11.CKA_CLASS, PyKCS11.CKO_SECRET_KEY), (PyKCS11.CKA_KEY_TYPE, PyKCS11.CKK_AES),
    (PyKCS11.CKA_VALUE_LEN, 32), (PyKCS11.CKA_TOKEN, True), (PyKCS11.CKA_PRIVATE, True), (PyKCS11.CKA_LABEL, "vault-data-1"),
    (PyKCS11.CKA_SENSITIVE, True), (PyKCS11.CKA_EXTRACTABLE, False), (PyKCS11.CKA_ENCRYPT, True), (PyKCS11.CKA_DECRYPT, True)],
    PyKCS11.Mechanism(PyKCS11.CKM_AES_KEY_GEN))
mac = s.generateKey([(PyKCS11.CKA_CLASS, PyKCS11.CKO_SECRET_KEY), (PyKCS11.CKA_KEY_TYPE, PyKCS11.CKK_GENERIC_SECRET),
    (PyKCS11.CKA_VALUE_LEN, 32), (PyKCS11.CKA_TOKEN, True), (PyKCS11.CKA_PRIVATE, True), (PyKCS11.CKA_LABEL, "vault-index-1"),
    (PyKCS11.CKA_SENSITIVE, True), (PyKCS11.CKA_EXTRACTABLE, False), (PyKCS11.CKA_SIGN, True), (PyKCS11.CKA_VERIFY, True)],
    PyKCS11.Mechanism(PyKCS11.CKM_GENERIC_SECRET_KEY_GEN))
try:
    v = s.getAttributeValue(aes, [PyKCS11.CKA_VALUE]); print("read key value:", "GOT IT (bad)" if v and v[0] else "refused (None)")
except PyKCS11.PyKCS11Error as e: print("read key value refused:", e)
wrapk = s.generateKey([(PyKCS11.CKA_CLASS, PyKCS11.CKO_SECRET_KEY), (PyKCS11.CKA_KEY_TYPE, PyKCS11.CKK_AES), (PyKCS11.CKA_VALUE_LEN, 32),
    (PyKCS11.CKA_WRAP, True), (PyKCS11.CKA_TOKEN, False)], PyKCS11.Mechanism(PyKCS11.CKM_AES_KEY_GEN))
try:
    s.wrapKey(wrapk, aes, PyKCS11.Mechanism(PyKCS11.CKM_AES_KEY_WRAP_PAD)); print("wrap out: ALLOWED (bad)")
except PyKCS11.PyKCS11Error as e: print("wrap out refused:", e)
num = b"298765432101"
def gcm(): return PyKCS11.AES_GCM_Mechanism(os.urandom(12), b"ref:ar_test", 128)
iv = os.urandom(12); m = PyKCS11.AES_GCM_Mechanism(iv, b"ref:ar_test", 128)
ct = bytes(s.encrypt(aes, num, m)); print("ciphertext bytes:", len(ct))
pt = bytes(s.decrypt(aes, ct, PyKCS11.AES_GCM_Mechanism(iv, b"ref:ar_test", 128))); print("round trip:", pt == num)
bad = bytearray(ct); bad[0] ^= 1
try:
    s.decrypt(aes, bytes(bad), PyKCS11.AES_GCM_Mechanism(iv, b"ref:ar_test", 128)); print("tampered: ACCEPTED (bad)")
except PyKCS11.PyKCS11Error as e: print("tampered refused:", e)
try:
    s.decrypt(aes, ct, PyKCS11.AES_GCM_Mechanism(iv, b"ref:ar_OTHER", 128)); print("other ref (AAD): ACCEPTED (bad)")
except PyKCS11.PyKCS11Error as e: print("other ref (AAD) refused:", e)
h1 = bytes(s.sign(mac, num, PyKCS11.Mechanism(PyKCS11.CKM_SHA256_HMAC))); h2 = bytes(s.sign(mac, num, PyKCS11.Mechanism(PyKCS11.CKM_SHA256_HMAC)))
print("hmac deterministic:", h1 == h2, len(h1), "bytes")
N = 20000
for name, fn in (("encrypt", lambda: s.encrypt(aes, num, gcm())),
                 ("decrypt", lambda: s.decrypt(aes, ct, PyKCS11.AES_GCM_Mechanism(iv, b"ref:ar_test", 128))),
                 ("hmac", lambda: s.sign(mac, num, PyKCS11.Mechanism(PyKCS11.CKM_SHA256_HMAC)))):
    t = time.perf_counter()
    for _ in range(N): fn()
    d = time.perf_counter() - t; print(f"{name}: {N/d:,.0f} ops/s, {d/N*1e6:.1f} us each (one session, one thread, Python)")
s.logout(); s.closeSession()
s2 = lib.openSession(slot)
print("keys visible without login:", len(s2.findObjects([(PyKCS11.CKA_CLASS, PyKCS11.CKO_SECRET_KEY)])))
