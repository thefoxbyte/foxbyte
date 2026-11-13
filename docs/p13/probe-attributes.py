# SPDX-License-Identifier: AGPL-3.0-or-later
# Throwaway probe 2: the attributes an evidence report would read, and a restart.
import PyKCS11, sys
lib = PyKCS11.PyKCS11Lib(); lib.load("/usr/lib/softhsm/libsofthsm2.so")
slot = lib.getSlotList(tokenPresent=True)[0]
ti = lib.getTokenInfo(slot)
print("token:", ti.label.strip(), "| maker:", ti.manufacturerID.strip(), "| model:", ti.model.strip(), "| serial:", ti.serialNumber.strip())
s = lib.openSession(slot, PyKCS11.CKF_SERIAL_SESSION | PyKCS11.CKF_RW_SESSION); s.login("1234")
if sys.argv[1] == "make":
    s.generateKey([(PyKCS11.CKA_CLASS, PyKCS11.CKO_SECRET_KEY), (PyKCS11.CKA_KEY_TYPE, PyKCS11.CKK_AES), (PyKCS11.CKA_VALUE_LEN, 32),
        (PyKCS11.CKA_TOKEN, True), (PyKCS11.CKA_PRIVATE, True), (PyKCS11.CKA_LABEL, "vault-data-1"), (PyKCS11.CKA_ID, b"\x01"),
        (PyKCS11.CKA_SENSITIVE, True), (PyKCS11.CKA_EXTRACTABLE, False), (PyKCS11.CKA_ENCRYPT, True), (PyKCS11.CKA_DECRYPT, True)],
        PyKCS11.Mechanism(PyKCS11.CKM_AES_KEY_GEN))
for k in s.findObjects([(PyKCS11.CKA_CLASS, PyKCS11.CKO_SECRET_KEY)]):
    a = [PyKCS11.CKA_LABEL, PyKCS11.CKA_VALUE_LEN, PyKCS11.CKA_SENSITIVE, PyKCS11.CKA_EXTRACTABLE, PyKCS11.CKA_ALWAYS_SENSITIVE, PyKCS11.CKA_NEVER_EXTRACTABLE, PyKCS11.CKA_LOCAL]
    v = s.getAttributeValue(k, a)
    print(dict(zip(["label","len","sensitive","extractable","always_sensitive","never_extractable","local(made in token)"], v)))
    try:
        s.setAttributeValue(k, [(PyKCS11.CKA_EXTRACTABLE, True)]); print("set extractable: ALLOWED (bad)")
    except PyKCS11.PyKCS11Error as e: print("set extractable refused:", e)
