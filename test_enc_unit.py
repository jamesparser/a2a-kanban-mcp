import sys
sys.path.insert(0, r"C:/Users/agnesagent/work/a2a-mesh-encrypted")
import mesh_enc
k1 = mesh_enc.new_key(); k2 = mesh_enc.new_key()
w = mesh_enc.encrypt(k2, "laptop", "rci-vps", "11111111-2222-3333-4444-555555555555", "hello secret body")
print("wire:", w[:30], "... len", len(w))
pt = mesh_enc.decrypt(k2, "laptop", "rci-vps", "11111111-2222-3333-4444-555555555555", w)
print("roundtrip:", pt == b"hello secret body")
try:
    mesh_enc.decrypt(k1, "laptop", "rci-vps", "11111111-2222-3333-4444-555555555555", w)
    print("WRONG-KEY: NOT DETECTED")
except Exception as e:
    print("wrong-key rejected:", type(e).__name__)
bad = w[:-4] + ("AAAA" if not w.endswith("AAAA") else "BBBB")
try:
    mesh_enc.decrypt(k2, "laptop", "rci-vps", "11111111-2222-3333-4444-555555555555", bad)
    print("TAMPER: NOT DETECTED")
except Exception as e:
    print("tamper rejected:", type(e).__name__)
try:
    mesh_enc.decrypt(k2, "laptop", "rci-vps", "99999999-2222-3333-4444-555555555555", w)
    print("REPLAY-ID: NOT DETECTED")
except Exception as e:
    print("wrong-aad rejected:", type(e).__name__)
try:
    mesh_enc.decrypt(k2, "evil", "rci-vps", "11111111-2222-3333-4444-555555555555", w)
    print("WRONG-SENDER: NOT DETECTED")
except Exception as e:
    print("wrong-sender rejected:", type(e).__name__)
print("encrypted detection:", mesh_enc.is_encrypted(w), mesh_enc.is_encrypted("plain text"))
