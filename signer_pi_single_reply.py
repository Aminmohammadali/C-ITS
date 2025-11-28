#!/usr/bin/env python3
# signer_pi_manual_ts.py
# -----------------------------------------------------
# Raspberry Pi SIGNER (Single Signature with Manual Timestamp)
# Generates ONE signature with user-provided timestamp
# for replay attack testing.
#
# Usage example:
#   python3 signer_pi_manual_ts.py --host 192.168.2.2 --port 5000 --ts 1234567890 --data Alice

import argparse, json, socket, struct, hashlib, sys, time
from bplib import bp
from bplib.bp import BpGroup
from petlib.bn import Bn

# ============================
# Predefined public parameters
# ============================
H_HEX  = "021671ad1d26a4f36a13d7e784c30f5fb8a2dbdd520f96c68c28158317120c0194"
H1_HEX = "020d88e6287ceaf04a0686abd6bad9325dfee53a9c2606b37b62122cf611c1a4fe"
Y_HEX  = "021483d905ed81ae2a6c267bc339777fe15380e1403f924268d888e85c29b0a7e6"
W_HEX  = "15749bbf9d02337fb8cc860a256350ef4ae07eb8c148825db06911612d5c6a940bab2361cd512c36098308259502631adb4bd594c06fae47249a68b2a922459d075308a6d76f5004c268e5434059224398be1ac87c0e29b513b6ce82b50637ab158329a65a7da006e60debf1f4cfc0857de22f32568296a4c8cc310be7297677"

# ============================
# Predefined member secrets
# ============================
A_I_HEX = "03104a3fdf718f364afa819caec046cef6643932d24fb658d245598ae462b888ca"
X_I_HEX = "22b42a5548c529ed47667df4ebcc7a28f6e91ab6b06ec6bf348aee196a889050"
Y_I_HEX = "1906f3322b39de69420d399b3497709bd2b4ec776b5a05ce43ef6345e3c2229c"

# ============================
# Helpers
# ============================

def clean_hex(s: str) -> str:
    if s is None:
        return ""
    return s.replace("<","").replace(">","").replace("0x","").replace(" ","").strip()

def _g1_from_hex(h: str, G: BpGroup):
    return bp.G1Elem.from_bytes(bytes.fromhex(clean_hex(h)), G)

def _g2_from_hex(h: str, G: BpGroup):
    return bp.G2Elem.from_bytes(bytes.fromhex(clean_hex(h)), G)

def _bn_from_hex(h: str) -> Bn:
    return Bn.from_binary(bytes.fromhex(clean_hex(h)))

def _hash_to_Zp(data: bytes, p: Bn) -> Bn:
    digest = hashlib.sha256(data).digest()
    n = int.from_bytes(digest, "big")
    n_bytes = n.to_bytes((n.bit_length() + 7) // 8 or 1, "big")
    return Bn.from_binary(n_bytes) % p

def _hash_to_g1(data: bytes, g1, p):
    return _hash_to_Zp(data, p) * g1

def _message_to_bytes(msg: str) -> bytes:
    ts_str, D_str = msg.split("||", 1)
    ts = int(ts_str)
    D_bytes = D_str.encode("utf-8")
    ts_bytes = ts.to_bytes((ts.bit_length() + 7) // 8 or 1, "big")
    return ts_bytes + D_bytes

def _send_json(sock: socket.socket, obj: dict):
    data = json.dumps(obj).encode("utf-8")
    sock.sendall(struct.pack("!I", len(data)))
    sock.sendall(data)

def _recv_json(sock: socket.socket) -> dict:
    hdr = sock.recv(4)
    if len(hdr) < 4:
        raise ConnectionError("Short read on header")
    (length,) = struct.unpack("!I", hdr)
    buf = b""
    while len(buf) < length:
        chunk = sock.recv(length - len(buf))
        if not chunk:
            raise ConnectionError("Short read on payload")
        buf += chunk
    return json.loads(buf.decode("utf-8"))

# ============================
# Build params
# ============================

G = BpGroup()
p = G.order()
g1 = G.gen1()
g2 = G.gen2()

h  = _g1_from_hex(H_HEX,  G)
h1 = _g1_from_hex(H1_HEX, G)
Y  = _g1_from_hex(Y_HEX,  G)
w  = _g2_from_hex(W_HEX,  G)

gpk = {"g1": g1, "g2": g2, "h": h, "h1": h1, "Y": Y, "w": w}

A_i = _g1_from_hex(A_I_HEX, G)
x_i = _bn_from_hex(X_I_HEX)
y_i = _bn_from_hex(Y_I_HEX)
gsk_i = {"A_i": A_i, "x_i": x_i, "y_i": y_i}

# ============================
# Signing
# ============================

def ARA_Sign(message_str: str):
    g1_, h_, h1_, Y_ = gpk['g1'], gpk['h'], gpk['h1'], gpk['Y']
    A_i_, x_i_, y_i_ = gsk_i['A_i'], gsk_i['x_i'], gsk_i['y_i']

    M = _message_to_bytes(message_str)
    def r(): return Bn.random(p - 1) + 1
    k   = r()
    r_k = r()
    r_x = r()
    r_d = r()
    r_y = r()

    delta1 = (x_i_ * k) % p

    Hm = _hash_to_g1(M, g1_, p)
    T1 = x_i_ * Hm
    T2 = k * g1_
    T3 = A_i_ + (k * h_)
    T4 = r_x * (T3 + Hm) + (-r_d * h_) + (-r_k * Y_) + (r_y * h1_)

    R1 = r_k * g1_
    R2 = (r_x * T2) + (-r_d * g1_)

    c = _hash_to_Zp(T1.export()+T2.export()+T3.export()+T4.export()+R1.export()+R2.export()+M, p)

    s_k = (r_k + c * k)            % p
    s_x = (r_x + c * x_i_)         % p
    s_d = (r_d + c * delta1)       % p
    s_y = (r_y + c * y_i_)         % p

    return {
        "T1_hex": T1.export().hex(),
        "T2_hex": T2.export().hex(),
        "T3_hex": T3.export().hex(),
        "T4_hex": T4.export().hex(),
        "c_hex":  c.binary().hex(),
        "s_k_hex": s_k.binary().hex(),
        "s_x_hex": s_x.binary().hex(),
        "s_d_hex": s_d.binary().hex(),
        "s_y_hex": s_y.binary().hex(),
        "M_hex": M.hex(),
        "message_str": message_str
    }

# ============================
# Main
# ============================

def main():
    ap = argparse.ArgumentParser(description="ARA Signer (Single Signature with Manual Timestamp)")
    ap.add_argument("--host", required=True, help="Verifier IP (e.g. 192.168.2.2)")
    ap.add_argument("--port", type=int, default=5000, help="Verifier TCP port (default 5000)")
    ap.add_argument("--ts", type=int, required=True, help="Timestamp (Unix epoch seconds)")
    ap.add_argument("--data", default="Alice", help="Data payload (default 'Alice')")
    ap.add_argument("--timeout", type=float, default=10.0, help="Socket timeout seconds")
    args = ap.parse_args()

    # Build message as "timestamp||data"
    message_str = f"{args.ts}||{args.data}"
    
    print(f"[i] Generating signature for message: '{message_str}'")
    print(f"[i] Current time: {int(time.time())} (for reference)")
    
    # Generate signature
    t_sign_start = time.time()
    sigma = ARA_Sign(message_str)
    t_sign_end = time.time()
    sign_time_ms = (t_sign_end - t_sign_start) * 1000.0
    
    print(f"[✓] Signature generated in {sign_time_ms:.3f} ms")

    # Prepare payload for single signature
    payload = {
        "type": "signature",
        "sigma_hex": sigma,
        "timestamp": args.ts,
        "data": args.data
    }

    # Send to verifier
    print(f"[→] Sending to verifier at {args.host}:{args.port}...")
    try:
        with socket.create_connection((args.host, args.port), timeout=args.timeout) as s:
            _send_json(s, payload)
            resp = _recv_json(s)
    except Exception as e:
        print(f"[!] Network error: {e}")
        sys.exit(1)

    # Display result
    print(f"\n{'='*60}")
    if resp.get("ok", False):
        print(f"[✓] Verification: SUCCESS")
        if "verify_time_ms" in resp:
            print(f"[i] Verification time: {resp['verify_time_ms']} ms")
        if "replay_attack_detected" in resp and resp["replay_attack_detected"]:
            print(f"[!] WARNING: Replay attack detected!")
            print(f"    Timestamp: {resp.get('signature_timestamp', 'N/A')}")
            print(f"    Verifier time: {resp.get('verifier_timestamp', 'N/A')}")
            print(f"    Age: {resp.get('age_seconds', 'N/A')} seconds")
            print(f"    Max allowed: {resp.get('max_age_seconds', 'N/A')} seconds")
    else:
        print(f"[✗] Verification: FAILED")
        if "error" in resp:
            print(f"[!] Error: {resp['error']}")
        if "replay_attack_detected" in resp and resp["replay_attack_detected"]:
            print(f"[!] Reason: Replay attack detected")
            print(f"    Timestamp: {resp.get('signature_timestamp', 'N/A')}")
            print(f"    Verifier time: {resp.get('verifier_timestamp', 'N/A')}")
            print(f"    Age: {resp.get('age_seconds', 'N/A')} seconds")
            print(f"    Max allowed: {resp.get('max_age_seconds', 'N/A')} seconds")
    
    print(f"{'='*60}\n")
    
    # Exit with appropriate code
    sys.exit(0 if resp.get("ok", False) else 2)

if __name__ == "__main__":
    main()