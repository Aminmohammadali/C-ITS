#!/usr/bin/env python3
# verifier_pi_replay_detect.py
# Raspberry Pi VERIFIER with Replay Attack Detection
# - All original features: batch verification, Sybil detection, fallback
# - NEW: Replay attack detection (40-second timestamp freshness check)
# - Checks timestamp freshness for both single and batch signatures

import argparse, json, socket, struct, hashlib, sys, time
from bplib import bp
from bplib.bp import BpGroup
from petlib.bn import Bn

# ============================
# Predefined public parameters (must match signer)
# ============================
H_HEX  = "021671ad1d26a4f36a13d7e784c30f5fb8a2dbdd520f96c68c28158317120c0194"
H1_HEX = "020d88e6287ceaf04a0686abd6bad9325dfee53a9c2606b37b62122cf611c1a4fe"
Y_HEX  = "021483d905ed81ae2a6c267bc339777fe15380e1403f924268d888e85c29b0a7e6"
W_HEX  = "15749bbf9d02337fb8cc860a256350ef4ae07eb8c148825db06911612d5c6a940bab2361cd512c36098308259502631adb4bd594c06fae47249a68b2a922459d075308a6d76f5004c268e5434059224398be1ac87c0e29b513b6ce82b50637ab158329a65a7da006e60debf1f4cfc0857de22f32568296a4c8cc310be7297677"

# ============================
# Policy
# ============================
THRESHOLD = 10  # minimum required; also the maximum we will actually verify per batch
MAX_TIMESTAMP_AGE_SECONDS = 40  # Replay attack threshold

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

def _bn_from_hex(h: str):
    return Bn.from_binary(bytes.fromhex(clean_hex(h)))

def _hash_to_Zp(data: bytes, p: Bn) -> Bn:
    digest = hashlib.sha256(data).digest()
    n = int.from_bytes(digest, "big")
    n_bytes = n.to_bytes((n.bit_length() + 7) // 8 or 1, "big")
    return Bn.from_binary(n_bytes) % p

def _hash_to_g1(data: bytes, g1, p):
    return _hash_to_Zp(data, p) * g1

def _recv_json(conn: socket.socket) -> dict:
    hdr = conn.recv(4)
    if len(hdr) < 4:
        raise ConnectionError("Short read on header")
    (length,) = struct.unpack("!I", hdr)
    buf = b""
    while len(buf) < length:
        chunk = conn.recv(length - len(buf))
        if not chunk:
            raise ConnectionError("Short read on payload")
        buf += chunk
    return json.loads(buf.decode("utf-8"))

def _send_json(conn: socket.socket, obj: dict):
    data = json.dumps(obj).encode("utf-8")
    conn.sendall(struct.pack("!I", len(data)))
    conn.sendall(data)

def _message_to_bytes(msg: str) -> bytes:
    ts_str, D_str = msg.split("||", 1)
    ts = int(ts_str)
    D_bytes = D_str.encode("utf-8")
    ts_bytes = ts.to_bytes((ts.bit_length() + 7) // 8 or 1, "big")
    return ts_bytes + D_bytes

# ============================
# Timestamp validation (NEW)
# ============================

def check_timestamp_freshness(message_str: str, max_age_sec: int = MAX_TIMESTAMP_AGE_SECONDS):
    """
    Extract timestamp from message and check if it's within acceptable age.
    Returns: (is_fresh: bool, sig_ts: int, verifier_ts: int, age_sec: float)
    """
    try:
        ts_str = message_str.split("||", 1)[0]
        sig_timestamp = int(ts_str)
    except (ValueError, IndexError):
        return (False, None, None, None)
    
    verifier_timestamp = int(time.time())
    age_seconds = verifier_timestamp - sig_timestamp
    
    is_fresh = age_seconds <= max_age_sec
    
    return (is_fresh, sig_timestamp, verifier_timestamp, age_seconds)

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

# ============================
# Verify (single)
# ============================

def ARA_Verify(gpk, sigma_hex: dict) -> bool:
    # Build points/scalars from hex
    T1 = _g1_from_hex(sigma_hex["T1_hex"], G)
    T2 = _g1_from_hex(sigma_hex["T2_hex"], G)
    T3 = _g1_from_hex(sigma_hex["T3_hex"], G)
    T4 = _g1_from_hex(sigma_hex["T4_hex"], G)
    c  = _bn_from_hex(sigma_hex["c_hex"])
    s_k = _bn_from_hex(sigma_hex["s_k_hex"])
    s_x = _bn_from_hex(sigma_hex["s_x_hex"])
    s_d = _bn_from_hex(sigma_hex["s_d_hex"])
    s_y = _bn_from_hex(sigma_hex["s_y_hex"])

    # Rebuild M (prefer message_str if provided; else M_hex)
    if "message_str" in sigma_hex and sigma_hex["message_str"]:
        M = _message_to_bytes(sigma_hex["message_str"])
    else:
        M = bytes.fromhex(clean_hex(sigma_hex["M_hex"]))

    g1_ = gpk['g1']; g2_ = gpk['g2']; h_ = gpk['h']; h1_ = gpk['h1']; w_ = gpk['w']; Y_ = gpk['Y']

    # Recompute H(m)
    Hm = _hash_to_g1(M, g1_, p)

    # Recompute the Schnorr-style checks
    R1_dash = (s_k * g1_) + ((-c) * T2)
    R2_dash = (s_x * T2) + ((-s_d) * g1_)

    c_dash = _hash_to_Zp(
        T1.export() + T2.export() + T3.export() + T4.export() +
        R1_dash.export() + R2_dash.export() + M, p
    )

    KK  = T4 \
          + (-s_x) * T3 \
          + c * T1 \
          + s_k * Y_ \
          + c * g1_ \
          + (-s_x) * Hm \
          + (-s_y) * h1_ \
          + s_d * h_

    e_KK_g2 = G.pair(KK, g2_)
    e_cT3_w = G.pair(c * T3, w_)

    return (c_dash == c) and (e_KK_g2 == e_cT3_w)

# ============================
# Verify (batch, split checks + timings)
# ============================

def verify_batch_split(gpk, sig_list):
    """Part 1: per-sig c*_i == c_i (no pairings)
       Part 2: one aggregated pairing equality"""
    t_start = time.time()

    g1_ = gpk['g1']; g2_ = gpk['g2']; h_ = gpk['h']; h1_ = gpk['h1']; w_ = gpk['w']; Y_ = gpk['Y']

    def get_M(sig):
        if "message_str" in sig and sig["message_str"]:
            return _message_to_bytes(sig["message_str"])
        return bytes.fromhex(clean_hex(sig["M_hex"]))

    M0 = get_M(sig_list[0])
    for i, s in enumerate(sig_list[1:], start=1):
        if get_M(s) != M0:
            return {
                "ok": False, "part1_all": False, "part2": False,
                "error": f"Batch aggregation requires identical messages; mismatch at index {i}."
            }

    Hm = _hash_to_g1(M0, g1_, p)

    t1_start = time.time()
    part1_results, part1_all_ok = [], True

    zero_g1 = g1_ * 0
    sum_T4 = zero_g1
    sum_neg_sx_T3 = zero_g1
    sum_c_T1 = zero_g1
    sum_c_T3 = zero_g1

    sum_sk = Bn(0)
    sum_c  = Bn(0)
    sum_sx = Bn(0)
    sum_sy = Bn(0)
    sum_sd = Bn(0)

    for idx, sig in enumerate(sig_list):
        T1 = _g1_from_hex(sig["T1_hex"], G)
        T2 = _g1_from_hex(sig["T2_hex"], G)
        T3 = _g1_from_hex(sig["T3_hex"], G)
        T4 = _g1_from_hex(sig["T4_hex"], G)
        c  = _bn_from_hex(sig["c_hex"])
        s_k = _bn_from_hex(sig["s_k_hex"])
        s_x = _bn_from_hex(sig["s_x_hex"])
        s_d = _bn_from_hex(sig["s_d_hex"])
        s_y = _bn_from_hex(sig["s_y_hex"])

        R1_dash = (s_k * g1_) + ((-c) * T2)
        R2_dash = (s_x * T2) + ((-s_d) * g1_)
        c_dash = _hash_to_Zp(T1.export()+T2.export()+T3.export()+T4.export()+R1_dash.export()+R2_dash.export()+M0, p)
        ok_i = (c_dash == c)
        part1_results.append({"index": idx, "ok": bool(ok_i)})
        part1_all_ok = part1_all_ok and ok_i

        sum_T4        = sum_T4 + T4
        sum_neg_sx_T3 = sum_neg_sx_T3 + ((-s_x) * T3)
        sum_c_T1      = sum_c_T1 + (c * T1)
        sum_c_T3      = sum_c_T3 + (c * T3)

        sum_sk = (sum_sk + s_k) % p
        sum_c  = (sum_c  + c)   % p
        sum_sx = (sum_sx + s_x) % p
        sum_sy = (sum_sy + s_y) % p
        sum_sd = (sum_sd + s_d) % p

    t1_end = time.time()
    time_part1_sec = round(t1_end - t1_start, 6)

    t2_start = time.time()

    left_G1  = sum_T4 + sum_neg_sx_T3 + sum_c_T1
    left_G1  = left_G1 + (sum_sk * Y_) + (sum_c * g1_) + ((-sum_sx) * Hm) + ((-sum_sy) * h1_) + (sum_sd * h_)
    right_cT3 = sum_c_T3

    e_left  = G.pair(left_G1, g2_)
    e_right = G.pair(right_cT3, w_)
    part2_ok = (e_left == e_right)

    t2_end = time.time()
    time_part2_sec = round(t2_end - t2_start, 6)
    total_time_sec = round(time.time() - t_start, 6)

    return {
        "ok": bool(part1_all_ok and part2_ok),
        "part1_all": bool(part1_all_ok),
        "part1_results": part1_results,
        "part2": bool(part2_ok),
        "time_part1_sec": time_part1_sec,
        "time_part2_sec": time_part2_sec,
        "total_verify_time_sec": total_time_sec,
    }

# ============================
# Server loop
# ============================

def main():
    ap = argparse.ArgumentParser(description="ARA Verifier (Raspberry Pi) with Replay Attack Detection")
    ap.add_argument("--port", type=int, default=5000, help="Listen port (default 5000)")
    ap.add_argument("--host", default="0.0.0.0", help="Bind address (default 0.0.0.0)")
    ap.add_argument("--max-age", type=int, default=MAX_TIMESTAMP_AGE_SECONDS, 
                    help=f"Max timestamp age in seconds (default {MAX_TIMESTAMP_AGE_SECONDS})")
    args = ap.parse_args()

    max_age = args.max_age

    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as srv:
        srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        srv.bind((args.host, args.port))
        srv.listen(1)
        print(f"[*] Verifier listening on {args.host}:{args.port}")
        print(f"[*] Replay attack threshold: {max_age} seconds")

        while True:
            conn, addr = srv.accept()
            with conn:
                try:
                    payload = _recv_json(conn)
                    ptype = payload.get("type")

                    # ---- Clock-sync ping
                    if ptype == "ping":
                        print("[ping] replying with verifier_now_ns")
                        _send_json(conn, {"ok": True, "type": "pong", "verifier_now_ns": time.time_ns()})
                        continue

                    # ---- Single-signature path (now with replay detection)
                    if ptype == "signature":
                        sigma_hex = payload.get("sigma_hex", {})
                        message_str = sigma_hex.get("message_str", "")
                        
                        if not message_str:
                            _send_json(conn, {
                                "ok": False,
                                "error": "Missing message_str in signature",
                                "verifier_end_ns": time.time_ns()
                            })
                            print(f"[!] {addr[0]}:{addr[1]} -> missing message_str")
                            continue

                        # NEW: Check timestamp freshness
                        is_fresh, sig_ts, ver_ts, age_sec = check_timestamp_freshness(message_str, max_age)
                        
                        if not is_fresh:
                            response = {
                                "ok": False,
                                "error": "Replay attack detected: timestamp too old",
                                "replay_attack_detected": True,
                                "signature_timestamp": sig_ts,
                                "verifier_timestamp": ver_ts,
                                "age_seconds": age_sec,
                                "max_age_seconds": max_age,
                                "verifier_end_ns": time.time_ns()
                            }
                            _send_json(conn, response)
                            print(f"[!] {addr[0]}:{addr[1]} -> REPLAY ATTACK: "
                                  f"ts={sig_ts}, age={age_sec}s > {max_age}s")
                            continue

                        # Timestamp is fresh, proceed with verification
                        t_single_start = time.time()
                        ok = ARA_Verify(gpk, sigma_hex)
                        verify_time_ms = round((time.time() - t_single_start) * 1000.0, 3)
                        _send_json(conn, {
                            "ok": bool(ok),
                            "verify_time_ms": verify_time_ms,
                            "replay_attack_detected": False,
                            "signature_timestamp": sig_ts,
                            "verifier_timestamp": ver_ts,
                            "age_seconds": age_sec,
                            "max_age_seconds": max_age,
                            "verifier_end_ns": time.time_ns()
                        })
                        print(f"[+] {addr[0]}:{addr[1]} -> single: {'OK' if ok else 'FAIL'} "
                              f"in {verify_time_ms} ms (ts={sig_ts}, age={age_sec}s)")
                        continue

                    # ---- Batch path (with min-count gate, cap at THRESHOLD, Sybil filter, fallback, and NEW: replay detection)
                    if ptype == "signatures":
                        sig_list = payload.get("sigma_hex", [])
                        if not isinstance(sig_list, list) or not sig_list:
                            _send_json(conn, {"ok": False, "error": "sigma_hex must be a non-empty list",
                                              "verifier_end_ns": time.time_ns()})
                            continue

                        total_received = len(sig_list)

                        # Require at least THRESHOLD signatures to proceed
                        if total_received < THRESHOLD:
                            _send_json(conn, {
                                "ok": False,
                                "error": f"Batch verification requires at least {THRESHOLD} signatures.",
                                "min_required": THRESHOLD,
                                "count": total_received,
                                "verifier_end_ns": time.time_ns()
                            })
                            print(f"[!] {addr[0]}:{addr[1]} -> batch rejected: count={total_received} < {THRESHOLD}")
                            continue

                        # NEW: Check timestamp freshness for batch (using first signature's timestamp)
                        first_sig = sig_list[0]
                        first_msg = first_sig.get("message_str", "")
                        if first_msg:
                            is_fresh, sig_ts, ver_ts, age_sec = check_timestamp_freshness(first_msg, max_age)
                            if not is_fresh:
                                response = {
                                    "ok": False,
                                    "error": "Replay attack detected: batch timestamp too old",
                                    "replay_attack_detected": True,
                                    "signature_timestamp": sig_ts,
                                    "verifier_timestamp": ver_ts,
                                    "age_seconds": age_sec,
                                    "max_age_seconds": max_age,
                                    "count": total_received,
                                    "verifier_end_ns": time.time_ns()
                                }
                                _send_json(conn, response)
                                print(f"[!] {addr[0]}:{addr[1]} -> BATCH REPLAY ATTACK: "
                                      f"ts={sig_ts}, age={age_sec}s > {max_age}s")
                                continue

                        # If more than THRESHOLD, verify only THRESHOLD of them (first THRESHOLD, deterministic)
                        subset_used = False
                        selected_indices = list(range(THRESHOLD))
                        if total_received > THRESHOLD:
                            subset_used = True
                            sig_list_used = [sig_list[i] for i in selected_indices]
                            print(f"[i] {addr[0]}:{addr[1]} -> received {total_received}; "
                                  f"verifying first {THRESHOLD} only (indices {selected_indices}).")
                        else:
                            sig_list_used = sig_list

                        # -------- Sybil detection by T1_hex --------
                        t1_map = {}
                        for local_i, sig in enumerate(sig_list_used):
                            t1_hex = sig.get("T1_hex", "")
                            orig_index = selected_indices[local_i] if subset_used else local_i
                            t1_map.setdefault(t1_hex, []).append(orig_index)

                        sybil_groups = []
                        sybil_dropped_local = set()
                        sybil_kept_local = []

                        seen_t1 = set()
                        for local_i, sig in enumerate(sig_list_used):
                            t1_hex = sig.get("T1_hex", "")
                            if t1_hex in seen_t1:
                                sybil_dropped_local.add(local_i)
                            else:
                                seen_t1.add(t1_hex)
                                sybil_kept_local.append(local_i)

                        for t1_hex, orig_list in t1_map.items():
                            if len(orig_list) > 1:
                                sybil_groups.append({
                                    "t1_hex_prefix": t1_hex[:16],
                                    "original_indices": sorted(orig_list),
                                    "count": len(orig_list)
                                })

                        sybil_detected = len(sybil_groups) > 0

                        filtered_sig_list_used = [sig_list_used[i] for i in sybil_kept_local]

                        kept_original_indices = [
                            (selected_indices[i] if subset_used else i) for i in sybil_kept_local
                        ]
                        dropped_original_indices = [
                            (selected_indices[i] if subset_used else i) for i in sorted(sybil_dropped_local)
                        ]

                        if sybil_detected:
                            print(f"[!] {addr[0]}:{addr[1]} -> Sybil detected: "
                                  f"{len(sybil_groups)} group(s); dropped {len(dropped_original_indices)} duplicate(s).")

                        if not filtered_sig_list_used:
                            out = {
                                "ok": False,
                                "error": "All signatures dropped due to Sybil (duplicate T1) filter.",
                                "sybil_detected": True,
                                "sybil_groups": sybil_groups,
                                "sybil_dropped_indices": dropped_original_indices,
                                "sybil_kept_indices": kept_original_indices,
                                "count": 0,
                                "original_count": total_received,
                                "subset_used": subset_used,
                                "selected_indices": selected_indices if subset_used else None,
                                "verifier_end_ns": time.time_ns()
                            }
                            _send_json(conn, out)
                            print(f"[!] {addr[0]}:{addr[1]} -> all signatures filtered out by Sybil rule.")
                            continue
                        # -------- END Sybil detection --------

                        t_all_start = time.time()
                        res = verify_batch_split(gpk, filtered_sig_list_used)

                        # Add friendly millisecond fields
                        res["part1_ms"] = round(res.get("time_part1_sec", 0.0) * 1000.0, 3)
                        res["part2_ms"] = round(res.get("time_part2_sec", 0.0) * 1000.0, 3)
                        res["verify_time_ms"] = round(res.get("total_verify_time_sec", 0.0) * 1000.0, 3)

                        # If pairing batch verification failed, run individual verification for each signature in the USED & FILTERED subset
                        if res.get("part2") is False:
                            print(f"[!] {addr[0]}:{addr[1]} -> batch pairing failed; "
                                  f"falling back to individual verification of {len(filtered_sig_list_used)} signatures.")
                            individual_results = []
                            individual_times_ms = []
                            all_ok = True
                            for kept_pos, sig in enumerate(filtered_sig_list_used):
                                orig_index = kept_original_indices[kept_pos]
                                t_ind = time.time()
                                try:
                                    ok_i = ARA_Verify(gpk, sig)
                                except Exception:
                                    ok_i = False
                                dt_ms = (time.time() - t_ind) * 1000.0
                                individual_times_ms.append(round(dt_ms, 3))
                                individual_results.append({"index": orig_index, "ok": bool(ok_i)})
                                all_ok = all_ok and ok_i

                            res["fallback_individual"] = True
                            res["individual_results"] = individual_results
                            res["individual_verify_ms"] = individual_times_ms
                            res["individual_verify_total_ms"] = round(sum(individual_times_ms), 3)
                            res["ok"] = bool(all_ok)

                        # Remap part1_results indexes to original indexes after both subset and Sybil filter
                        if "part1_results" in res:
                            remapped = []
                            for item in res["part1_results"]:
                                kept_pos = item.get("index", 0)  # index within filtered_sig_list_used
                                if 0 <= kept_pos < len(kept_original_indices):
                                    remapped.append({"index": kept_original_indices[kept_pos], "ok": bool(item.get("ok"))})
                            res["part1_results"] = remapped

                        # Augment with book-keeping fields (plus subset & Sybil info)
                        res["count"] = len(filtered_sig_list_used)
                        res["original_count"] = total_received
                        res["subset_used"] = subset_used
                        if subset_used:
                            res["selected_indices"] = selected_indices
                        res["sybil_detected"] = sybil_detected
                        if sybil_detected:
                            res["sybil_groups"] = sybil_groups
                            res["sybil_dropped_indices"] = dropped_original_indices
                            res["sybil_kept_indices"] = kept_original_indices

                        # NEW: Add replay attack info (not detected if we got here)
                        res["replay_attack_detected"] = False
                        if first_msg:
                            res["signature_timestamp"] = sig_ts
                            res["verifier_timestamp"] = ver_ts
                            res["age_seconds"] = age_sec
                            res["max_age_seconds"] = max_age

                        # Outer wall time for the whole batch handler
                        res["elapsed_sec"] = round(time.time() - t_all_start, 6)
                        res["verify_wall_ms"] = round(res["elapsed_sec"] * 1000.0, 3)

                        res["verifier_end_ns"] = time.time_ns()

                        _send_json(conn, res)
                        ok_count = sum(1 for r in res.get("part1_results", []) if r.get("ok"))
                        print(f"[+] {addr[0]}:{addr[1]} -> batch part1 {ok_count}/{res['count']} OK; "
                              f"part2={res.get('part2')} total_ok={res.get('ok')} | "
                              f"verify_time={res.get('verify_time_ms')} ms (wall={res.get('verify_wall_ms')} ms) "
                              f"(ts={sig_ts if first_msg else 'N/A'}, age={age_sec if first_msg else 'N/A'}s, "
                              f"subset_used={subset_used}, original_count={total_received}, "
                              f"sybil_detected={sybil_detected}, dropped={len(dropped_original_indices)})")
                        continue

                    _send_json(conn, {"ok": False, "error": f"Unsupported payload type: {ptype}",
                                      "verifier_end_ns": time.time_ns()})

                except Exception as e:
                    try:
                        _send_json(conn, {"ok": False, "error": str(e), "verifier_end_ns": time.time_ns()})
                    except Exception:
                        pass
                    print(f"[!] Error processing connection from {addr}: {e}")

if __name__ == "__main__":
    main()