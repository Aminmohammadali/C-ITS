from bplib import bp
from bplib.bp import BpGroup
from petlib.bn import Bn
import pickle
import hashlib

# ---------------------------
# Pretty printing helpers
# ---------------------------

def _fp(b: bytes) -> str:
    return hashlib.sha256(b).hexdigest()[:16]

def _show_point(name: str, P):
    b = P.export()
    print(f"{name}: {P.__class__.__name__} len={len(b)} hex={b.hex()} sha256={_fp(b)}…")

def _show_bn(name: str, x: Bn):
    b = x.binary()
    print(f"{name}: bits={x.num_bits()} len={len(b)} hex={b.hex()}")

# ---------------------------
# Robust converters
# ---------------------------

def _bn(v) -> Bn:
    """
    Accept Bn | bytes | int | str (decimal or '0x..' hex) and return Bn.
    This avoids the petlib Bn(int) upper-bound trap.
    """
    if isinstance(v, Bn):
        return v
    if isinstance(v, bytes):
        return Bn.from_binary(v)
    if isinstance(v, int):
        bl = max(1, (v.bit_length() + 7) // 8)
        return Bn.from_binary(v.to_bytes(bl, "big"))
    if isinstance(v, str):
        s = v.strip().lower()
        if s.startswith("0x"):
            return Bn.from_binary(bytes.fromhex(s[2:]))
        # assume decimal
        return Bn.from_decimal(s)
    raise TypeError(f"Unsupported type for Bn: {type(v)}")

# ---------------------------
# Globals
# ---------------------------

G = BpGroup()
p = G.order()

# ---------------------------
# Load keys (compatible with old & new pickles)
# ---------------------------

def load_keys():
    """
    Expected secret_keys.pkl shapes (any of these is OK):

    Old style you used earlier:
      {
        'gmsk': {'eta1': <int>, 'gamma': <int>},
        'gpk' : {'g1_bytes', 'g2_bytes', 'h_bytes', 'h1_bytes', 'Y_bytes', 'w_bytes'}  # optional
      }

    Newer/safer style (binary):
      {
        'gmsk': {'eta1_bin': <bytes>, 'gamma_bin': <bytes>, 'eta2_bin': <bytes>?},
        'gpk' : same '..._bytes' dict as above
      }
    """
    with open("secret_keys.pkl", "rb") as f:
        secret = pickle.load(f)

    gmsk_raw = secret.get("gmsk", {})
    gpk_raw  = secret.get("gpk",  {})

    # Secrets (handle bytes/int/str)
    eta1  = _bn(gmsk_raw.get("eta1_bin", gmsk_raw.get("eta1")))
    gamma = _bn(gmsk_raw.get("gamma_bin", gmsk_raw.get("gamma")))
    eta2v = gmsk_raw.get("eta2_bin", gmsk_raw.get("eta2"))
    eta2  = _bn(eta2v) if eta2v is not None else None

    # Generators
    g1 = G.gen1()
    g2 = G.gen2()

    # Public points: prefer restoring from bytes if available
    if gpk_raw.get("h_bytes"):
        h = bp.G1Elem.from_bytes(gpk_raw["h_bytes"], G)
    else:
        h = g1 * eta1

    if gpk_raw.get("h1_bytes"):
        h1 = bp.G1Elem.from_bytes(gpk_raw["h1_bytes"], G)
    else:
        if eta2 is None:
            raise ValueError("Need either 'h1_bytes' in secret['gpk'] or 'eta2' in secret['gmsk'] to reconstruct an independent h1.")
        h1 = g1 * eta2  # independent h1

    if gpk_raw.get("w_bytes"):
        w = bp.G2Elem.from_bytes(gpk_raw["w_bytes"], G)
    else:
        w = g2 * gamma

    if gpk_raw.get("Y_bytes"):
        Y = bp.G1Elem.from_bytes(gpk_raw["Y_bytes"], G)
    else:
        Y = h * gamma

    # Quick subgroup sanity
    O1 = g1 * 0
    assert h  * p == O1,  "h not in subgroup"
    assert h1 * p == O1,  "h1 not in subgroup"
    assert Y  * p == O1,  "Y not in subgroup"
    assert w  * p == g2 * 0, "w not in subgroup"

    gpk  = {"g1": g1, "g2": g2, "h": h, "h1": h1, "Y": Y, "w": w}
    gmsk = {"eta1": eta1, "gamma": gamma}
    if eta2 is not None:
        gmsk["eta2"] = eta2
    return gpk, gmsk

# ---------------------------
# Join (issue member secret)
# ---------------------------

def ARA_Join(gpk, gmsk):
    """
    Issue (A_i, x_i, y_i) in transport form.
      A_i = (g1 - y_i * h1) * (gamma + x_i)^{-1}  in G1
    """
    g1  = gpk["g1"]
    h1  = gpk["h1"]
    gamma = gmsk["gamma"]

    # Sample x_i, y_i in [1, p-1]
    def rand_scalar(mod=p):
        return Bn.random(mod - 1) + 1

    x_i = rand_scalar()
    y_i = rand_scalar()

    temp = (gamma + x_i) % p
    temp_inv = temp.mod_inverse(p)   # inverse in Zp

    A_i = temp_inv * (g1 + (h1 * (-y_i)))

    # Return transport-friendly dict (bytes)
    return {
        "A_i_bytes": A_i.export(),
        "x_i_bytes": x_i.binary(),
        "y_i_bytes": y_i.binary(),
    }

# ---------------------------
# Main
# ---------------------------

if __name__ == "__main__":
    print("[*] Loading system parameters...")
    gpk, gmsk = load_keys()
    print("[✓] Keys loaded successfully\n")

    print("=== Group Public Key (actual compressed hex) ===")
    _show_point("g1", gpk["g1"])
    _show_point("g2", gpk["g2"])
    _show_point("h ", gpk["h"])
    _show_point("h1", gpk["h1"])
    _show_point("Y ", gpk["Y"])
    _show_point("w ", gpk["w"])

    print("\n=== Group Manager Secret Key (binary) ===")
    _show_bn("eta1", gmsk["eta1"])
    _show_bn("gamma", gmsk["gamma"])
    if "eta2" in gmsk:
        _show_bn("eta2", gmsk["eta2"])
    print()

    print("[*] Issuing member secret...")
    gsk_i_bytes = ARA_Join(gpk, gmsk)
    print("[✓] User key issued\n")

    print("=== gsk_i_bytes (copy/paste friendly) ===")
    print("A_i_bytes =", gsk_i_bytes["A_i_bytes"].hex())
    print("x_i_bytes =", gsk_i_bytes["x_i_bytes"].hex())
    print("y_i_bytes =", gsk_i_bytes["y_i_bytes"].hex())
