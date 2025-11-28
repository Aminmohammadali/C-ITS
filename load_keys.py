from bplib import bp
from bplib.bp import BpGroup
from petlib.bn import Bn
import pickle

# Initialize the bilinear pairing group
G = BpGroup()
p = G.order()

def load_keys():
    """Load gpk (public) and gmsk (secret) from generated files"""

    # --- Load public parameters ---
    with open("public_params.pkl", "rb") as f:
        gpk_bytes = pickle.load(f)

    # Reconstruct elliptic curve elements from bytes
    gpk = {
        "g1": bp.G1Elem.from_bytes(gpk_bytes["g1_bytes"], G),
        "g2": bp.G2Elem.from_bytes(gpk_bytes["g2_bytes"], G),
        "h":  bp.G1Elem.from_bytes(gpk_bytes["h_bytes"],  G),
        "h1": bp.G1Elem.from_bytes(gpk_bytes["h1_bytes"], G),
        "Y":  bp.G1Elem.from_bytes(gpk_bytes["Y_bytes"],  G),
        "w":  bp.G2Elem.from_bytes(gpk_bytes["w_bytes"],  G)
    }

    # --- Load secret manager keys ---
    with open("secret_keys.pkl", "rb") as f:
        secret_data = pickle.load(f)

    eta1 = Bn(secret_data["gmsk"]["eta1"])
    gamma = Bn(secret_data["gmsk"]["gamma"])

    gmsk = {"eta1": eta1, "gamma": gamma}

    return gpk, gmsk
