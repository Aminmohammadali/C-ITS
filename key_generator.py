from bplib import bp
from bplib.bp import BpGroup
from petlib.bn import Bn
import pickle

# Initialize bilinear pairing group
G = BpGroup()
p_bn = G.order()

def ARA_Setup():
    """
    Setup phase: Generate group public key (gpk) and group manager secret key (gmsk)
    """
    # Define bilinear groups G1, G2, GT
    g1 = G.gen1()
    g2 = G.gen2()
    
    # Choose random scalars gamma, eta1 ∈ Zp*
    gamma = Bn.random(p_bn) + 1
    eta1 = Bn.random(p_bn) + 1
    
    # Choose random elements h, h1 ∈ G1
    h = g1 * eta1
    h1 = G.gen1()
    
    # Calculate w = g2^gamma and Y = h^gamma
    w = g2 * gamma
    Y = h * gamma
    
    # Convert to bytes for serialization
    g1_bytes = g1.export()
    g2_bytes = g2.export()
    h_bytes = h.export()
    h1_bytes = h1.export()
    w_bytes = w.export()
    Y_bytes = Y.export()

    # Group public key (PUBLIC)
    gpk = {
        'g1': g1,
        'g2': g2,
        'h': h,
        'h1': h1,
        'Y': Y,
        'w': w
    }

    # Group Manager Secret key (SECRET)
    gmsk = {
        'eta1': eta1,
        'gamma': gamma
    }

    # Public bytes (for saving)
    gpk_bytes = {
        'g1_bytes': g1_bytes,
        'g2_bytes': g2_bytes,
        'h1_bytes': h1_bytes,
        'Y_bytes': Y_bytes,
        'h_bytes': h_bytes,
        'w_bytes': w_bytes
    }

    # ✅ NEW: print keys for inspection
    print("\n=== Group Public Key (gpk) ===")
    for key, val in gpk.items():
        print(f"{key}: {val}")

    print("\n=== Group Manager Secret Key (gmsk) ===")
    print(f"eta1: {eta1}")
    print(f"gamma: {gamma}")
    print()

    return gpk, gmsk, gpk_bytes


def save_keys_to_files(gpk, gmsk, gpk_bytes):
    """Save keys to files and immediately clear them from memory"""
    with open('public_params.pkl', 'wb') as f:
        pickle.dump(gpk_bytes, f)
    print("[✓] Public parameters saved to 'public_params.pkl'")
    
    secret_data = {
        'gmsk': {
            'eta1': int(gmsk['eta1']),
            'gamma': int(gmsk['gamma'])
        },
        'gpk': {
            'g1_bytes': gpk['g1'].export(),
            'g2_bytes': gpk['g2'].export(),
            'h_bytes': gpk['h'].export(),
            'h1_bytes': gpk['h1'].export(),
            'Y_bytes': gpk['Y'].export(),
            'w_bytes': gpk['w'].export()
        }
    }
    with open('secret_keys.pkl', 'wb') as f:
        pickle.dump(secret_data, f)
    print("[✓] Secret keys saved to 'secret_keys.pkl'")
    
    del gpk, gmsk, secret_data
    print("[✓] Secret parameters cleared from memory")


if __name__ == "__main__":
    print("=" * 50)
    print("   ARA+ Key Generator")
    print("=" * 50)
    print()

    print("[*] Generating ARA+ system parameters...")
    gpk, gmsk, gpk_bytes = ARA_Setup()
    print("[✓] System parameters generated successfully")
    print()

    print("[*] Saving keys to files...")
    save_keys_to_files(gpk, gmsk, gpk_bytes)
    print()
    
    print("=" * 50)
    print("Files Created:")
    print("=" * 50)
    print("1. public_params.pkl  → Contains: g1, g2, h, h1, Y, w")
    print("2. secret_keys.pkl   → Contains: gamma, eta1 (SENSITIVE!)")
    print("=" * 50)
    print()
    print("[!] SECURITY NOTES:")
    print("    • secret_keys.pkl must NEVER leave the key issuer server")
    print("    • public_params.pkl can be freely distributed")
    print("    • These keys will be used for ALL user registrations")
    print()
    print("[✓] Key generation complete!")
    print("    Next step: Run key_issuer_server.py to start issuing credentials")
