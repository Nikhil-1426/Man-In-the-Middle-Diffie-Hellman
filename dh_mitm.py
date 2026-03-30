import tkinter as tk
from tkinter import scrolledtext, ttk
import random
import time
import hashlib
import hmac as hmac_lib
import threading
import math
import matplotlib
matplotlib.use("TkAgg")
import matplotlib.pyplot as plt
import matplotlib.gridspec as gridspec

# ================================================================
# =====================  MATH / CRYPTO  ==========================
# ================================================================

def is_prime(n, k=5):
    if n < 2: return False
    if n in (2, 3): return True
    if n % 2 == 0: return False
    d, r = n - 1, 0
    while d % 2 == 0:
        d //= 2; r += 1
    for _ in range(k):
        a = random.randrange(2, n - 1)
        x = pow(a, d, n)
        if x in (1, n - 1): continue
        for _ in range(r - 1):
            x = pow(x, 2, n)
            if x == n - 1: break
        else:
            return False
    return True


def generate_safe_prime(bits):
    while True:
        q = random.getrandbits(bits - 1)
        q |= (1 << (bits - 2)) | 1
        if not is_prime(q): continue
        p = 2 * q + 1
        if is_prime(p): return p, q


def find_generator(p, q):
    for g in range(2, 200):
        if pow(g, 2, p) != 1 and pow(g, q, p) != 1:
            return g
    raise ValueError("No generator found")


def dh_public(g, p, priv):
    return pow(g, priv, p)


def dh_shared(pub, priv, p):
    return pow(pub, priv, p)


# ================================================================
# ===========  PREVENTION 1: ELGAMAL SIGNATURE  =================
# ================================================================
# Each party has a long-term ElGamal key pair.
# They sign their DH public key before sending.
# Nischay substitutes a fake key but CANNOT produce a valid
# ElGamal signature without the sender's long-term private key.
# Receiver verifies signature → forgery detected → MITM blocked.
#
# Sign:   r = g^k mod p,  s = k^{-1}(m - x*r) mod (p-1)
# Verify: g^m ≡ y^r * r^s (mod p)

def elgamal_keygen(p, g, q):
    """Long-term signing key pair."""
    x = random.randint(2, p - 2)   # private
    y = pow(g, x, p)               # public
    return x, y


def elgamal_sign(msg_int, p, g, q, x):
    modulus = p - 1
    m = msg_int % modulus
    for _ in range(2000):
        k = random.randint(2, modulus - 1)
        if math.gcd(k, modulus) != 1:
            continue
        k_inv = pow(k, -1, modulus)
        r = pow(g, k, p)
        if r == 0:
            continue
        s = (k_inv * (m - x * r)) % modulus
        if s == 0:
            continue
        return r, s
    return 1, 1   # fallback (extremely unlikely)


def elgamal_verify(msg_int, r, s, p, g, q, y):
    if not (0 < r < p and 0 <= s < (p - 1)):
        return False
    m   = msg_int % (p - 1)
    lhs = pow(g, m, p)
    rhs = (pow(y, r, p) * pow(r, s, p)) % p
    return lhs == rhs


# ================================================================
# ===========  PREVENTION 2: SHA-256 BINDING  ===================
# ================================================================
# Each party commits to their DH public key:
#   commitment = SHA-256(DH_public_key || identity)
# They send (DH_pub, commitment) together.
# Nischay replaces DH_pub with fake_key, but the hash of fake_key
# won't match the original commitment → detected.

def sha256_commit(dh_pub: int, identity: str) -> str:
    return hashlib.sha256((str(dh_pub) + "||" + identity).encode()).hexdigest()


def sha256_verify(dh_pub: int, identity: str, commitment: str) -> bool:
    return sha256_commit(dh_pub, identity) == commitment


# ================================================================
# ===========  PREVENTION 3: HMAC AUTHENTICATION  ===============
# ================================================================
# Alice and Bob share a pre-shared secret (PSK) out-of-band.
# Every public key transmission carries:
#   tag = HMAC-SHA256(PSK, DH_pub || identity)
# Nischay doesn't know PSK → cannot compute valid HMAC for
# the forged key → receiver rejects it → MITM blocked.

def hmac_tag(dh_pub: int, identity: str, psk: bytes) -> str:
    data = (str(dh_pub) + "||" + identity).encode()
    return hmac_lib.new(psk, data, hashlib.sha256).hexdigest()


def hmac_verify_tag(dh_pub: int, identity: str, psk: bytes, tag: str) -> bool:
    return hmac_lib.compare_digest(hmac_tag(dh_pub, identity, psk), tag)


# ================================================================
# =========================  COLORS  =============================
# ================================================================

C = {
    "bg":      "#0d1117",
    "panel":   "#161b22",
    "border":  "#21262d",
    "red":     "#da3633",
    "green":   "#3fb950",
    "orange":  "#d29922",
    "blue":    "#1f6feb",
    "purple":  "#8957e5",
    "cyan":    "#39d0d8",
    "text":    "#c9d1d9",
    "subtext": "#6e7681",
    "alice":   "#1a3a52",
    "bob":     "#1a3a52",
    "nischay": "#4a1010",
}


# ================================================================
# =========================  GUI APP  ============================
# ================================================================

class DHMITMApp:

    def __init__(self, root: tk.Tk):
        self.root = root
        self.root.title("DH MITM Attack & Prevention — Nischay")
        self.root.geometry("1360x820")
        self.root.configure(bg=C["bg"])
        self.root.resizable(True, True)

        self.p = self.g = self.q = None
        self.a = self.b = self.A = self.B = None

        self.bits_var = tk.IntVar(value=256)
        self.mitm_var = tk.BooleanVar(value=False)
        self.prev_var = tk.StringVar(value="ElGamal Signature")

        self.param_times  = {256: [], 512: [], 768: []}
        self.test_results = []

        self._build_ui()

    # ------------------------------------------------------------------ #
    #                           UI                                       #
    # ------------------------------------------------------------------ #

    def _build_ui(self):
        left = tk.Frame(self.root, bg=C["panel"], width=262)
        left.pack(side=tk.LEFT, fill=tk.Y, padx=(10, 5), pady=10)
        left.pack_propagate(False)

        self._lbl(left, "DH MITM VISUALIZER", 12, bold=True,
                  fg=C["blue"]).pack(pady=(16, 2))
        self._lbl(left, "MITM Attack  |  3 Prevention Methods",
                  8, fg=C["subtext"]).pack(pady=(0, 12))

        self._lbl(left, "Key Size (bits)", 9, fg=C["subtext"]).pack()
        ttk.Combobox(left, textvariable=self.bits_var,
                     values=[256, 512, 768], width=16,
                     state="readonly").pack(pady=(2, 10))

        self._lbl(left, "Prevention Method", 9, fg=C["subtext"]).pack()
        ttk.Combobox(left, textvariable=self.prev_var,
                     values=["ElGamal Signature", "SHA-256 Binding", "HMAC Auth"],
                     width=20, state="readonly").pack(pady=(2, 12))

        for label, cmd in [
            ("⚙️  Generate Parameters",     self._thread(self._generate_params)),
            ("🔑  Generate Public Keys",     self._thread(self._generate_public)),
            ("📤  Send Alice → Bob",         self._thread(self._send_keys)),
            ("🛡️  Apply Prevention (Demo)",  self._thread(self._apply_prevention)),
            ("🔁  Run 25 Attack Tests",      self._thread(self._run_attack_tests)),
            ("🔒  Run 25 Prevention Tests",  self._thread(self._run_prevention_tests)),
            ("📊  Show Graphs",              self._show_graphs),
            ("🗑️  Clear Log",                self._clear_log),
        ]:
            tk.Button(left, text=label, command=cmd,
                      bg=C["border"], fg=C["text"], relief=tk.FLAT,
                      activebackground=C["blue"], activeforeground="white",
                      font=("Consolas", 9), cursor="hand2",
                      padx=8, pady=5, anchor="w").pack(fill=tk.X, padx=8, pady=2)

        tk.Checkbutton(
            left, text="🕵  MITM Active (Nischay)",
            variable=self.mitm_var, onvalue=True, offvalue=False,
            command=self._on_mitm_toggle,
            bg=C["panel"], fg=C["text"], selectcolor=C["nischay"],
            activebackground=C["panel"], activeforeground=C["text"],
            font=("Consolas", 9), cursor="hand2"
        ).pack(anchor="w", padx=10, pady=(10, 4))

        self.status_lbl = tk.Label(left, text="● Idle",
                                   font=("Consolas", 11, "bold"),
                                   bg=C["panel"], fg=C["subtext"])
        self.status_lbl.pack(pady=12)

        self.progress = ttk.Progressbar(left, length=210, mode="determinate")
        self.progress.pack(padx=8, pady=2)
        self.prog_lbl = tk.Label(left, text="", bg=C["panel"],
                                 fg=C["subtext"], font=("Consolas", 8))
        self.prog_lbl.pack()

        right = tk.Frame(self.root, bg=C["bg"])
        right.pack(side=tk.RIGHT, fill=tk.BOTH, expand=True, padx=(5, 10), pady=10)

        self.canvas = tk.Canvas(right, height=195, bg=C["panel"], highlightthickness=0)
        self.canvas.pack(fill=tk.X, pady=(0, 5))
        self._draw_network()

        self._lbl(right, "EXECUTION LOG", 9, fg=C["subtext"],
                  anchor="w", bg=C["bg"]).pack(fill=tk.X)
        self.logbox = scrolledtext.ScrolledText(
            right, bg=C["panel"], fg=C["text"],
            font=("Consolas", 9), insertbackground=C["text"],
            relief=tk.FLAT, borderwidth=0, padx=10, pady=8
        )
        self.logbox.pack(fill=tk.BOTH, expand=True, pady=(2, 0))

        for tag, fg in [("ok",     C["green"]),  ("warn",   C["orange"]),
                        ("danger", C["red"]),    ("header", C["blue"]),
                        ("secure", C["cyan"]),   ("purple", C["purple"]),
                        ("dim",    C["subtext"])]:
            self.logbox.tag_config(tag, foreground=fg)

        s = ttk.Style(); s.theme_use("default")
        s.configure("TCombobox", fieldbackground=C["border"],
                    background=C["border"], foreground=C["text"])

    # ------------------------------------------------------------------ #
    #                        NETWORK CANVAS                              #
    # ------------------------------------------------------------------ #

    def _draw_network(self):
        self.canvas.update_idletasks()
        W    = max(self.canvas.winfo_width(), 860)
        mitm = self.mitm_var.get()
        self.canvas.delete("all")

        ax, ay = 130, 95
        bx, by = W - 130, 95
        nx, ny = W // 2, 155

        def node(x, y, emoji, label, fill, outline):
            self.canvas.create_oval(x-54, y-38, x+54, y+38,
                                    fill=fill, outline=outline, width=2)
            self.canvas.create_text(x, y - 6, text=emoji, font=("Arial", 20))
            self.canvas.create_text(x, y + 20, text=label,
                                    font=("Consolas", 9, "bold"), fill=outline)

        node(ax, ay, "👩", "Alice",           C["alice"],   C["green"])
        node(bx, by, "👨", "Bob",             C["bob"],     C["green"])

        if mitm:
            node(nx, ny, "🕵", "Nischay (MITM)", C["nischay"], C["red"])
            self.canvas.create_line(ax+54, ay, nx-54, ny, arrow=tk.LAST,
                                    width=2, fill=C["red"], dash=(5, 3))
            self.canvas.create_line(nx+54, ny, bx-54, by, arrow=tk.LAST,
                                    width=2, fill=C["red"], dash=(5, 3))
            self.canvas.create_text(W//2, 26,
                                    text="⚠  MITM ACTIVE — Nischay intercepts all traffic",
                                    font=("Consolas", 10, "bold"), fill=C["red"])
        else:
            self.canvas.create_line(ax+54, ay, bx-54, by, arrow=tk.LAST,
                                    width=2, fill=C["green"])
            self.canvas.create_text(W//2, 26,
                                    text="✔  Secure Direct Channel — No MITM",
                                    font=("Consolas", 10, "bold"), fill=C["green"])

    # ------------------------------------------------------------------ #
    #                           HELPERS                                  #
    # ------------------------------------------------------------------ #

    def _lbl(self, parent, text, size=10, bold=False, fg=None, bg=None, **kw):
        return tk.Label(parent, text=text,
                        font=("Consolas", size, "bold" if bold else "normal"),
                        bg=bg or C["panel"], fg=fg or C["text"], **kw)

    def _thread(self, fn):
        return lambda: threading.Thread(target=fn, daemon=True).start()

    def _log(self, msg, tag=""):
        self.logbox.insert(tk.END, msg + "\n", tag)
        self.logbox.see(tk.END)
        self.root.update_idletasks()

    def _clear_log(self):
        self.logbox.delete("1.0", tk.END)

    def _set_status(self, text, color):
        self.status_lbl.config(text=f"● {text}", fg=C[color])

    def _set_progress(self, val, total, label=""):
        self.progress["value"] = int(val / total * 100) if total else 0
        self.prog_lbl.config(text=label or f"{val}/{total}")
        self.root.update_idletasks()

    def _on_mitm_toggle(self):
        self._draw_network()
        if self.mitm_var.get():
            self._set_status("MITM ENABLED", "red")
            self._log("\n⚠  Nischay (MITM) is now ACTIVE.", "warn")
        else:
            self._set_status("MITM Off", "green")
            self._log("\n✔  MITM disabled.", "ok")

    def _sep(self, ch="═", n=66, tag="header"):
        self._log(ch * n, tag)

    # ------------------------------------------------------------------ #
    #                     GENERATE PARAMETERS                            #
    # ------------------------------------------------------------------ #

    def _generate_params(self):
        bits = self.bits_var.get()
        self._set_status("Generating…", "orange")
        self._sep()
        self._log(f"  GENERATE DH PARAMETERS  ({bits}-bit safe prime)", "header")
        self._sep()
        t0 = time.time()
        try:
            self.p, self.q = generate_safe_prime(bits)
            self.g = find_generator(self.p, self.q)
        except Exception as e:
            self._log(f"  [ERROR] {e}", "danger")
            self._set_status("Error", "red"); return
        elapsed = time.time() - t0
        self.param_times.setdefault(bits, []).append(elapsed)
        self._log(f"  Bits : {bits}", "dim")
        self._log(f"  p    = {str(self.p)[:72]}…", "dim")
        self._log(f"  q    = {str(self.q)[:72]}…", "dim")
        self._log(f"  g    = {self.g}", "dim")
        self._log(f"  Time : {elapsed:.4f}s", "ok")
        self._set_status("Params Ready", "green")

    # ------------------------------------------------------------------ #
    #                     GENERATE PUBLIC KEYS                           #
    # ------------------------------------------------------------------ #

    def _generate_public(self):
        if not self.p:
            self._log("  [!] Generate parameters first.", "warn"); return
        bits = self.bits_var.get()
        self.a = random.getrandbits(bits - 2)
        self.b = random.getrandbits(bits - 2)
        self.A = dh_public(self.g, self.p, self.a)
        self.B = dh_public(self.g, self.p, self.b)
        self._sep("─")
        self._log("  PUBLIC KEY GENERATION", "header")
        self._sep("─")
        self._log(f"  [ALICE]  a (private) = {str(self.a)[:56]}…", "dim")
        self._log(f"           A (public)  = {str(self.A)[:56]}…", "ok")
        self._log(f"  [BOB]    b (private) = {str(self.b)[:56]}…", "dim")
        self._log(f"           B (public)  = {str(self.B)[:56]}…", "ok")
        self._set_status("Keys Ready", "green")

    # ------------------------------------------------------------------ #
    #                       MANUAL KEY EXCHANGE                          #
    # ------------------------------------------------------------------ #

    def _send_keys(self):
        if self.A is None:
            self._log("  [!] Generate public keys first.", "warn"); return
        mitm = self.mitm_var.get()
        bits = self.bits_var.get()
        self._sep("─")
        if mitm:
            self._log("  KEY EXCHANGE — MITM ACTIVE ⚠", "danger")
            self._sep("─")
            e1 = random.getrandbits(bits - 2)
            e2 = random.getrandbits(bits - 2)
            fake_A    = dh_public(self.g, self.p, e1)
            fake_B    = dh_public(self.g, self.p, e2)
            alice_key = dh_shared(fake_B, self.a, self.p)
            bob_key   = dh_shared(fake_A, self.b, self.p)
            nis_A     = dh_shared(self.A, e2, self.p)
            nis_B     = dh_shared(self.B, e1, self.p)
            ok = (alice_key == nis_A and bob_key == nis_B)
            self._log(f"  Alice's real A      = {str(self.A)[:52]}…", "ok")
            self._log(f"  Nischay sends Bob fake_A = {str(fake_A)[:52]}…", "danger")
            self._log(f"  Bob's real B        = {str(self.B)[:52]}…", "ok")
            self._log(f"  Nischay sends Alice fake_B = {str(fake_B)[:52]}…", "danger")
            self._log(f"  Alice shared key    = {str(alice_key)[:52]}…", "warn")
            self._log(f"  Bob   shared key    = {str(bob_key)[:52]}…", "warn")
            self._log(f"  Nischay↔Alice key   = {str(nis_A)[:52]}…", "danger")
            self._log(f"  Nischay↔Bob key     = {str(nis_B)[:52]}…", "danger")
            self._log(f"  alice_key == nis_A  : {alice_key == nis_A}")
            self._log(f"  bob_key   == nis_B  : {bob_key   == nis_B}")
            self._log(f"\n  ► MITM SUCCESS = {ok}", "danger" if ok else "warn")
            self._set_status("VULNERABLE" if ok else "MITM Failed",
                             "red" if ok else "orange")
        else:
            self._log("  KEY EXCHANGE — Secure Direct Channel", "ok")
            self._sep("─")
            alice_key = dh_shared(self.B, self.a, self.p)
            bob_key   = dh_shared(self.A, self.b, self.p)
            ok = alice_key == bob_key
            self._log(f"  Alice key = {str(alice_key)[:60]}…")
            self._log(f"  Bob   key = {str(bob_key)[:60]}…")
            self._log(f"\n  ► Shared secret match = {ok}", "ok" if ok else "danger")
            self._set_status("SECURE", "green")
        self._draw_network()

    # ------------------------------------------------------------------ #
    #                    MANUAL PREVENTION DEMO                          #
    # ------------------------------------------------------------------ #

    def _apply_prevention(self):
        if not self.p:
            self._log("  [!] Generate parameters first.", "warn"); return
        method = self.prev_var.get()
        bits   = self.bits_var.get()

        a  = random.getrandbits(bits - 2)
        b  = random.getrandbits(bits - 2)
        A  = dh_public(self.g, self.p, a)
        B  = dh_public(self.g, self.p, b)
        e1 = random.getrandbits(bits - 2)
        e2 = random.getrandbits(bits - 2)
        fake_A = dh_public(self.g, self.p, e1)
        fake_B = dh_public(self.g, self.p, e2)

        self._sep()
        self._log(f"  PREVENTION DEMO — {method}", "secure")
        self._sep()
        self._log(f"  Real A (Alice) = {str(A)[:60]}…", "ok")
        self._log(f"  Real B (Bob)   = {str(B)[:60]}…", "ok")
        self._log(f"  fake_A (MITM)  = {str(fake_A)[:60]}…", "danger")
        self._log(f"  fake_B (MITM)  = {str(fake_B)[:60]}…", "danger")

        blocked = False

        if method == "ElGamal Signature":
            self._log("\n  How it works:", "dim")
            self._log("  • Alice signs her DH public key A using long-term private key.", "dim")
            self._log("  • Bob verifies the signature before accepting A.", "dim")
            self._log("  • Nischay cannot forge Alice's signature → fake_A rejected.\n", "dim")
            sx_a, sy_a = elgamal_keygen(self.p, self.g, self.q)
            sx_b, sy_b = elgamal_keygen(self.p, self.g, self.q)
            sig_A = elgamal_sign(A, self.p, self.g, self.q, sx_a)
            sig_B = elgamal_sign(B, self.p, self.g, self.q, sx_b)
            self._log(f"  Alice long-term public Y_A = {str(sy_a)[:50]}…", "dim")
            self._log(f"  Signature of A:  (r={str(sig_A[0])[:24]}…, s={str(sig_A[1])[:24]}…)", "purple")
            self._log(f"  Bob   long-term public Y_B = {str(sy_b)[:50]}…", "dim")
            self._log(f"  Signature of B:  (r={str(sig_B[0])[:24]}…, s={str(sig_B[1])[:24]}…)", "purple")
            v_real   = elgamal_verify(B,      sig_B[0], sig_B[1], self.p, self.g, self.q, sy_b)
            v_forged = elgamal_verify(fake_B, sig_B[0], sig_B[1], self.p, self.g, self.q, sy_b)
            self._log(f"\n  Verify real B with Y_B    = {v_real}", "ok")
            self._log(f"  Verify fake_B with Y_B    = {v_forged}", "danger")
            blocked = not v_forged

        elif method == "SHA-256 Binding":
            self._log("\n  How it works:", "dim")
            self._log("  • Commitment = SHA-256(DH_pub || identity)", "dim")
            self._log("  • Sent alongside the public key.", "dim")
            self._log("  • Nischay replaces DH_pub but hash won't match → detected.\n", "dim")
            commit_A = sha256_commit(A, "Alice")
            commit_B = sha256_commit(B, "Bob")
            self._log(f"  Commit(A) = {commit_A}", "purple")
            self._log(f"  Commit(B) = {commit_B}", "purple")
            v_real   = sha256_verify(B,      "Bob", commit_B)
            v_forged = sha256_verify(fake_B, "Bob", commit_B)
            self._log(f"\n  Verify real B vs Commit(B)    = {v_real}", "ok")
            self._log(f"  Verify fake_B vs Commit(B)    = {v_forged}", "danger")
            blocked = not v_forged

        elif method == "HMAC Auth":
            self._log("\n  How it works:", "dim")
            self._log("  • Alice & Bob share a Pre-Shared Key (PSK) out-of-band.", "dim")
            self._log("  • Tag = HMAC-SHA256(PSK, DH_pub || identity)", "dim")
            self._log("  • Nischay doesn't know PSK → HMAC on fake key fails.\n", "dim")
            psk = random.getrandbits(256).to_bytes(32, "big")
            self._log(f"  PSK     = {psk.hex()[:48]}…", "dim")
            tag_A = hmac_tag(A, "Alice", psk)
            tag_B = hmac_tag(B, "Bob",   psk)
            self._log(f"  HMAC(A) = {tag_A}", "purple")
            self._log(f"  HMAC(B) = {tag_B}", "purple")
            v_real   = hmac_verify_tag(B,      "Bob", psk, tag_B)
            v_forged = hmac_verify_tag(fake_B, "Bob", psk, tag_B)
            self._log(f"\n  Verify real B HMAC tag    = {v_real}", "ok")
            self._log(f"  Verify fake_B HMAC tag    = {v_forged}", "danger")
            blocked = not v_forged

        self._log(f"\n  ► MITM BLOCKED = {blocked}",
                  "secure" if blocked else "danger")
        self._set_status("SECURE" if blocked else "WARNING",
                         "green" if blocked else "red")

    # ------------------------------------------------------------------ #
    #                   25 DETAILED ATTACK TESTS                         #
    # ------------------------------------------------------------------ #

    def _run_attack_tests(self):
        self.test_results = [r for r in self.test_results if r.get("type") != "attack"]

        key_sizes = [256, 512, 768]
        counts    = {256: 9, 512: 8, 768: 8}
        total     = 25
        done      = 0

        self._sep()
        self._log(f"  RUNNING {total} AUTOMATED ATTACK TEST CASES", "header")
        self._log(f"  Key sizes: 256 / 512 / 768 bit  |  MITM always active", "header")
        self._sep()
        self._set_status("Attacking…", "orange")
        self._set_progress(0, total)

        for bits in key_sizes:
            self._log(f"\n  {'─'*26} KEY SIZE: {bits}-bit {'─'*26}", "header")
            t0 = time.time()
            try:
                p, q = generate_safe_prime(bits)
                g    = find_generator(p, q)
            except Exception as e:
                self._log(f"  [ERROR] {e}", "danger"); continue
            pt = time.time() - t0
            self.param_times[bits].append(pt)
            self._log(f"  p generated in {pt:.4f}s  |  g = {g}\n", "dim")

            for _ in range(counts[bits]):
                if done >= total: break
                done += 1

                t_start = time.time()
                a  = random.getrandbits(bits - 2)
                b  = random.getrandbits(bits - 2)
                A  = dh_public(g, p, a)
                B  = dh_public(g, p, b)
                e1 = random.getrandbits(bits - 2)
                e2 = random.getrandbits(bits - 2)
                fake_A    = dh_public(g, p, e1)
                fake_B    = dh_public(g, p, e2)
                alice_key = dh_shared(fake_B, a, p)
                bob_key   = dh_shared(fake_A, b, p)
                nis_A     = dh_shared(A, e2, p)
                nis_B     = dh_shared(B, e1, p)
                elapsed   = time.time() - t_start

                success = (alice_key == nis_A and bob_key == nis_B)

                self.test_results.append({
                    "bits": bits, "mitm_success": success,
                    "time": elapsed, "type": "attack"
                })
                self._set_progress(done, total, f"Attack {done}/{total}")

                # ── FULL DETAILED PRINT ────────────────────────────────
                self._log(f"  ┌──────────── TEST CASE {done:02d} (ATTACK) ── {bits}-bit ────────────────", "header")
                self._log(f"  │  p (first 60 digits)  = {str(p)[:60]}…", "dim")
                self._log(f"  │  g                    = {g}", "dim")
                self._log(f"  │", "dim")
                self._log(f"  │  Alice private  a     = {str(a)[:60]}…", "dim")
                self._log(f"  │  Alice public   A     = {str(A)[:60]}…", "ok")
                self._log(f"  │  Bob   private  b     = {str(b)[:60]}…", "dim")
                self._log(f"  │  Bob   public   B     = {str(B)[:60]}…", "ok")
                self._log(f"  │", "dim")
                self._log(f"  │  [NISCHAY intercepts A and B]", "danger")
                self._log(f"  │  Nischay ephemeral e1 = {str(e1)[:60]}…", "danger")
                self._log(f"  │  Nischay ephemeral e2 = {str(e2)[:60]}…", "danger")
                self._log(f"  │  fake_A = g^e1 mod p  = {str(fake_A)[:60]}…", "danger")
                self._log(f"  │  fake_B = g^e2 mod p  = {str(fake_B)[:60]}…", "danger")
                self._log(f"  │", "dim")
                self._log(f"  │  [KEYS COMPUTED]", "warn")
                self._log(f"  │  Alice computes (fake_B)^a mod p = {str(alice_key)[:52]}…", "warn")
                self._log(f"  │  Bob   computes (fake_A)^b mod p = {str(bob_key)[:52]}…",  "warn")
                self._log(f"  │  Nischay: A^e2 mod p (↔Alice)   = {str(nis_A)[:52]}…", "danger")
                self._log(f"  │  Nischay: B^e1 mod p (↔Bob)     = {str(nis_B)[:52]}…", "danger")
                self._log(f"  │", "dim")
                self._log(f"  │  alice_key == Nischay↔Alice : {alice_key == nis_A}")
                self._log(f"  │  bob_key   == Nischay↔Bob   : {bob_key   == nis_B}")
                self._log(f"  │  Elapsed time               : {elapsed:.6f}s")
                self._log(f"  └─► MITM SUCCESS = {success}",
                          "danger" if success else "warn")
                self._log("")

        atk = [r for r in self.test_results if r["type"] == "attack"]
        succ = sum(1 for r in atk if r["mitm_success"])
        rate = succ / len(atk) * 100 if atk else 0

        self._sep()
        self._log("  ATTACK SUMMARY", "header")
        self._sep()
        self._log(f"  Total tests      : {len(atk)}", "ok")
        self._log(f"  MITM successes   : {succ}",   "danger")
        self._log(f"  Attack success % : {rate:.1f}%",
                  "danger" if rate >= 90 else "warn")
        self._sep()
        self._log(f"  ✅ All {len(atk)} attack test cases completed.", "ok")
        self._set_status("Attacks Done", "red" if rate >= 90 else "orange")
        self._set_progress(len(atk), total, "Done")

    # ------------------------------------------------------------------ #
    #                  25 DETAILED PREVENTION TESTS                      #
    # ------------------------------------------------------------------ #

    def _run_prevention_tests(self):
        if not self.p:
            self._log("  [!] Generate parameters first.", "warn"); return

        # Remove old prevention results
        self.test_results = [r for r in self.test_results if r.get("type") != "prevention"]

        key_sizes = [256, 512, 768]
        counts    = {256: 9, 512: 8, 768: 8}
        total     = 25
        done      = 0

        blocked_count = {"ElGamal": 0, "SHA256": 0, "HMAC": 0}

        self._sep()
        self._log(f"  RUNNING {total} PREVENTION TEST CASES", "secure")
        self._log(f"  Preventions: ElGamal Signature | SHA-256 Binding | HMAC Auth", "secure")
        self._sep()
        self._set_status("Testing Prevention…", "orange")
        self._set_progress(0, total)

        for bits in key_sizes:
            self._log(f"\n  {'─'*26} KEY SIZE: {bits}-bit {'─'*26}", "secure")
            try:
                param_t0 = time.time()
                p, q = generate_safe_prime(bits)
                g    = find_generator(p, q)
            except Exception as e:
                self._log(f"  [ERROR] {e}", "danger"); continue
            self.param_times.setdefault(bits, []).append(time.time() - param_t0)

            # PSK for HMAC (shared between Alice & Bob, unknown to Nischay)
            psk = random.getrandbits(256).to_bytes(32, "big")
            self._log(f"  PSK (HMAC) = {psk.hex()[:40]}…", "dim")

            for _ in range(counts[bits]):
                if done >= total: break
                done += 1

                common_t0 = time.time()
                a  = random.getrandbits(bits - 2)
                b  = random.getrandbits(bits - 2)
                A  = dh_public(g, p, a)
                B  = dh_public(g, p, b)
                e1 = random.getrandbits(bits - 2)
                e2 = random.getrandbits(bits - 2)
                fake_A = dh_public(g, p, e1)
                fake_B = dh_public(g, p, e2)
                common_setup_time = time.time() - common_t0

                self._set_progress(done, total, f"Prev {done}/{total}")

                self._log(f"\n  ┌──────── TEST CASE {done:02d} (PREVENTION) ── {bits}-bit ──────────────", "secure")
                self._log(f"  │  Real A (Alice)  = {str(A)[:58]}…", "ok")
                self._log(f"  │  Real B (Bob)    = {str(B)[:58]}…", "ok")
                self._log(f"  │  fake_A (Nischay)= {str(fake_A)[:58]}…", "danger")
                self._log(f"  │  fake_B (Nischay)= {str(fake_B)[:58]}…", "danger")
                self._log(f"  │", "dim")

                # ── Prevention 1: ElGamal Signature ────────────────────
                t0 = time.time()
                sx_a, sy_a = elgamal_keygen(p, g, q)
                sx_b, sy_b = elgamal_keygen(p, g, q)
                sig_B      = elgamal_sign(B, p, g, q, sx_b)
                eg_ok_real = elgamal_verify(B,      sig_B[0], sig_B[1], p, g, q, sy_b)
                eg_ok_fake = elgamal_verify(fake_B, sig_B[0], sig_B[1], p, g, q, sy_b)
                eg_blocked = not eg_ok_fake
                eg_time    = common_setup_time + (time.time() - t0)
                if eg_blocked: blocked_count["ElGamal"] += 1

                self._log(f"  │  [ElGamal Sig]  sig_B = (r={str(sig_B[0])[:18]}…, s={str(sig_B[1])[:18]}…)", "purple")
                self._log(f"  │                 real B verifies  : {eg_ok_real}  |  fake_B verifies: {eg_ok_fake}", "dim")
                self._log(f"  │                 BLOCKED = {eg_blocked}   time={eg_time:.6f}s",
                          "secure" if eg_blocked else "danger")

                # ── Prevention 2: SHA-256 Binding ──────────────────────
                t0 = time.time()
                commit_B      = sha256_commit(B, "Bob")
                sha_ok_real   = sha256_verify(B,      "Bob", commit_B)
                sha_ok_fake   = sha256_verify(fake_B, "Bob", commit_B)
                sha_blk       = not sha_ok_fake
                sha_time      = common_setup_time + (time.time() - t0)
                if sha_blk: blocked_count["SHA256"] += 1

                self._log(f"  │  [SHA-256]      commit_B = {commit_B[:36]}…", "purple")
                self._log(f"  │                 real B matches   : {sha_ok_real}  |  fake_B matches : {sha_ok_fake}", "dim")
                self._log(f"  │                 BLOCKED = {sha_blk}   time={sha_time:.6f}s",
                          "secure" if sha_blk else "danger")

                # ── Prevention 3: HMAC Auth ─────────────────────────────
                t0 = time.time()
                tag_B          = hmac_tag(B, "Bob", psk)
                hmac_ok_real   = hmac_verify_tag(B,      "Bob", psk, tag_B)
                hmac_ok_fake   = hmac_verify_tag(fake_B, "Bob", psk, tag_B)
                hmac_blk       = not hmac_ok_fake
                hmac_time      = common_setup_time + (time.time() - t0)
                if hmac_blk: blocked_count["HMAC"] += 1

                self._log(f"  │  [HMAC Auth]    tag_B   = {tag_B[:36]}…", "purple")
                self._log(f"  │                 real B passes    : {hmac_ok_real}  |  fake_B passes  : {hmac_ok_fake}", "dim")
                self._log(f"  │                 BLOCKED = {hmac_blk}   time={hmac_time:.6f}s",
                          "secure" if hmac_blk else "danger")

                all_blocked = eg_blocked and sha_blk and hmac_blk
                self.test_results.append({
                    "bits": bits, "type": "prevention",
                    "eg_blocked":   eg_blocked,  "eg_time":   eg_time,
                    "sha_blocked":  sha_blk,     "sha_time":  sha_time,
                    "hmac_blocked": hmac_blk,    "hmac_time": hmac_time,
                })
                self._log(f"  └─► ALL 3 PREVENTED = {all_blocked}",
                          "secure" if all_blocked else "danger")
                self._log("")

        prev = [r for r in self.test_results if r["type"] == "prevention"]
        n    = max(len(prev), 1)
        eg_r  = blocked_count["ElGamal"] / n * 100
        sha_r = blocked_count["SHA256"]  / n * 100
        hm_r  = blocked_count["HMAC"]    / n * 100

        avg_eg   = sum(r["eg_time"]   for r in prev) / n
        avg_sha  = sum(r["sha_time"]  for r in prev) / n
        avg_hmac = sum(r["hmac_time"] for r in prev) / n

        self._sep()
        self._log("  PREVENTION SUMMARY", "secure")
        self._sep()
        self._log(f"  ElGamal Signature : {blocked_count['ElGamal']}/{n}  blocked  ({eg_r:.1f}%)  avg={avg_eg:.6f}s",   "secure")
        self._log(f"  SHA-256 Binding   : {blocked_count['SHA256']}/{n}  blocked  ({sha_r:.1f}%)  avg={avg_sha:.6f}s",  "secure")
        self._log(f"  HMAC Auth         : {blocked_count['HMAC']}/{n}  blocked  ({hm_r:.1f}%)  avg={avg_hmac:.6f}s",    "secure")
        self._sep()
        self._log(f"  ✅ All {n} prevention test cases completed.", "secure")
        self._set_status("Prevention Done", "green")
        self._set_progress(n, total, "Done")

    # ------------------------------------------------------------------ #
    #                           GRAPHS                                   #
    # ------------------------------------------------------------------ #

    def _show_graphs(self):
        atk  = [r for r in self.test_results if r.get("type") == "attack"]
        prev = [r for r in self.test_results if r.get("type") == "prevention"]

        if not atk and not prev:
            self._log("  [!] Run attack and/or prevention tests first.", "warn")
            return

        all_bits   = [256, 512, 768]
        param_avg  = {b: (sum(self.param_times[b]) / len(self.param_times[b])
                          if self.param_times[b] else 0) for b in all_bits}
        param_min  = {b: (min(self.param_times[b]) if self.param_times[b] else 0)
                          for b in all_bits}
        param_max  = {b: (max(self.param_times[b]) if self.param_times[b] else 0)
                          for b in all_bits}
        param_n    = {b: len(self.param_times[b]) for b in all_bits}

        # Attack stats
        atk_n    = max(len(atk), 1)
        atk_succ = sum(1 for r in atk if r["mitm_success"])
        atk_rate = atk_succ / atk_n * 100
        atk_times= [r["time"] for r in atk]
        rate_by_bit = {}
        for b in all_bits:
            sub = [r for r in atk if r["bits"] == b]
            rate_by_bit[b] = sum(1 for r in sub if r["mitm_success"]) / max(len(sub), 1) * 100

        # Prevention stats
        prev_n    = max(len(prev), 1)
        eg_rate   = sum(1 for r in prev if r["eg_blocked"])   / prev_n * 100
        sha_rate  = sum(1 for r in prev if r["sha_blocked"])  / prev_n * 100
        hmac_rate = sum(1 for r in prev if r["hmac_blocked"]) / prev_n * 100
        avg_eg_t  = sum(r["eg_time"]   for r in prev) / prev_n
        avg_sha_t = sum(r["sha_time"]  for r in prev) / prev_n
        avg_hm_t  = sum(r["hmac_time"] for r in prev) / prev_n
        avg_atk_t = sum(atk_times) / max(len(atk_times), 1)
        best_prev = max(eg_rate, sha_rate, hmac_rate)

        # ── Figure ──────────────────────────────────────────────────────
        plt.close("all")
        fig = plt.figure(figsize=(18, 11), facecolor="#0d1117")
        fig.suptitle("DH MITM — Attack & Prevention Analysis Dashboard",
                     color="white", fontsize=15, fontweight="bold", y=0.99)
        gs = gridspec.GridSpec(2, 3, figure=fig, hspace=0.50, wspace=0.36,
                               left=0.06, right=0.97, top=0.93, bottom=0.07)
        axs = dict(facecolor="#161b22")
        bkw = dict(edgecolor="none")

        def style(ax, title, xl="", yl=""):
            ax.set_title(title, color="white", fontsize=10, pad=8)
            ax.set_xlabel(xl, color="#6e7681", fontsize=8)
            ax.set_ylabel(yl, color="#6e7681", fontsize=8)
            ax.tick_params(colors="white", labelsize=8)
            for sp in ax.spines.values(): sp.set_edgecolor("#21262d")

        def blabels(ax, bars, vals=None, fmt="{:.1f}%"):
            for i, bar in enumerate(bars):
                h = bar.get_height()
                v = vals[i] if vals else h
                ax.text(bar.get_x() + bar.get_width()/2, h + 1.5,
                        fmt.format(v), ha="center", va="bottom",
                        color="white", fontsize=9, fontweight="bold")

        # ── G1: Before vs After ─────────────────────────────────────────
        ax1 = fig.add_subplot(gs[0, 0], **axs)
        b1  = ax1.bar(["Before\n(No Prevention)", "After\n(Best Prevention)"],
                      [atk_rate, 100 - best_prev],
                      color=["#da3633", "#3fb950"], width=0.5, **bkw)
        blabels(ax1, b1)
        ax1.set_ylim(0, 115)
        style(ax1, "Attack Success Rate\nBefore vs After Prevention", yl="Rate (%)")

        # ── G2: Param Gen Time vs Key Size ──────────────────────────────
        ax2 = fig.add_subplot(gs[0, 1], **axs)
        p_t = [param_avg[b] for b in all_bits]
        if any(v > 0 for v in p_t):
            yerr_low = [param_avg[b] - param_min[b] for b in all_bits]
            yerr_hi  = [param_max[b] - param_avg[b] for b in all_bits]
            ax2.errorbar(all_bits, p_t, yerr=[yerr_low, yerr_hi], fmt="-o",
                         color="#1f6feb", linewidth=2, markersize=8, capsize=5)
            peak = max(p_t)
            for xi, yi, n in zip(all_bits, p_t, [param_n[b] for b in all_bits]):
                if yi > 0:
                    ax2.text(xi, yi + peak * 0.04, f"{yi:.3f}s\nn={n}",
                             ha="center", va="bottom", color="white", fontsize=8)
            ax2.set_xticks(all_bits)
        else:
            ax2.text(0.5, 0.5, "Generate params at\nmultiple key sizes",
                     transform=ax2.transAxes, ha="center", va="center",
                     color="#6e7681", fontsize=9)
        style(ax2, "Param Generation Time\nvs Key Size (avg with range)", xl="Key Size (bits)", yl="Time (s)")

        # ── G3: CIA Triad ────────────────────────────────────────────────
        ax3  = fig.add_subplot(gs[0, 2], **axs)
        cb   = [100 - atk_rate, 100 - atk_rate, 0]
        ca   = [100, 100, 100]
        xlbl = ["Confidentiality", "Integrity", "Authentication"]
        xp   = list(range(3))
        ax3.bar([x - 0.22 for x in xp], cb, width=0.4,
                color="#da3633", label="Before", **bkw)
        ax3.bar([x + 0.22 for x in xp], ca, width=0.4,
                color="#3fb950", label="After",  **bkw)
        ax3.set_xticks(xp); ax3.set_xticklabels(xlbl, rotation=12, fontsize=8)
        ax3.set_ylim(0, 120)
        ax3.legend(facecolor="#161b22", labelcolor="white", fontsize=8)
        style(ax3, "CIA Security Properties\nBefore vs After", yl="Rate (%)")

        # ── G4: Attack Latency per Test ──────────────────────────────────
        ax4 = fig.add_subplot(gs[1, 0], **axs)
        if atk_times:
            cols4 = ["#da3633" if r["mitm_success"] else "#d29922" for r in atk]
            ax4.bar(range(1, len(atk_times)+1), atk_times,
                    color=cols4, width=0.7, **bkw)
            ax4.axhline(avg_atk_t, color="white", linestyle="--",
                        linewidth=1, alpha=0.5, label=f"avg={avg_atk_t:.5f}s")
            ax4.legend(facecolor="#161b22", labelcolor="white", fontsize=8)
        style(ax4, "Attack Latency per Test\n(red=success, yellow=fail)",
              xl="Test Case #", yl="Time (s)")

        # ── G5: Prevention Method Comparison ────────────────────────────
        ax5 = fig.add_subplot(gs[1, 1], **axs)
        m5  = ["ElGamal\nSignature", "SHA-256\nBinding", "HMAC\nAuth"]
        r5  = [eg_rate, sha_rate, hmac_rate]
        b5  = ax5.bar(m5, r5, color=["#8957e5", "#1f6feb", "#39d0d8"],
                      width=0.5, **bkw)
        blabels(ax5, b5)
        ax5.set_ylim(0, 115)
        style(ax5, "Prevention Methods\nMITM Blocked Rate", yl="Blocked (%)")

        # ── G6: Latency Overhead ─────────────────────────────────────────
        ax6 = fig.add_subplot(gs[1, 2], **axs)
        m6  = ["Attack", "ElGamal\nSig", "SHA-256\nBinding", "HMAC\nAuth"]
        t6  = [avg_atk_t, avg_eg_t, avg_sha_t, avg_hm_t]
        b6  = ax6.bar(m6, t6,
                      color=["#da3633", "#8957e5", "#1f6feb", "#39d0d8"],
                      width=0.5, **bkw)
        mx6 = max(t6) if any(v > 0 for v in t6) else 1
        for bar, val in zip(b6, t6):
            ax6.text(bar.get_x() + bar.get_width()/2, bar.get_height() + mx6*0.02,
                     f"{val:.5f}s", ha="center", va="bottom",
                     color="white", fontsize=8, fontweight="bold")
        style(ax6, "Average End-to-End Time\nAttack vs Prevention",
              yl="Avg Time (s)")

        plt.show()
        self._log("  📊 All 6 graphs displayed in a separate window.", "ok")


# ================================================================
# =========================  MAIN  ===============================
# ================================================================

if __name__ == "__main__":
    root = tk.Tk()
    app = DHMITMApp(root)
    root.mainloop()
