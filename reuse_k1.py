import random
import threading
import time
import tkinter as tk
import hashlib
import hmac
from math import gcd
from tkinter import scrolledtext, ttk

import matplotlib
matplotlib.use("TkAgg")
import matplotlib.gridspec as gridspec
import matplotlib.pyplot as plt


# ================================================================
# =====================  MATH / CRYPTO  ==========================
# ================================================================

def is_prime(n, k=10):
    if n < 2:
        return False
    if n == 2:
        return True
    if n % 2 == 0:
        return False

    d, r = n - 1, 0
    while d % 2 == 0:
        d //= 2
        r += 1

    for _ in range(k):
        a = random.randrange(2, n - 1)
        x = pow(a, d, n)
        if x in (1, n - 1):
            continue
        for _ in range(r - 1):
            x = pow(x, 2, n)
            if x == n - 1:
                break
        else:
            return False
    return True


def generate_safe_prime(bits):
    while True:
        q = random.getrandbits(bits - 1)
        q |= (1 << (bits - 2)) | 1
        if not is_prime(q):
            continue
        p = 2 * q + 1
        if is_prime(p):
            return p, q


def find_generator(p, q):
    for g in range(2, 200):
        if pow(g, 2, p) != 1 and pow(g, q, p) != 1:
            return g
    raise ValueError("No generator found in range 2-200")


# ================================================================
# =====================  HASH HELPERS  ===========================
# ================================================================

def simple_hash(data: str, mod: int) -> int:
    digest = hashlib.sha256(data.encode()).digest()
    return int.from_bytes(digest, "big") % mod


def hmac_hash(x, m, mod: int) -> int:
    digest = hmac.new(str(x).encode(), str(m).encode(), hashlib.sha256).digest()
    return int.from_bytes(digest, "big") % mod


# ================================================================
# ======================  K GENERATORS  ==========================
# ================================================================

def normalize_k(candidate: int, modulus: int) -> int:
    candidate %= modulus
    if candidate < 2:
        candidate = 2
    while candidate < modulus and gcd(candidate, modulus) != 1:
        candidate += 1
    if candidate >= modulus:
        candidate = 2
        while gcd(candidate, modulus) != 1:
            candidate += 1
    return candidate


def random_k(p: int) -> int:
    bit_len = (p - 1).bit_length()
    while True:
        k = random.getrandbits(bit_len)
        if 1 < k < p - 1 and gcd(k, p - 1) == 1:
            return k


def sha_k(x, m, p: int) -> int:
    val = simple_hash(f"{x}|{m}", p - 1)
    return normalize_k(val, p - 1)


def hmac_k(x, m, p: int) -> int:
    val = hmac_hash(x, m, p - 1)
    return normalize_k(val, p - 1)


# ================================================================
# ====================  SIGNATURE SCHEME  ========================
# ================================================================

def sign(p, g, x, m, k):
    r = pow(g, k, p)
    s = (pow(k, -1, p - 1) * (m - x * r)) % (p - 1)
    return r, s


def recover_k_from_reuse(m1, m2, s1, s2, order):
    diff_s = (s1 - s2) % order
    diff_m = (m1 - m2) % order
    return (diff_m * pow(diff_s, -1, order)) % order


def recover_x(m, s, k, r, order):
    return ((m - s * k) * pow(r, -1, order)) % order


# ================================================================
# =========================  GUI APP  ============================
# ================================================================

class ReuseKApp:
    COLORS = {
        "bg": "#0f1117",
        "panel": "#1a1d27",
        "accent": "#4f8ef7",
        "red": "#e05252",
        "green": "#52c97a",
        "orange": "#f0a04b",
        "text": "#d0d8f0",
        "subtext": "#7880a0",
        "border": "#2a2d3e",
    }

    KEY_SIZES = [256, 512, 768]

    def __init__(self, root: tk.Tk):
        self.root = root
        self.root.title("Reuse-k Attack & Prevention")
        self.root.geometry("1250x740")
        self.root.configure(bg=self.COLORS["bg"])
        self.root.resizable(True, True)

        self.p = None
        self.q = None
        self.g = None
        self.generated_keys = {}

        self.bits_var = tk.IntVar(value=256)
        self.method_var = tk.StringVar(value="Random")

        self.attack_successes = []
        self.random_unique = []
        self.sha_unique = []
        self.hmac_unique = []
        self.attack_times = []
        self.random_times = []
        self.sha_times = []
        self.hmac_times = []
        self.prevention_times = []
        self.key_gen_times = []
        self.bits_tested = []
        self.test_case_results = []

        self._build_ui()

    def _build_ui(self):
        c = self.COLORS

        left = tk.Frame(self.root, bg=c["panel"], width=240)
        left.pack(side=tk.LEFT, fill=tk.Y, padx=(12, 6), pady=12)
        left.pack_propagate(False)

        self._lbl(left, "REUSE-K ATTACK", 14, bold=True, fg=c["accent"]).pack(pady=(18, 4))
        self._lbl(left, "ElGamal Signature Vulnerability", 9, fg=c["subtext"]).pack(pady=(0, 16))

        self._lbl(left, "Key Size (bits)", 10, fg=c["subtext"]).pack()
        ttk.Combobox(
            left,
            textvariable=self.bits_var,
            values=self.KEY_SIZES,
            width=14,
            state="readonly",
        ).pack(pady=(2, 10))

        self._lbl(left, "Prevention Method", 10, fg=c["subtext"]).pack()
        ttk.Combobox(
            left,
            textvariable=self.method_var,
            values=["Random", "SHA", "HMAC"],
            width=14,
            state="readonly",
        ).pack(pady=(2, 14))

        buttons = [
            ("Generate Keys", self._thread(self._generate_keys)),
            ("Run Attack", self._thread(self._run_attack)),
            ("Apply Prevention", self._thread(self._run_prevention)),
            ("Run 25 Test Cases", self._thread(self._run_25_tests)),
            ("Show Graphs", self._show_graphs),
            ("Clear Log", self._clear_log),
        ]
        for label, cmd in buttons:
            tk.Button(
                left,
                text=label,
                command=cmd,
                bg=c["border"],
                fg=c["text"],
                relief=tk.FLAT,
                activebackground=c["accent"],
                activeforeground="white",
                font=("Consolas", 10),
                cursor="hand2",
                padx=10,
                pady=6,
                anchor="w",
            ).pack(fill=tk.X, padx=10, pady=3)

        self.status_lbl = tk.Label(
            left,
            text="Idle",
            font=("Consolas", 11, "bold"),
            bg=c["panel"],
            fg=c["subtext"],
        )
        self.status_lbl.pack(pady=20)

        self.progress = ttk.Progressbar(left, length=200, mode="determinate")
        self.progress.pack(padx=10, pady=4)
        self.prog_lbl = tk.Label(left, text="", bg=c["panel"], fg=c["subtext"], font=("Consolas", 8))
        self.prog_lbl.pack()

        right = tk.Frame(self.root, bg=c["bg"])
        right.pack(side=tk.RIGHT, fill=tk.BOTH, expand=True, padx=(6, 12), pady=12)

        self._lbl(right, "EXECUTION LOG", 10, fg=c["subtext"], anchor="w").pack(fill=tk.X)
        self.logbox = scrolledtext.ScrolledText(
            right,
            bg=c["panel"],
            fg=c["text"],
            font=("Consolas", 10),
            insertbackground=c["text"],
            relief=tk.FLAT,
            borderwidth=0,
            padx=10,
            pady=8,
        )
        self.logbox.pack(fill=tk.BOTH, expand=True, pady=(4, 0))
        self.logbox.tag_config("ok", foreground=c["green"])
        self.logbox.tag_config("warn", foreground=c["orange"])
        self.logbox.tag_config("danger", foreground=c["red"])
        self.logbox.tag_config("header", foreground=c["accent"])
        self.logbox.tag_config("dim", foreground=c["subtext"])
        self.logbox.tag_config("info", foreground=c["text"])

        style = ttk.Style()
        style.theme_use("default")
        style.configure(
            "TCombobox",
            fieldbackground=c["border"],
            background=c["border"],
            foreground=c["text"],
            selectbackground=c["accent"],
        )

    def _lbl(self, parent, text, size=10, bold=False, fg=None, **kwargs):
        font = ("Consolas", size, "bold" if bold else "normal")
        return tk.Label(parent, text=text, font=font, bg=self.COLORS["panel"], fg=fg or self.COLORS["text"], **kwargs)

    def _now(self):
        return time.perf_counter()

    def _thread(self, fn):
        return lambda: threading.Thread(target=fn, daemon=True).start()

    def _log(self, msg, tag=""):
        self.logbox.insert(tk.END, msg + "\n", tag)
        self.logbox.see(tk.END)
        self.root.update_idletasks()

    def _clear_log(self):
        self.logbox.delete("1.0", tk.END)

    def _set_status(self, text, color_key):
        self.status_lbl.config(text=text, fg=self.COLORS[color_key])

    def _set_progress(self, val, total, label=""):
        pct = int(val / total * 100) if total else 0
        self.progress["value"] = pct
        self.prog_lbl.config(text=label or f"{val}/{total}")
        self.root.update_idletasks()

    def _ensure_keys(self):
        selected_bits = self.bits_var.get()
        if selected_bits not in self.generated_keys:
            self._generate_keys()
        return self.p is not None and self.g is not None

    def _generate_keys(self):
        self.bits_tested.clear()
        self.key_gen_times.clear()
        self.generated_keys.clear()

        self._set_status("Generating Keys", "orange")
        self._log("\n" + "=" * 60, "header")
        self._log("GENERATING SAFE PRIMES FOR 256, 512, 768 BITS", "header")
        self._log("=" * 60, "header")

        total = len(self.KEY_SIZES)
        for index, key_size in enumerate(self.KEY_SIZES, start=1):
            self._set_progress(index - 1, total, f"Generating {key_size}-bit key")
            start = self._now()
            p, q = generate_safe_prime(key_size)
            g = find_generator(p, q)
            elapsed = self._now() - start

            self.generated_keys[key_size] = (p, q, g)
            self.bits_tested.append(key_size)
            self.key_gen_times.append(elapsed)
            self._log(f"{key_size}-bit key generated in {elapsed:.4f} sec", "info")

        selected_bits = self.bits_var.get()
        self.p, self.q, self.g = self.generated_keys[selected_bits]

        self._set_progress(total, total, "Complete")
        self._set_status("Keys Ready", "green")
        self._log(f"Selected active key size: {selected_bits} bits", "ok")

    def _run_attack(self):
        if not self._ensure_keys():
            self._log("[!] Unable to generate keys.", "warn")
            return

        self.p, self.q, self.g = self.generated_keys[self.bits_var.get()]
        self._set_status("Attacking", "orange")
        self._log("\n" + "=" * 60, "danger")
        self._log("REUSE-k ATTACK SIMULATION", "danger")
        self._log("=" * 60, "danger")

        bits = self.bits_var.get()
        order = self.p - 1
        attempts = 0

        while True:
            attempts += 1
            x = random.getrandbits(bits // 2)
            m1 = random.getrandbits(128)
            m2 = random.getrandbits(128)
            k = random_k(self.p)

            t0 = self._now()
            r1, s1 = sign(self.p, self.g, x, m1, k)
            r2, s2 = sign(self.p, self.g, x, m2, k)

            if gcd((s1 - s2) % order, order) != 1:
                continue
            if gcd(r1, order) != 1:
                continue

            try:
                k_rec = recover_k_from_reuse(m1, m2, s1, s2, order)
                x_rec = recover_x(m1, s1, k_rec, r1, order)
            except ValueError:
                continue

            elapsed = self._now() - t0
            success = x == x_rec

            self._log(f"Attempts needed : {attempts}", "info")
            self._log(f"Private key x   : {x}", "info")
            self._log(f"Recovered k     : {k_rec}", "info")
            self._log(f"Recovered x     : {x_rec}", "info")
            self._log(f"Time            : {elapsed:.6f}s", "info")
            if success:
                self._log("Attack succeeded: private key fully recovered.", "danger")
                self._set_status("Vulnerable", "red")
            else:
                self._log("Attack failed this round.", "warn")
                self._set_status("Attack Failed", "orange")
            return

    def _run_prevention(self):
        if not self._ensure_keys():
            self._log("[!] Unable to generate keys.", "warn")
            return

        self.p, self.q, self.g = self.generated_keys[self.bits_var.get()]
        method = self.method_var.get()
        bits = self.bits_var.get()
        x = random.getrandbits(bits // 2)
        m1 = random.getrandbits(128)
        m2 = random.getrandbits(128)

        self._log("\n" + "=" * 60, "ok")
        self._log(f"PREVENTION DEMO - {method}", "ok")
        self._log("=" * 60, "ok")

        t0 = self._now()
        if method == "Random":
            k1 = random_k(self.p)
            k2 = random_k(self.p)
        elif method == "SHA":
            k1 = sha_k(x, m1, self.p)
            k2 = sha_k(x, m2, self.p)
        else:
            k1 = hmac_k(x, m1, self.p)
            k2 = hmac_k(x, m2, self.p)
        elapsed = self._now() - t0

        unique = k1 != k2
        self._log(f"Method  : {method}", "info")
        self._log(f"k1      : {k1}", "info")
        self._log(f"k2      : {k2}", "info")
        self._log(f"Unique? : {unique}", "ok" if unique else "danger")
        self._log(f"Time    : {elapsed:.6f}s", "info")
        self._set_status("Secure" if unique else "Warning", "green" if unique else "red")

    def _run_25_tests(self):
        if not self._ensure_keys():
            self._log("[!] Unable to generate keys.", "warn")
            return

        self.p, self.q, self.g = self.generated_keys[self.bits_var.get()]

        self.attack_successes.clear()
        self.random_unique.clear()
        self.sha_unique.clear()
        self.hmac_unique.clear()
        self.attack_times.clear()
        self.random_times.clear()
        self.sha_times.clear()
        self.hmac_times.clear()
        self.prevention_times.clear()
        self.test_case_results.clear()

        bits = self.bits_var.get()
        order = self.p - 1
        target = 25
        done = 0

        self._log("\n" + "=" * 60, "header")
        self._log(f"RUNNING {target} DETAILED TEST CASES ({bits}-bit)", "header")
        self._log("=" * 60, "header")
        self._set_status("Testing", "orange")
        self._set_progress(0, target, "Starting tests")

        while done < target:
            x = random.getrandbits(bits // 2)
            m1 = random.getrandbits(128)
            m2 = random.getrandbits(128)
            k = random_k(self.p)

            attack_start = self._now()
            r1, s1 = sign(self.p, self.g, x, m1, k)
            r2, s2 = sign(self.p, self.g, x, m2, k)

            if gcd((s1 - s2) % order, order) != 1:
                continue
            if gcd(r1, order) != 1:
                continue

            try:
                k_rec = recover_k_from_reuse(m1, m2, s1, s2, order)
                x_rec = recover_x(m1, s1, k_rec, r1, order)
            except ValueError:
                continue

            attack_elapsed = self._now() - attack_start
            attack_ok = x == x_rec

            random_start = self._now()
            k1_r = random_k(self.p)
            k2_r = random_k(self.p)
            random_elapsed = self._now() - random_start

            sha_start = self._now()
            k1_s = sha_k(x, m1, self.p)
            k2_s = sha_k(x, m2, self.p)
            sha_elapsed = self._now() - sha_start

            hmac_start = self._now()
            k1_h = hmac_k(x, m1, self.p)
            k2_h = hmac_k(x, m2, self.p)
            hmac_elapsed = self._now() - hmac_start
            prevention_elapsed = random_elapsed + sha_elapsed + hmac_elapsed

            self.attack_successes.append(attack_ok)
            self.random_unique.append(k1_r != k2_r)
            self.sha_unique.append(k1_s != k2_s)
            self.hmac_unique.append(k1_h != k2_h)
            self.attack_times.append(attack_elapsed)
            self.random_times.append(random_elapsed)
            self.sha_times.append(sha_elapsed)
            self.hmac_times.append(hmac_elapsed)
            self.prevention_times.append(prevention_elapsed)
            self.test_case_results.append({
                "case": done + 1,
                "bits": bits,
                "x": x,
                "m1": m1,
                "m2": m2,
                "k": k,
                "r1": r1,
                "s1": s1,
                "r2": r2,
                "s2": s2,
                "k_rec": k_rec,
                "x_rec": x_rec,
                "attack_ok": attack_ok,
                "attack_time": attack_elapsed,
                "k1_r": k1_r,
                "k2_r": k2_r,
                "random_unique": k1_r != k2_r,
                "random_time": random_elapsed,
                "k1_s": k1_s,
                "k2_s": k2_s,
                "sha_unique": k1_s != k2_s,
                "sha_time": sha_elapsed,
                "k1_h": k1_h,
                "k2_h": k2_h,
                "hmac_unique": k1_h != k2_h,
                "hmac_time": hmac_elapsed,
                "prevention_total_time": prevention_elapsed,
            })

            done += 1
            self._set_progress(done, target, f"Test {done}/{target}")

            self._log("", "info")
            self._log(f"========== TEST CASE {done:02d} ==========" , "header")
            self._log("ATTACK DETAILS", "danger")
            self._log(f"Key size                = {bits}", "info")
            self._log(f"Private key x           = {x}", "info")
            self._log(f"Message m1              = {m1}", "info")
            self._log(f"Message m2              = {m2}", "info")
            self._log(f"Reused nonce k          = {k}", "info")
            self._log(f"Signature 1 (r1, s1)    = ({r1}, {s1})", "info")
            self._log(f"Signature 2 (r2, s2)    = ({r2}, {s2})", "info")
            self._log(f"Recovered nonce k       = {k_rec}", "info")
            self._log(f"Recovered private key x = {x_rec}", "info")
            self._log(f"Attack success          = {attack_ok}", "ok" if attack_ok else "danger")
            self._log(f"Attack time             = {attack_elapsed * 1000:.3f} ms", "info")
            self._log("", "info")
            self._log("PREVENTION DETAILS", "ok")
            self._log(f"[Random] k1             = {k1_r}", "info")
            self._log(f"[Random] k2             = {k2_r}", "info")
            self._log(f"[Random] unique?        = {k1_r != k2_r}", "ok" if k1_r != k2_r else "danger")
            self._log(f"[Random] time           = {random_elapsed * 1000:.3f} ms", "info")
            self._log(f"[SHA]    k1             = {k1_s}", "info")
            self._log(f"[SHA]    k2             = {k2_s}", "info")
            self._log(f"[SHA]    unique?        = {k1_s != k2_s}", "ok" if k1_s != k2_s else "danger")
            self._log(f"[SHA]    time           = {sha_elapsed * 1000:.3f} ms", "info")
            self._log(f"[HMAC]   k1             = {k1_h}", "info")
            self._log(f"[HMAC]   k2             = {k2_h}", "info")
            self._log(f"[HMAC]   unique?        = {k1_h != k2_h}", "ok" if k1_h != k2_h else "danger")
            self._log(f"[HMAC]   time           = {hmac_elapsed * 1000:.3f} ms", "info")
            self._log(f"Total prevention time   = {prevention_elapsed * 1000:.3f} ms", "info")

        atk_rate = sum(self.attack_successes) / target * 100
        rand_rate = sum(self.random_unique) / target * 100
        sha_rate = sum(self.sha_unique) / target * 100
        hmac_rate = sum(self.hmac_unique) / target * 100

        self._log("\n" + "-" * 60, "header")
        self._log(f"Attack success rate  : {atk_rate:.1f}%", "danger")
        self._log(f"Random prevention    : {rand_rate:.1f}%", "ok")
        self._log(f"SHA prevention       : {sha_rate:.1f}%", "ok")
        self._log(f"HMAC prevention      : {hmac_rate:.1f}%", "ok")
        self._log("-" * 60, "header")
        self._log(f"All {target} test cases completed.", "ok")

        self._set_status("Tests Done", "green")
        self._set_progress(target, target, "Complete")

    def _show_graphs(self):
        if not self.attack_successes:
            self._log("[!] Run 25 test cases first.", "warn")
            return

        n = len(self.attack_successes)
        atk_rate = sum(self.attack_successes) / n * 100
        rand_rate = sum(self.random_unique) / n * 100
        sha_rate = sum(self.sha_unique) / n * 100
        hmac_rate = sum(self.hmac_unique) / n * 100
        avg_atk = sum(self.attack_times) / len(self.attack_times)
        avg_random = sum(self.random_times) / len(self.random_times)
        avg_sha = sum(self.sha_times) / len(self.sha_times)
        avg_hmac = sum(self.hmac_times) / len(self.hmac_times)
        avg_prev = sum(self.prevention_times) / len(self.prevention_times)

        key_sizes = []
        key_times = []
        for bits, elapsed in zip(self.bits_tested, self.key_gen_times):
            if bits in self.KEY_SIZES:
                key_sizes.append(bits)
                key_times.append(elapsed)

        attack_ms = [v * 1000 for v in self.attack_times]
        random_ms = [v * 1000 for v in self.random_times]
        sha_ms = [v * 1000 for v in self.sha_times]
        hmac_ms = [v * 1000 for v in self.hmac_times]
        prev_total_ms = [v * 1000 for v in self.prevention_times]
        avg_atk_ms = avg_atk * 1000
        avg_random_ms = avg_random * 1000
        avg_sha_ms = avg_sha * 1000
        avg_hmac_ms = avg_hmac * 1000
        avg_prev_ms = avg_prev * 1000

        plt.close("all")
        fig = plt.figure(figsize=(16, 10), facecolor="#0f1117")
        fig.suptitle("Reuse-k Attack and Prevention Analysis Dashboard", color="white", fontsize=15, fontweight="bold", y=0.98)

        gs = gridspec.GridSpec(2, 3, figure=fig, hspace=0.45, wspace=0.35, left=0.06, right=0.97, top=0.92, bottom=0.08)
        ax_style = dict(facecolor="#1a1d27")
        bar_kw = dict(edgecolor="none", width=0.5)

        ax1 = fig.add_subplot(gs[0, 0], **ax_style)
        categories = ["Before\n(Reuse-k)", "After\n(HMAC-k)"]
        values = [atk_rate, 100 - hmac_rate]
        colors = ["#e05252", "#52c97a"]
        bars = ax1.bar(categories, values, color=colors, **bar_kw)
        for bar, val in zip(bars, values):
            ax1.text(bar.get_x() + bar.get_width() / 2, bar.get_height() + 1.5, f"{val:.1f}%", ha="center", va="bottom", color="white", fontsize=10, fontweight="bold")
        ax1.set_ylim(0, 115)
        ax1.set_title("Attack Success Rate\nBefore vs After Prevention", color="white", fontsize=10)
        ax1.set_ylabel("Success Rate (%)", color="#7880a0")
        ax1.tick_params(colors="white")
        for spine in ax1.spines.values():
            spine.set_edgecolor("#2a2d3e")

        ax2 = fig.add_subplot(gs[0, 1], **ax_style)
        ax2.plot(key_sizes, key_times, marker="o", color="#4f8ef7", linewidth=2, markersize=7)
        for x_val, y_val in zip(key_sizes, key_times):
            ax2.text(x_val, y_val + 0.002, f"{y_val:.3f}s", ha="center", va="bottom", color="white", fontsize=8)
        ax2.set_xticks(self.KEY_SIZES)
        ax2.set_title("Key Generation Time\nfor 256, 512, 768 bits", color="white", fontsize=10)
        ax2.set_xlabel("Key Size (bits)", color="#7880a0")
        ax2.set_ylabel("Time (s)", color="#7880a0")
        ax2.tick_params(colors="white")
        for spine in ax2.spines.values():
            spine.set_edgecolor("#2a2d3e")

        ax3 = fig.add_subplot(gs[0, 2], **ax_style)
        cia_before = [100 - atk_rate, 100 - atk_rate, 0]
        cia_after = [100, 100, hmac_rate]
        cia_labels = ["Confidentiality", "Integrity", "Authentication"]
        x_pos = range(len(cia_labels))
        ax3.bar([p - 0.22 for p in x_pos], cia_before, width=0.4, color="#e05252", label="Before")
        ax3.bar([p + 0.22 for p in x_pos], cia_after, width=0.4, color="#52c97a", label="After")
        ax3.set_xticks(list(x_pos))
        ax3.set_xticklabels(cia_labels, rotation=10, color="white", fontsize=8)
        ax3.set_ylim(0, 120)
        ax3.set_title("CIA Security Properties\nBefore vs After", color="white", fontsize=10)
        ax3.set_ylabel("Rate (%)", color="#7880a0")
        ax3.legend(facecolor="#1a1d27", labelcolor="white", fontsize=8)
        ax3.tick_params(colors="white")
        for spine in ax3.spines.values():
            spine.set_edgecolor("#2a2d3e")

        ax4 = fig.add_subplot(gs[1, 0], **ax_style)
        summary_methods = ["Attack", "Random", "SHA", "HMAC", "All Prev"]
        summary_vals = [avg_atk_ms, avg_random_ms, avg_sha_ms, avg_hmac_ms, avg_prev_ms]
        summary_cols = ["#e05252", "#f0a04b", "#4f8ef7", "#52c97a", "#b07cff"]
        bars4 = ax4.bar(summary_methods, summary_vals, color=summary_cols, **bar_kw)
        for bar, val in zip(bars4, summary_vals):
            ax4.text(bar.get_x() + bar.get_width() / 2, bar.get_height() + max(summary_vals) * 0.03, f"{val:.3f} ms", ha="center", va="bottom", color="white", fontsize=8, fontweight="bold")
        ax4.set_title("Latency Summary\nPer-method averages", color="white", fontsize=10)
        ax4.set_ylabel("Time (ms)", color="#7880a0")
        ax4.tick_params(colors="white")
        for spine in ax4.spines.values():
            spine.set_edgecolor("#2a2d3e")

        ax5 = fig.add_subplot(gs[1, 1], **ax_style)
        methods = ["Random\n(unique k)", "SHA-k", "HMAC-k"]
        rates = [rand_rate, sha_rate, hmac_rate]
        colors5 = ["#f0a04b", "#4f8ef7", "#52c97a"]
        bars5 = ax5.bar(methods, rates, color=colors5, **bar_kw)
        for bar, val in zip(bars5, rates):
            ax5.text(bar.get_x() + bar.get_width() / 2, bar.get_height() + 1, f"{val:.1f}%", ha="center", va="bottom", color="white", fontsize=10, fontweight="bold")
        ax5.set_ylim(0, 115)
        ax5.set_title("Prevention Methods\nUnique-k Success Rate", color="white", fontsize=10)
        ax5.set_ylabel("Rate (%)", color="#7880a0")
        ax5.tick_params(colors="white")
        for spine in ax5.spines.values():
            spine.set_edgecolor("#2a2d3e")

        ax6 = fig.add_subplot(gs[1, 2], **ax_style)
        bars6 = ax6.bar(
            ["Attack", "Random", "SHA", "HMAC", "All Prev\n(total)"],
            [avg_atk_ms, avg_random_ms, avg_sha_ms, avg_hmac_ms, avg_prev_ms],
            color=["#e05252", "#f0a04b", "#4f8ef7", "#52c97a", "#b07cff"],
            **bar_kw,
        )
        for bar, val in zip(bars6, [avg_atk_ms, avg_random_ms, avg_sha_ms, avg_hmac_ms, avg_prev_ms]):
            ax6.text(bar.get_x() + bar.get_width() / 2, bar.get_height() * 1.02 if val else 0.001, f"{val:.3f} ms", ha="center", va="bottom", color="white", fontsize=9, fontweight="bold")
        ax6.set_title("Average Latency by Method", color="white", fontsize=10)
        ax6.set_ylabel("Time (ms)", color="#7880a0")
        ax6.tick_params(colors="white")
        for spine in ax6.spines.values():
            spine.set_edgecolor("#2a2d3e")

        latency_fig = plt.figure(figsize=(15, 7), facecolor="#0f1117")
        latency_fig.suptitle("Reuse-k Latency per Test Case", color="white", fontsize=14, fontweight="bold", y=0.98)
        latency_ax = latency_fig.add_subplot(111, facecolor="#1a1d27")
        case_ids = list(range(1, n + 1))
        width = 0.2
        latency_ax.bar([i - 1.5 * width for i in case_ids], attack_ms, width=width, color="#e05252", label="Attack")
        latency_ax.bar([i - 0.5 * width for i in case_ids], random_ms, width=width, color="#f0a04b", label="Random")
        latency_ax.bar([i + 0.5 * width for i in case_ids], sha_ms, width=width, color="#4f8ef7", label="SHA")
        latency_ax.bar([i + 1.5 * width for i in case_ids], hmac_ms, width=width, color="#52c97a", label="HMAC")
        latency_ax.set_title("Per-test latency in milliseconds", color="white", fontsize=11)
        latency_ax.set_xlabel("Test Case #", color="#7880a0")
        latency_ax.set_ylabel("Time (ms)", color="#7880a0")
        latency_ax.set_xticks(case_ids)
        latency_ax.legend(facecolor="#1a1d27", labelcolor="white", fontsize=9)
        latency_ax.tick_params(colors="white")
        for spine in latency_ax.spines.values():
            spine.set_edgecolor("#2a2d3e")

        plt.show(block=False)
        self._log("Graphs displayed in separate windows, including a dedicated latency figure.", "ok")


if __name__ == "__main__":
    root = tk.Tk()
    app = ReuseKApp(root)
    root.mainloop()
