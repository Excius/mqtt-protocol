import os
import pandas as pd
import matplotlib.pyplot as plt
import numpy as np

# -----------------------------
# Plot Styling
# -----------------------------

plt.style.use("seaborn-v0_8-paper")

plt.rcParams.update({
    "font.size": 12,
    "axes.titlesize": 14,
    "axes.labelsize": 12,
    "legend.fontsize": 11,
    "figure.figsize": (8,5)
})

# -----------------------------
# Output directory
# -----------------------------

os.makedirs("figures", exist_ok=True)

print("Loading datasets...")

baseline = pd.read_csv("experiments/baseline/results.csv")
phase1B = pd.read_csv("experiments/phase1/phase1B_concurrent/results.csv")
phase1C = pd.read_csv("experiments/phase1/phase1C_sustained/results.csv")

psk = pd.read_csv("experiments/phase2_psk/results.csv")
psk_opt = pd.read_csv("experiments/psk_optimized/results.csv")

session_new = pd.read_csv("experiments/session_resumption/results_new_handshake.csv")
session_resumed = pd.read_csv("experiments/session_resumption/results_session_resumed.csv")

user_vuln = pd.read_csv("experiments/user_property_attack/results_vulnerable.csv")
user_prot = pd.read_csv("experiments/user_property_attack/results_protected.csv")

auth_vuln = pd.read_csv("experiments/auth_flood/results_vulnerable.csv")
auth_prot = pd.read_csv("experiments/auth_flood/results_protected.csv")

print("Generating Paper A graphs...")

# ======================================================
# 1 Authentication Boxplot
# ======================================================

auth_methods = ["cert_standard", "psk_standard", "psk_optimized", "psk_resumed"]

means = []
stds = []

for method in auth_methods:
    values = psk_opt[psk_opt["method"] == method]["handshake_ms"]
    means.append(values.mean())
    stds.append(values.std())

plt.figure()

plt.bar(
    auth_methods,
    means,
    yerr=stds,
    capsize=5
)

plt.ylabel("Handshake Latency (ms)")
plt.xlabel("Authentication Method")

plt.title(
    "TLS Authentication Performance\n"
    "(Error bars = latency variability)"
)

plt.tight_layout()

plt.savefig("figures/authentication_comparison.png")
plt.close()


# ======================================================
# User Property Attack Heatmap
# ======================================================

attack_vectors = user_vuln[
    [
        "vt1_sent",
        "vt2_sent",
        "vt3_sent",
        "vt4_sent",
        "vt5_sent"
    ]
]

plt.figure()

plt.imshow(
    attack_vectors.T,
    aspect="auto"
)

plt.colorbar(label="Packets Sent")

plt.yticks(
    range(5),
    [
        "VT1 Count Overflow",
        "VT2 Key Overflow",
        "VT3 Value Overflow",
        "VT4 Payload Overflow",
        "VT5 Budget Drain"
    ]
)

plt.xlabel("Attack Iteration")

plt.title("User Property Attack Intensity Heatmap")

plt.tight_layout()

plt.savefig("figures/user_property_attack_heatmap.png")
plt.close()


# ======================================================
# 4 Session Resumption Histogram
# ======================================================

plt.figure()

plt.hist(
    session_new["handshake_ms"],
    alpha=0.6,
    label="Full Handshake"
)

plt.hist(
    session_resumed["handshake_ms"],
    alpha=0.6,
    label="Session Resumed"
)

plt.xlabel("Handshake Latency (ms)")
plt.ylabel("Frequency")

plt.title("TLS Session Resumption Speedup")

plt.legend()

plt.tight_layout()

plt.savefig("figures/session_resumption_histogram.png")
plt.close()


# ======================================================
# 5 Latency CDF
# ======================================================

plt.figure()

for label, df in {
    "Certificate": baseline,
    "PSK": psk,
    "Resumed": session_resumed
}.items():

    x = np.sort(df["handshake_ms"])
    y = np.arange(len(x)) / len(x)

    plt.plot(x, y, label=label)

plt.xlabel("Handshake Latency (ms)")
plt.ylabel("CDF")

plt.title("TLS Handshake Latency Distribution (CDF)")

plt.legend()

plt.tight_layout()

plt.savefig("figures/latency_cdf.png")
plt.close()

print("Generating Paper B graphs...")

# ======================================================
# 6 User Property Attack Memory Comparison
# ======================================================

plt.figure()

plt.plot(
    user_vuln["iteration"],
    user_vuln["mem_kb"]/1024,
    label="Vulnerable",
    color="tab:red"
)

plt.plot(
    user_prot["iteration"],
    user_prot["mem_kb"]/1024,
    label="Protected",
    color="tab:green"
)

plt.xlabel("Attack Iteration")
plt.ylabel("Broker Memory (MB)")

plt.title("User Property Injection Attack Impact")

plt.legend()

plt.tight_layout()

plt.savefig("figures/user_property_memory_comparison.png")
plt.close()


# ======================================================
# 7 User Property Drop Reasons (Line Visualization)
# ======================================================

plt.figure()

plt.plot(user_prot["iteration"], user_prot["prop_count_drops"], label="Count Limit")
plt.plot(user_prot["iteration"], user_prot["key_size_drops"], label="Key Size")
plt.plot(user_prot["iteration"], user_prot["val_size_drops"], label="Value Size")
plt.plot(user_prot["iteration"], user_prot["payload_drops"], label="Payload Limit")
plt.plot(user_prot["iteration"], user_prot["budget_drops"], label="Budget Limit")

plt.xlabel("Attack Iteration")
plt.ylabel("Packets Dropped")

plt.title("User Property Defense Rules Triggered")

plt.legend()

plt.tight_layout()

plt.savefig("figures/user_property_drop_lines.png")
plt.close()


# ======================================================
# 8 AUTH Flood Impact (Latency + Memory)
# ======================================================

fig, ax1 = plt.subplots()

ax1.plot(
    auth_vuln["iteration"],
    auth_vuln["legit_latency_ms"],
    marker="o",
    color="tab:red",
    label="Latency"
)

ax1.set_xlabel("Iteration")
ax1.set_ylabel("Latency (ms)", color="tab:red")

ax2 = ax1.twinx()

ax2.plot(
    auth_vuln["iteration"],
    auth_vuln["mem_kb"]/1024,
    marker="s",
    color="tab:blue",
    label="Memory"
)

ax2.set_ylabel("Memory (MB)", color="tab:blue")

plt.title("Impact of AUTH Flood on Broker Performance")

fig.legend(loc="upper left")

plt.tight_layout()

plt.savefig("figures/auth_flood_latency_memory.png")
plt.close()


# ======================================================
# 9 AUTH Flood Connections
# ======================================================

plt.figure()

plt.plot(
    auth_vuln["iteration"],
    auth_vuln["flood_conns"],
    label="Vulnerable",
    color="tab:red"
)

plt.plot(
    auth_prot["iteration"],
    auth_prot["flood_conns"],
    label="Protected",
    color="tab:green"
)

plt.xlabel("Iteration")
plt.ylabel("Connections Reaching Broker")

plt.title("AUTH Flood Mitigation Effectiveness")

plt.legend()

plt.tight_layout()

plt.savefig("figures/auth_flood_connections.png")
plt.close()


# ======================================================
# 11 Security Improvement Summary (Normalized)
# ======================================================

metrics = {
    "User Property\nMemory": (18, 1.3),
    "AUTH Flood\nConnections": (3300, 10),
    "Legitimate\nLatency": (9.9, 1.2)
}

labels = []
improvement = []

for k,(v,p) in metrics.items():
    labels.append(k)
    improvement.append((v-p)/v * 100)

plt.figure()

plt.bar(labels, improvement, color="tab:purple")

plt.ylabel("Improvement (%)")

plt.title("Security Improvements Achieved by MQTT-NG")

plt.ylim(0,100)

plt.tight_layout()

plt.savefig("figures/security_summary.png")
plt.close()


print("All graphs generated successfully.")
print("Saved in ./figures/")