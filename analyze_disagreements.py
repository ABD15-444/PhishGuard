import pandas as pd

df = pd.read_csv("urls_for_investigation.csv")

print("DISAGREEMENT ANALYSIS")
print("=" * 60)

for _, row in df.iterrows():
    print(f"\nURL: {row['url']}")
    print(f"ML phishing probability: {row['ml_phishing_probability']}")
    print(f"VirusTotal malicious: {row['malicious']}")
    print(f"VirusTotal suspicious: {row['suspicious']}")
    print(f"VirusTotal harmless: {row['harmless']}")
    print(f"VirusTotal undetected: {row['undetected']}")
    print(f"Source: {row['source']}")

print("\nSummary:")
print("Total records:", len(df))
print(
    "Mean ML phishing probability:",
    round(df["ml_phishing_probability"].mean() * 100, 2),
    "%"
)