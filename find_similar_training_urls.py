
import pandas as pd

TRAIN_FILE = "ml_train.csv"

targets = [
    "https://auth-we.xyz/",
    "https://netfilxservicio.com/",
    "https://paypal-banking.pro/",
    "https://fide-lltny.cyou/",
]

df = pd.read_csv(TRAIN_FILE)
df["url"] = df["url"].astype(str)

for target in targets:
    target_host = target.split("://", 1)[-1].split("/", 1)[0]
    target_parts = set(target_host.lower().replace(".", "-").split("-"))

    df["host"] = (
        df["url"].str.replace(r"^https?://", "", regex=True)
        .str.split("/").str[0].str.lower()
    )

    df["url_length"] = df["url"].str.len()
    df["shared_parts"] = df["host"].apply(
        lambda host: len(
            target_parts & set(host.replace(".", "-").split("-"))
        )
    )

    candidates = df[
        (df["shared_parts"] > 0) |
        ((df["url_length"] - len(target)).abs() <= 5)
    ].copy()

    candidates = candidates.sort_values(
        ["shared_parts", "url_length"],
        ascending=[False, True]
    )

    print("\n" + "=" * 70)
    print("TARGET:", target)
    print("Closest training examples:")

    print(
        candidates[["url", "label", "source"]]
        .head(10)
        .to_string(index=False)
    )
