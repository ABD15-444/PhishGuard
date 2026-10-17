
from ml_features import extract_url_features

urls = [
    "https://olxhit.com/",
    "https://transparenzregister.cc/",
    "https://www.wikipedia.org/",
    "https://paypal.example/login/verify-account",
]

for url in urls:
    print("\n" + "=" * 70)
    print("URL:", url)

    features = extract_url_features(url)

    for name, value in features.items():
        print(f"{name:30} {value}")
