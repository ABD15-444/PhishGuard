
from ml_features import extract_url_features

urls = [
    "https://www.paypal-banking.pro",
    "https://paypal-banking.pro/",
    "https://paypal.me/",
    "https://fide-litiy.cyou/",
    "https://fide-lltny.cyou/",
]

for url in urls:
    print("\n" + "=" * 65)
    print("URL:", url)

    features = extract_url_features(url)

    for name, value in features.items():
        print(f"{name:30} {value}")
