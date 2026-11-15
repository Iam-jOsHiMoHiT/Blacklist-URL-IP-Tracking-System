import pandas as pd
import joblib
import ipaddress

from urllib.parse import urlparse

from sklearn.model_selection import train_test_split
from sklearn.pipeline import Pipeline
from sklearn.preprocessing import StandardScaler
from sklearn.impute import SimpleImputer
from sklearn.linear_model import LogisticRegression

from sklearn.metrics import (
    accuracy_score,
    classification_report,
    confusion_matrix
)


import os
HERE = os.path.dirname(os.path.abspath(__file__))

df = pd.read_csv(os.path.join(HERE, "rawurl.csv"))

print("Dataset:")
print(df.head())

print("\nDataset Information:")
print(df.info())


df = df.dropna(subset=["URL", "label"])

df["URL"] = df["URL"].astype(str).str.strip()

df = df[df["URL"] != ""]

df = df.drop_duplicates(subset=["URL"])

df["label"] = df["label"].astype(int)

print("\nCleaned Dataset:")
print(df.head())

print("\nLabel Distribution:")
print(df["label"].value_counts())


def extract_features(url):

    url = str(url).strip()

    parsed = urlparse(url)

    domain = parsed.hostname or ""
    path = parsed.path or ""


    try:
        ipaddress.ip_address(domain)
        has_ip = 1
    except ValueError:
        has_ip = 0


    digit_count = sum(c.isdigit() for c in url)


    special_count = sum(not c.isalnum() for c in url)


    words = [
        "login", "verify", "secure",
        "update", "password", "bank"
    ]

    suspicious_count = sum(
        word in url.lower() for word in words
    )

    return {

        "url_length": len(url),

        "https": int(url.lower().startswith("https://")),

        "http": int(url.lower().startswith("http://")),

        "dot_count": url.count("."),

        "digit_count": digit_count,

        "hyphen_count": url.count("-"),

        "has_ip": has_ip,

        "at_count": url.count("@"),

        "path_length": len(path),

        "special_count": special_count,

        "suspicious_count": suspicious_count
    }


features = df["URL"].apply(extract_features)


X = pd.DataFrame(features.tolist())

y = df["label"]

print("\nExtracted Features:")
print(X.head())


X_train, X_test, y_train, y_test = train_test_split(

    X,
    y,

    test_size=0.20,

    random_state=42,

    stratify=y
)

print("\nTraining Data:", len(X_train))
print("Testing Data:", len(X_test))


model = Pipeline([

    ("imputer", SimpleImputer(strategy="median")),

    ("scaler", StandardScaler()),

    ("classifier", LogisticRegression(
        max_iter=1000,
        class_weight="balanced"
    ))

])


model.fit(X_train, y_train)

print("\nModel Training Completed!")


y_pred = model.predict(X_test)

print("\nAccuracy:")
print(accuracy_score(y_test, y_pred))

print("\nClassification Report:")
print(classification_report(
    y_test,
    y_pred,
    zero_division=0
))

print("\nConfusion Matrix:")
print(confusion_matrix(y_test, y_pred))


joblib.dump(model, "url_model.pkl")

print("\nModel Saved Successfully!")


imputer = model.named_steps["imputer"]
scaler = model.named_steps["scaler"]
classifier = model.named_steps["classifier"]

with open(os.path.join(HERE, "ml_weights.txt"), "w") as out:
    out.write("# URL spam model exported by url_ml.py - class 1 = legitimate, class 0 = spam\n")
    out.write("# name  median  mean  scale  weight\n")
    for i, name in enumerate(X.columns):
        out.write("%s %.17g %.17g %.17g %.17g\n" % (
            name,
            imputer.statistics_[i],
            scaler.mean_[i],
            scaler.scale_[i],
            classifier.coef_[0][i]))
    out.write("intercept %.17g\n" % classifier.intercept_[0])

print("Weights exported to ml_weights.txt")


def predict_url(url):


    features = extract_features(url)


    input_data = pd.DataFrame([features])


    prediction = model.predict(input_data)[0]


    probabilities = model.predict_proba(input_data)[0]

    classes = model.classes_

    print("\nURL:", url)

    if prediction == 0:
        print("Result: SPAM / MALICIOUS")
    else:
        print("Result: LEGITIMATE")

    print("Spam Probability:",
          round(probabilities[list(classes).index(0)], 3))

    print("Legitimate Probability:",
          round(probabilities[list(classes).index(1)], 3))


predict_url("https://www.google.com")

predict_url("https://www.youtube.com")

predict_url("http://fake-login-bank-example.com")
