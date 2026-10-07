"""Train the RandomForest attack classifier.

Run from the repository root:
    python -m member2_detection_engine.train_model
"""
import os

import joblib
import pandas as pd
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import (accuracy_score, classification_report, confusion_matrix,
                             precision_recall_fscore_support)
from sklearn.model_selection import train_test_split

from .feature_extractor import FEATURE_NAMES, features_to_vector

HERE = os.path.dirname(os.path.abspath(__file__))
DATASET_PATH = os.path.join(HERE, "dataset.csv")
MODEL_PATH = os.path.join(HERE, "model", "attack_detection_model.pkl")
LABELS = ["NORMAL", "SQL_INJECTION", "XSS", "BRUTE_FORCE", "API_ABUSE"]
RANDOM_STATE = 42


def load_dataset(path=DATASET_PATH):
    df = pd.read_csv(path, keep_default_na=False)
    X = [features_to_vector(rec) for rec in df.drop(columns=["label"]).to_dict("records")]
    return pd.DataFrame(X, columns=FEATURE_NAMES), df["label"]


def train(save=True, verbose=True):
    X, y = load_dataset()
    # split BEFORE fitting anything -> no leakage (no scaler / selection is fitted on test data)
    X_tr, X_te, y_tr, y_te = train_test_split(X, y, test_size=0.2, stratify=y, random_state=RANDOM_STATE)
    clf = RandomForestClassifier(n_estimators=200, max_depth=14, min_samples_leaf=2,
                                 class_weight="balanced", random_state=RANDOM_STATE, n_jobs=1)
    clf.fit(X_tr, y_tr)
    pred = clf.predict(X_te)
    p, r, f1, _ = precision_recall_fscore_support(y_te, pred, average="weighted", zero_division=0)
    metrics = {"accuracy": accuracy_score(y_te, pred), "precision": p, "recall": r, "f1": f1,
               "train_size": len(X_tr), "test_size": len(X_te)}
    if verbose:
        print("Dataset: %d rows | train=%d test=%d" % (len(X), len(X_tr), len(X_te)))
        print("Accuracy : %.4f" % metrics["accuracy"])
        print("Precision: %.4f (weighted)" % p)
        print("Recall   : %.4f (weighted)" % r)
        print("F1 score : %.4f (weighted)\n" % f1)
        print(classification_report(y_te, pred, labels=LABELS, digits=3, zero_division=0))
        print("Confusion matrix (rows=true, cols=pred; order=%s)" % LABELS)
        print(confusion_matrix(y_te, pred, labels=LABELS))
        top = sorted(zip(FEATURE_NAMES, clf.feature_importances_), key=lambda t: -t[1])[:8]
        print("\nTop features:", ", ".join("%s=%.3f" % t for t in top))
    if save:
        os.makedirs(os.path.dirname(MODEL_PATH), exist_ok=True)
        joblib.dump({"model": clf, "feature_names": FEATURE_NAMES, "labels": list(clf.classes_),
                     "metrics": metrics}, MODEL_PATH)
        if verbose:
            print("\nModel saved -> %s" % MODEL_PATH)
    return clf, metrics


if __name__ == "__main__":
    train()
