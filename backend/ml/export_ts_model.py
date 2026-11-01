"""
backend/ml/export_ts_model.py
────────────────────────────────────────────────────────────────────────────
Exports the trained XGBoost model from backend/ml/model.joblib into a compact
JSON decision tree structure that can be evaluated directly in TypeScript/JS
inside the Chrome extension with zero Python and zero server dependencies.
"""

import json
from pathlib import Path
import joblib

ML_DIR = Path(__file__).resolve().parent
ROOT_DIR = ML_DIR.parent.parent
TARGET_TS_PATH = ROOT_DIR / "extension" / "background" / "ml" / "trainedModel.json"

def export_model():
    model_obj = joblib.load(ML_DIR / "model.joblib")
    clf = model_obj["model"]
    meta = model_obj["meta"]

    booster = clf.get_booster()
    dump = booster.get_dump(dump_format="json")
    trees = [json.loads(tree_str) for tree_str in dump]

    export_data = {
        "version": meta.get("version", "1.0.0"),
        "feature_names": meta.get("feature_names", []),
        "trees": trees,
        "base_score": 0.5,
    }

    TARGET_TS_PATH.parent.mkdir(parents=True, exist_ok=True)
    with open(TARGET_TS_PATH, "w", encoding="utf-8") as f:
        json.dump(export_data, f, separators=(",", ":"))

    print(f"[SafeClick] Exported {len(trees)} trees to {TARGET_TS_PATH} ({TARGET_TS_PATH.stat().st_size / 1024:.1f} KB)")

if __name__ == "__main__":
    export_model()
