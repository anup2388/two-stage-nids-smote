"""Build combined_dataset.csv from the cleaned CSE-CIC-IDS2018 release on Mendeley Data.

Source data
    Mohamed, A. (2024). CSE-CIC-IDS2018 [Data set]. Mendeley Data, V1.
    https://doi.org/10.17632/29hdbdzx2r.1  (licence: CC BY 4.0)
    A cleaned version of CSE-CIC-IDS2018 (Sharafaldin et al., ICISSP 2018), distributed as one
    CSV file per attack class.

Steps
    1. Download "CSE-CIC-IDS2018.zip" from https://data.mendeley.com/datasets/29hdbdzx2r/1
    2. Extract it.
    3. python build_dataset.py --src <extracted folder> --out combined_dataset.csv

    Optional: --compare <existing combined_dataset.csv> checks whether an existing file holds the
    same rows in the same order (row order determines the train/test split).

What the script does
    * concatenates the 14 CSV files in sorted file-name order, with no other change;
    * reports rows, columns and labels per file, and duplicate rows within and across files;
    * prints a content fingerprint computed exactly as the pipeline computes `input_fingerprint`
      (preprocessing_log.json), so a rebuilt file can be matched to a reported run.

The reported run used a file with 9,625,148 rows and 79 columns (78 features + Label).
Memory: about 15 GB of RAM for the build, about 20 GB with --compare.
"""
import argparse
import glob
import hashlib
import os
import sys

import numpy as np
import pandas as pd

EXPECTED_FILES = sorted([
    "Bot.csv", "Brute Force -Web.csv", "Brute Force -XSS.csv", "DDOS attack-HOIC.csv",
    "DDOS attack-LOIC-UDP.csv", "DDoS attacks-LOIC-HTTP.csv", "DoS attacks-GoldenEye.csv",
    "DoS attacks-Hulk.csv", "DoS attacks-SlowHTTPTest.csv", "DoS attacks-Slowloris.csv",
    "FTP-BruteForce.csv", "Infilteration.csv", "SQL Injection.csv", "SSH-Bruteforce.csv",
])
EXPECTED_ROWS, EXPECTED_COLS = 9_625_148, 79
LABEL_COL = "Label"


def read_like_pipeline(path):
    """Read a CSV exactly as the pipeline does."""
    df = pd.read_csv(path, low_memory=False)
    df.columns = df.columns.str.strip()
    return df


def row_hashes(df):
    return pd.util.hash_pandas_object(df, index=False).values


def fingerprint(df):
    return hashlib.sha256(row_hashes(df).tobytes()).hexdigest()


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--src", required=True, help="folder with the extracted Mendeley CSV files")
    ap.add_argument("--out", default="combined_dataset.csv")
    ap.add_argument("--compare", help="existing combined_dataset.csv to compare with the rebuilt file")
    a = ap.parse_args()

    found = {os.path.basename(p): p for p in glob.glob(os.path.join(a.src, "**", "*.csv"), recursive=True)}
    missing = [f for f in EXPECTED_FILES if f not in found]
    extra = sorted(set(found) - set(EXPECTED_FILES))
    if missing:
        sys.exit(f"Missing files: {missing}")
    if extra:
        print(f"Ignoring files not in the Mendeley release: {extra}")

    frames, rows = [], []
    for name in EXPECTED_FILES:                      # sorted file-name order
        df = read_like_pipeline(found[name])
        if frames and list(df.columns) != list(frames[0].columns):
            if sorted(df.columns) != sorted(frames[0].columns):
                sys.exit(f"{name}: columns differ from {EXPECTED_FILES[0]}")
            print(f"{name}: same columns in a different order; reordered to match")
            df = df[frames[0].columns]
        h = row_hashes(df)
        labels = df[LABEL_COL].value_counts()
        rows.append({"file": name, "rows": len(df), "cols": df.shape[1],
                     "dup_rows_within_file": int(len(h) - len(np.unique(h))),
                     "labels": "; ".join(f"{k}={v}" for k, v in labels.items())})
        frames.append(df)
        print(f"read {name:30s} {len(df):>10,} rows")

    combined = pd.concat(frames, ignore_index=True)
    del frames
    h_all = row_hashes(combined)
    n_unique = len(np.unique(h_all))
    dup_total = len(h_all) - n_unique
    dup_within = sum(r["dup_rows_within_file"] for r in rows)

    report = pd.DataFrame(rows)
    pd.set_option("display.width", 200, "display.max_colwidth", 120)
    print("\nPer-file summary:\n" + report.drop(columns="labels").to_string(index=False))
    print("\nLabels per file:\n" + report[["file", "labels"]].to_string(index=False))
    print(f"\nTotal rows: {len(combined):,}   columns: {combined.shape[1]}")
    print(f"Exact duplicate rows: {dup_total:,}  (within files: {dup_within:,}; "
          f"only across files: {dup_total - dup_within:,})")
    print("Label counts (before the pipeline removes duplicates):")
    print(combined[LABEL_COL].value_counts().to_string())
    if (len(combined), combined.shape[1]) != (EXPECTED_ROWS, EXPECTED_COLS):
        print(f"WARNING: expected {EXPECTED_ROWS:,} rows x {EXPECTED_COLS} columns as in the reported run.")

    combined.to_csv(a.out, index=False)
    report.to_csv(os.path.splitext(a.out)[0] + "_build_report.csv", index=False)
    del combined
    rebuilt = read_like_pipeline(a.out)          # fingerprint exactly as the pipeline sees the file
    fp_new = fingerprint(rebuilt)
    print(f"\nWrote {a.out}")
    print(f"input_fingerprint (rebuilt): {fp_new}")

    if a.compare:
        old = read_like_pipeline(a.compare)
        fp_old = fingerprint(old)
        print(f"input_fingerprint (compare): {fp_old}")
        if fp_old == fp_new:
            print("MATCH: same rows in the same order. The pipeline will reproduce the reported split.")
        elif old.shape == rebuilt.shape and list(old.columns) == list(rebuilt.columns) and \
                np.array_equal(np.sort(row_hashes(old)), np.sort(row_hashes(rebuilt))):
            print("SAME ROWS, DIFFERENT ORDER: the stratified split, and so the exact numbers, will differ.")
        else:
            print(f"DIFFERENT CONTENT: compare {old.shape} vs rebuilt {rebuilt.shape}; "
                  f"columns equal: {list(old.columns) == list(rebuilt.columns)}")


if __name__ == "__main__":
    main()
