#!/usr/bin/env python3
"""
Value Counter Script
Master Thesis: Record Linkage with Match Key Algorithms - Is it secure?
Author: Babett Müller

This script counts distinct (non-NA) values per column in a CSV file.
The results are printed to the console.

Usage:
    python3 scripts/valuecounter.py --infile input.csv [--chunksize 50000] [--sample 5]
"""

import argparse
import os
import sys
import pandas as pd

# Function to count distinct values
def count_distinct_values(csv_path: str, chunksize: int = 0, sample: int = 0):
    # Check if file exists
    if not os.path.isfile(csv_path):
        print(f"File not found: {csv_path}", file=sys.stderr)
        sys.exit(1)

    # Non-chunked mode
    if not chunksize:
        # Read entire file
        df = pd.read_csv(csv_path, low_memory=False)
        results = {}
        # Count distinct values per column
        for col in df.columns:
            distinct = df[col].dropna().unique()
            # Store results
            results[col] = {
                "distinct_count": len(distinct),
                "sample_values": list(distinct[:sample]) if sample else None
            }
        print_report(results, csv_path)
        return

    # Chunked mode
    distinct_sets = {}
    # Read file in chunks
    for chunk in pd.read_csv(csv_path, chunksize=chunksize, low_memory=False):
        # Update distinct sets per column
        for col in chunk.columns:
            s = chunk[col].dropna()
            if not len(s):
                continue
            # Initialize set if not present
            distinct_sets.setdefault(col, set()).update(s.tolist())

    # Compile final results
    results = {
        col: {
            "distinct_count": len(values),
            "sample_values": (list(values)[:sample]) if sample else None
        }
        for col, values in distinct_sets.items()
    }
    print_report(results, csv_path)

# Function to print the report
def print_report(results: dict, csv_path: str):
    print(f"Distinct value counts for: {csv_path}")
    if not results:
        print("No columns found.")
        return
    width = max(len(col) for col in results.keys())
    header = f"{'Column'.ljust(width)}  Distinct"
    print(header)
    print("-" * len(header))
    for col, meta in results.items():
        print(f"{col.ljust(width)}  {meta['distinct_count']}")
        if meta.get("sample_values") is not None:
            print(f"  sample: {meta['sample_values']}")

# Argument parsing
def parse_args():
    p = argparse.ArgumentParser(description="Count distinct (non-NA) values per column in a CSV file.")
    p.add_argument("--infile", help="Path to CSV file.")
    p.add_argument("--chunksize", type=int, default=0, help="Read file in chunks (e.g. 50000). 0 = read whole file.")
    p.add_argument("--sample", type=int, default=0, help="Show up to N sample distinct values per column.")
    return p.parse_args()

def main():
    args = parse_args()
    count_distinct_values(
        csv_path=args.infile,
        chunksize=args.chunksize,
        sample=args.sample
    )

if __name__ == "__main__":
    main()