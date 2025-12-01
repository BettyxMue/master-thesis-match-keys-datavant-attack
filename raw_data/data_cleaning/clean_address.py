import argparse
from pathlib import Path
import sys
import pandas as pd

SUPPORTED_EXTS = {".csv", ".xlsx", ".xls", ".parquet"}

def load_df(path: Path, string_columns=None) -> pd.DataFrame:
    ext = path.suffix.lower()
    sc = list(string_columns) if string_columns else []
    if ext == ".csv":
        return pd.read_csv(path, dtype=({c: "string" for c in sc} if sc else None))
    if ext in {".xlsx", ".xls"}:
        # Use converters to ensure text cells (independent of pandas version)
        converters = {c: (lambda x: None if pd.isna(x) else str(x)) for c in sc} if sc else None
        return pd.read_excel(path, converters=converters)
    if ext == ".parquet":
        df = pd.read_parquet(path)
        if sc:
            for c in sc:
                if c in df.columns:
                    df[c] = df[c].astype("string")
        return df
    raise ValueError(f"Unsupported input extension: {ext}")

def save_df(df: pd.DataFrame, path: Path) -> None:
    ext = path.suffix.lower()
    if ext == ".csv":
        df.to_csv(path, index=False)
    elif ext in {".xlsx", ".xls"}:
        df.to_excel(path, index=False)
    elif ext == ".parquet":
        df.to_parquet(path, index=False)
    else:
        raise ValueError(f"Unsupported output extension: {ext}")

def compute_output_path(inp: Path) -> Path:
    return inp.with_name(f"{inp.stem}.cleaned{inp.suffix}")

def clean_addresses(df: pd.DataFrame, col: str) -> pd.DataFrame:
    if col not in df.columns:
        raise KeyError(f"Column '{col}' not found.")
    s = df[col].astype(str)
    # Remove all digits, collapse multiple spaces, and trim
    s = s.str.replace(r"\d+", "", regex=True).str.replace(r"\s+", " ", regex=True).str.strip()
    df[col] = s
    return df

def parse_args():
    p = argparse.ArgumentParser(description="Remove numbers from an address column and keep only street names.")
    p.add_argument("--input", type=Path, help="Input file (.csv, .xlsx, .xls, .parquet)")
    p.add_argument("-o", "--output", type=Path, help="Output file path (defaults to <input>.cleaned<ext>)")
    p.add_argument("-c", "--column", default="address", help="Column name to clean (default: address)")
    p.add_argument("--inplace", action="store_true", help="Overwrite the input file in place")
    # New: force columns to be treated as strings on read, e.g., -S birth_year
    p.add_argument("-S", "--string-columns", nargs="+", help="Columns to force to string dtype when reading")
    return p.parse_args()

def main():
    args = parse_args()
    if not args.input.exists():
        print(f"Input not found: {args.input}", file=sys.stderr)
        sys.exit(1)
    if args.input.suffix.lower() not in SUPPORTED_EXTS:
        print(f"Unsupported input extension: {args.input.suffix}", file=sys.stderr)
        sys.exit(1)
    if args.inplace and args.output:
        print("Use either --inplace or --output, not both.", file=sys.stderr)
        sys.exit(1)

    out_path = args.input if args.inplace else (args.output or compute_output_path(args.input))
    if out_path.suffix.lower() not in SUPPORTED_EXTS:
        print(f"Unsupported output extension: {out_path.suffix}", file=sys.stderr)
        sys.exit(1)

    df = load_df(args.input, string_columns=args.string_columns)
    try:
        df = clean_addresses(df, args.column)
    except KeyError as e:
        print(str(e), file=sys.stderr)
        sys.exit(1)

    save_df(df, out_path)
    print(f"Saved: {out_path}")

if __name__ == "__main__":
    main()
