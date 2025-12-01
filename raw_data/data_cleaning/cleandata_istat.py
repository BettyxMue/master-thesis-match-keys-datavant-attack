import pandas as pd
import argparse
import re
import random
import unicodedata

# New helper: normalize and transliterate names
def normalize_name(s: str) -> str:
    if not s:
        return ""
    s = s.strip().lower()
    # specific replacements
    repl = {
        "ä": "ae", "ö": "oe", "ü": "ue",
        "ß": "ss"
    }
    out = []
    for ch in s:
        if ch in repl:
            out.append(repl[ch])
        else:
            # strip diacritics
            decomposed = unicodedata.normalize("NFKD", ch)
            ascii_chars = "".join(c for c in decomposed if not unicodedata.combining(c))
            # keep only alphanum / space
            ascii_chars = re.sub(r"[^a-z0-9 ]", "", ascii_chars)
            out.append(ascii_chars)
    cleaned = "".join(out)
    # collapse internal spaces
    cleaned = re.sub(r"\s+", "", cleaned)
    return cleaned

def normalize_address(s: str) -> str:
    if not s:
        return ""
    s = s.strip().lower()
    # simple collapse of whitespace
    s = re.sub(r"\s+", " ", s)
    return s

def normalize_sex(s: str) -> str:
    s = s.strip().lower()
    if s in ["m", "male"]:
        return "m"
    elif s in ["f", "female"]:
        return "f"
    return "u"

def process_file(input_path: str, output_path: str, fillyear: bool):
    df = pd.read_csv(input_path, delimiter=",", quotechar='"', dtype=str, encoding="utf-8")
    # Ensure expected columns exist
    required = ["PERNAME1","PERNAME2","DOB_DAY","DOB_MON","DOB_YEAR","ENUMCAP","SEX"]
    missing = [c for c in required if c not in df.columns]
    if missing:
        raise ValueError(f"Missing required columns: {missing}")

    # Clean / rename
    first = df["PERNAME1"].fillna("").apply(normalize_name)
    last = df["PERNAME2"].fillna("").apply(normalize_name)

    # Vectorized Y/M/D handling
    year_raw = df["DOB_YEAR"].fillna("").astype(str).str.strip()
    if fillyear:
        year = year_raw.copy()
        missing_y = year.eq("")
        if missing_y.any():
            year.loc[missing_y] = [f"{random.randint(1945, 2007):04d}" for _ in range(int(missing_y.sum()))]
    else:
        year = year_raw
    # keep empty if no digits; otherwise zero-pad
    year_digits = year.str.extract(r"(\d{1,4})")[0].fillna("")
    year = year_digits.str.zfill(4).where(year_digits.ne(""), "")

    month_raw = df["DOB_MON"].fillna("").astype(str).str.strip()
    month_digits = month_raw.str.extract(r"(\d{1,2})")[0].fillna("")
    month = month_digits.str.zfill(2).where(month_digits.ne(""), "")

    day_raw = df["DOB_DAY"].fillna("").astype(str).str.strip()
    day_digits = day_raw.str.extract(r"(\d{1,2})")[0].fillna("")
    day = day_digits.str.zfill(2).where(day_digits.ne(""), "")

    # Only form dob when all parts present
    valid_dob = (year.ne("")) & (month.ne("")) & (day.ne(""))
    dob = pd.Series([""] * len(df), index=df.index, dtype="object")
    dob.loc[valid_dob] = year.loc[valid_dob] + month.loc[valid_dob] + day.loc[valid_dob]

    address = df["ENUMCAP"].fillna("").apply(normalize_address)
    sex = df["SEX"].fillna("").str.strip().str.lower().apply(normalize_sex)

    # Assign stable random ZIP per distinct address
    address_to_zip = {}
    def get_zip(a: str) -> str:
        if a not in address_to_zip:
            address_to_zip[a] = f"{random.randint(1067, 99991):05d}"
        return address_to_zip[a]
    zip_codes = address.apply(get_zip)

    # remove empty records (require dob built)
    non_empty = (first != "") & (last != "") & (dob != "") & (address != "")
    first = first[non_empty]
    last = last[non_empty]
    dob = dob[non_empty]
    address = address[non_empty]
    zip_codes = zip_codes[non_empty]
    sex = sex[non_empty]
    yob = year[non_empty]

    out = pd.DataFrame({
        "first_name": first,
        "last_name": last,
        "dob": dob,
        "yob": yob,
        "address": address,
        "zip": zip_codes,
        "sex": sex
    })
    out.to_csv(output_path, index=False)

def main():
    ap = argparse.ArgumentParser(description='Clean dataset and normalize.')
    ap.add_argument('--input', '-i', required=True, help='Path to input CSV')
    ap.add_argument('--output', '-o', required=True, help='Path to output CSV')
    ap.add_argument('--fillyear', action='store_true', help='Fill missing year with random YOB between 1945 and 2007')
    args = ap.parse_args()
    process_file(args.input, args.output, args.fillyear)

if __name__ == "__main__":
    main()