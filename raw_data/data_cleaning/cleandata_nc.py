import pandas as pd
import re
from gender_guesser.detector import Detector
import numpy as np

# Load a sample of the voter dataset
file_path = r"ncvoter_Statewide.txt"
# df = pd.read_csv(file_path)
df = pd.read_csv(file_path, delimiter="\t", dtype=str, encoding="ISO-8859-1")
# df = pd.read_csv(file_path, dtype={"zip": str, "phone": str})

# Select relevant columns
df_copy = df[[
    "first_name",
    "last_name",
    "birth_year",
    "zip_code",
    "res_street_address",
    "gender_code"
]]

df_new = df_copy.rename(columns={
    "res_street_address": "address",
    "zip_code": "zip",
    "gender_code": "sex",
    "birth_year": "year_of_birth"
})

############################
# Helper Functions
############################

# Replace German special characters with ASCII equivalents
"""def replace_german_chars(s):
    if isinstance(s, str):
        s = s.replace("ä", "ae").replace("ö", "oe").replace("ü", "ue")
        s = s.replace("Ä", "Ae").replace("Ö", "Oe").replace("Ü", "Ue")
        s = s.replace("ß", "ss")
    return s"""

# Normalize common German abbreviations in addresses
address_replacements = {
    "rd": "road",
    "st": "street",
    "ave": "avenue",
    "blvd": "boulevard",
    "ln": "lane",
    "dr": "drive",
    "ct": "court",
    "pl": "place",
    "hwy": "highway",
    "pkwy": "parkway",
    "trl": "trail",
    "sq": "square",
    "cir": "circle"
}
_STREET_ABBR = set(address_replacements.keys())
_STREET_FULL = set(address_replacements.values())
_STREET_TERMINATORS = _STREET_ABBR | _STREET_FULL

def normalize_address(address):
    if pd.isna(address):
        return ""
    s = str(address).lower()
    s = re.sub(r"[.,/#]", " ", s)
    s = re.sub(r"\s+", " ", s).strip()
    if not s:
        return ""
    tokens = re.findall(r"[0-9a-z]+", s)
    truncated = []
    for t in tokens:
        if re.match(r"\d+st$", t):  # keep ordinals like 1st, 21st as non-terminators
            truncated.append(t)
            continue
        truncated.append(t)
        if t in _STREET_TERMINATORS:
            break
    # expand abbreviations inside truncated list
    expanded = []
    for t in truncated:
        if re.match(r"\d+st$", t):
            expanded.append(t)
        else:
            expanded.append(address_replacements.get(t, t))
    return " ".join(expanded)

def normalize_sex(s: str) -> str:
    s = s.strip().lower()
    if s in ["m", "male"]:
        return "m"
    elif s in ["f", "female"]:
        return "f"
    return "u"

############################
# Data Cleaning
############################

# Remove entries with missing values
df_new = df_new.dropna()

# Remove duplicates
df_new = df_new.drop_duplicates()

# Adjust sex
df_new["sex"] = df_new["sex"].apply(normalize_sex)

# Adjust addresses
df_new["address"] = df_new["address"].apply(normalize_address)

# Adjust zip
df_new["zip"] = pd.to_numeric(df_new["zip"], errors="coerce").astype('Int64').astype(str).str.strip().str.lower()

# Add birthday
if "dob" not in df_new.columns or df_new["dob"].isnull().any():
    print("Generating 'dob' values for missing entries based on DOB distribution in Ohio...")
    ohio_dob_path = r"ohio_cleaned.csv"
    df_ohio = pd.read_csv(ohio_dob_path, delimiter=",", quotechar='"', dtype=str, encoding="utf-8")

    # Build normalized DOB distribution (YYYYMMDD) then reduce to MMDD
    dob_series = (
        df_ohio["dob"].astype(str)
        .str.replace(r"[^0-9]", "", regex=True)
        .str.slice(0, 8)
    )
    dob_series = dob_series[dob_series.str.len() == 8]
    mmdd_series = dob_series.str[-4:]
    mmdd_dist = mmdd_series.value_counts(normalize=True)
    mmdd_values = mmdd_dist.index.to_numpy()
    mmdd_probs = mmdd_dist.values

    # Prepare target mask and valid years
    if "dob" not in df_new.columns:
        # initialize as string dtype to avoid float->string assignment warning
        df_new["dob"] = pd.Series(pd.NA, index=df_new.index, dtype="string")
    else:
        # ensure string dtype before filling
        df_new["dob"] = df_new["dob"].astype("string")
    missing_mask = df_new["dob"].isna() | (df_new["dob"].astype(str).str.strip() == "")

    # Clean year_of_birth to 4 digits
    yob_clean = (
        df_new["year_of_birth"].astype(str)
        .str.extract(r"(\d{4})")[0]
    )
    valid_yob_mask = yob_clean.notna() & yob_clean.str.fullmatch(r"\d{4}")

    target_mask = missing_mask & valid_yob_mask
    n = int(target_mask.sum())
    if n > 0:
        sampled_mmdd = np.random.choice(mmdd_values, size=n, p=mmdd_probs)
        years = yob_clean[target_mask].to_numpy()

        # Fix leap-day 0229 for non-leap years -> 0228
        years_i = years.astype(int, copy=False)
        is_leap = ((years_i % 4 == 0) & ((years_i % 100 != 0) | (years_i % 400 == 0)))
        bad_0229 = (sampled_mmdd == "0229") & (~is_leap)
        if bad_0229.any():
            sampled_mmdd[bad_0229] = "0228"

        idx = df_new.index[target_mask]
        df_new.loc[idx, "dob"] = pd.Series(years + sampled_mmdd, index=idx, dtype="string")
else:
    print("'dob' column already exists and has no missing values.")

# Normalize dob to 8-digit string
df_new["dob"] = (
    df_new["dob"].astype(str)
    .str.replace(r"[^0-9]", "", regex=True)
    .str.slice(0, 8)
)

# Extract the birth year from the date of birth (fill only missing/blank)
if "year_of_birth" in df_new.columns:
    ymask = df_new["year_of_birth"].isna() | (df_new["year_of_birth"].astype(str).str.strip() == "")
    df_new.loc[ymask & df_new["dob"].notna(), "year_of_birth"] = df_new.loc[ymask, "dob"].str[:4]

df_new["address"] = df_new["address"].replace(r"(?i)^removed$", "", regex=True).str.lower()
df_new["address"] = df_new["address"].str.replace(r"#\s*\w+", "", regex=True)
df_new["address"] = df_new["address"].apply(lambda x: " ".join(x.split()) if isinstance(x, str) else x)
df_new["last_name"] = df_new["last_name"].str.replace("#", "", regex=False)

# Optional: Strip whitespace and standardize formatting
df_new["first_name"] = df_new["first_name"].str.strip().str.lower()
df_new["last_name"] = df_new["last_name"].str.strip().str.lower()
df_new["address"] = df_new["address"].str.strip().str.lower()
df_new["zip"] = df_new["zip"].fillna("").astype(str).str.strip().str.lower()

############################
# Save to File
############################

# Save the cleaned version
output_path = r"nc_cleaned.csv"
df_new.to_csv(output_path, index=False, encoding="utf-8")