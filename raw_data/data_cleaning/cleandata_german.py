import pandas as pd
import re
import random

# Load a sample of the voter dataset
file_path = r"known_data_new_50000.csv"
df = pd.read_csv(file_path)

# Select relevant columns
df_new = df[[
    "first_name",
    "last_name",
    "dob",
    "year_of_birth",
    "gender",
    "zip",
    "address"
]].copy()

############################
# Helper Functions
############################

# Replace German special characters with ASCII equivalents
def replace_german_chars(s):
    if isinstance(s, str):
        s = s.replace("ä", "ae").replace("ö", "oe").replace("ü", "ue")
        s = s.replace("Ä", "Ae").replace("Ö", "Oe").replace("Ü", "Ue")
        s = s.replace("ß", "ss")
    return s

# Normalize common German abbreviations in addresses
address_replacements = {
    "str.": "strasse",
    "nr.": "nummer"
}

def normalize_address(address):
    for abbr, full in address_replacements.items():
        address = address.replace(abbr, full)
    return address.strip().lower() if isinstance(address, str) else address

# Remove leading zeros from numbers in addresses
def remove_leading_zeros_from_address(address):
    return re.sub(r'\b0+(\d+)', r'\1', address) if isinstance(address, str) else address

# Process housenumber if greater than 1501 (Germany's biggstes housenumber in Cologne)
def process_housenumber(address):
    if not isinstance(address, str):
        return address
    # Find all numbers in the address
    matches = list(re.finditer(r'\d+', address))
    if not matches:
        return address
    # Only process the first number (assumed to be the housenumber)
    match = matches[0]
    num_str = match.group()
    try:
        num = int(num_str)
    except ValueError:
        return address
    if num > 1501:
        if len(num_str) >= 2:
            first_two = num_str[:2]
            if first_two[0] == '0':
                new_num = num_str[-2:]
            else:
                new_num = num_str[:2]
            address = address[:match.start()] + new_num
    if num == 0:
        new_num = str(random.randint(1, 501))
        address = address[:match.start()] + new_num
    return address

############################
# Data Cleaning
############################

# Remove entries with missing values
df_new = df_new.dropna()

# Remove duplicates
df_new = df_new.drop_duplicates()

# Normalize German characters and abbreviations
for col in ["first_name", "last_name", "address", "email"]:
    if col in df_new.columns:
        df_new[col] = df_new[col].apply(replace_german_chars)

# Adjust first names
df_new["first_name"] = df_new["first_name"].str.strip().str.replace("-", "").str.replace(" ", "").str.lower()

# Adjust last names
df_new["last_name"] = df_new["last_name"].str.replace("Beng", "", regex=False)
df_new["last_name"] = df_new["last_name"].str.strip().str.replace("-", "").str.replace(" ", "").str.lower()

# Adjust addresses
df_new["address"] = df_new["address"].apply(normalize_address)
df_new["address"] = df_new["address"].str.replace(
    r'\b(\d+)/(\d+)\b',
    lambda m: m.group(2) if int(m.group(1)) == 0 else m.group(1),
    regex=True
)
df_new["address"] = df_new["address"].str.replace(
    r'\b(\d+)-(\d+)\b',
    lambda m: m.group(2) if int(m.group(1)) == 0 else m.group(1),
    regex=True
)
df_new["address"] = df_new["address"].apply(remove_leading_zeros_from_address)
df_new["address"] = df_new["address"].apply(process_housenumber)
df_new["address"] = df_new["address"].str.strip().str.lower()

# Adjust phone number
if "phone" in df_new.columns:
    df_new["phone"] = df_new["phone"].str.replace("-", "", regex=False)
    df_new["phone"] = df_new["phone"].str.replace("(0)", "", regex=False)
    df_new["phone"] = df_new["phone"].str.replace("+49", "0", regex=False)
    df_new["phone"] = df_new["phone"].str.replace("(", "", regex=False)
    df_new["phone"] = df_new["phone"].str.replace(")", "", regex=False)
    df_new["phone"] = df_new["phone"].str.replace(" ", "", regex=False)
    df_new["phone"] = df_new["phone"].str.strip().str.lower()

# Adjust email addresses
if "email" in df_new.columns:
    df_new["email"] = df_new["email"].str.strip().str.lower()

# Extract the birth year from the date of birth
if df_new["year_of_birth"].empty and df_new["dob"].notna():
    df_new["year_of_birth"] = df_new["dob"].str[:4]

############################
# Save to File
############################

# Save the cleaned version
output_path = r"known_data_new_clean_50000.csv"
df_new.to_csv(output_path, index=False, encoding="utf-8")