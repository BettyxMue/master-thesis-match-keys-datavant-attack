import argparse
import pandas as pd

def process_file(input_path: str, output_path: str):
    df = pd.read_csv(input_path, delimiter=",", quotechar='"', dtype=str, encoding="utf-8")

    # Select relevant columns
    if all(col in df.columns for col in ["first_name","last_name","dob","year_of_birth","zip","address","gender"]):
        df_new = df[[
            "first_name",
            "last_name",
            "dob",
            "year_of_birth",
            "zip",
            "address",
            "gender"
        ]].copy()
    elif all(col in df.columns for col in ["first_name","last_name","dob","zip","address","sex"]):
        df_new = df[[
            "first_name",
            "last_name",
            "dob",
            "zip",
            "address",
            "sex"
        ]].copy()

    ############################
    # Data Cleaning
    ############################

    # Replace DOB with fixed value
    df_new["dob"] = "20000101"
    df_new["year_of_birth"] = "2000"

    # Save the cleaned version
    df_new.to_csv(output_path, index=False, encoding="utf-8")

def main():
    ap = argparse.ArgumentParser(description='Replace DOB with fixed value.')
    ap.add_argument('--input', '-i', required=True, help='Path to input CSV')
    ap.add_argument('--output', '-o', required=True, help='Path to output CSV')
    args = ap.parse_args()
    process_file(args.input, args.output)

if __name__ == '__main__':
    main()