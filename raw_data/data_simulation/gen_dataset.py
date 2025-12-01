import pandas as pd
import random
from faker import Faker
import re
from gender_guesser.detector import Detector
from datetime import datetime, timedelta

# Reinitialize Faker after kernel reset
fake = Faker('de_DE')   # Use German or US (en_US) locale

Faker.seed(1234)    # Set seed (1234), (4321) or (5678)
random.seed(1234)   # Set seed (1234), (4321) or (5678)

# Helper to normalize strings
def normalize(s):
    return re.sub(r'\W+', '', s.lower().strip()) if s else ""

# Function to clean and extract first and last names robustly
def extract_clean_names_robust(profile_name):
    # Define a list of common German and academic prefixes/titles
    known_titles = {
        "dr", "prof", "bsc", "msc", "ba", "ma", "mba", "b.eng", "m.eng", "dipl", "dipl-ing", "diplom",
        "mag", "med", "herr", "frau", "ing", "univprof"
    }

    # Clean punctuation, lowercase, and split
    parts = re.sub(r'[^\wäöüÄÖÜß\- ]+', '', profile_name.lower()).split()

    # Filter out titles and honorifics
    name_parts = [part for part in parts if part not in known_titles]

    # Assign names based on what's left
    if len(name_parts) == 0:
        return "", ""
    elif len(name_parts) == 1:
        return name_parts[0].capitalize(), ""
    else:
        # Heuristic: first name is the first part, last name is the rest
        first_name = name_parts[0].capitalize()
        last_name = " ".join([p.capitalize() for p in name_parts[1:]])
        return first_name, last_name

# Updated function to generate a single record with aligned sex
def generate_records():
    sex = random.choice(['M', 'F'])
    profile = fake.simple_profile(sex='M' if sex == 'M' else 'F')

    # Extract clean first and last name
    first_name, last_name = extract_clean_names_robust(profile['name'])

    # Adjust sex based on first name
    detector = Detector()
    # Check if the first name includes whitespace or '-'
    if '-' in first_name:
        first_name_part = first_name.split('-')[0]
    elif ' ' in last_name:
        first_name_part = first_name.split(' ')[0]
    else:
        first_name_part = first_name

    # Use the first part of the name for sex detection
    guess = detector.get_sex(first_name_part)
    if guess == 'male' or guess == "mostly male":
        sex = 'M'
    elif guess == 'female' or guess == "mostly female":
        sex = 'F'
    else:
        sex = 'U' # unknown

    # Generate a birthdate between 18 and 80 years before January 1st of this year
    min_age = 18    # adjust min year for age
    max_age = 80    # adjust max year for age
    random_birthdate = fake.date_of_birth(minimum_age=min_age, maximum_age=max_age)
    dob = random_birthdate.strftime('%Y%m%d')
    year_of_birth = random_birthdate.strftime('%Y')

    """ # Generate email aligned with first and last name but with randomization
    email_domains = ["example.com", "mail.com", "test.org"]
    random_domain = random.choice(email_domains)
    email = f"{normalize(first_name)}.{normalize(last_name)}{random.randint(1, 99)}@{random_domain}" """

    """# email = fake.email()
    email = profile['mail']
    phone = fake.phone_number()"""

    postcode = fake.postcode()
    address = fake.street_address()

    return {
        "first_name": first_name,
        "last_name": last_name,
        "dob": dob,
        "year_of_birth": year_of_birth,
        "sex": sex,
        "zip": postcode,
        "address": address
    }

# Generate records
records = [generate_records() for _ in range(50000)]
df = pd.DataFrame(records)

# Save to CSV
csv_path = "known_data_new_50000.csv"
df.to_csv(csv_path, index=False)