import json
import csv
import argparse

def extract_fields(entry):
    csv_entry = []
    
    ip = entry["ip"]
    csv_entry.append(ip)
    
    tls_log = entry["tls_log"]["handshake_log"]
    server_hello = tls_log["server_hello"]
    
    version_name = server_hello["version"]["name"]
    csv_entry.append(version_name)
    
    certificate = tls_log["server_certificates"]["certificate"]
    
    raw_certificate = certificate["raw"]
    csv_entry.append(raw_certificate)
    
    parsed_certificate = certificate["parsed"]
    
    version = parsed_certificate["version"]
    serial_number = parsed_certificate["serial_number"]
    signature_algorithm_name = parsed_certificate["signature_algorithm"]["name"]
    signature_algorithm_oid = parsed_certificate["signature_algorithm"]["oid"]
    signature_value = parsed_certificate["signature"]["value"]
    signature_valid = parsed_certificate["signature"]["valid"]
    self_signed = parsed_certificate["signature"]["self_signed"]
    
    csv_entry.append(version)
    csv_entry.append(serial_number)
    csv_entry.append(signature_algorithm_name)
    csv_entry.append(signature_algorithm_oid)
    csv_entry.append(signature_value)
    csv_entry.append(signature_valid)
    csv_entry.append(self_signed)
    
    issuer = parsed_certificate["issuer"]
    issuer_common_name = issuer["common_name"][0] if "common_name" in issuer else "null"
    issuer_country = issuer["country"][0] if "country" in issuer else "null"
    issuer_locality = issuer["locality"][0] if "locality" in issuer else "null"
    issuer_province = issuer["province"][0] if "province" in issuer else "null"
    issuer_organization = issuer["organization"][0] if "organization" in issuer else "null"
    issuer_organization_unit = issuer["organization_unit"][0] if "organization_unit" in issuer else "null"
    issuer_email = issuer["email_address"][0] if "email_address" in issuer else "null"
    issuer_dn = parsed_certificate["issuer_dn"] if "issuer_dn" in parsed_certificate else "null"
    
    csv_entry.append(issuer_common_name)
    csv_entry.append(issuer_country)
    csv_entry.append(issuer_locality)
    csv_entry.append(issuer_province)
    csv_entry.append(issuer_organization)
    csv_entry.append(issuer_organization_unit)
    csv_entry.append(issuer_email)
    csv_entry.append(issuer_dn)
    
    validity = parsed_certificate["validity"]
    validity_start = validity["start"]
    validity_end = validity["end"]
    validity_length = validity["length"]
    
    csv_entry.append(validity_start)
    csv_entry.append(validity_end)
    csv_entry.append(validity_length)
    
    
    subject = parsed_certificate["subject"]
    subject_common_name = subject["common_name"][0] if "common_name" in subject else "null"
    subject_country = subject["country"][0] if "country" in subject else "null"
    subject_locality = subject["locality"][0] if "locality" in subject else "null"
    subject_province = subject["province"][0] if "province" in subject else "null"
    subject_organization = subject["organization"][0] if "organization" in subject else "null"
    subject_organization_unit = subject["organization_unit"][0] if "organization_unit" in subject else "null"
    subject_email = subject["email_address"][0] if "email_address" in subject else "null"
    
    subject_dn = parsed_certificate["subject_dn"] if "subject_dn" in parsed_certificate else "null"
    
    csv_entry.append(subject_common_name)
    csv_entry.append(subject_country)
    csv_entry.append(subject_locality)
    csv_entry.append(subject_province)
    csv_entry.append(subject_organization)
    csv_entry.append(subject_organization_unit)
    csv_entry.append(subject_email)
    csv_entry.append(subject_dn)
    
    
    subject_key_info = parsed_certificate["subject_key_info"]
    
    subject_key_algo_name = subject_key_info["key_algorithm"]["name"]
    rsa_public_key = subject_key_info["rsa_public_key"] if "rsa_public_key" in subject_key_info else {}
    exponent = rsa_public_key["exponent"] if "exponent" in rsa_public_key else "null"
    modulus = rsa_public_key["modulus"] if "modulus" in rsa_public_key else "null"
    key_length = rsa_public_key["length"] if "length" in rsa_public_key else "null"
    subject_key_fingerprint_sha256 = rsa_public_key["fingerprint_sha256"] if "fingerprint_sha256" in rsa_public_key else "null"
    
    
    csv_entry.append(subject_key_algo_name)
    csv_entry.append(exponent)
    csv_entry.append(modulus)
    csv_entry.append(key_length)
    csv_entry.append(subject_key_fingerprint_sha256)
    

    fingerprint_md5 = parsed_certificate["fingerprint_md5"] if "fingerprint_md5" in parsed_certificate else "null"
    fingerprint_sha1 = parsed_certificate["fingerprint_sha1"] if "fingerprint_sha1" in parsed_certificate else "null"
    fingerprint_sha256 = parsed_certificate["fingerprint_sha256"] if "fingerprint_sha256" in parsed_certificate else "null"
    tbs_noct_fingerprint = parsed_certificate["tbs_noct_fingerprint"] if "tbs_noct_fingerprint" in parsed_certificate else "null"
    spki_subject_fingerprint = parsed_certificate["spki_subject_fingerprint"] if "spki_subject_fingerprint" in parsed_certificate else "null"
    tbs_fingerprint = parsed_certificate["tbs_fingerprint"] if "tbs_fingerprint" in parsed_certificate else "null"
    validation_level = parsed_certificate["validation_level"] if "validation_level" in parsed_certificate else "null"
    redacted = parsed_certificate["redacted"] if "redacted" in parsed_certificate else "null"
    
    csv_entry.append(fingerprint_md5)
    csv_entry.append(fingerprint_sha1)
    csv_entry.append(fingerprint_sha256)
    csv_entry.append(tbs_noct_fingerprint)
    csv_entry.append(spki_subject_fingerprint)
    csv_entry.append(tbs_fingerprint)
    csv_entry.append(validation_level)
    csv_entry.append(redacted)
    
    return csv_entry

csv_fields = ["ip", "version_name", "raw_certificate",
              "version", "serial_number", "signature_algorithm_name", "signature_algorithm_oid", "signature_value", "signature_valid", "self_signed",
              "issuer_common_name", "issuer_country", "issuer_locality", "issuer_province", "issuer_organization","issuer_organization_unit", "issuer_email", "issuer_dn",
              "validity_start", "validity_end", "validity_length",
              "subject_common_name", "subject_country", "subject_locality", "subject_province", 'subject_organization', "subject_organization_unit", "subject_email", "subject_dn",
               "subject_key_algo_name", "exponent", "modulus", "key_length", "subject_key_fingerprint_sha256",
               "fingerprint_md5", "fingerprint_sha1", "fingerprint_sha256", "tbs_noct_fingerprint", 'spki_subject_fingerprint', "tbs_fingerprint", "validation_level", "redacted"
              ]

parser = argparse.ArgumentParser(description='Convert JSON to CSV')
parser.add_argument('-i', '--input', type=str, default='output.json', help='Input JSON file')
parser.add_argument('-o', '--output', type=str, default='output.csv', help='Output CSV file')
args = parser.parse_args()

with open('args.input', 'r') as file:
    data = file.readlines()[:]
    with open('args.output', 'w', newline='') as csv_file:
        writer = csv.writer(csv_file)
        writer.writerow(csv_fields)
        
        for line in data:
            entry = json.loads(line)
            csv_entry = extract_fields(entry)
            writer.writerow(csv_entry)




