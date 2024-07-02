use openssl::base64;
use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize, Debug)]
#[serde(rename_all="PascalCase")]
struct LicenseData {
    provider: String,
    features: String,
    expiration: String,
    license_key: String,
}

#[derive(Serialize, Deserialize, Debug)]
#[serde(rename_all="PascalCase")]
struct LicenseSignature {
    hash_algorithm: String,
    signature_value: String,
}

#[derive(Serialize, Deserialize, Debug)]
#[serde(rename_all="PascalCase")]
struct License {
    data: LicenseData,
    signature: LicenseSignature,
}

impl License {
    fn new(data: LicenseData, signature: LicenseSignature) -> License {
        License { data, signature }
    }
}

fn main() {
    // ssl private key
    let private_key = include_str!("../private_key.pem");
    let public_key = include_str!("../public_key.pem");

    // ask for inputs from the user
    let mut provider = String::new();
    let mut features = String::new();
    let mut expiration = String::new();
    let mut license_key = String::new();

    // take the input from the user
    ask_input("Provider name", &mut provider);
    ask_input("Features", &mut features);
    ask_input("Expiration", &mut expiration);
    ask_input("License Key", &mut license_key);

    // create the license data
    let license_data = LicenseData {
        provider,
        features,
        expiration,
        license_key,
    };

    // create the signature
    let mut signature = LicenseSignature {
        hash_algorithm: "SHA256".to_string(),
        signature_value: "".to_string(),
    };

    let data_to_sign = serde_xml_rs::to_string(&license_data).unwrap(); 
    let mut signer = openssl::sign::Signer::new(
        openssl::hash::MessageDigest::sha256(),
        &openssl::pkey::PKey::private_key_from_pem(private_key.as_bytes()).unwrap()
    ).unwrap();
    signer.update(data_to_sign.as_bytes()).unwrap();
    let signature_value = signer.sign_to_vec().unwrap();
    // convert the signature to base64
    signature.signature_value = base64::encode_block(&signature_value);

    // create the license
    let license = License::new(license_data, signature);

    // to xml
    let xml = serde_xml_rs::to_string(&license).unwrap();
    println!("{}", xml);

    // write to file license.xml
    std::fs::write("license.xml", xml).expect("Unable to write file");

    // read from file license.xml
    let xml = std::fs::read_to_string("license.xml").expect("Unable to read file");
    let license: License = serde_xml_rs::from_str(&xml).unwrap();

    // verify the signature
    let data_to_verify = serde_xml_rs::to_string(&license.data).unwrap();
    let signature_value = base64::decode_block(&license.signature.signature_value).unwrap();
    let p_key_public = openssl::pkey::PKey::public_key_from_pem(public_key.as_bytes()).unwrap();

    let mut verifier = openssl::sign::Verifier::new(
        openssl::hash::MessageDigest::sha256(),
        &p_key_public
    ).unwrap();

    verifier.update(data_to_verify.as_bytes()).unwrap();    
    let signature_valid = verifier.verify(&signature_value).unwrap();
    println!("Signature valid: {}", signature_valid);
}

fn ask_input(name: &str, pointer: &mut String) {
    println!("Enter the value for {}: ", name);
    let mut input = String::new();
    std::io::stdin()
        .read_line(&mut input)
        .expect("Failed to read line");
    *pointer = input.trim().to_string();
}
