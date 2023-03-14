fn main() {
    println!("Hello, world!");
}

#[cfg(test)]
mod tests {
    use bitcoin::blockdata::transaction::EncodeSigningDataResult;
    use bitcoin::consensus::deserialize;
    use bitcoin::hashes::{hex, sha256d, Hash};
    use bitcoin::util::sighash;
    use std::env;
    use std::str::FromStr;

    #[test]
    fn test_sighash() {
        let rawtx = "020000000001015ce1d4ffc716022f83cc0d557e6dad0500eeff9e9623bde014bdc09c5b672d750000000000fdffffff025fb7460b000000001600142cf4c1dc0352e0658971ca62a7457a1cd8c3389c4ce3a2000000000016001433f57fe374c6ceab61c8639128c038ac2a8c8db60247304402203cb50efb5c4a9aa7fd369ab6f4b226db99f44f9c610b5b50bc42f343a6aa401302201af791542eee6c1b11705e8895cc5adc36458910dc91aadcafb76a6478a29b9f01210242e811e66fd17e9a6e4ef772766c668d6e0595ca1d7f0583148bc460b575fbfdf0df0b00";

        let bytes: Vec<u8> = hex::FromHex::from_hex(&rawtx).expect("hex decoding");
        let tx: bitcoin::Transaction = deserialize(&bytes).expect("tx deserialization");

        let pk = bitcoin::secp256k1::PublicKey::from_str(
            "0242e811e66fd17e9a6e4ef772766c668d6e0595ca1d7f0583148bc460b575fbfd",
        )
        .unwrap();

        let mut sighash = sighash::SighashCache::new(&tx);
        let mut out_bytes = vec![];
        sighash
            .segwit_encode_signing_data_to(
                &mut out_bytes,
                0,
                &bitcoin::Script::from_str("76a914f5693fbaf062221baf891d813d5856e4f8ab54eb88ac")
                    .unwrap(),
                200000000,
                bitcoin::EcdsaSighashType::All,
            )
            .expect("computing sighash");

        println!("{}", hex::ToHex::to_hex(&out_bytes[..]));

        let sig = bitcoin::secp256k1::ecdsa::Signature::from_str(
         "304402203cb50efb5c4a9aa7fd369ab6f4b226db99f44f9c610b5b50bc42f343a6aa401302201af791542eee6c1b11705e8895cc5adc36458910dc91aadcafb76a6478a29b9f",
     ).unwrap();
        let secp = bitcoin::secp256k1::Secp256k1::new();

        let hash = sha256d::Hash::hash(&out_bytes);
        let msg = bitcoin::secp256k1::Message::from_slice(&hash[..]).unwrap();
        secp.verify_ecdsa(&msg, &sig, &pk).unwrap();
    }

    #[test]
    fn test_sighash_multisig() {
        let rawtx = "0100000001d611ad58b2f5bc0db7d15dfde4f497d6482d1b4a1e8c462ef077d4d32b3dae7901000000da0047304402203b17b4f64fa7299e8a85a688bda3cb1394b80262598bbdffd71dab1d7f266098022019cc20dc20eae417374609cb9ca22b28261511150ed69d39664b9d3b1bcb3d1201483045022100cfff9c400abb4ce5f247bd1c582cf54ec841719b0d39550b714c3c793fb4347b02201427a961a7f32aba4eeb1b71b080ea8712705e77323b747c03c8f5dbdda1025a01475221032d7306898e980c66aefdfb6b377eaf71597c449bf9ce741a3380c5646354f6de2103e8c742e1f283ef810c1cd0c8875e5c2998a05fc5b23c30160d3d33add7af565752aeffffffff020ed000000000000016001477800cff52bd58133b895622fd1220d9e2b47a79cd0902000000000017a914da55145ca5c56ba01f1b0b98d896425aa4b0f4468700000000";

        let bytes: Vec<u8> = hex::FromHex::from_hex(&rawtx).expect("hex decoding");
        let tx: bitcoin::Transaction = deserialize(&bytes).expect("tx deserialization");

        let pk_vec = vec![
            "032d7306898e980c66aefdfb6b377eaf71597c449bf9ce741a3380c5646354f6de",
            "03e8c742e1f283ef810c1cd0c8875e5c2998a05fc5b23c30160d3d33add7af5657",
        ];
        let sig_vec = vec!["304402203b17b4f64fa7299e8a85a688bda3cb1394b80262598bbdffd71dab1d7f266098022019cc20dc20eae417374609cb9ca22b28261511150ed69d39664b9d3b1bcb3d12", "3045022100cfff9c400abb4ce5f247bd1c582cf54ec841719b0d39550b714c3c793fb4347b02201427a961a7f32aba4eeb1b71b080ea8712705e77323b747c03c8f5dbdda1025a"];

        let sighash = sighash::SighashCache::new(&tx);
        let mut out_bytes = vec![];
        let res = sighash
            .legacy_encode_signing_data_to(
                &mut out_bytes,
                0,
                &bitcoin::Script::from_str("5221032d7306898e980c66aefdfb6b377eaf71597c449bf9ce741a3380c5646354f6de2103e8c742e1f283ef810c1cd0c8875e5c2998a05fc5b23c30160d3d33add7af565752ae")
                    .unwrap(),
                //188508,
                1u32, //bitcoin::EcdsaSighashType::All
            );
        match res {
            EncodeSigningDataResult::SighashSingleBug => println!("!!! SighashSingleBug"),
            EncodeSigningDataResult::WriteResult(Ok(_)) => println!("sighash Ok"),
            EncodeSigningDataResult::WriteResult(Err(err)) => println!("{}", err),
        }
        let hash = sha256d::Hash::hash(&out_bytes);
        let msg = bitcoin::secp256k1::Message::from_slice(&hash[..]).unwrap();

        println!("sighash is {}", hex::ToHex::to_hex(&out_bytes[..]));

        for pk in &pk_vec {
            let pk = bitcoin::secp256k1::PublicKey::from_str(pk).unwrap();
            for sig in &sig_vec {
                let sig = bitcoin::secp256k1::ecdsa::Signature::from_str(sig).unwrap();
                let secp = bitcoin::secp256k1::Secp256k1::new();
                match secp.verify_ecdsa(&msg, &sig, &pk) {
                    Ok(_) => println!("{}", pk),
                    Err(err) => println!("{}", err),
                }
            }
        }
    }
}
