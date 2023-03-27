fn main() {
    println!("Hello, world!");
}

#[cfg(test)]
mod tests {
    use bitcoin::blockdata::script::Instruction;
    use bitcoin::blockdata::transaction::EncodeSigningDataResult;
    use bitcoin::consensus::deserialize;
    use bitcoin::hashes::{sha256d, Hash};
    use bitcoin::sighash;
    use bitcoin_internals::hex::display::DisplayHex;
    use hex_lit::hex;
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
        let script_bytes = hex!("76a914f5693fbaf062221baf891d813d5856e4f8ab54eb88ac");
        sighash
            .segwit_encode_signing_data_to(
                &mut out_bytes,
                0,
                &bitcoin::Script::from_bytes(&script_bytes),
                200000000,
                bitcoin::sighash::EcdsaSighashType::All,
            )
            .expect("computing sighash");

        println!("{:x}", out_bytes.as_hex());

        let sig = bitcoin::secp256k1::ecdsa::Signature::from_str(
         "304402203cb50efb5c4a9aa7fd369ab6f4b226db99f44f9c610b5b50bc42f343a6aa401302201af791542eee6c1b11705e8895cc5adc36458910dc91aadcafb76a6478a29b9f",
     ).unwrap();
        let secp = bitcoin::secp256k1::Secp256k1::new();

        let hash = sha256d::Hash::hash(&out_bytes);
        let msg = bitcoin::secp256k1::Message::from_slice(&hash[..]).unwrap();
        secp.verify_ecdsa(&msg, &sig, &pk).unwrap();
    }

    #[test]
    fn test_sighash_p2sh_multisig_2x2() {
        let rawtx = "0100000001d611ad58b2f5bc0db7d15dfde4f497d6482d1b4a1e8c462ef077d4d32b3dae7901000000da0047304402203b17b4f64fa7299e8a85a688bda3cb1394b80262598bbdffd71dab1d7f266098022019cc20dc20eae417374609cb9ca22b28261511150ed69d39664b9d3b1bcb3d1201483045022100cfff9c400abb4ce5f247bd1c582cf54ec841719b0d39550b714c3c793fb4347b02201427a961a7f32aba4eeb1b71b080ea8712705e77323b747c03c8f5dbdda1025a01475221032d7306898e980c66aefdfb6b377eaf71597c449bf9ce741a3380c5646354f6de2103e8c742e1f283ef810c1cd0c8875e5c2998a05fc5b23c30160d3d33add7af565752aeffffffff020ed000000000000016001477800cff52bd58133b895622fd1220d9e2b47a79cd0902000000000017a914da55145ca5c56ba01f1b0b98d896425aa4b0f4468700000000";

        test_sighash_p2sh_multisig(rawtx, 0);
    }

    #[test]
    fn test_sighash_p2sh_multisig_2x3() {
        let rawtx = "010000000a2aafcf32a7d0998e146f02d9948b8530a7c574f24e51ac4e5f8009dc8121228800000000fdfd000047304402205b959fc960be4256a6fe61f75013beb552f7f78352c4b8ddf5cd9747a7757af702207e540d95c8be8b096976685f61ec9d38ccaf68903c34ada54b9878ce21c40d3b014830450221009d2386c125126dcf7a90b85145b57983c4777b6d31526bb01c3dc44ad6b66d3f02205bfdfe89a6114d2d9e5d27f090fad46393251510777880817db65ada47ee3c49014c69522102261f84d51bb64371cb5e9eec3bbc0c0c7320eb7fa9c5076a394a48a9cd74bfd321023e66621cf94ac25d8bb687abef86d01847805d6e9bff8c3999f18f478cde5ab62102d844059fae247b8e1325f56519d1eb7d4b632ec77b9f71f03102167f3c7fa59153aeffffffff902196cd0936b8854a2f6a748c4a15ce397bb213e59599f809ac823b9fd2dec700000000fdfd0000483045022100dc2e50c9f852edf89a9d295995c91bb07857c3b18e98549b68c2b45a76f4b608022076cfff6d39245b7b8602691cbe9466a254b398d3d9f114a63a59febae645449401473044022012f66786119c435832fb715520232f45c7b541d68db0158c2d1e13b27c7b4dcd022051011c7bb2256236ca238a935bace3f073c851111fa9274fa609422d77cb617f014c69522102261f84d51bb64371cb5e9eec3bbc0c0c7320eb7fa9c5076a394a48a9cd74bfd321023e66621cf94ac25d8bb687abef86d01847805d6e9bff8c3999f18f478cde5ab62102d844059fae247b8e1325f56519d1eb7d4b632ec77b9f71f03102167f3c7fa59153aeffffffff2e9dbb1cabff6041ea2951105f877fb14addb45fa42e70eaec2d1ab17e0d37c300000000fdfe0000483045022100c1510121f06ee1cf200ef9dc19cc5fff5f6a2ec087dc618e39c053eb397722a202203672ac3c49a0d9f332efcd03801bc7d68e9d4bc6b84e77591f22d7088108baca01483045022100baf85a48dd5b90b95e94961a54ce6d004d0ab0d6c82e898f4038654d284ffb77022002719f0b1c5bf069a296df8df40fce65ed5922a6469fd2b5774714b742a59893014c69522102261f84d51bb64371cb5e9eec3bbc0c0c7320eb7fa9c5076a394a48a9cd74bfd321023e66621cf94ac25d8bb687abef86d01847805d6e9bff8c3999f18f478cde5ab62102d844059fae247b8e1325f56519d1eb7d4b632ec77b9f71f03102167f3c7fa59153aeffffffff7ae4f4513dc761a41855b7ec5f111e192fd40f0490aa6b01c0cbb9f32585db9c00000000fdfd0000473044022065ac8212e0fda09bc286169af551fa90ab20b54c28acc8bbb3c44e3a0f2af5de022056d41d30a2b845fba3c0e80d1fe4991b36717608b0bd3e5e31f8a7c5f608a1b9014830450221008f9c17289fcc945e9ffed612a779962faaa477e36400288708766b11e3b75c7602207e2b4994fd7ac2a8d06cf676d4819de1880b597f90ca1a97fac5f92a4af2ffd7014c69522102261f84d51bb64371cb5e9eec3bbc0c0c7320eb7fa9c5076a394a48a9cd74bfd321023e66621cf94ac25d8bb687abef86d01847805d6e9bff8c3999f18f478cde5ab62102d844059fae247b8e1325f56519d1eb7d4b632ec77b9f71f03102167f3c7fa59153aeffffffff924c652d9953c90ba157e17009f3d609f3e9c74944b1905098c34f7cebdf307b01000000fc004730440220229015b2578422b9cfc67a7ae63956cba017efd3a85546dc26b482bd2a0ac3fe02206447c1f8e27784a796ded47988d0ddf57f1ec35bd2e3fea85ce1698f057d7e550147304402206de04ad86eac89ee9faeaadf9111a28c6dbb11f0f13e759dcafdece70c30843702204dd198460c0877eb3c006205750f1d221b76c0a92efadd27c848974545da305a014c69522102d828f488cb7999b5e8f86d96ffdfca8df623b9c69110deb17bebbf078fba5c712102ddb0d4d376eddf45d3342dc10ff990a8824a8ee27cbf677d8b8598e95d39dfa021037ec133aafd59281211f544672eeae73d41c7997c93f339dc7656a8d3dd7564e053aeffffffff9e34c86d4547fa8a66a34cf2261da011e4d7b32110273881678c58ad65af6deb00000000fdfe0000483045022100cf6c69951457ec074ade356043089d9ebadb53cc003be857c0de9c884cac4d6102205616d1ab0e0c11d602247d379436b6500a1d07c774ad61dc944a53cdee1809d101483045022100a7e9e63c92108cc3ac014ddd593755feec949bdae2450de001dadfe94038a1b8022033ba6ca06ee46e3808dd027c27f5cb630fc1bd6807487ec7af2c789854daba4f014c69522102d828f488cb7999b5e8f86d96ffdfca8df623b9c69110deb17bebbf078fba5c712102ddb0d4d376eddf45d3342dc10ff990a8824a8ee27cbf677d8b8598e95d39dfa021037ec133aafd59281211f544672eeae73d41c7997c93f339dc7656a8d3dd7564e053aeffffffffafde87dca43f6b06dbe1520a9389ad31e70af9e3324bf9c1bca013b1bb76fdc900000000fdfd00004730440220727a0e2be9949e991ab5ff203001281127a7b5d13a1b3ca9b7276333f9371b3602206a3f07b6879eae1759046a1ce47b4a303587eaf47aada346b19b8924fb99d80e01483045022100e4a947ccf698f670ef45b5963cd0baced9886defcbdc8f65e951a414f51df86e022010715ee835a68f1c20e3be46b48b80e8f05d587c9edc562e7bf2fa307f21cff8014c695221023cbc2ad2dad9231a9e907a4a69dcfe2514d04db5a0fc5a903361fb892b16be8021027b766284e7c9db06628dd9481c6176dd94524c2317f7ca4e8f1ab549c9fe8da62103a9e76e199de14118b683187c1c7fcbf5427e8cc2c290d5daf1261a716742a69c53aeffffffffdfc3afe3f49543716276373812826f55b9dc4e9f2ee2c858cb0b5e19e33f7c9500000000fdfd00004730440220685655193c0dd894bc348bb5b8ac0247764784b947ab53b538a4f88008749f6402204a4b5912d558aa278a8ee3744ba74384c30420e8d2724ed13b35201fb013437301483045022100ae6da2282de47eb9d655b801b41d1494ccf995753104d9741a0d63bd4646eb1b0220607cbcbe76e6628fe902bf3ea6597400f878e9ef2302ff7ae4e62a70c95babaf014c695221023cbc2ad2dad9231a9e907a4a69dcfe2514d04db5a0fc5a903361fb892b16be8021027b766284e7c9db06628dd9481c6176dd94524c2317f7ca4e8f1ab549c9fe8da62103a9e76e199de14118b683187c1c7fcbf5427e8cc2c290d5daf1261a716742a69c53aeffffffff9de37111afcc701f30167f463c14467ffff8af317837e8b0644220610dcaacc501000000fdfd000047304402207b240fdcde83165df09dcb7b7e9f7fd768106ab648520b47e2d723e6263306cb02201f1f803e8f35a54aeb683d2d22e7215ee03e8a4a584c144a588a6ce0355fc85101483045022100f3ebeab2532d71945fdc945a8ca7b7e46107a0478754938cdf4f82d1a51561b302203ba1e1b33bf6e71032e34c0916f78bb6a333c2049a16b16642ab5638aa6204a6014c695221023c5d83e61fbb07fae23b1ef5600b44e068d79de7025b7c97b4a17103e2e65cf921032b873786d37b7769b1777f43081bd14b6f6d7f5ea26c2362860eda0b2a60116a2103e23f0e9748f618bd53b4b6c23c56714b031623691425c1b5c82c907fdc0f5e0c53aeffffffff554fbce7a6e82360095f213752d97ffa3fc6b1b600d298b72b5e261c83ca614b01000000fdfd000047304402207c9b7e46feedbd77143e81bb4c099cfe0db441e634307a9de2f70305fec2c381022051912c43a004ae2348b440013dd6218136800b89a3a4f1418ca4b27ffa40bf1001483045022100c38e31dfe2437d2fdfeab15a7533c1d3fcb6a7c8d26e5498695cccc43001296c022072e708c8e3a4dbc64dd3a6eac8e2fc0d0a3d55ba746e972b2a5d8275b556ec1d014c695221023d69319c33f4ad28b6518744798ee2a77116d8495785c1cc84d6f219d85ef4f62102678747b4b9aeed0abdc55e02bec75e1eb74fdcd11fee8785ae989ab7b5976c302102882b1281ed00e9b3629f16752f0436932941ea7065f42d4f5725cf4cf153932153aeffffffff0200a3e111000000001976a91442be95374aed1876e1fa0a8ec6a2fa0b0fe1214088ac3dc648000000000017a91442118ab92bfdcfcc884e5edf3063e90f51a3d2488700000000";

        test_sighash_p2sh_multisig(rawtx, 3);
    }

    #[test]
    fn test_sighash_p2wsh_multisig_2x2() {
        let rawtx = "010000000001011b9eb4122976fad8f809ee4cea8ac8d1c5b6b8e0d0f9f93327a5d78c9a3945280000000000ffffffff02ba3e0d00000000002200201c3b09401aaa7c9709d118a75d301bdb2180fb68b2e9b3ade8ad4ff7281780cfa586010000000000220020a41d0d894799879ca1bd88c1c3f1c2fd4b1592821cc3c5bfd5be5238b904b09f040047304402201c7563e876d67b5702aea5726cd202bf92d0b1dc52c4acd03435d6073e630bac022032b64b70d7fba0cb8be30b882ea06c5f8ec7288d113459dd5d3e294214e2c96201483045022100f532f7e3b8fd01a0edc86de4870db4e04858964d0a609df81deb99d9581e6c2e02206d9e9b6ab661176be8194faded62f518cdc6ee74dba919e0f35d77cff81f38e5014752210289da5da9d3700156db2d01e6362491733f6c886971791deda74b4e9d707190b2210323c437f30384498be79df2990ce5a8de00844e768c0ccce914335b6c26adea7352ae00000000";
        let ref_out_value = 968240;

        test_sighash_p2wsh_multisig(rawtx, 0, ref_out_value);
    }

    #[test]
    fn test_sighash_p2ms_multisig_2x3() {
        let rawtx = "010000000110a5fee9786a9d2d72c25525e52dd70cbd9035d5152fac83b62d3aa7e2301d58000000009300483045022100af204ef91b8dba5884df50f87219ccef22014c21dd05aa44470d4ed800b7f6e40220428fe058684db1bb2bfb6061bff67048592c574effc217f0d150daedcf36787601483045022100e8547aa2c2a2761a5a28806d3ae0d1bbf0aeff782f9081dfea67b86cacb321340220771a166929469c34959daf726a2ac0c253f9aff391e58a3c7cb46d8b7e0fdc4801ffffffff0180a21900000000001976a914971802edf585cdbc4e57017d6e5142515c1e502888ac00000000";
        let reftx_script_pubkey_bytes = hex!("524104d81fd577272bbe73308c93009eec5dc9fc319fc1ee2e7066e17220a5d47a18314578be2faea34b9f1f8ca078f8621acd4bc22897b03daa422b9bf56646b342a24104ec3afff0b2b66e8152e9018fe3be3fc92b30bf886b3487a525997d00fd9da2d012dce5d5275854adc3106572a5d1e12d4211b228429f5a7b2f7ba92eb0475bb14104b49b496684b02855bc32f5daefa2e2e406db4418f3b86bca5195600951c7d918cdbe5e6d3736ec2abf2dd7610995c3086976b2c0c7b4e459d10b34a316d5a5e753ae");

        test_sighash_p2ms_multisig(rawtx, 0, &reftx_script_pubkey_bytes);
    }

    /// reftx output's scriptPubKey.type is "scripthash"
    fn test_sighash_p2sh_multisig(rawtx: &str, inp_idx: usize) {
        let bytes: Vec<u8> = hex::FromHex::from_hex(&rawtx).expect("hex decoding");
        let tx: bitcoin::Transaction = deserialize(&bytes).expect("tx deserialization");
        let inp = &tx.input[inp_idx];
        let script_sig = &inp.script_sig;
        println!("script_sig {}", script_sig);
        let mut script_pubkey_bytes: &[u8] = &[];
        let mut sig_vec = vec![];
        let mut last_sighash_flag = 0;
        //here we assume that we have an M of N multisig.`An assert will fail later if it's not.
        for (k, instr) in script_sig.instructions().enumerate() {
            match instr.unwrap() {
                Instruction::PushBytes(pb) => {
                    //extract sig_vec, script_pubkey_bytes from script_sig
                    if k == 0 {
                        assert!(pb.is_empty(), "first must be PUSHBYTES_0 got {:?}", pb)
                    } else if k == script_sig.instructions().count() - 1 {
                        script_pubkey_bytes = pb.as_bytes(); //last is ScriptPubkey
                    } else {
                        //all others must be signatures between 70 and 73 bytes
                        let (sighash_flag, sig) = pb.as_bytes().split_last().unwrap();
                        assert!(
                            sig.len() <= 73 && sig.len() >= 70,
                            "signature length {} out of bounds",
                            sig.len()
                        );
                        //take sighash_flag into account - can they be different?
                        assert!(
                            last_sighash_flag == 0 || last_sighash_flag == *sighash_flag,
                            "different sighash flags"
                        );
                        last_sighash_flag = *sighash_flag;
                        sig_vec.push(sig);
                    }
                    println!("PushBytes len {}: {:?}", pb.as_bytes().to_vec().len(), pb)
                }
                Instruction::Op(op) => {
                    assert!(false, "we only expect PushBytes here, got Op({})", op)
                }
            }
        }
        println!("sig vec {:?}", sig_vec);

        let script_pubkey = bitcoin::Script::from_bytes(script_pubkey_bytes);
        let (required_sig_cnt, pubkey_vec) = decode_script_pubkey(&script_pubkey);

        let sighash = sighash::SighashCache::new(&tx);
        let mut out_bytes = vec![];
        let res = sighash.legacy_encode_signing_data_to(
            &mut out_bytes,
            inp_idx,
            &script_pubkey,
            last_sighash_flag, //bitcoin::EcdsaSighashType::All
        );
        match res {
            EncodeSigningDataResult::SighashSingleBug => println!("!!! SighashSingleBug"),
            EncodeSigningDataResult::WriteResult(Ok(_)) => println!("sighash Ok"),
            EncodeSigningDataResult::WriteResult(Err(err)) => println!("{}", err),
        }
        let hash = sha256d::Hash::hash(&out_bytes);
        let msg = bitcoin::secp256k1::Message::from_slice(&hash[..]).unwrap();

        println!("sighash is {:x}", out_bytes.as_hex());

        let mut sig_verified_cnt = 0;
        for pk in &pubkey_vec {
            let pk = bitcoin::secp256k1::PublicKey::from_slice(pk).unwrap();
            for sig in &sig_vec {
                let sig = bitcoin::secp256k1::ecdsa::Signature::from_der(sig).unwrap();
                let secp = bitcoin::secp256k1::Secp256k1::new();
                match secp.verify_ecdsa(&msg, &sig, &pk) {
                    Ok(_) => {
                        sig_verified_cnt += 1;
                        println!("{}", pk)
                    }
                    Err(err) => println!("{}", err),
                }
            }
        }
        assert!(
            sig_verified_cnt == required_sig_cnt,
            "{} signatures verified out of {} expected",
            sig_verified_cnt,
            required_sig_cnt
        )
    }

    /// reftx output's scriptPubKey.type is "witness_v0_scripthash"
    fn test_sighash_p2wsh_multisig(rawtx: &str, inp_idx: usize, value: u64) {
        let bytes: Vec<u8> = hex::FromHex::from_hex(&rawtx).expect("hex decoding");
        let tx: bitcoin::Transaction = deserialize(&bytes).expect("tx deserialization");
        let inp = &tx.input[inp_idx];
        let witness = &inp.witness;
        println!("witness {:?}", witness);
        let mut sig_vec = vec![];
        let mut last_sighash_flag = 0;

        let script_pubkey_bytes: &[u8] = witness.last().expect("Out of Bounds");
        let script_pubkey = bitcoin::Script::from_bytes(script_pubkey_bytes);
        let (required_sig_cnt, pubkey_vec) = decode_script_pubkey(&script_pubkey);

        for n in witness.len() - required_sig_cnt - 1..witness.len() - 1 {
            let (sighash_flag, sig) = witness.nth(n).expect("Out of Bounds").split_last().unwrap();
            sig_vec.push(sig);
            //take sighash_flag into account - can they be different?
            assert!(
                last_sighash_flag == 0 || last_sighash_flag == *sighash_flag,
                "different sighash flags"
            );
            last_sighash_flag = *sighash_flag;
        }
        println!("sig vec {:?}", sig_vec);

        let mut sighash = sighash::SighashCache::new(&tx);
        let mut out_bytes = vec![];
        sighash
            .segwit_encode_signing_data_to(
                &mut out_bytes,
                inp_idx,
                &script_pubkey,
                value,
                bitcoin::sighash::EcdsaSighashType::All, //TODO deal with the flags u8 does not work
            )
            .unwrap();
        let hash = sha256d::Hash::hash(&out_bytes);
        let msg = bitcoin::secp256k1::Message::from_slice(&hash[..]).unwrap();

        println!("sighash is {:x}", out_bytes.as_hex());

        let mut sig_verified_cnt = 0;
        for pk in &pubkey_vec {
            let pk = bitcoin::secp256k1::PublicKey::from_slice(pk).unwrap();
            for sig in &sig_vec {
                let sig = bitcoin::secp256k1::ecdsa::Signature::from_der(sig).unwrap();
                let secp = bitcoin::secp256k1::Secp256k1::new();
                match secp.verify_ecdsa(&msg, &sig, &pk) {
                    Ok(_) => {
                        sig_verified_cnt += 1;
                        println!("{}", pk)
                    }
                    Err(err) => println!("{}", err),
                }
            }
        }
        assert!(
            sig_verified_cnt == required_sig_cnt,
            "{} signatures verified out of {} expected",
            sig_verified_cnt,
            required_sig_cnt
        )
    }

    /// reftx output's scriptPubKey.type is "multisig"
    fn test_sighash_p2ms_multisig(rawtx: &str, inp_idx: usize, script_pubkey_bytes: &[u8]) {
        let bytes: Vec<u8> = hex::FromHex::from_hex(&rawtx).expect("hex decoding");
        let tx: bitcoin::Transaction = deserialize(&bytes).expect("tx deserialization");
        let inp = &tx.input[inp_idx];
        let script_sig = &inp.script_sig;
        println!("script_sig {}", script_sig);
        //let mut script_pubkey_bytes: &[u8] = hex!(reftx_script_pubkey_str);
        let mut sig_vec = vec![];
        let mut last_sighash_flag = 0;
        //
        //here we assume that we have an M of N multisig.`An assert will fail later if it's not.
        for (k, instr) in script_sig.instructions().enumerate() {
            match instr.unwrap() {
                Instruction::PushBytes(pb) => {
                    //extract sig_vec from script_sig
                    if k == 0 {
                        assert!(pb.is_empty(), "first must be PUSHBYTES_0 got {:?}", pb)
                    } else {
                        //all others must be signatures between 70 and 73 bytes
                        let (sighash_flag, sig) = pb.as_bytes().split_last().unwrap();
                        assert!(
                            sig.len() <= 73 && sig.len() >= 70,
                            "signature length {} out of bounds",
                            sig.len()
                        );
                        //take sighash_flag into account - can they be different?
                        assert!(
                            last_sighash_flag == 0 || last_sighash_flag == *sighash_flag,
                            "different sighash flags"
                        );
                        last_sighash_flag = *sighash_flag;
                        sig_vec.push(sig);
                    }
                    println!("PushBytes len {}: {:?}", pb.as_bytes().to_vec().len(), pb)
                }
                Instruction::Op(op) => {
                    assert!(false, "we only expect PushBytes here, got Op({})", op)
                }
            }
        }
        println!("sig vec {:?}", sig_vec);

        let script_pubkey = bitcoin::Script::from_bytes(script_pubkey_bytes);
        let (required_sig_cnt, pubkey_vec) = decode_script_pubkey(&script_pubkey);

        let sighash = sighash::SighashCache::new(&tx);
        let mut out_bytes = vec![];
        let res = sighash.legacy_encode_signing_data_to(
            &mut out_bytes,
            inp_idx,
            &script_pubkey,
            last_sighash_flag, //bitcoin::EcdsaSighashType::All
        );
        match res {
            EncodeSigningDataResult::SighashSingleBug => println!("!!! SighashSingleBug"),
            EncodeSigningDataResult::WriteResult(Ok(_)) => println!("sighash Ok"),
            EncodeSigningDataResult::WriteResult(Err(err)) => println!("{}", err),
        }
        let hash = sha256d::Hash::hash(&out_bytes);
        let msg = bitcoin::secp256k1::Message::from_slice(&hash[..]).unwrap();

        println!("sighash is {:x}", out_bytes.as_hex());

        let mut sig_verified_cnt = 0;
        for pk in &pubkey_vec {
            let pk = bitcoin::secp256k1::PublicKey::from_slice(pk).unwrap();
            for sig in &sig_vec {
                let sig = bitcoin::secp256k1::ecdsa::Signature::from_der(sig).unwrap();
                let secp = bitcoin::secp256k1::Secp256k1::new();
                match secp.verify_ecdsa(&msg, &sig, &pk) {
                    Ok(_) => {
                        sig_verified_cnt += 1;
                        println!("{}", pk)
                    }
                    Err(err) => println!("{}", err),
                }
            }
        }
        assert!(
            sig_verified_cnt == required_sig_cnt,
            "{} signatures verified out of {} expected",
            sig_verified_cnt,
            required_sig_cnt
        )
    }

    fn decode_script_pubkey(script_pubkey: &bitcoin::Script) -> (usize, Vec<&[u8]>) {
        println!("script_pubkey: {:?}", script_pubkey);

        let mut pubkey_vec = vec![];
        let mut pubkey_cnt = 0;
        let mut required_sig_cnt = 0;
        for (k, instr) in script_pubkey.instructions().enumerate() {
            match instr.unwrap() {
                Instruction::PushBytes(pb) => {
                    assert!(k > 0);
                    pubkey_vec.push(pb.as_bytes());
                }
                Instruction::Op(op) => {
                    if k == 0 {
                        // convert OP_PUSHNUM_N to N by subtracting OP_PUSHNUM_1 hex offset
                        required_sig_cnt =
                            op.to_u8() - bitcoin::blockdata::opcodes::all::OP_PUSHNUM_1.to_u8() + 1;
                    } else if op == bitcoin::blockdata::opcodes::all::OP_CHECKMULTISIG {
                        assert!(
                            pubkey_vec.len() == pubkey_cnt.into(),
                            "{}: {} -- pubkey vec len {}, pubkey cnt {}",
                            k,
                            op,
                            pubkey_vec.len(),
                            pubkey_cnt
                        );
                        println!("{}x{} MULTISIG", required_sig_cnt, pubkey_cnt);
                    } else {
                        assert!(k == pubkey_vec.len() + 1);
                        // convert OP_PUSHNUM_N to N by subtracting OP_PUSHNUM_1 hex offset
                        pubkey_cnt =
                            op.to_u8() - bitcoin::blockdata::opcodes::all::OP_PUSHNUM_1.to_u8() + 1;
                        assert!(pubkey_vec.len() == pubkey_cnt.into());
                    }
                }
            }
        }

        (required_sig_cnt.into(), pubkey_vec)
    }
}
