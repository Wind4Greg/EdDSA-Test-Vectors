/*
    Steps to create a signed verifiable credential with an *EcdsaSecp256r1Signature2019*
    based on "DataIntegrityProof" representation. This has not be specified in a draft yet.
*/

import { mkdir, readFile, writeFile } from 'fs/promises';
import jsonld from 'jsonld';
import { localLoader } from './documentLoader.js';
import { base58btc } from "multiformats/bases/base58";
import { P256 } from '@noble/curves/p256';
import { sha256 } from '@noble/hashes/sha256';
import { bytesToHex, concatBytes, hexToBytes } from '@noble/hashes/utils';

// Create output directory for the results
const baseDir = "./output/ecdsa-rdfc-2019-p256/";
let status = await mkdir(baseDir, {recursive: true});

jsonld.documentLoader = localLoader; // Local loader for JSON-LD

const keyPair = {
    publicKeyMultibase: "zDnaepBuvsQ8cpsWrVKw8fbpGpvPeNSjVPTWoq6cRqaYzBKVP"
};


let privateKey = hexToBytes("C9AFA9D845BA75166B5C215767B1D6934E50C3DB36E89B127B8A622B120F6721");
let publicKey = P256.getPublicKey(privateKey);

// Read input document from a file or just specify it right here.
let document = JSON.parse(
    await readFile(
      new URL('./input/unsigned.json', import.meta.url)
    )
  );

// Signed Document Creation Steps:

// Canonize the document
let cannon = await jsonld.canonize(document);
console.log("Canonized unsigned document:")
console.log(cannon);
writeFile(baseDir + 'canonDocECDSAP256.txt', cannon);


// Hash canonized document
let docHash = sha256(cannon); // @noble/hash will convert string to bytes via UTF-8
console.log("Hash of canonized document in hex:")
console.log(bytesToHex(docHash));
writeFile(baseDir + 'docHashECDSAP256.txt', bytesToHex(docHash));

// Set proof options per draft
let proofConfig = {};
proofConfig.type = "DataIntegrityProof";
proofConfig.cryptosuite = "ecdsa-rdfc-2019";
proofConfig.created = "2023-02-24T23:36:38Z";
// proofConfig.verificationMethod = "https://vc.example/issuers/5678#" + keyPair.publicKeyMultibase;
proofConfig.verificationMethod = 'did:key:' + keyPair.publicKeyMultibase + '#' 
  + keyPair.publicKeyMultibase;
proofConfig.proofPurpose = "assertionMethod";
proofConfig["@context"] = document["@context"]; // Missing from draft!!!
writeFile(baseDir + 'proofConfigECDSAP256.json', JSON.stringify(proofConfig, null, 2));

// canonize the proof config
let proofCanon = await jsonld.canonize(proofConfig);
console.log("Proof Configuration Canonized:");
console.log(proofCanon);
writeFile(baseDir + 'proofCanonECDSAP256.txt', proofCanon);

// Hash canonized proof config
let proofHash = sha256(proofCanon); // @noble/hash will convert string to bytes via UTF-8
console.log("Hash of canonized proof in hex:")
console.log(bytesToHex(proofHash));
writeFile(baseDir + 'proofHashECDSAP256.txt', bytesToHex(proofHash));

// Combine hashes
let combinedHash = concatBytes(proofHash, docHash);
writeFile(baseDir + 'combinedHashECDSAP256.txt', bytesToHex(combinedHash));

// Sign
let msgHash = sha256(combinedHash); // Hash is done outside of the algorithm in noble/curve case.
let signature = P256.sign(msgHash, privateKey);
console.log(signature);
writeFile(baseDir + 'sigHexECDSAP256.txt', bytesToHex(signature.toCompactRawBytes()));
console.log("Computed Signature from private key:");
console.log(base58btc.encode(signature.toCompactRawBytes()));
writeFile(baseDir + 'sigBTC58ECDSAP256.txt', base58btc.encode(signature.toCompactRawBytes()));

// Verify (just to see we have a good private/public pair)
let pbk = base58btc.decode(keyPair.publicKeyMultibase);
pbk = pbk.slice(2, pbk.length); // First two bytes are multi-format indicator
console.log(`Public Key hex: ${bytesToHex(pbk)}, Length: ${pbk.length}`);
let result = P256.verify(signature, msgHash, pbk);
console.log(`Signature verified: ${result}`);

// Construct Signed Document
let signedDocument = Object.assign({}, document);
delete proofConfig['@context'];
signedDocument.proof = proofConfig;
signedDocument.proof.proofValue = base58btc.encode(signature.toCompactRawBytes());

console.log(JSON.stringify(signedDocument, null, 2));
writeFile(baseDir + 'signedECDSAP256.json', JSON.stringify(signedDocument, null, 2));

