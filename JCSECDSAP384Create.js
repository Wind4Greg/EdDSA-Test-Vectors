/*
    Steps to create a signed verifiable credential with an *EcdsaSecp384r1Signature2019*
    based on "DataIntegrityProof" representation. This has not be specified in a draft yet.
*/

import { mkdir, readFile, writeFile } from 'fs/promises';
import { base58btc } from "multiformats/bases/base58";
import { P384 } from '@noble/curves/p384';
import { sha384 } from '@noble/hashes/sha512';
import { bytesToHex, concatBytes, hexToBytes } from '@noble/hashes/utils';
import canonicalize from 'canonicalize';

// Create output directory for the results
const baseDir = "./output/ecdsa-rdfc-2019-p384/";
let status = await mkdir(baseDir, {recursive: true});
const keyPair = {
    publicKeyMultibase: "z82LkuBieyGShVBhvtE2zoiD6Kma4tJGFtkAhxR5pfkp5QPw4LutoYWhvQCnGjdVn14kujQ"
};


let privateKey = hexToBytes("6B9D3DAD2E1B8C1C05B19875B6659F4DE23C3B667BF297BA9AA47740787137D896D5724E4C70A825F872C9EA60D2EDF5");
let publicKey = P384.getPublicKey(privateKey);

// Read input document from a file or just specify it right here.
let document = JSON.parse(
    await readFile(
      new URL('./input/unsigned.json', import.meta.url)
    )
  );

// Signed Document Creation Steps:

// Canonize the document
let cannon = canonicalize(document);
console.log("Canonized unsigned document:")
console.log(cannon);
writeFile(baseDir + 'canonDocJCSECDSAP384.txt', cannon);


// Hash canonized document
let docHash = sha384(cannon); // @noble/hash will convert string to bytes via UTF-8
console.log("Hash of canonized document in hex:")
console.log(bytesToHex(docHash));
writeFile(baseDir + 'docHashJCSECDSAP384.txt', bytesToHex(docHash));

// Set proof options per draft
let proofConfig = {};
proofConfig.type = "DataIntegrityProof";
proofConfig.cryptosuite = "ecdsa-jcs-2019";
proofConfig.created = "2023-02-24T23:36:38Z";
proofConfig.verificationMethod = "https://vc.example/issuers/5678#" + keyPair.publicKeyMultibase;
proofConfig.proofPurpose = "assertionMethod";
writeFile(baseDir + 'proofConfigJCSECDSAP384.json', JSON.stringify(proofConfig, null, 2));

// canonize the proof config
let proofCanon = canonicalize(proofConfig);
console.log("Proof Configuration Canonized:");
console.log(proofCanon);
writeFile(baseDir + 'proofCanonJCSECDSAP384.txt', proofCanon);

// Hash canonized proof config
let proofHash = sha384(proofCanon); // @noble/hash will convert string to bytes via UTF-8
console.log("Hash of canonized proof in hex:")
console.log(bytesToHex(proofHash));
writeFile(baseDir + 'proofHashJCSECDSAP384.txt', bytesToHex(proofHash));

// Combine hashes
let combinedHash = concatBytes(proofHash, docHash); // Hash order different from draft
writeFile(baseDir + 'combinedHashJCSECDSAP384.txt', bytesToHex(combinedHash));

// Sign
let msgHash = sha384(combinedHash); // Hash is done outside of the algorithm in noble/curve case.
let signature = P384.sign(msgHash, privateKey);
console.log(signature);
writeFile(baseDir + 'sigHexJCSECDSAP384.txt', bytesToHex(signature.toCompactRawBytes()));
console.log("Computed Signature from private key:");
console.log(base58btc.encode(signature.toCompactRawBytes()));
writeFile(baseDir + 'sigBTC58JCSECDSAP384.txt', base58btc.encode(signature.toCompactRawBytes()));

// Verify (just to see we have a good private/public pair)
let pbk = base58btc.decode(keyPair.publicKeyMultibase);
pbk = pbk.slice(2, pbk.length); // First two bytes are multi-format indicator
console.log(`Public Key hex: ${bytesToHex(pbk)}, Length: ${pbk.length}`);
let result = P384.verify(signature, msgHash, pbk);
console.log(`Signature verified: ${result}`);

// Construct Signed Document
let signedDocument = Object.assign({}, document);
delete proofConfig['@context'];
signedDocument.proof = proofConfig;
signedDocument.proof.proofValue = base58btc.encode(signature.toCompactRawBytes());

console.log(JSON.stringify(signedDocument, null, 2));
writeFile(baseDir + 'signedJCSECDSAP384.json', JSON.stringify(signedDocument, null, 2));

