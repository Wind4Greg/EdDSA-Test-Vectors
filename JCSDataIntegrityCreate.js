/*
    Steps to create a signed verifiable credential in the *DataIntegrityProof*
    with cryptosuite: "json-eddsa-2022", i.e., JCS for canonicalization.
*/

import { readFile, writeFile } from 'fs/promises';
import { base58btc } from "multiformats/bases/base58";
import { ed25519 as ed } from '@noble/curves/ed25519';
import { sha256 } from '@noble/hashes/sha256';
import { bytesToHex, concatBytes } from '@noble/hashes/utils';
import canonicalize from 'canonicalize';

const keyPair = {
  publicKeyMultibase: "z6MkrJVnaZkeFzdQyMZu1cgjg7k1pZZ6pvBQ7XJPt4swbTQ2",
  privateKeyMultibase: "z3u2en7t5LR2WtQH5PfFqMqwVHBeXouLzo6haApm8XHqvjxq"
};

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
writeFile('./output/canonDocJCS.txt', cannon);

// Hash canonized document
let docHash = sha256(cannon); // @noble/hash will convert string to bytes via UTF-8
console.log("Hash of canonized document in hex:")
console.log(bytesToHex(docHash));
writeFile('./output/docHashJCS.txt', bytesToHex(docHash));


// Set proof options per draft
let proofConfig = {};
proofConfig.type = "DataIntegrityProof";
proofConfig.cryptosuite = "json-eddsa-2022";
proofConfig.created = "2023-02-24T23:36:38Z";
proofConfig.verificationMethod = "https://vc.example/issuers/5678#" + keyPair.publicKeyMultibase;
proofConfig.proofPurpose = "assertionMethod";
// proofConfig["@context"] = document["@context"];  // Don't really need this for JCS
writeFile('./output/proofConfigJCS.json', JSON.stringify(proofConfig, null, 2));

// canonize the proof config
let proofCanon = canonicalize(proofConfig);
console.log("Proof Configuration Canonized:");
console.log(proofCanon);
writeFile('./output/proofCanonJCS.txt', proofCanon);


// Hash canonized proof config
let proofHash = sha256(proofCanon); // @noble/hash will convert string to bytes via UTF-8
console.log("Hash of canonized proof in hex:")
console.log(bytesToHex(proofHash));
writeFile('./output/proofHashJCS.txt', bytesToHex(proofHash));

// Combine hashes
let combinedHash = concatBytes(proofHash, docHash); // Hash order different from draft
writeFile('./output/combinedHashJCS.txt', bytesToHex(combinedHash));

// Sign
let privKey = base58btc.decode(keyPair.privateKeyMultibase);
privKey = privKey.slice(2, 34); // only want the first 2-34 bytes
console.log(`Secret key length ${privKey.length}, value in hex:`);
let signature = await ed.sign(combinedHash, privKey);
writeFile('./output/sigHexJCS.txt', bytesToHex(signature));
console.log("Computed Signature from private key:");
console.log(base58btc.encode(signature));
writeFile('./output/sigBTC58JCS.txt', base58btc.encode(signature));

// Verify (just to see we have a good private/public pair)
let pbk = base58btc.decode(keyPair.publicKeyMultibase);
pbk = pbk.slice(2, pbk.length); // First two bytes are multi-format indicator
console.log(`Public Key hex: ${bytesToHex(pbk)}, Length: ${pbk.length}`);
let result = await ed.verify(signature, combinedHash, pbk);
console.log(`Signature verified: ${result}`);

// Construct Signed Document
let signedDocument = Object.assign({}, document);
delete proofConfig['@context'];
signedDocument.proof = proofConfig;
signedDocument.proof.proofValue = base58btc.encode(signature);

console.log(JSON.stringify(signedDocument, null, 2));
writeFile('./output/signedJCS.json', JSON.stringify(signedDocument, null, 2));

