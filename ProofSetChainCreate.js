/*
    Steps to create a signed verifiable credential with a proof set and then a
    proof chain using Ed25519 signatures.
    representation.
*/

import { mkdir, readFile, writeFile } from 'fs/promises';
import jsonld from 'jsonld';
import { localLoader } from './documentLoader.js';
import { base58btc } from "multiformats/bases/base58";
import {ed25519 as ed} from '@noble/curves/ed25519';
import { sha256 } from '@noble/hashes/sha256';
import { bytesToHex, concatBytes } from '@noble/hashes/utils';

// Create output directory for the results
const baseDir = "./output/eddsa-set-chain-2022/";
let status = await mkdir(baseDir, {recursive: true});

jsonld.documentLoader = localLoader; // Local loader for JSON-LD

const keyPairs = JSON.parse(
  await readFile(
    new URL('./input/multiKeyPairs.json', import.meta.url)
  )
);

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
// writeFile(baseDir + 'canonDocDataInt.txt', cannon);

// Hash canonized document
let docHash = sha256(cannon); // @noble/hash will convert string to bytes via UTF-8
console.log("Hash of canonized document in hex:")
console.log(bytesToHex(docHash));
// writeFile(baseDir + 'docHashDataInt.txt', bytesToHex(docHash));

// Set up proof set, two different signers proof will be an array based on two

let setKeys = [keyPairs.keyPair1, keyPairs.keyPair2];
let proofSet = [];
const proofIds = ["urn:uuid:26329423-bec9-4b2e-88cb-a7c7d9dc4544",
  "urn:uuid:8cc9022b-6b14-4cf3-8571-74972c5feb54"];

for (let i = 0; i < setKeys.length; i++) {
  // different proof configurations
  // Set proof options per draft
  let proofConfig = {};
  proofConfig.type = "DataIntegrityProof";
  proofConfig.id = proofIds[i];
  proofConfig.cryptosuite = "eddsa-rdfc-2022";
  proofConfig.created = "2023-02-24T23:36:38Z";
  proofConfig.verificationMethod = "https://vc.example/issuers/5678" + (i+1) +
    "#" + setKeys[i].publicKeyMultibase;
  proofConfig.proofPurpose = "assertionMethod";
  proofConfig["@context"] = document["@context"]; // Missing from draft!!!
  // writeFile(baseDir + 'proofConfigDataInt.json', JSON.stringify(proofConfig, null, 2));

  // canonize the proof config
  let proofCanon = await jsonld.canonize(proofConfig);
  console.log("Proof Configuration Canonized:");
  console.log(proofCanon);
  // writeFile(baseDir + 'proofCanonDataInt.txt', proofCanon);

  // Hash canonized proof config
  let proofHash = sha256(proofCanon); // @noble/hash will convert string to bytes via UTF-8
  console.log("Hash of canonized proof in hex:")
  console.log(bytesToHex(proofHash));
  // writeFile(baseDir + 'proofHashDataInt.txt', bytesToHex(proofHash));

  // Combine hashes
  let combinedHash = concatBytes(proofHash, docHash);
  // writeFile(baseDir + 'combinedHashDataInt.txt', bytesToHex(combinedHash));

  // Sign
  let privKey = base58btc.decode(setKeys[i].privateKeyMultibase);
  privKey = privKey.slice(2, 34); // only want the first 2-34 bytes
  console.log(`Secret key length ${privKey.length}, value in hex:`);
  let signature = await ed.sign(combinedHash, privKey);
  // writeFile(baseDir + 'sigHexDataInt.txt', bytesToHex(signature));
  console.log("Computed Signature from private key:");
  console.log(base58btc.encode(signature));
  // writeFile(baseDir + 'sigBTC58DataInt.txt', base58btc.encode(signature));
  proofConfig.proofValue = base58btc.encode(signature);
  delete proofConfig['@context'];
  proofSet.push(proofConfig);
}

// Construct Signed Document
let signedDocument = Object.assign({}, document);
signedDocument.proof = proofSet;

// console.log(JSON.stringify(signedDocument, null, 2));
writeFile(baseDir + 'signedProofSet.json', JSON.stringify(signedDocument, null, 2));

// Now construct a proof chain with keyPair3
let proofConfigChain = {};
proofConfigChain.type = "DataIntegrityProof";
proofConfigChain.cryptosuite = "eddsa-rdfc-2022";
proofConfigChain.created = "2023-02-25T22:36:38Z"; // Signing later
proofConfigChain.verificationMethod = "https://vc.example/issuers/5678" + (3) +
  "#" + keyPairs.keyPair3.publicKeyMultibase;
proofConfigChain.proofPurpose = "assertionMethod";
proofConfigChain["@context"] = document["@context"];
proofConfigChain.previousProof = proofIds; // Want to include both proofs from the proof set
// Dave's algorithm update
document.proof = proofSet; // These are the "matching proofs" though I didn't actually check the ids
// Canonize the "chained" document
cannon = await jsonld.canonize(document);
console.log("Canonized chained document:")
console.log(cannon);
// writeFile(baseDir + 'canonDocDataInt.txt', cannon);

// Hash canonized chained document
docHash = sha256(cannon); // @noble/hash will convert string to bytes via UTF-8
console.log("Hash of canonized document in hex:")
console.log(bytesToHex(docHash));
// writeFile(baseDir + 'docHashDataInt.txt', bytesToHex(docHash));


  // canonize the proof config
  let proofCanon = await jsonld.canonize(proofConfigChain);
  console.log("Proof Configuration Chain Canonized:");
  console.log(proofCanon);
  // writeFile(baseDir + 'proofCanonDataInt.txt', proofCanon);

  // Hash canonized proof config
  let proofHash = sha256(proofCanon); // @noble/hash will convert string to bytes via UTF-8
  console.log("Hash of canonized proof in hex:")
  console.log(bytesToHex(proofHash));
  // writeFile(baseDir + 'proofHashDataInt.txt', bytesToHex(proofHash));

  // Combine hashes
  let combinedHash = concatBytes(proofHash, docHash);
  // writeFile(baseDir + 'combinedHashDataInt.txt', bytesToHex(combinedHash));

  // Sign
  let privKey = base58btc.decode(keyPairs.keyPair3.privateKeyMultibase);
  privKey = privKey.slice(2, 34); // only want the first 2-34 bytes
  console.log(`Secret key length ${privKey.length}, value in hex:`);
  let signature = await ed.sign(combinedHash, privKey);
  // writeFile(baseDir + 'sigHexDataInt.txt', bytesToHex(signature));
  console.log("Computed Chain Signature from private key:");
  console.log(base58btc.encode(signature));
  // writeFile(baseDir + 'sigBTC58DataInt.txt', base58btc.encode(signature));
  proofConfigChain.proofValue = base58btc.encode(signature);
  delete proofConfigChain['@context'];
  let allProofs = proofSet.concat(proofConfigChain);
// Construct Signed Document
  signedDocument = Object.assign({}, document);
  signedDocument.proof = allProofs;

// console.log(JSON.stringify(signedDocument, null, 2));
writeFile(baseDir + 'signedProofChain.json', JSON.stringify(signedDocument, null, 2));


