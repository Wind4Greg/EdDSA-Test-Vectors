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

let signedDocument = Object.assign({}, document);
// Canonize the document
let cannon = await jsonld.canonize(document);
// console.log("Canonized unsigned document:")
// console.log(cannon);
// writeFile(baseDir + 'canonDocDataInt.txt', cannon);

// Hash canonized document
let docHash = sha256(cannon); // @noble/hash will convert string to bytes via UTF-8
// console.log("Hash of canonized document in hex:")
// console.log(bytesToHex(docHash));
// writeFile(baseDir + 'docHashDataInt.txt', bytesToHex(docHash));

// Set up proof set, two different signers proof will be an array based on two
let setKeys = [keyPairs.keyPair1, keyPairs.keyPair2];
let proofSet = [];
const proofIds = ["urn:uuid:26329423-bec9-4b2e-88cb-a7c7d9dc4544",
  "urn:uuid:8cc9022b-6b14-4cf3-8571-74972c5feb54",
  "urn:uuid:d94f792a-c546-4d06-b38a-da070ab56c23",
  "urn:uuid:24148446-6ce5-49a6-b221-d29f1ca8a2f9"];

// Proof Sets processing loop
for (let i = 0; i < setKeys.length; i++) {
  // different proof configurations
  // Set proof options per draft
  let proofConfig = {};
  proofConfig.type = "DataIntegrityProof";
  proofConfig.id = proofIds[i];
  proofConfig.cryptosuite = "eddsa-rdfc-2022";
  proofConfig.created = "2023-02-24T23:36:38Z";
  // proofConfig.verificationMethod = "https://vc.example/issuers/5678" + (i+1) +
  //   "#" + setKeys[i].publicKeyMultibase;
  proofConfig.verificationMethod = 'did:key:' + setKeys[i].publicKeyMultibase 
    + '#' + setKeys[i].publicKeyMultibase;

  proofConfig.proofPurpose = "assertionMethod";
  writeFile(baseDir + `proofSetConfig${i+1}.json`, JSON.stringify(proofConfig, null, 2));
  proofConfig["@context"] = document["@context"];


  // canonize the proof config
  let proofCanon = await jsonld.canonize(proofConfig);
  // console.log("Proof Configuration Canonized:");
  // console.log(proofCanon);
  // writeFile(baseDir + 'proofCanonDataInt.txt', proofCanon);

  // Hash canonized proof config
  let proofHash = sha256(proofCanon); // @noble/hash will convert string to bytes via UTF-8
  // console.log("Hash of canonized proof in hex:")
  // console.log(bytesToHex(proofHash));
  // writeFile(baseDir + 'proofHashDataInt.txt', bytesToHex(proofHash));

  // Combine hashes
  let combinedHash = concatBytes(proofHash, docHash);
  // writeFile(baseDir + 'combinedHashDataInt.txt', bytesToHex(combinedHash));

  // Sign
  let privKey = base58btc.decode(setKeys[i].privateKeyMultibase);
  privKey = privKey.slice(2, 34); // only want the first 2-34 bytes
  // console.log(`Secret key length ${privKey.length}, value in hex:`);
  let signature = await ed.sign(combinedHash, privKey);
  // writeFile(baseDir + 'sigHexDataInt.txt', bytesToHex(signature));
  // console.log("Computed Signature from private key:");
  // console.log(base58btc.encode(signature));
  // writeFile(baseDir + 'sigBTC58DataInt.txt', base58btc.encode(signature));
  proofConfig.proofValue = base58btc.encode(signature);
  delete proofConfig['@context'];
  writeFile(baseDir + `proofSetConfigSigned${i+1}.json`, JSON.stringify(proofConfig, null, 2));
  proofSet.push(proofConfig);
  // Construct Signed Document
  if (proofSet.length > 1) {
    signedDocument.proof = proofSet;
  } else {
    signedDocument.proof = proofSet[0];
  }
  // console.log(JSON.stringify(signedDocument, null, 2));
  writeFile(baseDir + `signedProofSet${i+1}.json`, JSON.stringify(signedDocument, null, 2));
}


// **Proof Chains** starting from previous signed document

const chainKeys = [keyPairs.keyPair3, keyPairs.keyPair4];
// Third proof depends on both proofs in the proof set, Fourth proof just depends on third proof
const previousProofs = [proofIds.slice(0,2), proofIds[2]];
for (let i = 0; i < chainKeys.length; i++) {
  let allProofs = signedDocument.proof;
  // Set up the proof configuration for the chain
  let proofConfigChain = {};
  proofConfigChain.type = "DataIntegrityProof";
  if (i !== (chainKeys.length - 1)) { // Don't need id for last item in chain
    proofConfigChain.id = proofIds[i+2];
  }
  proofConfigChain.cryptosuite = "eddsa-rdfc-2022";
  proofConfigChain.created = `2023-02-26T22:${i}6:38Z`; // Signing later for realism ;-)
  // proofConfigChain.verificationMethod = "https://vc.example/issuers/5678" + (i + 3) +
  //   "#" + keyPairs.keyPair3.publicKeyMultibase;
  proofConfigChain.verificationMethod = 'did:key:' + chainKeys[i].publicKeyMultibase + 
    '#' + chainKeys[i].publicKeyMultibase;

  proofConfigChain.proofPurpose = "assertionMethod";

  proofConfigChain.previousProof = previousProofs[i]; // Want to include both proofs from the proof set
  writeFile(baseDir + `proofChainConfig${i+1}.json`, JSON.stringify(proofConfigChain, null, 2));
  proofConfigChain["@context"] = document["@context"];
  // Dave's algorithm update
  let matchingProofs = findMatchingProofs(proofConfigChain.previousProof, allProofs);
  document.proof = matchingProofs;
  console.log(`Matching proofs for i = ${i}`);
  console.log(matchingProofs);
  // Canonize the "chained" document
  writeFile(baseDir + `proofChainTempDoc${i+1}.json`, JSON.stringify(document, null, 2));
  cannon = await jsonld.canonize(document);
  // console.log("Canonized chained document:")
  // console.log(cannon);
  // writeFile(baseDir + 'canonDocDataInt.txt', cannon);

  // Hash canonized chained document
  docHash = sha256(cannon); // @noble/hash will convert string to bytes via UTF-8
  // console.log("Hash of canonized document in hex:")
  // console.log(bytesToHex(docHash));
  // writeFile(baseDir + 'docHashDataInt.txt', bytesToHex(docHash));


  // canonize the proof config
  let proofCanon = await jsonld.canonize(proofConfigChain);
  // console.log("Proof Configuration Chain Canonized:");
  // console.log(proofCanon);
  // writeFile(baseDir + 'proofCanonDataInt.txt', proofCanon);

  // Hash canonized proof config
  let proofHash = sha256(proofCanon); // @noble/hash will convert string to bytes via UTF-8
  // console.log("Hash of canonized proof in hex:")
  // console.log(bytesToHex(proofHash));
  // writeFile(baseDir + 'proofHashDataInt.txt', bytesToHex(proofHash));

  // Combine hashes
  let combinedHash = concatBytes(proofHash, docHash);
  // writeFile(baseDir + 'combinedHashDataInt.txt', bytesToHex(combinedHash));

  // Sign
  let privKey = base58btc.decode(chainKeys[i].privateKeyMultibase);
  privKey = privKey.slice(2, 34); // only want the first 2-34 bytes
  // console.log(`Secret key length ${privKey.length}, value in hex:`);
  let signature = await ed.sign(combinedHash, privKey);
  // writeFile(baseDir + 'sigHexDataInt.txt', bytesToHex(signature));
  // console.log("Computed Chain Signature from private key:");
  // console.log(base58btc.encode(signature));
  // writeFile(baseDir + 'sigBTC58DataInt.txt', base58btc.encode(signature));
  proofConfigChain.proofValue = base58btc.encode(signature);
  delete proofConfigChain['@context'];
  writeFile(baseDir + `proofChainConfigSigned${i+1}.json`, JSON.stringify(proofConfigChain, null, 2));

  // Construct Signed Document
  signedDocument = Object.assign({}, document);
  signedDocument.proof = allProofs.concat(proofConfigChain);

  // console.log(JSON.stringify(signedDocument, null, 2));
  writeFile(baseDir + `signedProofChain${i+1}.json`, JSON.stringify(signedDocument, null, 2));
}

// function to get all matching proofs (only first level no dependencies)
// prevProofs is either a string or an array
// proofs is an array of proofs
function findMatchingProofs(prevProofs, proofs) {
  console.log(`findMatch called with ${prevProofs}`);
  let matches = [];
  if (Array.isArray(prevProofs)) {
      prevProofs.forEach(pp => {
        let matchProof = proofs.find(p => p.id === pp);
        if (!matchProof) {
          throw new Error(`Missing proof for id = ${pp}`);
        }
        matches.push(matchProof);
      })
  } else {
      let matchProof = proofs.find(p => p.id === prevProofs);
      if (!matchProof) {
        throw new Error(`Missing proof for id = ${prevProofs}`);
      }
      matches.push(matchProof);
  }
  return matches;
}
