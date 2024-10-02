/*
    Steps to verify a signed verifiable credential containing a proof set or
    chain.
*/
import { readFile } from 'fs/promises';
import { localLoader } from './documentLoader.js';
import jsonld from 'jsonld';
import { base58btc } from "multiformats/bases/base58";
import {ed25519 as ed} from '@noble/curves/ed25519';
import { sha256 } from '@noble/hashes/sha256';
import { bytesToHex, concatBytes } from '@noble/hashes/utils';

const baseDir = "./output/eddsa-set-chain-2022/";

jsonld.documentLoader = localLoader;

// Read signed input document from a file or just specify it right here.
const fname = "signedProofChain2.json"; //"signedProofSet.json"; "proofChainEdDSA1.json"; "signedProofChain2.json"
const signedDocument = JSON.parse(
    await readFile(
      new URL(baseDir + fname, import.meta.url)
    )
  );

// Document without proof
let document = Object.assign({}, signedDocument);
delete document.proof;
let proofs = signedDocument.proof;
if (!Array.isArray(proofs)) { // If not an array make it a one element array
    proofs = [proofs];
}

// Need to iterate over all proofs and check validity
for (let proof of proofs) {
    // Get matching, depending
    if (proof.previousProof) {
        let matchingProofs = findMatchingProofs(proof.previousProof, proofs);
        document.proof = matchingProofs; // These are the "matching proofs" though I didn't actually check the ids
        console.log(`Matching proofs for proof = ${proof}`);
        console.log(matchingProofs);
    }
    // Canonize the "chained" document
    let cannon = await jsonld.canonize(document);
    // console.log("Canonized unsigned document:")
    // console.log(cannon);
    delete document.proof; // Remove it after canonization
    // Hash canonized document
    let docHash = sha256(cannon); // @noble/hash will convert string to bytes via UTF-8
    // console.log("Hash of canonized document in hex:")
    // console.log(bytesToHex(docHash));

    // Set proof options
    let proofConfig = Object.assign({}, proof);
    delete proofConfig.proofValue;
    proofConfig["@context"] = signedDocument["@context"]; // Missing from draft!!!

    // canonize the proof config
    let proofCanon = await jsonld.canonize(proofConfig);
    // console.log("Proof Configuration Canonized:");
    // console.log(proofCanon);

    // Hash canonized proof config
    let proofHash = sha256(proofCanon); // @noble/hash will convert string to bytes via UTF-8
    // console.log("Hash of canonized proof in hex:")
    // console.log(bytesToHex(proofHash));

    // Combine hashes
    let combinedHash = concatBytes(proofHash, docHash); // Hash order different from draft

    // Get public key
    let encodedPbk = proof.verificationMethod.split("#")[1];
    let pbk = base58btc.decode(encodedPbk);
    pbk = pbk.slice(2, pbk.length); // First two bytes are multi-format indicator
    console.log(`Public Key multibase: ${encodedPbk}`);

    // Verify
    let signature = base58btc.decode(proof.proofValue);
    let result = await ed.verify(signature, combinedHash, pbk);
    console.log(`Signature verified: ${result}`);
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