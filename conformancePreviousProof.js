/*
    Steps to create a signed verifiable credential with a simple
    proof chain using Ed25519 signatures.
*/

import { mkdir } from 'fs/promises';
import { createRequire } from 'module';
import jsonld from 'jsonld';
import { localLoader } from './documentLoader.js';
import {secureDocument} from './conformanceTools.js';


const require = createRequire(import.meta.url);

// Create output directory for the results
const baseDir = "./output/eddsa-rdfc-2022/conformance/";
// recursively create the dirs for the baseDir is needed
let status = await mkdir(baseDir, {recursive: true});

jsonld.documentLoader = localLoader; // Local loader for JSON-LD

const keyPairs = require('./input/multiKeyPairs.json');
const chainKeys = [keyPairs.keyPair1, keyPairs.keyPair2]

const previousProof = 'urn:uuid:26329423-bec9-4b2e-88cb-a7c7d9dc4544';
const proofIds = [previousProof];
// set the first entry to null to prevent the first proof
// from having a previousProof set
const previousProofs = [null, previousProof];

// Read input documents from files.
const documents = new Map([
  ['1.1', require('./input/v1/unsecured.json')],
  ['2.0', require('./input/v2/unsecured.json')]
]);

// function to get all matching proofs (only first level no dependencies)
// prevProofs is either a string or an array
// proofs is an array of proofs
const findMatchingProofs = {
  valid(prevProofs, proofs) {
    console.log(`findMatch called with ${prevProofs}`);
    let matches = [];
    if (!prevProofs) { // In case of no previous proof edge case
      return matches;
    }
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
  },
  invalidType(prevProofs, proofs) {
    console.log(`findMatch called with ${prevProofs}`);
    let matches = [];
    if (!prevProofs) { // In case of no previous proof edge case
      return matches;
    }
    if (Array.isArray(prevProofs)) {
        prevProofs.forEach(pp => {
          // NOTE String is strictly for allowing the creation
          // of invalid test data in this case a number as a previousProof
          let matchProof = proofs.find(p => String(p.id) === String(pp));
          if (!matchProof) {
            throw new Error(`Missing proof for id = ${pp}`);
          }
          matches.push(matchProof);
        })
    } else {
        // NOTE String is strictly for allowing the creation
        // of invalid test data in this case a number as a previousProof
        let matchProof = proofs.find(p => String(p.id) === String(prevProofs));
        if (!matchProof) {
          throw new Error(`Missing proof for id = ${prevProofs}`);
        }
        matches.push(matchProof);
    }
    return matches;
  },
  missingPreviousProof(prevProofs, proofs){
    // for this test prevProofs don't match proof ids
    // so just return the proofs
    return proofs;
  }
}
// create versioned VCs with previousProof as string
for(const [version, credential] of documents) {
  await secureDocument({
    baseDir,
    credential,
    fileName: `${version}-previousProofStringOk`,
    previousProofType: 'string',
    proofIds,
    previousProofs,
    findMatchingProofs: findMatchingProofs.valid,
    chainKeys
  });
}
// create versioned VCs with previousProof as an Array
for(const [version, credential] of documents) {
  await secureDocument({
    baseDir,
    credential,
    fileName: `${version}-previousProofArrayOk`,
    findMatchingProofs: findMatchingProofs.valid,
    previousProofType: 'Array',
    proofIds,
    previousProofs,
    chainKeys
  });
}

// create versioned VCs with previousProof as a Number
for(const [version, credential] of documents) {
  await secureDocument({
    baseDir,
    credential,
    chainKeys,
    fileName: `${version}-previousProofNotStringFail`,
    findMatchingProofs: findMatchingProofs.invalidType,
    previousProofType: 'string',
    previousProofs: [null, 456321],
    proofIds: ['456321']
  });
}

// create versioned VCs with missing previousProof
for(const [version, credential] of documents) {
  await secureDocument({
    baseDir,
    credential,
    chainKeys,
    fileName: `${version}-previousProofMissingFail`,
    findMatchingProofs: findMatchingProofs.missingPreviousProof,
    previousProofType: 'string',
    // this will result in a signed VC with a missing previousProof
    previousProofs: [null, 'urn:uuid:38329423-2179-4b2e-88cb-a7c7d9dc4544'],
    proofIds
  });
}
