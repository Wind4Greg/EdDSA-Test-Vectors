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

// Read input documents from files.
const documents = new Map([
  ['1.1', require('./input/v1/unsecured.json')],
  ['2.0', require('./input/v2/unsecured.json')]
]);

// create versioned VCs with previousProof as string
for(const [version, credential] of documents) {
  await secureDocument({
    baseDir,
    credential,
    fileName: `${version}-previousProofStringOk`,
    previousProofType: 'string',
    chainKeys
  });
}
// create versioned VCs with previousProof as an Array
for(const [version, credential] of documents) {
  await secureDocument({
    baseDir,
    credential,
    fileName: `${version}-previousProofArrayOk`,
    previousProofType: 'Array',
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
    previousProofType: 'string',
    proofIds: [456321]
  });
}
