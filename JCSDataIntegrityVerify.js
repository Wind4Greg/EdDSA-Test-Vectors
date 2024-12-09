/*
    Steps to verify a signed verifiable credential in the *DataIntegrityProof*
    with cryptosuite: "json-eddsa-2022", i.e., JCS for canonicalization.
    Run this after JCSDataIntegrityCreate.js or modify to read in
    a signed file of your choice. Caveat: No error checking is performed.
*/
import { readFile } from 'fs/promises';
import { base58btc } from "multiformats/bases/base58";
import {ed25519 as ed} from '@noble/curves/ed25519';
import { sha256 } from '@noble/hashes/sha256';
import { bytesToHex, concatBytes } from '@noble/hashes/utils';
import  canonicalize from 'canonicalize';
import equal from 'deep-equal';

const baseDir = "./output/eddsa-jcs-2022/";

// Read signed input document from a file or just specify it right here.
// Use 'signedJCSOldStyle.json' or 'signedJCS.json'
const signedDocument = JSON.parse(
    await readFile(
      new URL(baseDir + 'signedJCS.json', import.meta.url)
    )
  );

// Document without proof
let document = Object.assign({}, signedDocument);
delete document.proof;
console.log(document);

// Set proof options per draft
let proofConfig = {};
proofConfig.type = signedDocument.proof.type;
proofConfig.cryptosuite = signedDocument.proof.cryptosuite;
proofConfig.created = signedDocument.proof.created;
proofConfig.verificationMethod = signedDocument.proof.verificationMethod;
proofConfig.proofPurpose = signedDocument.proof.proofPurpose;
proofConfig["@context"] = signedDocument.proof["@context"];

// check document context relative to proof context
const docContext = document["@context"];
const proofContext = proofConfig["@context"];
if (proofContext) {
  // Note from DM 2.0 the @context field must be an array
  let verifyContext = true;
  for (let i = 0; i < proofContext.length; i++) {
    if (typeof proofContext[i] == 'string') {
      verifyContext = proofContext[i] === docContext[i];
    } else {
      verifyContext = equal(proofContext[i], docContext[i]);
    }
    if (!verifyContext) {
      console.log(`@context not verified: ${proofContext[i]} not equal to ${docContext[i]}`);
    }
  }
  document['@context'] = proofContext; // For JCS we now do this.
}
// Canonize the document
let cannon = canonicalize(document);
console.log("Canonized unsigned document:")
console.log(cannon);

// Hash canonized document
let docHash = sha256(cannon); // @noble/hash will convert string to bytes via UTF-8
console.log("Hash of canonized document in hex:")
console.log(bytesToHex(docHash));



// canonize the proof config
let proofCanon = canonicalize(proofConfig);
console.log("Proof Configuration Canonized:");
console.log(proofCanon);

// Hash canonized proof config
let proofHash = sha256(proofCanon); // @noble/hash will convert string to bytes via UTF-8
console.log("Hash of canonized proof in hex:")
console.log(bytesToHex(proofHash));

// Combine hashes
let combinedHash = concatBytes(proofHash, docHash); // Hash order different from draft

// Get public key
let encodedPbk = signedDocument.proof.verificationMethod.split("#")[1];
let pbk = base58btc.decode(encodedPbk);
pbk = pbk.slice(2, pbk.length); // First two bytes are multi-format indicator
console.log(`Public Key hex: ${bytesToHex(pbk)}, Length: ${pbk.length}`);

// Verify
let signature = base58btc.decode(signedDocument.proof.proofValue);
let result = ed.verify(signature, combinedHash, pbk);
console.log(`Signature verified: ${result}`);
