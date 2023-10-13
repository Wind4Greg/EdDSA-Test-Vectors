/*
    Steps to verify a signed verifiable credential in the *DataIntegrityProof*
    representation with a "ecdsa-secp256r1-2019" cryptosuite. Run this after
    ECDSAP384Create.js or modify to read in
    a signed file of your choice. Caveat: No error checking is performed.
    Caveat 2: This is prior to a spec!
*/
import { readFile } from 'fs/promises';
import { localLoader } from './documentLoader.js';
import jsonld from 'jsonld';
import { base58btc } from "multiformats/bases/base58";
import { P384 } from '@noble/curves/p384';
import { sha384 } from '@noble/hashes/sha512';
import { bytesToHex, concatBytes } from '@noble/hashes/utils';

const baseDir = "./output/ecdsa-rdfc-2019-p384/";

jsonld.documentLoader = localLoader;

// Read signed input document from a file or just specify it right here.
const signedDocument = JSON.parse(
    await readFile(
      new URL(baseDir + 'signedECDSAP384.json', import.meta.url)
    )
  );

// Document without proof
let document = Object.assign({}, signedDocument);
delete document.proof;
console.log(document);

// Canonize the document
// Need to feed the canonize function a hash appropriate to the signing curve
// and hash used with signature.
class MessageDigest384 {
  constructor() {
    this.md = sha384.create()
  }
  update(msg) {
    this.md.update(msg)
  }
  digest() {
    return bytesToHex(this.md.digest())
  }
};
const canonOptions = { algorithm: 'URDNA2015',
  format: 'application/n-quads', createMessageDigest: () => new MessageDigest384()}
let cannon = await jsonld.canonize(document, canonOptions);
console.log("Canonized unsigned document:")
console.log(cannon);

// Hash canonized document
let docHash = sha384(cannon); // @noble/hash will convert string to bytes via UTF-8
console.log("Hash of canonized document in hex:")
console.log(bytesToHex(docHash));

// Set proof options per draft
let proofConfig = {};
proofConfig.type = signedDocument.proof.type;
proofConfig.cryptosuite = signedDocument.proof.cryptosuite;
proofConfig.created = signedDocument.proof.created;
proofConfig.verificationMethod = signedDocument.proof.verificationMethod;
proofConfig.proofPurpose = signedDocument.proof.proofPurpose;
proofConfig["@context"] = signedDocument["@context"]; // Missing from draft!!!

// canonize the proof config
let proofCanon = await jsonld.canonize(proofConfig, canonOptions);
console.log("Proof Configuration Canonized:");
console.log(proofCanon);

// Hash canonized proof config
let proofHash = sha384(proofCanon); // @noble/hash will convert string to bytes via UTF-8
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
let msgHash = sha384(combinedHash); // Hash is done outside of the algorithm in noble/curve case.
let signature = base58btc.decode(signedDocument.proof.proofValue);
let result = P384.verify(signature, msgHash, pbk);
console.log(`Signature verified: ${result}`);
