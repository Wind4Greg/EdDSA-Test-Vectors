/*
    Steps to create a signed verifiable credential with an *EcdsaSecp384r1Signature2019*
    based on "DataIntegrityProof" representation. This has not be specified in a draft yet.
*/

import { mkdir, readFile, writeFile } from 'fs/promises';
import jsonld from 'jsonld';
import { localLoader } from './documentLoader.js';
import { base58btc } from "multiformats/bases/base58";
import { P384 } from '@noble/curves/p384';
import { sha384 } from '@noble/hashes/sha512';
import { bytesToHex, concatBytes, hexToBytes } from '@noble/hashes/utils';

// Set input file and output directory here.
// const dirsAndFiles = {
//   outputDir: './output/ecdsa-rdfc-2019-p384/',
//   inputFile: './input/unsigned.json'
// }

const dirsAndFiles = {
  outputDir: './output/ecdsa-rdfc-2019-p384/employ/',
  inputFile: './input/employmentAuth.json'
}

// Create output directory for the results
const baseDir = dirsAndFiles.outputDir;
let status = await mkdir(baseDir, {recursive: true});

jsonld.documentLoader = localLoader; // Local loader for JSON-LD

const keyPair = {
    publicKeyMultibase: "z82LkuBieyGShVBhvtE2zoiD6Kma4tJGFtkAhxR5pfkp5QPw4LutoYWhvQCnGjdVn14kujQ"
};


let privateKey = hexToBytes("6B9D3DAD2E1B8C1C05B19875B6659F4DE23C3B667BF297BA9AA47740787137D896D5724E4C70A825F872C9EA60D2EDF5");
let publicKey = P384.getPublicKey(privateKey);

// Read input document from a file or just specify it right here.
let document = JSON.parse(
    await readFile(
      new URL(dirsAndFiles.inputFile, import.meta.url)
    )
  );

// Signed Document Creation Steps:

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
writeFile(baseDir + 'canonDocECDSAP384.txt', cannon);


// Hash canonized document
let docHash = sha384(cannon); // @noble/hash will convert string to bytes via UTF-8
console.log("Hash of canonized document in hex:")
console.log(bytesToHex(docHash));
writeFile(baseDir + 'docHashECDSAP384.txt', bytesToHex(docHash));

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
writeFile(baseDir + 'proofConfigECDSAP384.json', JSON.stringify(proofConfig, null, 2));

// canonize the proof config
let proofCanon = await jsonld.canonize(proofConfig, canonOptions);
console.log("Proof Configuration Canonized:");
console.log(proofCanon);
writeFile(baseDir + 'proofCanonECDSAP384.txt', proofCanon);

// Hash canonized proof config
let proofHash = sha384(proofCanon); // @noble/hash will convert string to bytes via UTF-8
console.log("Hash of canonized proof in hex:")
console.log(bytesToHex(proofHash));
writeFile(baseDir + 'proofHashECDSAP384.txt', bytesToHex(proofHash));

// Combine hashes
let combinedHash = concatBytes(proofHash, docHash); // Hash order different from draft
writeFile(baseDir + 'combinedHashECDSAP384.txt', bytesToHex(combinedHash));

// Sign
let msgHash = sha384(combinedHash); // Hash is done outside of the algorithm in noble/curve case.
let signature = P384.sign(msgHash, privateKey);
console.log(signature);
writeFile(baseDir + 'sigHexECDSAP384.txt', bytesToHex(signature.toCompactRawBytes()));
console.log("Computed Signature from private key:");
console.log(base58btc.encode(signature.toCompactRawBytes()));
writeFile(baseDir + 'sigBTC58ECDSAP384.txt', base58btc.encode(signature.toCompactRawBytes()));

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
writeFile(baseDir + 'signedECDSAP384.json', JSON.stringify(signedDocument, null, 2));

