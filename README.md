# Test Vector Creation and Validation for Multiple Verifiable Credential Proofs

## EdDSA-2022 Suite Test Vector Creation and Validation

For the EdDSA Cryptosuite v2020 draft there are currently the following 
"Proof Representations" that need test vectors:

1. DataIntegrityProof (type: "DataIntegrityProof", cryptosuite: "eddsa-rdfc-2022")
2. Ed25519Signature2020 (type: "Ed25519Signature2020"), this is "legacy" but well implemented
3. eddsa-jcs-2022 (type: "DataIntegrityProof", cryptosuite: "eddsa-jcs-2022")

We have create corresponding pairs of creation/verification examples to create test vectors
that illustrate the procedures from the draft step by step using only the basic primitives
of: canonicalization, hashing, signatures, and multi-format decoding.

The unsigned document input to all the signing (creation) examples comes from the file
`input//unsigned.json` or can be put in line with the example code. Generated signed
credentials are put in the `output` directory which are then used in the verification
examples.

Note that ECDSA examples/test vectors have been added for P-256 and P-384 cases with RDF and JCS canonicalization. These have crytosuite identifiers of `ecdsa-rdfc-2019` and `ecdsa-jcs-2019`. The different curves are determined for verification purposes by the public key type. For creation purposes we have separate files.

### Example Code

All example code uses `console.log` to produce output and write files to the `output` to generate the intermediate steps to show in test vectors.

1. [DataIntegrityCreate.js](DataIntegrityCreate.js) and [DataIntegrityVerify.js](DataIntegrityVerify.js) for the type: "DataIntegrityProof", cryptosuite: "eddsa-2022" case.
2. [EdSig2020Create.js](EdSig2020Create.js) and [EdSig2020Verify.js](EdSig2020Verify.js) for the type: "Ed25519Signature2020" case.
3. [JCSDataIntegrityCreate.js](JCSDataIntegrityCreate.js) and [JCSDataIntegrityVerify.js](JCSDataIntegrityVerify.js) for the type: "DataIntegrityProof", cryptosuite: "json-eddsa-2022".

### CHAPI Playground Verification

As of 2023-02-28 we downloaded a mock citizenship credential from the [CHAPI Playground](https://playground.chapi.io/issuer) this is stored in the file: `input/citizenship-v1.js`. By modifying two lines of the [EdSig2020Verify.js](EdSig2020Verify.js) example (comment out one line, uncomment another) you can use this as input for step by step Verifiable Credential Verification under the "Ed25519Signature2020" case. Yes, this verifies!. However, this credential is too long to be used as a test vector for the draft.

## ECDSA-2019 Suite Test Vector Creation and Validation

Work in progress as draft progresses.

### Code for Test Vector Generation/Validation

All example code uses `console.log` to produce output and write files to the `output` to generate the intermediate steps to show in test vectors.

1. [ECDSAP256Create.js](ECDSAP256Create.js) and [ECDSAP256Verify.js.js](ECDSAP256Verify.js.js) for the type: "DataIntegrityProof", cryptosuite: "ecdsa-secp256r1-2019" case.
2. [ECDSAP384Create.js](ECDSAP384Create.js) and [ECDSAP384Verify.js.js](ECDSAP384Verify.js.js) for the type: "DataIntegrityProof", cryptosuite: "ecdsa-secp384r1-2019" case.

## Libraries Used

See the `package.json` file for the most up to date list. Currently we use `@noble/ed25519` for signatures, 
`@noble/hashes` for hashes, `canonicalize` for JSON Canonicalization Scheme (JCS), `jsonld` for JSON-LD based canonicalization, `multiformats` for multi-format decoding, and `varint` to help with multicodec encoding. More information on each of these packages can be obtained via [NPM](https://www.npmjs.com/).

No higher level signing libraries were used since our aim is to generate vendor independent test vectors for the specification.

## JSON-LD Usage

For the examples that utilize JSON-LD we have set up a "local document loader" and  local *contexts* so this code does not need to request resources from the net.

## How to Use

All examples are based on JavaScript and Node.js with package management via NPM. I have tried to limit the tools and techniques used to what I used to cover in a first course on [Web Programming](https://www.grotto-networking.com/WebsiteDevelopment/WebDev.html). This code is suitable for generating test vectors and understanding the procedures in the draft specification and not intended for any other purpose.


