# Test Vector Creation and Validation for EdDSA-2022 Suite

For the EdDSA Cryptosuite v2020 draft there are currently the following 
"Proof Representations" that need test vectors:

1. DataIntegrityProof (type: "DataIntegrityProof", cryptosuite: "eddsa-2022")
2. Ed25519Signature2020 (type: "Ed25519Signature2020"), this is "legacy" but well implemented
3. json-eddsa-2022 (type: "DataIntegrityProof", cryptosuite: "json-eddsa-2022")

We have create corresponding pairs of creation/verification examples to create test vectors
that illustrate the procedures from the draft step by step using only the basic primitives
of: canonicalization, hashing, signatures, and multi-format decoding.

The unsigned document input to all the signing (creation) examples comes from the file
`input//unsigned.json` or can be put in line with the example code. Generated signed
credentials are put in the `output` directory which are then used in the verification
examples.

## Example Code

All example code uses `console.log` to produce output to generate the intermediate steps to show in test vectors.

1. [DataIntegrityCreate.js](DataIntegrityCreate.js) and [DataIntegrityVerify.js](DataIntegrityVerify.js) for the type: "DataIntegrityProof", cryptosuite: "eddsa-2022" case.
2. [EdSig2020Create.js](EdSig2020Create.js) and [EdSig2020Verify.js](EdSig2020Verify.js) for the type: "Ed25519Signature2020" case.
3. [JCSDataIntegrityCreate.js](JCSDataIntegrityCreate.js) and [JCSDataIntegrityVerify.js](JCSDataIntegrityVerify.js) for the type: "DataIntegrityProof", cryptosuite: "json-eddsa-2022".

## Libraries Used

See the `package.json` file for the most up to date list. Currently we use `@noble/ed25519` for signatures, 
`@noble/hashes` for hashes, `canonicalize` for JSON Canonicalization Scheme (JCS), `jsonld` for JSON-LD based canonicalization, and `multiformats` for multi-format decoding. More information on each of these packages can be obtained via [NPM](https://www.npmjs.com/).

No higher level signing libraries were used since our aim is to generate vendor independent test vectors for the specification.

## CHAPI Playground Verification

As of 2023-02-28 we downloaded a mock citizenship credential from the [CHAPI Playground](https://playground.chapi.io/issuer) this is stored in the file: `input/citizenship-v1.js`. By modifying two lines of the [EdSig2020Verify.js](EdSig2020Verify.js) example (comment out one line, uncomment another) you can use this as input for step by step Verifiable Credential Verification under the "Ed25519Signature2020" case. Yes, this verifies!. However, this credential is too long to be used as a test vector for the draft.

## JSON-LD Usage

For the examples that utilize JSON-LD we have set up a "local document loader" and  local *contexts* so this code does not need to request resources from the net.

## How to Use

All examples are based on JavaScript and Node.js with package management via NPM. I have tried to limit the tools and techniques used to what I used to cover in a first course on [Web Programming](https://www.grotto-networking.com/WebsiteDevelopment/WebDev.html). This code is suitable for generating test vectors and understanding the procedures in the draft specification and not intended for any other purpose.


