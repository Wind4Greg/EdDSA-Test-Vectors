/* Utility function to find matching proofs and their dependencies */

// Examples
const proofSet1 = [
    {
      "type": "DataIntegrityProof",
      "id": "urn:uuid:26329423-bec9-4b2e-88cb-a7c7d9dc4544",
      "cryptosuite": "eddsa-rdfc-2022",
      "created": "2023-02-24T23:36:38Z",
      "verificationMethod": "https://vc.example/issuers/56781#z6MktgKTsu1QhX6QPbyqG6geXdw6FQCZBPq7uQpieWbiQiG7",
      "proofPurpose": "assertionMethod",
      "proofValue": "z5KTX5yikM4eUukZW9qh66LGT3KZEUCACGpWcT2t4Yd54NMoFRchGmH4778omyNFAD3weSt6sNk5fuaMQmhhzNmEC"
    },
    {
      "type": "DataIntegrityProof",
      "id": "urn:uuid:8cc9022b-6b14-4cf3-8571-74972c5feb54",
      "cryptosuite": "eddsa-rdfc-2022",
      "created": "2023-02-24T23:36:38Z",
      "verificationMethod": "https://vc.example/issuers/56782#z6MkhWqdDBPojHA7cprTGTt5yHv5yUi1B8cnXn8ReLumkw6E",
      "proofPurpose": "assertionMethod",
      "proofValue": "z5KXNyXDcm822dHS37tmS6Xc7FFNo8c73AfeqmfHoywPxnXWNjWKYK3VQzt3CMUoK9uAqsboVHKJXxuYwbdnfxZeA"
    }
];

const prevProofs = [
    "urn:uuid:26329423-bec9-4b2e-88cb-a7c7d9dc4544",
    "urn:uuid:8cc9022b-6b14-4cf3-8571-74972c5feb54"
  ];

const proofSetChain1 = [
    {
      "type": "DataIntegrityProof",
      "id": "urn:uuid:26329423-bec9-4b2e-88cb-a7c7d9dc4544",
      "cryptosuite": "eddsa-rdfc-2022",
      "created": "2023-02-24T23:36:38Z",
      "verificationMethod": "https://vc.example/issuers/56781#z6MktgKTsu1QhX6QPbyqG6geXdw6FQCZBPq7uQpieWbiQiG7",
      "proofPurpose": "assertionMethod",
      "proofValue": "z5KTX5yikM4eUukZW9qh66LGT3KZEUCACGpWcT2t4Yd54NMoFRchGmH4778omyNFAD3weSt6sNk5fuaMQmhhzNmEC"
    },
    {
      "type": "DataIntegrityProof",
      "id": "urn:uuid:8cc9022b-6b14-4cf3-8571-74972c5feb54",
      "cryptosuite": "eddsa-rdfc-2022",
      "created": "2023-02-24T23:36:38Z",
      "verificationMethod": "https://vc.example/issuers/56782#z6MkhWqdDBPojHA7cprTGTt5yHv5yUi1B8cnXn8ReLumkw6E",
      "proofPurpose": "assertionMethod",
      "proofValue": "z5KXNyXDcm822dHS37tmS6Xc7FFNo8c73AfeqmfHoywPxnXWNjWKYK3VQzt3CMUoK9uAqsboVHKJXxuYwbdnfxZeA"
    },
    {
      "type": "DataIntegrityProof",
      "id": "urn:uuid:d94f792a-c546-4d06-b38a-da070ab56c23",
      "cryptosuite": "eddsa-rdfc-2022",
      "created": "2023-02-25T22:36:38Z",
      "verificationMethod": "https://vc.example/issuers/56783#z6MkmEq87wkHCYnWnNZkigeDMGTN7oUw1upkhzd77KuXERS1",
      "proofPurpose": "assertionMethod",
      "previousProof": [
        "urn:uuid:26329423-bec9-4b2e-88cb-a7c7d9dc4544",
        "urn:uuid:8cc9022b-6b14-4cf3-8571-74972c5feb54"
      ]
    }
];

const prevProof2 = "urn:uuid:d94f792a-c546-4d06-b38a-da070ab56c23";

// function to get all matching proofs and their dependencies
// prevProofs is either a string or an array
// proofs is an array of proofs
// matches is and empty set that you provide and will contain the result
function findMatchingProofs(prevProofs, proofs, matches) {
    console.log(`findMatch called with ${prevProofs}`);
    if (Array.isArray(prevProofs)) {
        prevProofs.forEach(pp => findMatchingProofs(pp, proofs, matches))
    } else {
        let matchProof = proofs.find(p => p.id === prevProofs)
        matches.add(matchProof);
        // Check for dependencies
        if (matchProof.previousProof) {
            findMatchingProofs(matchProof.previousProof, proofs, matches)
        }
    }
}

let matches = new Set();
findMatchingProofs(prevProofs, proofSet1, matches);
console.log(matches);

matches = new Set();
findMatchingProofs(prevProof2, proofSetChain1, matches);
console.log(matches);