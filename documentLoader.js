import jsonld from 'jsonld';
import { citizenv1 } from './contexts/citizenship-v1.js';
import { citizenv4 } from './contexts/citizenship-v4rc1.js';
import { vcv2 } from './contexts/credv2.js';
import { examplesv2 } from './contexts/examples-v2.js';
import { vcv1 } from './contexts/credv1.js';
import { edv1 } from './contexts/ed25519-signature-2020-v1.js';
import { diV2 } from './contexts/data-integrity-v2.js';


// Set up a document loader so we don't have to go to the net
const CONTEXTS = {
    "https://www.w3.org/ns/credentials/v2": { "@context": vcv2 },
    "https://www.w3.org/ns/credentials/examples/v2": { "@context": examplesv2 },
    "https://www.w3.org/2018/credentials/v1": { "@context": vcv1 },
    "https://w3id.org/citizenship/v1": { "@context": citizenv1 },
    "https://w3id.org/citizenship/v4rc1": { "@context": citizenv4 },
    "https://w3id.org/security/suites/ed25519-2020/v1": { "@context": edv1 },
    "https://w3id.org/security/data-integrity/v2": {"@context": diV2 }
};
// Only needed if you want remote loading, see comments below
const nodeDocumentLoader = jsonld.documentLoaders.node();

// change the default document loader
export const localLoader = async (url, options) => {
    if (url in CONTEXTS) {
        return {
            contextUrl: null, // this is for a context via a link header
            document: CONTEXTS[url], // this is the actual document that was loaded
            documentUrl: url // this is the actual context URL after redirects
        };
    }
    // uncomment if you want to load resources from remote sites
    // return nodeDocumentLoader(url);
    // comment out if your want to load resources from remote sites
    throw Error("Only local loading currently enabled");
};
