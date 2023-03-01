import jsonld from 'jsonld';
import { citizenv1 } from './contexts/citizenship-v1.js';
import { vcv2 } from './contexts/credv2.js';
import { vcv1 } from './contexts/credv1.js';
import { edv1 } from './contexts/ed25519-signature-2020-v1.js';


// Set up a document loader so we don't have to go to the net
const CONTEXTS = {
    "https://www.w3.org/ns/credentials/v2": { "@context": vcv2 },
    "https://www.w3.org/2018/credentials/v1": { "@context": vcv1 },
    "https://w3id.org/citizenship/v1": { "@context": citizenv1 },
    "https://w3id.org/security/suites/ed25519-2020/v1": { "@context": edv1 }
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