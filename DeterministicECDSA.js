/*
    Checking the noble curve implementation agains the test vectors in:
    https://www.rfc-editor.org/rfc/rfc6979.html

*/

import { P256 } from '@noble/curves/p256';
import {P384} from '@noble/curves/p384';
import { numberToHexUnpadded } from '@noble/curves/abstract/utils';
import { sha256 } from '@noble/hashes/sha256';
import { sha384 } from '@noble/hashes/sha512';
import { hexToBytes, bytesToHex } from '@noble/hashes/utils';

// Verifying P256 deterministic ECDSA implementation
/*
    From RFC6979 section A.2.5. 
    private key:
    x = C9AFA9D845BA75166B5C215767B1D6934E50C3DB36E89B127B8A622B120F6721

    public key: U = xG
    Ux = 60FED4BA255A9D31C961EB74C6356D68C049B8923B61FA6CE669622E60F29FB6
    Uy = 7903FE1008B8BC99A41AE9E95628BC64F2F1B20C2D7E9F5177A3C294D4462299
*/

let privateKey = hexToBytes("C9AFA9D845BA75166B5C215767B1D6934E50C3DB36E89B127B8A622B120F6721");
let publicKey = P256.getPublicKey(privateKey);
console.log(`private key length: ${privateKey.length}`);
console.log(bytesToHex(privateKey));
console.log(`Pubic key length ${publicKey.length}`);
console.log(bytesToHex(publicKey));
let Q = P256.ProjectivePoint.fromPrivateKey(privateKey).toAffine();
console.log(Q);
// Should be 60FED4BA255A9D31C961EB74C6356D68C049B8923B61FA6CE669622E60F29FB6
console.log(numberToHexUnpadded(Q.x));
// Should be 7903FE1008B8BC99A41AE9E95628BC64F2F1B20C2D7E9F5177A3C294D4462299
console.log(numberToHexUnpadded(Q.y));
let message = "sample";
let msgHash = sha256(message);
let signature = P256.sign(msgHash, privateKey);
console.log(signature);
/*
   From RFC6979 section A.2.5. 
   With SHA-256, message = "sample":
   k = A6E3C57DD01ABE90086538398355DD4C3B17AA873382B0F24D6129493D8AAD60
   r = EFD48B2AACB6A8FD1140DD9CD45E81D69D2C877B56AAF991C34D0EA84EAF3716
   s = F7CB1C942D657C41D436C7A1B6E29F65F3E900DBB9AFF4064DC4AB2F843ACDA8
*/
console.log(numberToHexUnpadded(signature.r));
console.log(numberToHexUnpadded(signature.s));

// P384
/* From section A.2.6.
   private key:

   x = 6B9D3DAD2E1B8C1C05B19875B6659F4DE23C3B667BF297BA9AA47740787137D8
       96D5724E4C70A825F872C9EA60D2EDF5

   public key: U = xG

   Ux = EC3A4E415B4E19A4568618029F427FA5DA9A8BC4AE92E02E06AAE5286B300C64
        DEF8F0EA9055866064A254515480BC13

   Uy = 8015D9B72D7D57244EA8EF9AC0C621896708A59367F9DFB9F54CA84B3F1C9DB1
        288B231C3AE0D4FE7344FD2533264720
*/
let privateKey384 = hexToBytes("6B9D3DAD2E1B8C1C05B19875B6659F4DE23C3B667BF297BA9AA47740787137D896D5724E4C70A825F872C9EA60D2EDF5");
let publicKey384 = P384.getPublicKey(privateKey384);
console.log(`private key length: ${privateKey384.length}`);
console.log(bytesToHex(privateKey384));
console.log(`Pubic key length ${publicKey384.length}`);
console.log(bytesToHex(publicKey384));
let Q384 = P384.ProjectivePoint.fromPrivateKey(privateKey384).toAffine();
console.log(Q384);
// Should be 60FED4BA255A9D31C961EB74C6356D68C049B8923B61FA6CE669622E60F29FB6
console.log(numberToHexUnpadded(Q384.x));
// Should be 7903FE1008B8BC99A41AE9E95628BC64F2F1B20C2D7E9F5177A3C294D4462299
console.log(numberToHexUnpadded(Q384.y));

/*
   With SHA-384, message = "sample":
   k = 94ED910D1A099DAD3254E9242AE85ABDE4BA15168EAF0CA87A555FD56D10FBCA
       2907E3E83BA95368623B8C4686915CF9
   r = 94EDBB92A5ECB8AAD4736E56C691916B3F88140666CE9FA73D64C4EA95AD133C
       81A648152E44ACF96E36DD1E80FABE46
   s = 99EF4AEB15F178CEA1FE40DB2603138F130E740A19624526203B6351D0A3A94F
       A329C145786E679E7B82C71A38628AC8
*/
let msgHash384 = sha384(message);
let sig384 = P384.sign(msgHash384, privateKey384);
console.log(sig384);
console.log(numberToHexUnpadded(sig384.r));
console.log(numberToHexUnpadded(sig384.s));
console.log(sig384.toCompactRawBytes().length);