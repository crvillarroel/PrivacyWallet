
//********************************
// CRYPTO KEY SUPPORT
//********************************

const KEYPAIR = 1
const SYMMETRIC = 2

class JWK {
    _type = 0
    _privateKey
    _publicKey

    constructor() {
    }

    async generateKeyPair() {
        // The key used is Elliptic but restricted to the one supported by browsers
        // in the standard crypto Subtle subsystem

        if (this._type > 0) {
            throw new Error("Already initialized")
        }

        // Ask browser to create a key pair with the p256 curve
        let keyPair = await crypto.subtle.generateKey(
            {
                name: "ECDSA",
                namedCurve: "P-256"
            },
            true,
            ["sign", "verify"]
        );

        this._privateKey = keyPair.privateKey
        this._publicKey = keyPair.publicKey
        this._type = KEYPAIR
        return keyPair

    }

    async generateEncryptionKey() {
        // Generate a symmetric key for encrypting credentials when in transit
        // The credentials (and other material) will be encrypted when sent to the
        // Secure Messaging Server

        if (this._type > 0) {
            throw new Error("Already initialized")
        }

        // Ask browser to create a symmetric key
        let key = await crypto.subtle.generateKey(
            {
                name: "AES-GCM",
                length: 256
            },
            true,
            ["encrypt", "decrypt"]
        );

        this._encryptionKey = key
        this._type = SYMMETRIC
        return key;

    }

    async exportToJWK(priv = false) {
        // Convert a key from CryptoKey (native) format to JWK format

        if (this._type == 0) {
            throw new Error("Not yet initialized, can not export")
        }

        // Export the key to the JWK format (see spec for details)
        let keyJWK
        if (priv) {
            if (this._type == KEYPAIR) {
                keyJWK = await crypto.subtle.exportKey("jwk", this._privateKey);
            } else {
                keyJWK = await crypto.subtle.exportKey("jwk", this._encryptionKey);
            }
        } else {
            keyJWK = await crypto.subtle.exportKey("jwk", this._publicKey);
        }
        return keyJWK;
    }

    async importFromJWK(jwk) {
        // Convert a key from JWK format to CryptoKey (native) format

        if (this._type > 0) {
            throw new Error("Already initialized")
        }

        let key

        if (jwk["d"]) {
            // Import a private key
            let keyUsages = ["sign"];

            key = await crypto.subtle.importKey(
                "jwk",
                jwk,
                {
                    name: "ECDSA",
                    namedCurve: "P-256"
                },
                true,
                keyUsages
            );

            this._privateKey = key

        } else {
            // Import a public key
            let keyUsages = ["verify"];

            key = await crypto.subtle.importKey(
                "jwk",
                jwk,
                {
                    name: "ECDSA",
                    namedCurve: "P-256"
                },
                true,
                keyUsages
            );

            this._publicKey = key

        }

        this._type = KEYPAIR
        return key
    }

    async sign(bytes) {

        if (this._type == 0) {
            throw new Error("Not yet initialized")
        }
        if (this._type != KEYPAIR || this._privateKey == undefined) {
            throw new Error("Not a private key")
        }

        let signature = await window.crypto.subtle.sign(
            {
                name: "ECDSA",
                hash: { name: "SHA-256" },
            },
            this._privateKey,
            bytes
        );

        return signature
    }

    async verify(signature, bytes) {

        if (this._type == 0) {
            throw new Error("Not yet initialized")
        }
        if (this._type != KEYPAIR || this._publicKey == undefined) {
            throw new Error("Not a public key")
        }

        let result = await window.crypto.subtle.verify(
            {
                name: "ECDSA",
                hash: { name: "SHA-256" },
            },
            this._publicKey,
            signature,
            bytes
        );

        return result
    }

    // Encrypt a byte array message with a symmetric key
    async encryptMessage(bytes) {

        if (this._type == 0) {
            throw new Error("Not yet initialized")
        }
        if (this._type != SYMMETRIC || this._encryptionKey == undefined) {
            throw new Error("Not an encryption key")
        }

        // Generate the iv
        // The iv must never be reused with a given key.
        iv = crypto.getRandomValues(new Uint8Array(12));

        // Perform the actual encryption
        ciphertext = await crypto.subtle.encrypt(
            {
                name: "AES-GCM",
                iv: iv
            },
            this._encryptionKey,
            bytes
        );

        // Return the resulting ArrayBuffer, together with the iv
        return { iv: iv, ciphertext: ciphertext };

    }

    async decryptMessage(iv, ciphertext) {

        if (this._type == 0) {
            throw new Error("Not yet initialized")
        }
        if (this._type != SYMMETRIC || this._encryptionKey == undefined) {
            throw new Error("Not an encryption key")
        }

        // Perform the decryption of the received ArrayBuffer
        var decrypted = await window.crypto.subtle.decrypt(
            {
                name: "AES-GCM",
                iv: iv
            },
            this._encryptionKey,
            ciphertext
        );

        // Return the byte array
        return decrypted;
    }

    btoaUrl(input) {
        // Encode using the standard Javascript function
        let astr = btoa(input)
        // Replace non-url compatible chars with base64 standard chars
        return astr.replace(/\+/g, '-').replace(/\//g, '_');
    }

    atobUrl(input) {
        // Replace non-url compatible chars with base64 standard chars
        input = input.replace(/-/g, '+').replace(/_/g, '/');
        // Decode using the standard Javascript function
        return decodeURIComponent(escape(atob(input)));
    }


}

//********************************
//********************************

var hexString = 'd28449a2012604446b696432a0581d50657269636f20506572657a2c207175652074616c20657374c3a1733f58405d9efb81c08a612d8a9ad2887f0881bc401912af8a3e717e1dd946660f84b1c162aa24dbeed87b74639e43d80f580e738abe72f721d7d20225124b63993f662c'

var encoded = hexStr2bytes(hexString)
var index = 0


// COSE Tags assigned to supported algorithms
// We support only the ones specified in eHealth Network document
const AlgToTags = {
    'ECDH-SS-512': -28,
    'ECDH-SS': -27,
    'ECDH-ES-512': -26,
    'ECDH-ES': -25,
    'ES256': -7,
    'direct': -6,
    'A128GCM': 1,
    'A192GCM': 2,
    'A256GCM': 3,
    'SHA-256_64': 4,
    'SHA-256-64': 4,
    'HS256/64': 4,
    'SHA-256': 5,
    'HS256': 5,
    'SHA-384': 6,
    'HS384': 6,
    'SHA-512': 7,
    'HS512': 7,
    'AES-CCM-16-64-128': 10,
    'AES-CCM-16-128/64': 10,
    'AES-CCM-16-64-256': 11,
    'AES-CCM-16-256/64': 11,
    'AES-CCM-64-64-128': 12,
    'AES-CCM-64-128/64': 12,
    'AES-CCM-64-64-256': 13,
    'AES-CCM-64-256/64': 13,
    'AES-MAC-128/64': 14,
    'AES-MAC-256/64': 15,
    'AES-MAC-128/128': 25,
    'AES-MAC-256/128': 26,
    'AES-CCM-16-128-128': 30,
    'AES-CCM-16-128/128': 30,
    'AES-CCM-16-128-256': 31,
    'AES-CCM-16-256/128': 31,
    'AES-CCM-64-128-128': 32,
    'AES-CCM-64-128/128': 32,
    'AES-CCM-64-128-256': 33,
    'AES-CCM-64-256/128': 33
};

// For converting from string to byte array (Uint8Array) in UTF-8 and viceversa
const utf8Encoder = new TextEncoder()
const utf8Decoder = new TextDecoder()

// Convert header parameter values from "human" to COSE values
const Translators = {

    // Convert from string to UTF-8 byte array
    'kid': (value) => {
        return utf8Encoder(value)
    },

    // Get the COSE Tag value assigned to the algorithm
    'alg': (value) => {
        if (!(AlgToTags[value])) {
            throw new Error('Unknown \'alg\' parameter, ' + value);
        }
        return AlgToTags[value];
    }

};

// Supported header parameters in COSE
// We really support only "alg" and "kid"
const HeaderParameters = {
    'partyUNonce': -22,
    'static_key_id': -3,
    'static_key': -2,
    'ephemeral_key': -1,
    'alg': 1,
    'crit': 2,
    'content_type': 3,
    'ctyp': 3, // one could question this but it makes testing easier
    'kid': 4,
    'IV': 5,
    'Partial_IV': 6,
    'counter_signature': 7
};


function TranslateHeaders(header) {
    // Translate an input map "human friendly" to a map
    // using the COSE tags and values

    const result = new Map();

    // Iterate the keys of the input map, and raise and error if some
    // parameter is not supported
    for (const key in header) {

        // Check if it is a COSE parameter
        if (!HeaderParameters[key]) {
            throw new Error('Unknown parameter, \'' + key + '\'');
        }

        let value = header[key];

        // Get the COSE values from the "human" representation
        if (Translators[key]) {
            value = Translators[key](header[key]);
        }

        // Add the header parameter/value if it is supported
        if (value !== undefined && value !== null) {
            result.set(HeaderParameters[key], value);
        }
    }
    return result;
};

const KeyParameters = {
    'crv': -1,
    'k': -1,
    'x': -2,
    'y': -3,
    'd': -4,
    'kty': 1
};

const KeyTypes = {
    'OKP': 1,
    'EC2': 2,
    'RSA': 3,
    'Symmetric': 4
};

const KeyCrv = {
    'P-256': 1,
    'P-384': 2,
    'P-521': 3,
    'X25519': 4,
    'X448': 5,
    'Ed25519': 6,
    'Ed448': 7
};

const KeyTranslators = {
    'kty': (value) => {
        if (!(KeyTypes[value])) {
            throw new Error('Unknown \'kty\' parameter, ' + value);
        }
        return KeyTypes[value];
    },
    'crv': (value) => {
        if (!(KeyCrv[value])) {
            throw new Error('Unknown \'crv\' parameter, ' + value);
        }
        return KeyCrv[value];
    }
};

function TranslateKey(key) {
    const result = new Map();
    for (const param in key) {
        if (!KeyParameters[param]) {
            throw new Error('Unknown parameter, \'' + param + '\'');
        }
        let value = key[param];
        if (KeyTranslators[param]) {
            value = KeyTranslators[param](value);
        }
        result.set(KeyParameters[param], value);
    }
    return result;
};


//******************************** */
//******************************** */
//******************************** */

const SignTag = 98;
const Sign1Tag = 18;

// Mapping from COSE Tags to COSE algorithm name
const AlgFromTags = {};
AlgFromTags[-7] = { 'sign': 'ES256', 'digest': 'SHA-256' };
AlgFromTags[-35] = { 'sign': 'ES384', 'digest': 'SHA-384' };
AlgFromTags[-36] = { 'sign': 'ES512', 'digest': 'SHA-512' };

const COSEAlgToWebCryptoAlg = {
    'ES256': { 'sign': 'ECDSA', 'digest': 'SHA-256' },
    'ES384': { 'sign': 'ECDSA', 'digest': 'SHA-384' },
    'ES512': { 'sign': 'ECDSA', 'digest': 'SHA-512' }
};

const COSEAlgToNodeAlg = {
    'ES256': { 'sign': 'p256', 'digest': 'sha256' },
    'ES384': { 'sign': 'p384', 'digest': 'sha384' },
    'ES512': { 'sign': 'p512', 'digest': 'sha512' }
};

function doSign(SigStructure, signer, alg) {
    return new Promise((resolve, reject) => {
        if (!AlgFromTags[alg]) {
            throw new Error('Unknown algorithm, ' + alg);
        }
        if (!COSEAlgToNodeAlg[AlgFromTags[alg].sign]) {
            throw new Error('Unsupported algorithm, ' + AlgFromTags[alg].sign);
        }

        const ec = new EC(COSEAlgToNodeAlg[AlgFromTags[alg].sign].sign);
        const key = ec.keyFromPrivate(signer.key.d);

        let ToBeSigned = cbor.encode(SigStructure);
        const hash = crypto.createHash(COSEAlgToNodeAlg[AlgFromTags[alg].sign].digest);
        hash.update(ToBeSigned);
        ToBeSigned = hash.digest();
        const signature = key.sign(ToBeSigned);
        const sig = Buffer.concat([signature.r.toArrayLike(Buffer), signature.s.toArrayLike(Buffer)]);
        resolve(sig);
    });
}

function create(headers, payload, signers, options) {
    options = options || {};
    let u = headers.u || {};
    let p = headers.p || {};

    p = common.TranslateHeaders(p);
    u = common.TranslateHeaders(u);
    let bodyP = p || {};
    bodyP = (bodyP.size === 0) ? EMPTY_BUFFER : cbor.encode(bodyP);
    if (Array.isArray(signers)) {
        if (signers.length === 0) {
            throw new Error('There has to be at least one signer');
        }
        if (signers.length > 1) {
            throw new Error('Only one signer is supported');
        }
        // TODO handle multiple signers
        const signer = signers[0];
        const externalAAD = signer.externalAAD || EMPTY_BUFFER;
        let signerP = signer.p || {};
        let signerU = signer.u || {};

        signerP = common.TranslateHeaders(signerP);
        signerU = common.TranslateHeaders(signerU);
        const alg = signerP.get(common.HeaderParameters.alg);
        signerP = (signerP.size === 0) ? EMPTY_BUFFER : cbor.encode(signerP);

        const SigStructure = [
            'Signature',
            bodyP,
            signerP,
            externalAAD,
            payload
        ];
        return doSign(SigStructure, signer, alg).then((sig) => {
            if (p.size === 0 && options.encodep === 'empty') {
                p = EMPTY_BUFFER;
            } else {
                p = cbor.encode(p);
            }
            const signed = [p, u, payload, [[signerP, signerU, sig]]];
            return cbor.encode(options.excludetag ? signed : new Tagged(SignTag, signed));
        });
    } else {
        const signer = signers;
        const externalAAD = signer.externalAAD || EMPTY_BUFFER;
        const alg = p.get(common.HeaderParameters.alg) || u.get(common.HeaderParameters.alg);
        const SigStructure = [
            'Signature1',
            bodyP,
            externalAAD,
            payload
        ];
        return doSign(SigStructure, signer, alg).then((sig) => {
            if (p.size === 0 && options.encodep === 'empty') {
                p = EMPTY_BUFFER;
            } else {
                p = cbor.encode(p);
            }
            const signed = [p, u, payload, sig];
            return cbor.encodeCanonical(options.excludetag ? signed : new Tagged(Sign1Tag, signed));
        });
    }
};

async function doVerify(SigStructure, verifier, alg, sig) {
    // Verification requires the following steps:
    // 1. Encode the SigStructure following CBOR rules
    // 2. Calculate the hash using the digest from the expected "alg"

    // Verification assumes that "alg" was used
    // First check if the "alg" is supported
    if (!AlgFromTags[alg]) {
        throw new Error('Unknown algorithm, ' + alg);
    }

    // Convert "alg" from COSE naming to WebCrypto (browser) terminology
    if (!COSEAlgToNodeAlg[AlgFromTags[alg].sign]) {
        throw new Error('Unsupported algorithm, ' + AlgFromTags[alg].sign);
    }

    // Encode the structure using CBOR rules
    let msgHash = cbor.encode(SigStructure);

    // Create the hash from the encoded stream
    const hash = crypto.createHash(COSEAlgToNodeAlg[AlgFromTags[alg].sign].digest);
    hash.update(msgHash);
    msgHash = hash.digest();


    const pub = { 'x': verifier.key.x, 'y': verifier.key.y };
    const ec = new EC(COSEAlgToNodeAlg[AlgFromTags[alg].sign].sign);
    const key = ec.keyFromPublic(pub);
    sig = { 'r': sig.slice(0, sig.length / 2), 's': sig.slice(sig.length / 2) };
    if (key.verify(msgHash, sig)) {
        resolve();
    } else {
        throw new Error('Signature missmatch');
    }

}

function getSigner(signers, verifier) {
    for (let i = 0; i < signers.length; i++) {
        const kid = signers[i][1].get(common.HeaderParameters.kid); // TODO create constant for header locations
        if (kid.equals(Buffer.from(verifier.key.kid, 'utf8'))) {
            return signers[i];
        }
    }
}

function getCommonParameter(first, second, parameter) {
    let result;
    if (first.get) {
        result = first.get(parameter);
    }
    if (!result && second.get) {
        result = second.get(parameter);
    }
    return result;
}

function verifyPP(payload, verifier, options) {
    options = options || {};
    return cbor.decodeFirst(payload)
        .then((obj) => {
            let type = options.defaultType ? options.defaultType : SignTag;
            if (obj instanceof Tagged) {
                if (obj.tag !== SignTag && obj.tag !== Sign1Tag) {
                    throw new Error('Unexpected cbor tag, \'' + obj.tag + '\'');
                }
                type = obj.tag;
                obj = obj.value;
            }

            if (!Array.isArray(obj)) {
                throw new Error('Expecting Array');
            }

            if (obj.length !== 4) {
                throw new Error('Expecting Array of lenght 4');
            }

            let [p, u, plaintext, signers] = obj;

            if (type === SignTag && !Array.isArray(signers)) {
                throw new Error('Expecting signature Array');
            }

            p = (!p.length) ? EMPTY_BUFFER : cbor.decodeFirstSync(p);
            u = (!u.size) ? EMPTY_BUFFER : u;

            let signer = (type === SignTag ? getSigner(signers, verifier) : signers);

            if (!signer) {
                throw new Error('Failed to find signer with kid' + verifier.key.kid);
            }

            if (type === SignTag) {
                const externalAAD = verifier.externalAAD || EMPTY_BUFFER;
                let [signerP, , sig] = signer;
                signerP = (!signerP.length) ? EMPTY_BUFFER : signerP;
                p = (!p.size) ? EMPTY_BUFFER : cbor.encode(p);
                const signerPMap = cbor.decode(signerP);
                const alg = signerPMap.get(common.HeaderParameters.alg);
                const SigStructure = [
                    'Signature',
                    p,
                    signerP,
                    externalAAD,
                    plaintext
                ];
                return doVerify(SigStructure, verifier, alg, sig)
                    .then(() => {
                        return plaintext;
                    });
            } else {
                const externalAAD = verifier.externalAAD || EMPTY_BUFFER;

                const alg = getCommonParameter(p, u, common.HeaderParameters.alg);
                p = (!p.size) ? EMPTY_BUFFER : cbor.encode(p);
                const SigStructure = [
                    'Signature1',
                    p,
                    externalAAD,
                    plaintext
                ];
                return doVerify(SigStructure, verifier, alg, signer)
                    .then(() => {
                        return plaintext;
                    });
            }
        });
};


//******************************** */
//******************************** */
//******************************** */


// The CBOR major types
const UINT = 0
const NEGINT = 1
const BYTES = 2
const UTF8 = 3
const ARRAY = 4
const MAP = 5
const TAG = 6
const FP_BREAK = 7


function float16_to_float(h) {
    var s = (h & 0x8000) >> 15;
    var e = (h & 0x7C00) >> 10;
    var f = h & 0x03FF;

    if (e == 0) {
        return (s ? -1 : 1) * Math.pow(2, -14) * (f / Math.pow(2, 10));
    } else if (e == 0x1F) {
        return f ? NaN : ((s ? -1 : 1) * Infinity);
    }

    return (s ? -1 : 1) * Math.pow(2, e - 15) * (1 + (f / Math.pow(2, 10)));
}

// The character codes for the ranges
var aCode = "a".charCodeAt(0)
var fCode = "f".charCodeAt(0)
var ACode = "A".charCodeAt(0)
var FCode = "F".charCodeAt(0)
var zeroCode = "0".charCodeAt(0)
var nineCode = "9".charCodeAt(0)

function charValue(char) {
    // Given a character, return the hex value
    // "0" -> 0
    // "a" or "A" -> 10
    // "f" or "F" -> 15
    var c = char.charCodeAt(0)

    if (c >= aCode && c <= fCode) {
        return c - aCode + 10
    }

    if (c >= ACode && c <= FCode) {
        return c - ACode + 10
    }

    if (c >= zeroCode && c <= nineCode) {
        return c - zeroCode
    }

}


function hexStr2bytes(hexString) {
    // Converts a string of hex values to a byte array (Uint8Array)
    // The input string should have 2 hex characters for each byte (even size)
    // The string should not start by 0X or any other prefix
    // Example: 'd28449a2012704'

    // Check if there is an even number of characters
    if ((hexString.length % 2) > 0) {
        console.log("ERROR: Hex String length incorrect")
        return undefined
    }

    // Create a byte array with one byte for each two input characters
    var array = new Uint8Array(hexString.length / 2);

    // Iterate for each pair of input characters
    for (let i = 0; i < hexString.length; i = i + 2) {
        // get the integer value for each of the two characters
        var code1 = charValue(hexString[i])
        var code2 = charValue(hexString[i + 1])

        // code1 is the most significant byte, code2 the least

        // Set the array entry. Index is i/2
        array[i / 2] = code1 * 16 + code2

    }

    return array

}

const lutArray = [
    "0", "1", "2", "3", "4", "5", "6", "7", "8", "9", "a", "b", "c", "d", "e", "f"
]

function bytes2hexStr(bytes) {
    // Convert a byte array to a hex string
    // Each byte is converted into two hex chars representing the byte

    // Initialize the hex string
    var hexStr = ""

    // Iterate the input byte array
    for (let i = 0; i < bytes.length; i = i + 1) {
        // Get the value of the 4 most significant bits
        nibHigh = bytes[i] >>> 4
        // Get the value of the 4 least significant bits
        nibLow = bytes[i] & 0x0F

        // Concatenate the two chars to the whole hex string
        hexStr = hexStr + lutArray[nibHigh] + lutArray[nibLow]
    }

    return hexStr
}


//********************************
// COSE
//********************************

// CBOR tags to assign semantic to the data structures
const CBOR_Magic_ID = 55799 // Magic tag number that identifies the data as CBOR-encoded
const COSE_Sign = 98        // COSE Signed Data Object
const COSE_Sign1 = 18       // COSE Single Signer Data Object

const MT_INTEGER = 0
const MT_NEGINTEGER = 1
const MT_BYTES = 2
const MT_UTF8 = 3
const MT_ARRAY = 4
const MT_MAP = 5
const MT_TAG = 6
const MT_FLOAT = 7

class COSE {

    // Just for indentation when printing console logs
    ii = 0

    constructor(buffer) {
        // buffer must be an array-like or iterable object

        // Create a byte array and store in a local variable
        this._buffer = buffer
        // Set _index to point to the beginning
        this._index = 0
    }

    take(i) {
        // Return a byte array of size "i" from the bufer at current index.
        // Increment index to point to next bytes
        let val = this._buffer.slice(this._index, this._index + i)
        this._index = this._index + i
        return val
    }

    getIB() {
        // Get the Initial Byte and additional info bytes

        // Decode the first byte
        let ib = this.take(1);
        let mt = ib >>> 5;				/* Major type */
        let ai = ib & 0x1f;				/* Additional info */
        let val = ai;					/* Value if no additional bytes */

        // Additional info (ai) specifies the number of additional bytes
        switch (ai) {
            case 24: val = uint(this.take(1)); break;
            case 25: val = uint(this.take(2)); break;
            case 26: val = uint(this.take(4)); break;
            case 27: val = bigint(this.take(8)); break;
            case 28: case 29: case 30:
                return undefined;
            case 31:
                return undefined;		/* We do not support Indefinite types */
        }

        return [ib, mt, ai, val]

    }

    cbor2json() {
        // This is a recursive function to decode a CBOR data structure
        // RFC-7049 https://tools.ietf.org/html/rfc7049

        this.ii = this.ii + 3;

        // Get info from the first byte
        // Full Initial Byte, Major Type, Additional Info, Value
        let [ib, mt, ai, val] = this.getIB()

        // process content depending on major type
        switch (mt) {

            case MT_INTEGER:
                // Integer, may be normal or BigInteger (8 bytes)
                if (ai == 27) {
                    console.log(" ".repeat(this.ii), "BigInteger:", val.toString());
                } else {
                    console.log(" ".repeat(this.ii), "Integer", val)
                }
                break;

            case MT_NEGINTEGER:
                // The value is (-1 - val), but take care of BigInt case
                if (ai == 27) {
                    val = BigInt(-1) - val
                    console.log(" ".repeat(this.ii), "Negative BigInteger:", val.toString());
                } else {
                    val = -1 - val
                    console.log(" ".repeat(this.ii), "Negative Integer", val)
                }
                break;

            case MT_FLOAT:
                // We only suport for the moment 16 bit floating point values
                console.log(" ".repeat(this.ii), "Floating")
                val = float16_to_float(val)
                break;

            case MT_BYTES:
                // Get the amount of bytes specified by the "val"
                val = this.take(val)
                console.log(" ".repeat(this.ii), "Bytes, length: ", val.length)
                break;

            case MT_UTF8:
                // There are "val" bytes representing a UTF-8 string
                let l = val
                val = utf8Decoder.decode(this.take(val));
                console.log(" ".repeat(this.ii), "UTF8", l, val)
                break;

            case MT_ARRAY:
                // Array with "val" items. Call recursively to cbor2json
                console.log(" ".repeat(this.ii), "Array, elements:", val)
                let lista = []
                for (let i = 0; i < val; i++) {
                    lista.push(this.cbor2json())
                }
                val = lista;
                break;

            case MT_MAP:
                // Map with "val" items. Each item has a key and a value
                // Call recursively to cbor2json, once for each of key and value
                console.log(" ".repeat(this.ii), "Map, elements:", val)
                let mapa = new Map()
                for (let i = 0; i < val; i++) {
                    let key = this.cbor2json()
                    let value = this.cbor2json()
                    mapa.set(key, value)
                }
                val = mapa
                break;

            case MT_TAG:
                // As per RFC-7049, we can safely ignore the tags and process the embedded
                // data item. Call recursively to cbor2json.
                console.log(" ".repeat(this.ii), "Tag", val)
                val = this.cbor2json()
                break;
        }

        this.ii = this.ii - 3
        return val

    }

    decode() {
        // Decode a COSE object, without checking the signature
        // The object is in the internal buffer, from the constructor of the class

        // We only support the COSE_Sign1 objects (one signature only)
        // We do not support (yet) multiple signatures or the other COSE objects

        // Reset the index, just in case
        this._index = 0;

        // Get the Initial Byte
        let [ib, mt, ai, val] = this.getIB()

        // Every COSE object should start with a TAG
        if (mt != TAG) {
            console.log("Error, NOT a COSE object")
            throw new Error("NOT a COSE object")
        }

        // Check if the TAG is the CBOR magic value
        if (val == CBOR_Magic_ID) {
            console.log("This is a CBOR structure")
            // Advance to the next byte
            ib = this.take(1);
            mt = ib >>> 5;
            ai = ib & 0x1f;
            val = ai;
        }

        // The object should start with a COSE_Sign1 Tag
        if (val != COSE_Sign1) {
            console.log("Not a COSE Single signature", val)
            throw new Error("Not a COSE Single signature")
        }

        // Decode the remaining structure
        val = this.cbor2json()

        return val

    }

    async verify(verifier) {
        // Verify the coseObject using the key specified by the "verifier"
        // The verifier should be a JWK object with the public key
        // The method is async because we call async crypto methods

        // Decode the object into an Array with 4 elements
        let [protectedHeaders, unprotectedHeaders, payload, signature] = this.decode()

        // The protected headers is a Map and should have the "alg" and "kid"

        // Create a new object with its own buffer and decode the headers
        let h = new COSE(protectedHeaders)
        let headersMap = h.cbor2json()

        let alg = getAlg(headersMap)
        let kid = getKid(headersMap)

        // Decode the payload, which is encoded as a bstr
        let plaintext = utf8Decoder.decode(payload)
        console.log("Payload:", plaintext)
        console.log(bytes2hexStr(payload))

        // Create the Sig_structure
        let sigObject = new COSE_encode(200)
        const Sig_structure = [
            sigObject.string2cbor("Signature1"),
            sigObject.bytes2cbor(protectedHeaders),
            sigObject.bytes2cbor(""),
            sigObject.bytes2cbor(payload)
        ];

        // And CBOR-encode it
        let Sig_structure_encoded = sigObject.shallowlist2cbor(Sig_structure)

        // Check that it was well built
        console.log("===================")
        console.log(bytes2hexStr(Sig_structure_encoded))
        let aux = new COSE(Sig_structure_encoded)
        let auxJson = aux.cbor2json(Sig_structure_encoded)
        console.log("===================")

        // Get the WebCrypto algorithm to use
        let webCryptoAlg = COSEAlgToWebCryptoAlg[alg.sign].sign
        // Convert "alg" from COSE naming to WebCrypto (browser) terminology
        if (!webCryptoAlg) {
            throw new Error('Unsupported algorithm, ' + alg.sign);
        }

        console.log(webCryptoAlg)

        let verified = await verifier.verify(signature, Sig_structure_encoded)
        console.log("Verified", verified)

    }


    get payload() {
        // Get the payload from the COSE object without verification

        // Decode the Object
        let decoded = this.decode()

        // The decoded object should be an Array
        let [protectedHeaders, unprotectedHeaders, payload, signature] = decoded

        // Decode the payload, which is encoded as a bstr
        let plaintext = utf8Decoder.decode(payload)

        return plaintext

    }


}


class COSE_encode {

    constructor(size = 1000) {
        this._buffer = new Uint8Array(1000)
        this._index = 0
    }

    async encodeAndSign(ph, uph, payload, signer) {
        // Encode the CBOR structure and sign it with the signer

        // ph is a Map with the protected headers
        // Encode as a Map wrapped on a bstr
        let eMap = this.map2cbor(ph)
        let eHeaders = this.bytes2cbor(eMap)

        let ePayload = this.bytes2cbor(payload)

        // Create the Sig_structure
        const Sig_structure = [
            this.string2cbor("Signature1"),
            eHeaders,
            this.bytes2cbor(""),
            ePayload
        ];

        // And CBOR-encode it
        let Sig_structure_encoded = this.shallowlist2cbor(Sig_structure)

        // Sign the structure and convert to byte array
        // The result of signing is an ArrayBuffer
        let rawSig = await signer.sign(Sig_structure_encoded)
        let signature = new Uint8Array(rawSig)

        // Create the COSE structure, which is an array of 4 elements
        let basicCOSE = [
            eHeaders,
            this.map2cbor(uph),
            ePayload,
            this.bytes2cbor(signature)
        ]

        // And CBOR-encode it
        let COSE_object = this.shallowlist2cbor(basicCOSE)

        return this.cbor2cose(COSE_object)

    }

    json2cbor(element) {
        // Check the type of the element and CBOR-encode it

        if (typeof (element) == "string") {
            return this.string2cbor(element)
        }

        if (typeof (element) == "number") {
            if (!Number.isInteger(element)) {
                throw new Error("Not an integer:", element)
            }
            return this.int2cbor(element)
        }

        if (element instanceof Map) {
            return this.map2cbor(element)
        }

        if (element instanceof Array) {
            return this.list2cbor(element)
        }

        if (element instanceof Uint8Array) {
            return this.bytes2cbor(element)
        }

    }

    cbor2cose(cbor) {
        // Tag a CBOR structure with the COSE and Magic tags

        // The COSE Tag
        let coseTag = (6 << 5) + 18

        // The Magic CBOR Tag
        let pp = 0xd9d9f7

        // let taggedCOSE = new Uint8Array(4 + cbor.length)
        // taggedCOSE[0] = 0xd9
        // taggedCOSE[1] = 0xd9
        // taggedCOSE[2] = 0xf7
        // taggedCOSE[3] = coseTag
        // taggedCOSE.set(cbor, 4)

        let taggedCOSE = new Uint8Array(1 + cbor.length)
        taggedCOSE[0] = coseTag
        taggedCOSE.set(cbor, 1)


        return taggedCOSE

    }

    length2cbor(len) {
        // Encodes a length using the rules of CBOR
        // It applies to any structure
        // Returns a byte array of the corresponding length, or undefined if it is not needed
        // It also returns the "ai" value

        if (!Number.isInteger(len)) {
            throw new Error("Not an integer:", len)
        }

        var ai = len
        var numAdditionalBytes = 0
        var additionalBytes

        if (len > 23 && len < 256) {
            ai = 24
            numAdditionalBytes = 1
            additionalBytes = new Uint8Array(1)
            additionalBytes[0] = len
        }
        if (len > 255 && len < 65536) {
            ai = 25
            numAdditionalBytes = 2
            additionalBytes = new Uint8Array(2)
            var lowByte = len % 256
            var highByte = (len - lowByte) / 256
            additionalBytes[0] = highByte
            additionalBytes[1] = lowByte
        }
        if (len > 65535) {
            throw new Error('String to encode too big');
        }

        return [ai, numAdditionalBytes, additionalBytes]

    }

    int2cbor(i) {
        // Encode an integer to CBOR

        if (!Number.isInteger(i)) {
            throw new Error("Not an integer:", i)
        }

        let mt
        let val

        if (i >= 0) {
            // Major type is 0
            mt = 0
            val = i

        } else {
            // Major type is 1
            mt = 1
            val = (-1) - i
        }

        // Use the same rules as a length
        var [ai, numAdditionalBytes, additionalBytes] = this.length2cbor(val)

        // Allocate a byte array of th eproper length
        var cborArray = new Uint8Array(1 + numAdditionalBytes)

        // Set the Initial Byte
        const ib = (mt << 5) + ai
        cborArray[0] = ib

        // Fill additional bytes if needed
        if (numAdditionalBytes > 0) {
            cborArray.set(additionalBytes, 1)
        }

        return cborArray

    }

    uint2cbor(u) {
        // Encode an unsigned integer to CBOR

        // Use the same rules as a length
        var [ai, numAdditionalBytes, additionalBytes] = this.length2cbor(u)

        // Major type is 0
        const mt = 0

        // Allocate a byte array of th eproper length
        var cborArray = new Uint8Array(1 + numAdditionalBytes)

        // Set the Initial Byte
        const ib = (mt << 5) + ai
        cborArray[0] = ib

        // Fill additional bytes if needed
        if (numAdditionalBytes > 0) {
            cborArray.set(additionalBytes, 1)
        }

        return cborArray

    }


    string2cbor(s) {
        // Encode a javascript string to CBOR

        // Get the string as a byte array in UTF-8
        var bs = utf8Encoder.encode(s)

        // Major type is 3
        const mt = 3

        var encoded = this.utf8_to_cbor(bs, mt)
        return encoded

    }

    bytes2cbor(bs) {
        // Encode a byte array to CBOR

        // Major type is 2
        const mt = 2

        var encoded = this.utf8_to_cbor(bs, mt)
        return encoded

    }


    utf8_to_cbor(bs, mt) {
        // Encode a byte array to CBOR, where "mt" specifies the Major Type in CBOR
        // It could represent either a utf8 bstring or a byte array
        // CBOR encoding is exactly the same except the Major Type

        // Get the length in CBOR format, including the Additional Info part of IB
        var len = bs.length
        var [ai, numAdditionalBytes, additionalBytes] = this.length2cbor(len)

        // Convert the Major type to the 3 most significan bits of the Initial Byte
        const ib = (mt << 5) + ai

        var cborArray = new Uint8Array(1 + numAdditionalBytes + len)
        cborArray[0] = ib

        if (numAdditionalBytes > 0) {
            cborArray.set(additionalBytes, 1)
        }
        cborArray.set(bs, 1 + numAdditionalBytes)
        return cborArray

    }

    shallowlist2cbor(l) {
        // Encode a list to CBOR
        // It is NOT recursive, assumes that the elements of the list are already CBOR-encoded

        // Major type is 4, convert to the 3 most significan bits of the Initial Byte
        const mt = 4

        // Get the length in CBOR format, including the Additional Info part of IB
        let len = l.length
        let [ai, numAdditionalBytes, additionalBytes] = this.length2cbor(len)

        // Iterate the list to get the total length of the buffer to allocate

        let encodedList = []
        let listSize = 0
        for (let i = 0; i < l.length; i++) {
            listSize = listSize + l[i].length
        }

        // Allocate a byte array to serialize the List
        let cborArray = new Uint8Array(1 + numAdditionalBytes + listSize)

        // Set the Initial Byte
        const ib = (mt << 5) + ai
        cborArray[0] = ib

        // Fill additional bytes if needed
        if (numAdditionalBytes > 0) {
            cborArray.set(additionalBytes, 1)
        }

        // Iterate the list to concatenate all elements at the right offset
        let offset = 1 + numAdditionalBytes
        for (let i = 0; i < l.length; i++) {
            cborArray.set(l[i], offset)
            offset = offset + l[i].length
        }

        return cborArray

    }


    list2cbor(l) {
        // Encode a list to CBOR
        // It is NOT recursive, assumes that the elements of the list are already CBOR-encoded

        // Major type is 4, convert to the 3 most significan bits of the Initial Byte
        const mt = 4

        // Get the length in CBOR format, including the Additional Info part of IB
        let len = l.length
        let [ai, numAdditionalBytes, additionalBytes] = this.length2cbor(len)

        // Iterate the list to get the total length of the buffer to allocate

        let encodedList = []
        let listSize = 0
        for (let i = 0; i < l.length; i++) {
            let encodedElem = this.json2cbor(l[i])
            encodedList.push(encodedElem)
            listSize = listSize + encodedElem.length
        }

        // Allocate a byte array to serialize the List
        let cborArray = new Uint8Array(1 + numAdditionalBytes + listSize)

        // Set the Initial Byte
        const ib = (mt << 5) + ai
        cborArray[0] = ib

        // Fill additional bytes if needed
        if (numAdditionalBytes > 0) {
            cborArray.set(additionalBytes, 1)
        }

        // Iterate the list to concatenate all elements at the right offset
        let offset = 1 + numAdditionalBytes
        for (let i = 0; i < encodedList.length; i++) {
            cborArray.set(encodedList[i], offset)
            offset = offset + encodedList[i].length
        }

        return cborArray

    }

    map2cbor(m) {
        // Encode a Map to CBOR
        // It is NOT recursive, assumes that the elements of the Map are already CBOR-encoded

        // The elements of the map can be integer, negative integer, string, byte array
        // Array or Map

        // Major type is 5
        const mt = 5

        // Get the length in CBOR format, including the Additional Info part of IB
        let len = m.size
        let [ai, numAdditionalBytes, additionalBytes] = this.length2cbor(len)

        // Iterate the map to create a new one with encoded elements
        // At the same time, calculate the total size

        let encodedMap = new Map()
        let mapSize = 0
        for (let [key, value] of m) {
            let keyEncoded = this.json2cbor(key)
            let valueEncoded = this.json2cbor(value)
            encodedMap.set(keyEncoded, valueEncoded)
            mapSize = mapSize + keyEncoded.length + valueEncoded.length
        }

        // Allocate a byte array to serialize the List
        let cborArray = new Uint8Array(1 + numAdditionalBytes + mapSize)

        // Set the Initial Byte
        const ib = (mt << 5) + ai
        cborArray[0] = ib

        // Fill additional bytes if needed
        if (numAdditionalBytes > 0) {
            cborArray.set(additionalBytes, 1)
        }

        // Iterate the Map concatenate all elements at the right offset
        let offset = 1 + numAdditionalBytes
        for (let [key, value] of encodedMap) {
            // First set the key object
            cborArray.set(key, offset)
            // And the value
            cborArray.set(value, offset + key.length)

            // Update the offset with the lengths of the key and the value
            offset = offset + key.length + value.length

        }

        return cborArray

    }

}

//********************************
//********************************




function uint(bytes) {
    // Convert a byte array of 2 or 4 bytes to an unsigned integer
    // The byte array is in network byte order

    // Get the first byte
    var value = bytes[0]

    // If there are more bytes, iterate the byte array
    var i = bytes.length
    for (let j = 1; j < i; j = j + 1) {
        value = value * 256
        value = value + bytes[j]
    }

    return value
}

function bigint(bytes) {
    // Convert a byte array of 8 bytes to an BigInteger
    // The byte array is in network byte order

    var value = BigInt(bytes[0])
    var i = bytes.length

    for (let j = 1; j < i; j = j + 1) {
        value = value * 256n
        value = value + BigInt(bytes[j])
    }

    return value
}






/* encoded = hexStr2bytes(hexString)
index = 0


val = coseDecode(encoded)
console.log(val)


message = utf8Decoder.decode(val[2])
console.log(message)


console.log("Decoding header")
encoded = val[0]
index = 0
console.log("Header length:", encoded.length)

val = cbor2json()
 */



function getAlg(coseHeader) {
    // Get the "alg" parameter from a COSE header, which is a CBOR Map

    // In COSE, the keys are numeric (e.g., alg is 1)
    // We use the HeaderParameters to keep the numbers

    // Try to get from the header the value for the algorithm
    // Return undefined if not found
    let algCOSE = coseHeader.get(HeaderParameters.alg)
    if (algCOSE) {
        alg = AlgFromTags[algCOSE]
    }
    return alg
}

function getKid(coseHeader) {
    // Get the "kid" parameter from a COSE header, which is a CBOR Map

    // get the "kid", which is a bstr
    let kid = coseHeader.get(HeaderParameters.kid)
    if (kid) {
        //Convert from bstr to a normal string
        kid = utf8Decoder.decode(kid)
    }
    return kid
}


// **********************************************
// **********************************************
// **********************************************

class CVD_COSE {

    // Nothing to be done
    constructor() {
        // Pass
    }

    // Decode a CVD from the QR as a string
    fromQR(qr) {

        // Check the type of the parameter: string, String or UInt8Array

        // Convert to string

        // The QR should start with the context identifier: "HC1:"
        if (!qr.startsWith("HC1:")) {
            // Raise an exception
        }

        // Decode from Base45
        let coseDeflated = decodeB45(qr.slice(4))    // Skip the context identifier

        // Decompress (inflate) from zlib-compressed
        let coseEU = pako.inflate(coseDeflated)

        // Decode the first layer of CVD COSE
        let c = new COSE(coseEU)
        let cvd_layer1 = c.decode()

        // We should have an array with 4 elements: protected, unprotected, payload and signature
        console.log("CVD first layer:", cvd_layer1)
        if (cvd_layer1.length != 4) {
            // ERROR: raise an exception
        }

        // Decode the payload which is a CBOR object
        let payload = new COSE(cvd_layer1[2])
        payload = payload.cbor2json()

        // Check that is is well-formed: a CBOR Map with 4 elements
        // key 1: "iss", CBOR type 2 (bstr). Issuer Country Code
        // key 6: "iat", CBOR type 2 (bstr). Issuance date
        // key 4: "exp", CBOR type 2 (bstr). Expiration date
        // key -260: "hcert", CBOR type 5 (map). CVD data depending on the type
        if (payload.size != 4) {
            // ERROR: raise an exception
        }

        // Get the Issuer
        let iss = payload.get(1)
        console.log("Issuer:", iss)
        if (!iss) {
            //ERROR: 
        }

        // Get the Issuance date
        let iat = payload.get(6)
        console.log("Issuance date:", iat)

        // Get the Expiration date
        let exp = payload.get(4)
        console.log("Issuance date:", exp)

        // Get the hcert, the envelope for the certificate data
        let hcert = payload.get(-260)
        console.log("Hcert:", hcert)

        let p = payload


        return p


    }


}



var cvd

window.onload = async function () {

    let coseKeyPublic = {
        kty: "EC",
        crv: "P-256",
        //        d: "l0DQr-fRnck8uC9kYPsdczMMFLD00Exec4sXQ9iAao0",
        x: "Td0V0b4vV-5jEsbMwx20DVvs0iulMZ74PssC8cjiOxY",
        y: "YXC5l5yIViHRD-royR0yO0d-aXvUDs7cBQaLKRCAPos",
        key_ops: ["verify"]
    }

    let coseKeyPrivate = {
        kty: "EC",
        crv: "P-256",
        d: "l0DQr-fRnck8uC9kYPsdczMMFLD00Exec4sXQ9iAao0",
        x: "Td0V0b4vV-5jEsbMwx20DVvs0iulMZ74PssC8cjiOxY",
        y: "YXC5l5yIViHRD-royR0yO0d-aXvUDs7cBQaLKRCAPos",
        key_ops: ["sign"]
    }

    let signer = new JWK()
    await signer.importFromJWK(coseKeyPrivate)

    let verifier = new JWK()
    await verifier.importFromJWK(coseKeyPublic)

    let coseBin = "d28454a20126044f444944566572696669636174696f6ea0581d50657269636f20506572657a2c207175652074616c20657374c3a1733f584072e9dd275d48f1431dda6b0ecc5b2f01a6f08957dda8bc31b8423910f5b2f043b2e4ee1576fad8aef9251560f9db415253d1e8ae9ac60a2b1ede9ac21b361bb2"

    let protectedHeaders = new Map()
    protectedHeaders.set(1, -7)
    protectedHeaders.set(4, utf8Encoder.encode("#key1"))

    let unprotectedHeaders = new Map()

    let payload = utf8Encoder.encode("Erase una vez un perico perez")

    let ee = new COSE_encode(1000)
    let encodedCOSE = await ee.encodeAndSign(protectedHeaders, unprotectedHeaders, payload, signer)

//    console.log("Encoded:", bytes2hexStr(encodedCOSE))


//    let pp = new COSE(encodedCOSE)
//    let pp = new COSE(hexStr2bytes(coseBin))
//    console.log("=============Verify")
//    let v = await pp.verify(verifier)

    // console.log("About to deflate", encodedCOSE)
    // const deflated = pako.deflate(encodedCOSE)
    // console.log("Deflated", deflated)

    // console.log("About to inflate")
    // const inflated = pako.inflate(deflated)
    // console.log("Inflated", inflated)

    // console.log("Encoding to B45")
    // const b45encoded = encode(deflated)
    // console.log("Encoded:", b45encoded)


// **********************************************************
    let cborEU1 = "bf6376657265312e302e30636e616dbf62666e754d7573746572667261752d47c3b6c39f696e67657263666e74754d5553544552465241553c474f455353494e47455262676e684761627269656c6563676e74684741425249454c45ff63646f626a313939382d30322d3236617681bf627467693834303533393030366276706a31313139333035303035626d706c45552f312f32302f31353238626d616d4f52472d31303030333032313562646e01627364026264746a323032312d30322d313862636f6241546269736e424d5347504b2041757374726961626369783075726e3a757663693a30313a41543a313038303738343346393441454530454535303933464243323534424438313350ffff"


    let coseEU1 = "d2844da20448d919375fc1e7b6b20126a0590124a4041a61817ca0061a60942ea001624154390103a101a4617681aa62646e01626d616d4f52472d3130303033303231356276706a313131393330353030356264746a323032312d30322d313862636f624154626369783075726e3a757663693a30313a41543a313038303738343346393441454530454535303933464243323534424438313350626d706c45552f312f32302f313532386269736e424d5347504b20417573747269616273640262746769383430353339303036636e616da463666e74754d5553544552465241553c474f455353494e47455262666e754d7573746572667261752d47c3b6c39f696e67657263676e74684741425249454c4562676e684761627269656c656376657265312e302e3063646f626a313939382d30322d3236584081da84d4e91916d68aa0708035827435e57b75bb1902633801759865c448fb417b0f7a4db7f0c8edf8f500b38662ff576807a251478d948703df05a8d2033a70"


    let compressedEU1 = "78da013c02c3fdd2844ea20448de52458744a8a049013824a0590124a4041a6092dd20061a60903a2001624154390103a101a4617681aa62646e01626d616d4f52472d3130303033303231356276706a313131393330353030356264746a323032312d30322d313862636f624154626369783075726e3a757663693a30313a41543a313038303738343346393441454530454535303933464243323534424438313350626d706c45552f312f32302f313532386269736e424d5347504b20417573747269616273640262746769383430353339303036636e616da463666e74754d5553544552465241553c474f455353494e47455262666e754d7573746572667261752d47c3b6c39f696e67657263676e74684741425249454c4562676e684761627269656c656376657265312e302e3063646f626a313939382d30322d3236590100000adf1e4d1cad951c4f1a11e3c7fa5bc2d706365f870eef6beacf618da7b190e264a14aeb4008ff4f95f34d88a745a1b7c842c48b822ea3d152b5ebd8c62351be5027cae4db852259557089d1e801181b574ee9aa22266c4d886766e63779fb554e1d9fb232bc0c44cba8da611974e48f1c3a2be1bf0ec80c26f83a14fb22594e960189af2a68fbec23c2c51886aa607b2777b3fd64fbca5501c79ffed3ebeaeefe4135db398b9ca6972a76b7d8b265711b33d3d75c2cb9e702e2144c636f41ca04799323986cacfcea12e33a7035d5c38a95b6277a20c1b3cc250374d607f40a0abe55ee2579aa624fd47c3d58061514497120d170d5350a62e49800b9e0d781a1e142"

    let base45EU1 = "NCF170WF0/3WUWGVLKO991IAN4HDELEA9H479CKM603XK2F3MPI8242F3MAI324/IC6TAY50.FK6ZK7:EDOLFVC*70B$D% D3IA4W5646946846.966KCN9E%961A69L6QW6B46XJCCWENF6OF63W5KF60A6WJCT3ETB8WJC0FDU56:KEPH7M/ESDD746IG77TA$96T476:6/Q6M*8CR63Y8R46WX8F46VL6/G8SF6DR64S8+96D7AQ$D.UDRYA 96NF6L/5SW6Y57+EDB.D+Y9V09HM9HC8 QE*KE0ECKQEPD09WEQDD+Q6TW6FA7C46TPCBEC8ZKW.CNWE.Y92OAGY82+8UB8-R7/0A1OA1C9K09UIAW.CE$E7%E7WE KEVKER EB39W4N*6K3/D5$CMPCG/DA8DBB85IAAY8WY8I3DA8D0EC*KE: CZ CO/EZKEZ96446C56GVC*JC1A6NA73W5KF6TF6FBB000%G1H$36S3C%I00AYB2TCP0RBB8RE*6E3H1CU UT/EC:8LAEILWC9L9C48JCW2/I3 9Q6L:JKBEP5%OQKG.VKNKAV T82P1FA:5AATP$XRIF42 A1JH%ET623U1BDOTCE45VD:AHH0DQ07 YVH*9M8KSI6ZO1QXPFRR 93B+SQP3SO5+6O2DPV-4IF7UXV2DBG/ICIHBG57%VJN4B-O41H*8CN:4.XMLYC2QP5A08AKQZQMVTJ6WH 6GC77 J/4JG0FYHR4$CXJ36ZQGTBQMNIG0LP2UPCCE8KP02RI5CJ4*LRQTUWSF8E31RHNHB1NYJF.LOG PTJ0Q2RE%U5G1%%A8X4DOL64AZVFY5B-T2 C9V64+BEXV6QMCW9JJMN:AR-KKL1"

    let prefix = "HC1:NCFTW2H:7*I06R3W/J:O6:P4QB3+7RKFVJWV66UBCE//UXDT:*ML-4D.NBXR+SRHMNIY6EB8I595+6UY9-+0DPIO6C5%0SBHN-OWKCJ6BLC2M.M/NPKZ4F3WNHEIE6IO26LB8:F4:JVUGVY8*EKCLQ..QCSTS+F$:0PON:.MND4Z0I9:GU.LBJQ7/2IJPR:PAJFO80NN0TRO1IB:44:N2336-:KC6M*2N*41C42CA5KCD555O/A46F6ST1JJ9D0:.MMLH2/G9A7ZX4DCL*010LGDFI$MUD82QXSVH6R.CLIL:T4Q3129HXB8WZI8RASDE1LL9:9NQDC/O3X3G+A:2U5VP:IE+EMG40R53CG9J3JE1KB KJA5*$4GW54%LJBIWKE*HBX+4MNEIAD$3NR E228Z9SS4E R3HUMH3J%-B6DRO3T7GJBU6O URY858P0TR8MDJ$6VL8+7B5$G CIKIPS2CPVDK%K6+N0GUG+TG+RB5JGOU55HXDR.TL-N75Y0NHQTZ3XNQMTF/ZHYBQ$8IR9MIQHOSV%9K5-7%ZQ/.15I0*-J8AVD0N0/0USH.3"

    // c = hexStr2bytes(coseEU1)
    // console.log(c)

    // c = new COSE(c)
    // console.log("About to decode")
    // const decoded = c.decode()
    // console.log("Inflated", decoded)

    // h = new COSE(decoded[2])
    // h = h.cbor2json()
    // console.log(h)

    // cvd = new CVD_COSE()
    // cvd = cvd.fromQR(prefix)


};


