
'use strict';

const curve25519 = require('../src/curve25519_wrapper');
const nodeCrypto = require('crypto');

const PUBLIC_KEY_DER_PREFIX = new Uint8Array([
    48, 42, 48, 5, 6, 3, 43, 101, 110, 3, 33, 0
]);
  
const PRIVATE_KEY_DER_PREFIX = new Uint8Array([
    48, 46, 2, 1, 0, 48, 5, 6, 3, 43, 101, 110, 4, 34, 4, 32
]);

function validatePrivKey(privKey) {
    if (privKey === undefined) {
        throw new Error("Undefined private key");
    }
    if (!(privKey instanceof Buffer)) {
        throw new Error(`Invalid private key type: ${privKey.constructor.name}`);
    }
    if (privKey.byteLength != 32) {
        throw new Error(`Incorrect private key length: ${privKey.byteLength}`);
    }
}

function scrubPubKeyFormat(pubKey) {
    if (!(pubKey instanceof Buffer)) {
        throw new Error(`Invalid public key type: ${pubKey.constructor.name}`);
    }
    if (pubKey === undefined || ((pubKey.byteLength != 33 || pubKey[0] != 5) && pubKey.byteLength != 32)) {
        throw new Error("Invalid public key");
    }
    if (pubKey.byteLength == 33) {
        return pubKey.slice(1);
    } else {
        console.error("WARNING: Expected pubkey of length 33, please report the ST and client that generated the pubkey");
        return pubKey;
    }
}

exports.createKeyPair = function(privKey) {
    validatePrivKey(privKey);
    const keys = curve25519.keyPair(privKey);
    // prepend version byte
    var origPub = new Uint8Array(keys.pubKey);
    var pub = new Uint8Array(33);
    pub.set(origPub, 1);
    pub[0] = 5;
    return {
        pubKey: Buffer.from(pub),
        privKey: Buffer.from(keys.privKey)
    };
};

exports.calculateAgreement = function(pubKey, privKey) {
    pubKey = scrubPubKeyFormat(pubKey);
    validatePrivKey(privKey);
    if (!pubKey || pubKey.byteLength != 32) {
        throw new Error("Invalid public key");
    }
    // return Buffer.from(curve25519.sharedSecret(pubKey, privKey));
    const nodePrivateKey = nodeCrypto.createPrivateKey({
        key: Buffer.concat([PRIVATE_KEY_DER_PREFIX, privKey]),
        format: 'der',
        type: 'pkcs8'
    });
    const nodePublicKey = nodeCrypto.createPublicKey({
        key: Buffer.concat([PUBLIC_KEY_DER_PREFIX, pubKey]),
        format: 'der',
        type: 'spki'
    });
    
    return nodeCrypto.diffieHellman({
        privateKey: nodePrivateKey,
        publicKey: nodePublicKey,
    });
};

exports.calculateSignature = function(privKey, message) {
    validatePrivKey(privKey);
    if (!message) {
        throw new Error("Invalid message");
    }
    return Buffer.from(curve25519.sign(privKey, message));
};

exports.verifySignature = function(pubKey, msg, sig) {
    pubKey = scrubPubKeyFormat(pubKey);
    if (!pubKey || pubKey.byteLength != 32) {
        throw new Error("Invalid public key");
    }
    if (!msg) {
        throw new Error("Invalid message");
    }
    if (!sig || sig.byteLength != 64) {
        throw new Error("Invalid signature");
    }
    return curve25519.verify(pubKey, msg, sig);
};

exports.generateKeyPair = function() {
    const {publicKey: publicDerBytes, privateKey: privateDerBytes} = nodeCrypto.generateKeyPairSync(
        'x25519',
        {
            publicKeyEncoding: { format: 'der', type: 'spki' },
            privateKeyEncoding: { format: 'der', type: 'pkcs8' }
        }
    );
    // 33 bytes
    // first byte = 5 (version byte)
    const pubKey = publicDerBytes.slice(PUBLIC_KEY_DER_PREFIX.length-1, PUBLIC_KEY_DER_PREFIX.length + 32);
    pubKey[0] = 5;

    const privKey = privateDerBytes.slice(PRIVATE_KEY_DER_PREFIX.length, PRIVATE_KEY_DER_PREFIX.length + 32);

    return {
        pubKey,
        privKey
    };
};
