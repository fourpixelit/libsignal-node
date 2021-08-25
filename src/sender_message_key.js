const HKDFv3 = require('./hkdfv3');

class SenderMessageKey {
    iteration = 0;

    iv = Buffer.alloc(0);

    cipherKey = Buffer.alloc(0);

    seed = Buffer.alloc(0);

    constructor(iteration, seed) {
        const derivative = new HKDFv3().deriveSecrets(seed, Buffer.from('WhisperGroup'), 48);
        /*const derivative = deriveSecrets(seed, Buffer.alloc(32), Buffer.from('WhisperGroup'));
        const A = derivative[0];
        const e = derivative[1];
        var t = new Uint8Array(32);
        t.set(new Uint8Array(A.slice(16)));
        t.set(new Uint8Array(e.slice(0, 16)), 16);
        this.iv = Buffer.from(A.slice(0, 16));
        this.cipherKey = Buffer.from(t.buffer);
        */


        this.iteration = iteration;
        this.seed = seed;
        this.iv = derivative.slice(0, 16);
        this.cipherKey = derivative.slice(16);
    }

    getIteration() {
        return this.iteration;
    }

    getIv() {
        return this.iv;
    }

    getCipherKey() {
        return this.cipherKey;
    }

    getSeed() {
        return this.seed;
    }
}
module.exports = SenderMessageKey;