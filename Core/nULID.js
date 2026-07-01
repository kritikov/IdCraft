export default class nULID {
    
    // Crockford's Base32 alphabet (excluding I, L, O, U to avoid visual ambiguity)
    static #BASE32_CHARS = "0123456789ABCDEFGHJKMNPQRSTVWXYZ";
    
    // Static state for the Monotonicity Guard
    static #lastTimestamp = 0;
    static #lastEntropyBytes = new Uint8Array(10);

    /**
     * Core method for generating batches of ULIDs.
     * @param {Object} options - Generation configuration options.
     * @param {number} [options.count=1] - Number of ULIDs to generate.
     * @param {string} [options.format="uppercase"] - Output casing: 'uppercase' or 'lowercase'.
     * @returns {Object} { valid: boolean, ulids: string[], monotonicUsed: boolean, error: string }
     */
    static generateMany(options = {}) {
        const {
            count = 1,
            format = "uppercase" // uppercase | lowercase
        } = options;

        const ulids = [];
        let monotonicUsed = false;

        for (let i = 0; i < count; i++) {
            const now = Date.now();
            let currentULID = "";

            if (now === nULID.#lastTimestamp) {
                // 📈 Same millisecond: Trigger Monotonic Increment
                monotonicUsed = true;
                nULID.#incrementEntropy();
            } else {
                // ✨ New millisecond: Generate fresh random entropy source
                nULID.#lastTimestamp = now;
                nULID.#generateRandomEntropy();
            }

            // 1. Encode the Timestamp component (48 bits -> 10 Base32 characters)
            const timePart = nULID.#encodeTime(now, 10);

            // 2. Encode the Entropy component (80 bits -> 16 Base32 characters)
            const entropyPart = nULID.#encodeEntropy(nULID.#lastEntropyBytes, 16);

            currentULID = timePart + entropyPart;

            // Apply text casing format
            if (format === "lowercase") {
                currentULID = currentULID.toLowerCase();
            }

            ulids.push(currentULID);
        }

        return {
            valid: true,
            ulids,
            monotonicUsed,
            error: ""
        };
    }

    // ===== PRIVATE STATIC METHODS =====

    /**
     * Converts a UNIX timestamp integer into a Crockford's Base32 string.
     */
    static #encodeTime(now, length) {
        let charArray = new Array(length);
        let time = now;

        for (let i = length - 1; i >= 0; i--) {
            const mod = time % 32;
            charArray[i] = nULID.#BASE32_CHARS[mod];
            time = Math.floor(time / 32);
        }
        return charArray.join("");
    }

    /**
     * Fills the entropy array using cryptographically secure random values.
     */
    static #generateRandomEntropy() {
        if (typeof crypto !== "undefined" && crypto.getRandomValues) {
            crypto.getRandomValues(nULID.#lastEntropyBytes);
        } else {
            // Fallback environment implementation if Web Crypto API is unavailable
            for (let i = 0; i < 10; i++) {
                nULID.#lastEntropyBytes[i] = Math.floor(Math.random() * 256);
            }
        }
    }

    /**
     * Increments the entropy byte array by 1 (Monotonic Guard) to handle rapid generation states.
     */
    static #incrementEntropy() {
        let i = nULID.#lastEntropyBytes.length - 1;
        while (i >= 0 && nULID.#lastEntropyBytes[i] === 255) {
            nULID.#lastEntropyBytes[i] = 0;
            i--;
        }
        if (i >= 0) {
            nULID.#lastEntropyBytes[i]++;
        }
    }

    /**
     * Converts the 10-byte entropy array into a Crockford's Base32 string.
     */
    static #encodeEntropy(bytes, length) {
        let charArray = new Array(length);
        
        // Map the 10 bytes (80 bits) into 5-bit Base32 chunks sequentially
        for (let i = 0; i < length; i++) {
            // Calculate bit-offset positioning for the current 5-bit segment
            const bitOffset = i * 5;
            const byteIdx = Math.floor(bitOffset / 8);
            const bitRemainder = bitOffset % 8;

            // Extract bits from the primary relative byte position
            let value = bytes[byteIdx] << (bitRemainder + 24);
            
            // Perform bitwise OR evaluations if chunks span across adjacent byte fields
            if (byteIdx + 1 < bytes.length) {
                value |= bytes[byteIdx + 1] << (bitRemainder + 16);
            }
            if (byteIdx + 2 < bytes.length) {
                value |= bytes[byteIdx + 2] << (bitRemainder + 8);
            }

            // Isolate the 5 MSB bits to resolve the specific Base32 character mapping index
            const base32Index = (value >>> 27) & 0x1F;
            charArray[i] = nULID.#BASE32_CHARS[base32Index];
        }

        return charArray.join("");
    }
}