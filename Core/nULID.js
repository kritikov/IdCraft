import Message from "./Messages/Message.js";
import Severity from "./Messages/Severity.js";
import Catalog from "./Messages/MessageCatalog.js";
import Codes from "./Messages/MessageCodes.js";

/**
 * Cryptographically Secure Universally Unique Lexicographically Sortable Identifier (ULID) Engine.
 * Features built-in Monotonicity Guard and full rich telemetry pipeline integration.
 */
export default class nULID {
    
    // Crockford's Base32 alphabet (excluding I, L, O, U to avoid visual ambiguity)
    static #BASE32_CHARS = "0123456789ABCDEFGHJKMNPQRSTVWXYZ";
    
    // Static state for the Monotonicity Guard
    static #lastTimestamp = 0;
    static #lastEntropyBytes = new Uint8Array(10);

    /**
     * Core structural method for generating batches of ULIDs with telemetry logs.
     * * @param {Object} [options={}] - Generation configuration parameters block.
     * @param {number} [options.count=1] - Total number of tokens to mint sequentially.
     * @param {string} [options.format="uppercase"] - Output casing layout selection ("uppercase" | "lowercase").
     * * @returns {{
     * valid: boolean, 
     * ulids: string[], 
     * monotonicUsed: boolean, 
     * messages: Array
     * }} Complete output operational execution telemetry block.
     */
    static generateMany(options = {}) {
        const {
            count = 1,
            format = "uppercase"
        } = options;

        const result = {
            valid: true,
            ulids: [],
            monotonicUsed: false,
            messages: []
        };

        // 1. Initial Validation Defenses
        if (typeof count !== "number" || count <= 0) {
            result.valid = false;
            nULID.#addMessage(result.messages, Codes.INPUT_INVALID_COUNT); // Define inside MessageCodes if missing
            return result;
        }

        let cryptoFallbackTriggered = false;

        // 2. Generation Loop Engine
        for (let i = 0; i < count; i++) {
            const now = Date.now();
            let currentULID = "";

            if (now === nULID.#lastTimestamp) {
                // Same millisecond threshold collision: Trigger Monotonic Increment Guard
                result.monotonicUsed = true;
                nULID.#incrementEntropy();
            } else {
                // New distinct millisecond frame: Seed fresh secure random entropy source
                nULID.#lastTimestamp = now;
                const usedFallback = nULID.#generateRandomEntropy();
                if (usedFallback) cryptoFallbackTriggered = true;
            }

            // Encode components utilising Crockford's Base32 specifications
            const timePart = nULID.#encodeTime(now, 10);
            const entropyPart = nULID.#encodeEntropy(nULID.#lastEntropyBytes, 16);

            currentULID = timePart + entropyPart;

            if (format === "lowercase") {
                currentULID = currentULID.toLowerCase();
            }

            result.ulids.push(currentULID);
        }

        // 3. Compile Diagnostic Status Telemetry
        if (result.monotonicUsed) {
            nULID.#addMessage(result.messages, Codes.ULID_MONOTONIC_GUARD_ACTIVE);
        } else {
            nULID.#addMessage(result.messages, Codes.ULID_STANDARD_GENERATION_ACTIVE);
        }

        if (cryptoFallbackTriggered) {
            nULID.#addMessage(result.messages, Codes.CRYPTO_FALLBACK_WARNING);
        } else {
            nULID.#addMessage(result.messages, Codes.CSPRNG_CONTEXT_SECURE);
        }

        return result;
    }

    // =====================================================
    // PRIVATE STATIC TELEMETRY & MATH HELPERS
    // =====================================================

    /**
     * Instantiates a diagnostic message and pushes it into the pipeline collection.
     * @private
     */
    static #addMessage(messages, code, titleData = null, data = null) {
        messages.push(new Message({ code: code, data: data, titleData: titleData, catalog: Catalog }));
    }

    /**
     * Converts a UNIX timestamp integer into a Crockford's Base32 string representation.
     * @private
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
     * Fills the active entropy payload matrix using cryptographically secure random routines.
     * @private
     * @returns {boolean} True if the insecure math fallback vector was forced.
     */
    static #generateRandomEntropy() {
        if (typeof crypto !== "undefined" && crypto.getRandomValues) {
            crypto.getRandomValues(nULID.#lastEntropyBytes);
            return false;
        } else {
            // Environment fallback execution matrix if native Web Crypto APIs are missing
            for (let i = 0; i < 10; i++) {
                nULID.#lastEntropyBytes[i] = Math.floor(Math.random() * 256);
            }
            return true;
        }
    }

    /**
     * Increments the entropy byte array bitwise by 1 to guarantee sortable monotonicity.
     * @private
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
     * Converts the 10-byte raw entropy array into a strict Crockford's Base32 string structure.
     * @private
     */
    static #encodeEntropy(bytes, length) {
        let charArray = new Array(length);
        
        for (let i = 0; i < length; i++) {
            const bitOffset = i * 5;
            const byteIdx = Math.floor(bitOffset / 8);
            const bitRemainder = bitOffset % 8;

            let value = bytes[byteIdx] << (bitRemainder + 24);
            
            if (byteIdx + 1 < bytes.length) {
                value |= bytes[byteIdx + 1] << (bitRemainder + 16);
            }
            if (byteIdx + 2 < bytes.length) {
                value |= bytes[byteIdx + 2] << (bitRemainder + 8);
            }

            const base32Index = (value >>> 27) & 0x1F;
            charArray[i] = nULID.#BASE32_CHARS[base32Index];
        }

        return charArray.join("");
    }
}