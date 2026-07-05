import Message from "./Messages/Message.js";
import Severity from "./Messages/Severity.js";
import Catalog from "./Messages/MessageCatalog.js";
import Codes from "./Messages/MessageCodes.js";

/**
 * Cryptographically Secure Nano ID Generation Engine.
 * Features strict modulo-bias cancellation and full rich telemetry pipeline integration.
 */
export default class nNanoID {
    static #LOWERCASE_CHARS = "abcdefghijklmnopqrstuvwxyz";
    static #UPPERCASE_CHARS = "ABCDEFGHIJKLMNOPQRSTUVWXYZ";
    static #NUMBER_CHARS = "0123456789";
    static #SYMBOL_CHARS = "_-";

    /**
     * Core structural method for generating batches of Nano IDs with telemetry logs.
     * @param {Object} [options={}] - Generation configuration parameters block.
     * @param {number} [options.count=1] - Total number of tokens to mint sequentially.
     * @param {number} [options.length=21] - The length of the core random part of the ID.
     * @param {boolean} [options.lowercase=true] - Include a-z character pool.
     * @param {boolean} [options.uppercase=false] - Include A-Z character pool.
     * @param {boolean} [options.numbers=false] - Include 0-9 character pool.
     * @param {boolean} [options.symbols=false] - Include default symbols (_-).
     * @param {string} [options.extra=""] - Additional custom characters to inject into the pool.
     * @param {string} [options.prefix=""] - String value to prepend to the final token.
     * @param {string} [options.suffix=""] - String value to append to the final token.
     * @returns {{
     * valid: boolean, 
     * nanoIds: string[], 
     * charsetLength: number,
     * messages: Array
     * }} Complete output operational execution telemetry block.
     */
    static generateMany(options = {}) {
        const {
            count = 1,
            length = 21,
            prefix = "",
            suffix = ""
        } = options;

        const result = {
            valid: true,
            nanoIds: [],
            charsetLength: 0,
            messages: []
        };

        // 1. Structural Validation Defenses
        if (typeof count !== "number" || count < 1 || count > 100) {
            result.valid = false;
            nNanoID.#addMessage(result.messages, Codes.INPUT_INVALID_COUNT);
            return result;
        }

        if (typeof length !== "number" || length < 1 || length > 128) {
            result.valid = false;
            nNanoID.#addMessage(result.messages, Codes.INVALID_STRING_LENGTH);
            return result;
        }

        const charset = nNanoID.#getSelectedCharset(options);
        result.charsetLength = charset.length;

        // Safety verification checks preventing extremely low entropy pools
        if (charset.length < 4 || new Set(charset).size < 4) {
            result.valid = false;
            nNanoID.#addMessage(result.messages, Codes.INSUFFICIENT_CHARSET_POOL);
            return result;
        }

        // To prevent modulo bias, calculate the largest multiple of charset.length that fits within 256
        const maxValid = Math.floor(256 / charset.length) * charset.length;
        let cryptoFallbackTriggered = false;

        // 2. Generation Loop Engine
        for (let i = 0; i < count; i++) {
            let core = "";

            while (core.length < length) {
                const bytes = new Uint8Array(length * 2);
                
                // Entropy sourcing with environmental fallback guard
                if (typeof crypto !== "undefined" && crypto.getRandomValues) {
                    crypto.getRandomValues(bytes);
                } else {
                    cryptoFallbackTriggered = true;
                    for (let j = 0; j < bytes.length; j++) {
                        bytes[j] = Math.floor(Math.random() * 256);
                    }
                }

                for (const byte of bytes) {
                    // Discard bytes outside maxValid range to ensure uniform distribution
                    if (byte >= maxValid) {
                        continue;
                    }

                    core += charset[byte % charset.length];

                    if (core.length >= length) {
                        break;
                    }
                }
            }

            result.nanoIds.push(`${prefix}${core}${suffix}`);
        }

        // 3. Compile Diagnostic Status Telemetry
        nNanoID.#addMessage(result.messages, Codes.GENERATION_SUCCESS);

        if (cryptoFallbackTriggered) {
            nNanoID.#addMessage(result.messages, Codes.CRYPTO_FALLBACK_WARNING);
        } else {
            nNanoID.#addMessage(result.messages, Codes.CSPRNG_CONTEXT_SECURE);
        }

        return result;
    }

    // =====================================================
    // PRIVATE STATIC HELPERS
    // =====================================================

    /**
     * Instantiates a diagnostic message and pushes it into the pipeline collection.
     * @private
     */
    static #addMessage(messages, code, titleData = null, data = null) {
        messages.push(new Message({ code: code, data: data, titleData: titleData, catalog: Catalog }));
    }

    /**
     * Combines predefined character sets and user-provided extra characters.
     * @private
     */
    static #getSelectedCharset(options = {}) {
        let charset = "";

        if (options.lowercase) charset += nNanoID.#LOWERCASE_CHARS;
        if (options.uppercase) charset += nNanoID.#UPPERCASE_CHARS;
        if (options.numbers) charset += nNanoID.#NUMBER_CHARS;
        if (options.symbols) charset += nNanoID.#SYMBOL_CHARS;

        if (options.extra) {
            charset += options.extra;
        }
        
        return charset;
    }
}