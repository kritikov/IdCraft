import Message from "./Messages/Message.js";
import Severity from "./Messages/Severity.js";
import Catalog from "./Messages/MessageCatalog.js";
import Codes from "./Messages/MessageCodes.js";
import nEntropy from "./nEntropy.js"; // 💡 Reusable entropy calculations!

export default class nString {
    static #LOWERCASE_CHARS = "abcdefghijklmnopqrstuvwxyz";
    static #UPPERCASE_CHARS = "ABCDEFGHIJKLMNOPQRSTUVWXYZ";
    static #NUMBER_CHARS = "0123456789";
    static #SYMBOL_CHARS = "!@#$%^&*()_+-=[]{}|;:,.<>?"; 
    static #SIMILAR_CHARS = ["O", "0", "I", "l", "1"];
    static #AMBIGUOUS_CHARS = ["'", '"', "`", "\\"];

    /**
     * Generates a secure, cryptographically strong random string based on configuration.
     * @param {Object} [options={}] - Configuration parameters adjustment block.
     * @returns {Object} Complete analytical output payload execution block.
     */
    static generate(options = {}) {
        const messages = [];
        
        // 1. Sanitize input options
        const config = {
            length: options.length ?? 16,
            lowercase: options.lowercase ?? true,
            uppercase: options.uppercase ?? false,
            numbers: options.numbers ?? false,
            symbols: options.symbols ?? false,
            excludeSimilar: options.excludeSimilar ?? false,
            excludeAmbiguous: options.excludeAmbiguous ?? false,
            guaranteeAll: options.guaranteeAll ?? true,
            extra: options.extra ?? ""
        };

        // 2. Structural Validation Phase
        const validation = nString.#validateOptions(config, messages);
        if (!validation.valid) {
            return {
                valid: false,
                string: "",
                charsetLength: 0,
                entropyBits: 0,
                messages: messages
            };
        }

        // 3. Build and filter character pool
        const charset = nString.#getFinalCharset(config, messages);
        const maxValid = Math.floor(256 / charset.length) * charset.length;

        let finalString = "";
        let attempts = 0;
        const maxAttempts = 1000; // Safety guard loop breaker

        // 4. Cryptographic Generation Loop
        while (attempts < maxAttempts) {
            attempts++;
            let core = "";

            while (core.length < config.length) {
                const bytes = crypto.getRandomValues(new Uint8Array(config.length * 2));

                for (const byte of bytes) {
                    if (byte >= maxValid) continue;
                    core += charset[byte % charset.length];
                    if (core.length >= config.length) break;
                }
            }

            // Verify generation satisfies criteria constraints if enabled
            if (!config.guaranteeAll || nString.#checkGuarantees(core, config)) {
                finalString = core;
                break;
            }
        }

        // 5. Handle fallback failures
        if (config.guaranteeAll && !finalString) {
            nString.#addMessage(messages, Codes.GENERATION_GUARANTEE_FAILED);
            return {
                valid: false,
                string: "",
                charsetLength: charset.length,
                entropyBits: 0,
                messages: messages
            };
        }

        // 6. Metrics and Telemetry calculation payload injection
        const entropyBits = nEntropy.calculateRawBits(finalString.length, charset.length);
        nString.#addMessage(messages, Codes.GENERATION_SUCCESS);

        return {
            valid: true,
            string: finalString,
            charsetLength: charset.length,
            entropyBits: Math.round(entropyBits * 100) / 100,
            messages: messages
        };
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
     * Evaluates integrity and configuration constraints before running execution loops.
     * @private
     */
    static #validateOptions(config, messages) {
        if (!Number.isInteger(config.length) || config.length < 1 || config.length > 128) {
            nString.#addMessage(messages, Codes.INVALID_STRING_LENGTH);
            return { valid: false };
        }

        const charset = nString.#getFinalCharset(config, []);

        if (charset.length < 4 || new Set(charset).size < 4) {
            nString.#addMessage(messages, Codes.INSUFFICIENT_CHARSET_POOL);
            return { valid: false };
        }

        return { valid: true };
    }

    /**
     * Compiles, filters, and deduplicates the active target character pool.
     * @private
     */
    static #getFinalCharset(config, messages) {
        let pool = "";

        if (config.lowercase) pool += nString.#LOWERCASE_CHARS;
        if (config.uppercase) pool += nString.#UPPERCASE_CHARS;
        if (config.numbers) pool += nString.#NUMBER_CHARS;
        if (config.symbols) pool += nString.#SYMBOL_CHARS;
        if (config.extra) pool += config.extra;

        let chars = pool.split("");

        if (config.excludeSimilar) {
            chars = chars.filter(c => !nString.#SIMILAR_CHARS.includes(c));
            if (messages.length > 0) nString.#addMessage(messages, Codes.FILTER_SIMILAR_ACTIVE);
        }

        if (config.excludeAmbiguous) {
            chars = chars.filter(c => !nString.#AMBIGUOUS_CHARS.includes(c));
            if (messages.length > 0) nString.#addMessage(messages, Codes.FILTER_AMBIGUOUS_ACTIVE);
        }

        return Array.from(new Set(chars)).join("");
    }

    /**
     * Confirms compliance of the target string against all active groups.
     * @private
     */
    static #checkGuarantees(str, config) {
        const chars = str.split("");

        if (config.lowercase && !chars.some(c => nString.#LOWERCASE_CHARS.includes(c) && (!config.excludeSimilar || !nString.#SIMILAR_CHARS.includes(c)))) return false;
        if (config.uppercase && !chars.some(c => nString.#UPPERCASE_CHARS.includes(c) && (!config.excludeSimilar || !nString.#SIMILAR_CHARS.includes(c)))) return false;
        if (config.numbers && !chars.some(c => nString.#NUMBER_CHARS.includes(c) && (!config.excludeSimilar || !nString.#SIMILAR_CHARS.includes(c)))) return false;
        if (config.symbols && !chars.some(c => nString.#SYMBOL_CHARS.includes(c) && (!config.excludeAmbiguous || !nString.#AMBIGUOUS_CHARS.includes(c)))) return false;
        
        if (config.extra && config.extra.trim().length > 0) {
            if (!chars.some(c => config.extra.includes(c))) return false;
        }
        
        return true;
    }
}