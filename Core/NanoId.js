export default class NanoID {
    static #LOWERCASE_CHARS = "abcdefghijklmnopqrstuvwxyz";
    static #UPPERCASE_CHARS = "ABCDEFGHIJKLMNOPQRSTUVWXYZ";
    static #NUMBER_CHARS = "0123456789";
    static #SYMBOL_CHARS = "_-";
    
    /**
     * Generates an array of cryptographically strong IDs based on provided options.
     * @param {Object} options - Configuration for ID generation.
     * @returns {Object} Result object containing the IDs or error details.
     */
    static generateMany(options = {}) {
        const {
            count = 1,
            length = 21,
            lowercase = true,
            uppercase = false,
            numbers = false,
            symbols = false,
            extra = "",
            prefix = "",
            suffix = ""
        } = options;

        const validation = this.#validateOptions(options);
        if (!validation.valid) {
            return {
                valid: false,
                nanoIds: [],
                error: validation.error
            };
        }

        const charset = this.#getSelectedCharset(options);

        // To prevent modulo bias, we calculate the largest multiple of charset.length 
        // that fits within 256 (the range of a byte). 
        const maxValid = Math.floor(256 / charset.length) * charset.length;
        const nanoIds = [];

        for (let i = 0; i < count; i++) {
            let core = "";

            while (core.length < length) {

                // Generate a batch of random bytes to reduce crypto.getRandomValues calls
                const bytes = crypto.getRandomValues(new Uint8Array(length * 2));

                for (const byte of bytes) {

                    // Discard bytes that fall outside our maxValid range to ensure 
                    // each character in the charset has an equal probability.
                    if (byte >= maxValid) {
                        continue;
                    }

                    core += charset[byte % charset.length];

                    if (core.length >= length) {
                        break;
                    }
                }
            }

            nanoIds.push(`${prefix}${core}${suffix}`);
        }

        return {
            valid: true,
            nanoIds,
            error: ""
        };
    }


    /// STATIC METHODS ///

    // validate options and return { valid: bool, error: string }
    static #validateOptions(options = {}) {
        const {
            count = 1,
            length = 21,
            lowercase = true,
            uppercase = false,
            numbers = false,
            symbols = false,
            extra = ""
        } = options;

        // Ensure the batch count is within reasonable limits
        if (!Number.isInteger(count) || count < 1 || count > 100) {
            return { valid: false, error: "Count must be between 1 and 100" };
        }

        // Ensure ID length is practical
        if (!Number.isInteger(length) || length < 1 || length > 128) {
            return { valid: false, error: "Length must be between 1 and 128" };
        }

        const charset = this.#getSelectedCharset(options);

        // Safety check to prevent extremely low entropy IDs
        if (charset.length < 4) {
            return { valid: false, error: "Very few characters available. Enable at least one charset option or add extra characters." };
        }
        
        // Ensure the resulting charset isn't composed of repetitive characters
        if (new Set(charset).size < 4) {
            return { valid: false, error: "Charset must contain at least 4 different characters." };
        }

        return { valid: true, error: ""};
    }

    
    /**
     * Combines predefined character sets and user-provided extra characters.
     */
    static #getSelectedCharset(options = {}) {
        let charset = "";

        if (options.lowercase) charset += NanoID.#LOWERCASE_CHARS;
        if (options.uppercase) charset += NanoID.#UPPERCASE_CHARS;
        if (options.numbers) charset += NanoID.#NUMBER_CHARS;
        if (options.symbols) charset += NanoID.#SYMBOL_CHARS;

        if (options.extra) charset += options.extra;
        return charset;
    }

}