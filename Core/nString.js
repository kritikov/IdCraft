export default class nString {
    static #LOWERCASE_CHARS = "abcdefghijklmnopqrstuvwxyz";
    static #UPPERCASE_CHARS = "ABCDEFGHIJKLMNOPQRSTUVWXYZ";
    static #NUMBER_CHARS = "0123456789";
    static #SYMBOL_CHARS = "!@#$%^&*()_+-=[]{}|;:,.<>?"; 
    static #SIMILAR_CHARS = ["O", "0", "I", "l", "1"];
    static #AMBIGUOUS_CHARS = ["'", '"', "`", "\\"];

    /**
     * Generates a secure, cryptographically strong random string based on options.
     * @param {Object} options - Configuration for string generation.
     * @returns {Object} Result object containing the string or error details.
     */
    static generate(options = {}) {
        const {
            length = 16,
            lowercase = true,
            uppercase = false,
            numbers = false,
            symbols = false,
            excludeSimilar = false,
            excludeAmbiguous = false,
            guaranteeAll = true,
            extra = ""
        } = options;

        // 1. Validation
        const validation = this.#validateOptions(options);
        if (!validation.valid) {
            return { valid: false, string: "", error: validation.error };
        }

        // 2. Build and clean the final charset
        const charset = this.#getFinalCharset(options);
        const maxValid = Math.floor(256 / charset.length) * charset.length;

        let finalString = "";
        let attempts = 0;
        const maxAttempts = 1000; // Safety guard to avoid infinite loop

        // 3. Generation Loop (with guarantee checking)
        while (attempts < maxAttempts) {
            attempts++;
            let core = "";

            while (core.length < length) {
                const bytes = crypto.getRandomValues(new Uint8Array(length * 2));

                for (const byte of bytes) {
                    if (byte >= maxValid) continue;

                    core += charset[byte % charset.length];

                    if (core.length >= length) break;
                }
            }

            // Check if the generated string satisfies the guarantee rule
            if (!guaranteeAll || this.#checkGuarantees(core, options)) {
                finalString = core;
                break;
            }
        }

        // Fallback in case guaranteeAll fails repeatedly due to tight restrictions
        if (guaranteeAll && !finalString) {
            return { valid: false, string: "", error: "Could not guarantee all groups. Try increasing length or adjusting filters." };
        }

        return {
            valid: true,
            string: finalString,
            error: ""
        };
    }

    /// PRIVATE STATIC METHODS ///

    static #validateOptions(options = {}) {
        const { length = 16, lowercase = true, uppercase = false, numbers = false, symbols = false, extra = "" } = options;

        if (!Number.isInteger(length) || length < 1 || length > 128) {
            return { valid: false, error: "Length must be between 1 and 128" };
        }

        const charset = this.#getFinalCharset(options);

        if (charset.length < 4) {
            return { valid: false, error: "Very few characters available. Enable more groups or remove exclusion filters." };
        }
        
        if (new Set(charset).size < 4) {
            return { valid: false, error: "The resulting charset must contain at least 4 unique characters." };
        }

        return { valid: true, error: "" };
    }

    /**
     * Builds, filters and deduplicates the character pool.
     */
    static #getFinalCharset(options = {}) {
        let pool = "";

        if (options.lowercase) pool += this.#LOWERCASE_CHARS;
        if (options.uppercase) pool += this.#UPPERCASE_CHARS;
        if (options.numbers) pool += this.#NUMBER_CHARS;
        if (options.symbols) pool += this.#SYMBOL_CHARS;
        if (options.extra) pool += options.extra;

        // Μετατροπή σε Array για φιλτράρισμα
        let chars = pool.split("");

        if (options.excludeSimilar) {
            chars = chars.filter(c => !this.#SIMILAR_CHARS.includes(c));
        }

        if (options.excludeAmbiguous) {
            chars = chars.filter(c => !this.#AMBIGUOUS_CHARS.includes(c));
        }

        // Deduplicate (Remove duplicate entries)
        return Array.from(new Set(chars)).join("");
    }

    /**
     * Verifies that the string contains at least one character from each active group,
     * including user-defined extra characters.
     */
    static #checkGuarantees(str, options) {
        const chars = str.split("");

        if (options.lowercase && !chars.some(c => this.#LOWERCASE_CHARS.includes(c) && (!options.excludeSimilar || !this.#SIMILAR_CHARS.includes(c)))) return false;
        if (options.uppercase && !chars.some(c => this.#UPPERCASE_CHARS.includes(c) && (!options.excludeSimilar || !this.#SIMILAR_CHARS.includes(c)))) return false;
        if (options.numbers && !chars.some(c => this.#NUMBER_CHARS.includes(c) && (!options.excludeSimilar || !this.#SIMILAR_CHARS.includes(c)))) return false;
        if (options.symbols && !chars.some(c => this.#SYMBOL_CHARS.includes(c) && (!options.excludeAmbiguous || !this.#AMBIGUOUS_CHARS.includes(c)))) return false;
        
        // Έλεγχος για το extra charset αν υπάρχει περιεχόμενο
        if (options.extra && options.extra.trim().length > 0) {
            if (!chars.some(c => options.extra.includes(c))) return false;
        }
        
        return true;
    }
}