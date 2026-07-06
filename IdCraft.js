import nNanoId from "./Core/nNanoId.js?ver=1";
import nUUID from "./Core/nUUID.js?ver=2";
import nString from "./Core/nString.js?ver=2";
import nULID from "./Core/nULID.js?ver=2";
import nEntropy from "./Core/nEntropy.js?ver=2";


/**
 * Main Entry point for the ID Generation library.
 * Provides a unified interface for generating and inspecting UUIDs and NanoIDs.
 */
export default class IdCraft {

    /**
     * Comprehensive structural diagnostic method designed for rich telemetry UI output.
     * Forward-call to the underlying nEntropy analytical engine.
     * * @param {string} input - Raw string token or password to analyze.
     * @param {Object} [options={}] - Configuration parameter adjustments block.
     * @param {number} [options.guessesPerSecond=1e10] - Number of brute-force attempts per second by the attacker.
     * @param {string} [options.searchMode="exhaustive"] - Execution analysis strategy ("exhaustive" or "smart").
     * @param {boolean} [options.trimSpaces=false] - If true, strips leading and trailing whitespaces before analysis.
     * @param {number|string} [options.poolOverride="auto"] - Manual override for the resolved character pool size (R).
     * * @returns {{
     * valid: boolean,
     * entropyBits: number,
     * poolSize: number,
     * stringLength: number,
     * crackTimeFormatted: string,
     * messages: Array
     * }} Complete analytical output payload execution block.
     */
    static analyzeEntropy(input, options = {}) {
        return nEntropy.analyze(input, options);
    }

    /**
     * Generates a cryptographically secure random string or password.
     * Uses the Web Crypto API client-side via the nString engine.
     * * @param {Object} options - Configuration for string generation.
     * @param {number} [options.length=16] - The length of the generated string (1-128).
     * @param {boolean} [options.lowercase=true] - Include lowercase characters (a-z).
     * @param {boolean} [options.uppercase=false] - Include uppercase characters (A-Z).
     * @param {boolean} [options.numbers=false] - Include numbers (0-9).
     * @param {boolean} [options.symbols=false] - Include special characters/symbols.
     * @param {boolean} [options.excludeSimilar=false] - Exclude visually similar chars (O, 0, I, l, 1).
     * @param {boolean} [options.excludeAmbiguous=false] - Exclude ambiguous characters (' " ` \).
     * @param {boolean} [options.guaranteeAll=true] - Ensure at least one char from each selected group.
     * @param {string} [options.extra=""] - Additional custom characters to include in the pool.
     * @returns {Object} Result object { valid: boolean, string: string, error: string }.
     */
    static getRandomString(options = {}) {
        return nString.generate(options);
    }

    /**
     * Generates a batch of Universally Unique Lexicographically Sortable Identifiers (ULIDs).
     * ULIDs combine a 48-bit millisecond timestamp with 80 bits of cryptographic randomness,
     * wrapped in Crockford's Base32 encoding (26 characters, case-insensitive, URL-safe).
     * * Includes a Monotonicity Guard to ensure strict chronological ordering even when
     * identifiers are generated sequentially within the exact same millisecond.
     * * @param {Object} options - Configuration for ULID generation.
     * @param {number} [options.count=1] - The number of ULIDs to generate in this batch.
     * @param {string} [options.format="uppercase"] - Text casing format: 'uppercase' (standard) or 'lowercase'.
     * @returns {Object} Result object containing:
     * - {boolean} valid: Whether the generation was successful.
     * - {string[]} ulids: Array of the generated ULID strings.
     * - {boolean} monotonicUsed: True if the monotonicity guard was triggered during generation.
     * - {string} error: Error message, if any.
     */
    static generateULIDs(options = {}) {
        return nULID.generateMany(options);
    }

    /**
     * Generates a batch of NanoIDs with customizable character sets and structure.
     * * @param {Object} options - Configuration for NanoID generation.
     * @param {number} [options.count=1] - Number of IDs to generate.
     * @param {number} [options.length=21] - Character length of each ID core.
     * @param {boolean} [options.lowercase=true] - Include lowercase letters.
     * @param {boolean} [options.uppercase=false] - Include uppercase letters.
     * @param {boolean} [options.numbers=false] - Include digits 0-9.
     * @param {boolean} [options.symbols=false] - Include symbols (_-).
     * @param {string} [options.extra=""] - Additional custom characters to include in the charset.
     * @param {string} [options.prefix=""] - String to prepend to every ID.
     * @param {string} [options.suffix=""] - String to append to every ID.
     * @returns {Object} Result containing 'valid' status, the array of 'nanoIds', and any 'error' message.
     */
    static generateNanoIds(options = {}) {
        return nNanoId.generateMany(options);
    }

    /**
     * Generates a batch of UUIDs based on the specified version and format.
     * * @param {Object} options - Configuration for UUID generation.
     * @param {number} [options.count=1] - Number of UUIDs to generate (1-100).
     * @param {string} [options.format="lowercase"] - Output case: "lowercase" or "uppercase".
     * @param {boolean} [options.withHyphens=false] - Whether to include standard UUID hyphens.
     * @param {string} [options.braces="none"] - Wrap style: "none" or "curly".
     * @param {string} [options.version="v4"] - UUID version: "v4" (random) or "v7" (time-ordered).
     * @returns {Object} Result containing an array of 'uuids', the 'source' of entropy, and 'reliability'.
     */
    static generateUUIDs(options = {}) {
        return nUUID.generateMany(options);
    }
    
    /**
     * Validates a UUID string and returns a detailed inspection object.
     * Generates a unified telemetry block optimized for the ToolsHelper UI component.
     * @param {string} uuid - The UUID string to inspect (supports various formats/braces).
     * @returns {Object} result - Inspection result and UI telemetry pack.
     */
    static inspectUUID(uuid) {
        const result = nUUID.isValidInput(uuid);
        if (!result.valid) {
            return {
                valid: false,
                error: result.error
            };
        }

        try {
            const uuidInstance = new nUUID(result.clean);

            // 1. Structural Info Message in plain English
            const infoMessage = {
                severity: "info",
                title: "Identifier Structural Analysis",
                details: uuidInstance.getInformation()
            };

            // 2. Mapping the Message instances from nUUID.warnings to flat UI objects
            const normalizedWarnings = (uuidInstance.warnings || []).map(w => {
                return {
                    // Ensures lowercase format (e.g., "warning", "critical") for ToolsHelper CSS classes
                    severity: String(w.severity).toLowerCase(), 
                    title: w.title,
                    details: w.details
                };
            });

            // 3. Unify into a flat array (Info first, then Warnings)
            const uiMessages = [infoMessage, ...normalizedWarnings];

            return {
                valid: true,
                uuid: uuidInstance,
                uiMessages: uiMessages // 🎯 Directly consumed by Code Behind
            };
        } 
        catch (err) {
            return {
                valid: false,
                error: err.message
            };
        }
    }

    /**
     * Performs a batch inspection on an array of UUID strings.
     * Useful for validating large lists of IDs from databases or user input.
     * @param {string[]} uuids - Array of UUID strings to validate.
     * @returns {Object[]} Array of inspection results.
     */
    static inspectUUIDs(uuids) {
        if (!uuids || uuids.length === 0) {
            return [];
        }
    
        return uuids.map(input => IdCraft.inspectUUID(input));
    }
}