import NanoId from "./Core/NanoId.js";
import UUID from "./Core/UUID.js";
import nString from "./Core/nString.js";


/**
 * Main Entry point for the ID Generation library.
 * Provides a unified interface for generating and inspecting UUIDs and NanoIDs.
 */
export default class IdCraft {

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
        return UUID.generateMany(options);
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
        return NanoId.generateMany(options);
    }

    /**
     * Validates a UUID string and returns a detailed inspection object.
     * If valid, it provides a UUID instance with metadata (version, variant, timestamp).
     * * @param {string} input - The UUID string to inspect (supports various formats/braces).
     * @returns {Object} result - Inspection result.
     * @returns {boolean} result.valid - True if the input is a valid UUID.
     * @returns {string} [result.error] - Error message if invalid.
     * @returns {UUID} [result.uuid] - A new UUID instance for further analysis if valid.
     */
    static inspectUUID(uuid) {
        const result = UUID.isValidInput(uuid);
        if (!result.valid) {
            return {
                valid: false,
                error: result.error
            };
        }
        else {
            return {
                valid: true,
                uuid: new UUID(result.clean)
            };
        }
    }

    /**
     * Performs a batch inspection on an array of UUID strings.
     * Useful for validating large lists of IDs from databases or user input.
     * * @param {string[]} uuids - Array of UUID strings to validate.
     * @returns {Object[]} Array of inspection results (see inspectUUID for object structure).
     */
    static inspectUUIDs(uuids) {
        if (!uuids || uuids.length === 0) {
            return [];
        }
    
        return uuids.map(input => IdCraft.inspectUUID(input));
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
}