import Message from "./Messages/Message.js";
import Severity from "./Messages/Severity.js";
import Catalog from "./Messages/MessageCatalog.js";
import Codes from "./Messages/MessageCodes.js";

export default class nEntropy {

    // Central registry for known dictionary and keyboard patterns
    static commonPatterns = [
        "qwerty", 
        "password", 
        "admin", 
        "welcome", 
        "login"
    ];

    /**
     * Calculates the raw Shannon entropy bits mathematically.
     * Silent method: Pure mathematical execution.
     * @param {number} length - The length of the string.
     * @param {number} poolSize - The size of the character pool (R).
     * @returns {number} The calculated bits of entropy.
     */
    static calculateRawBits(length, poolSize) {
        if (length <= 0 || poolSize <= 0) return 0;
        return length * Math.log2(poolSize);
    }

    /**
     * Formats a raw number of total permutations into a human-readable estimated crack time string (English only).
     * @param {number} entropyBits - The entropy score in bits.
     * @param {number} guessesPerSecond - Number of guesses the attacker can perform per second.
     * @returns {string} Formatted timeline text.
     */
    static formatCrackTime(entropyBits, guessesPerSecond) {
        if (entropyBits <= 0) return "Instantly";

        const totalCombinations = Math.pow(2, entropyBits);
        const seconds = totalCombinations / guessesPerSecond;

        if (seconds < 1) return "Instantly (< 1 sec)";
        
        const minutes = seconds / 60;
        if (minutes < 60) {
            const val = Math.floor(minutes);
            return `${val} ${val === 1 ? "minute" : "minutes"}`;
        }
        
        const hours = minutes / 60;
        if (hours < 24) {
            const val = Math.floor(hours);
            return `${val} ${val === 1 ? "hour" : "hours"}`;
        }
        
        const days = hours / 24;
        if (days < 365) {
            const val = Math.floor(days);
            return `${val} ${val === 1 ? "day" : "days"}`;
        }
        
        const years = days / 365;
        if (years < 2) {
            return `${Math.floor(years)} year`;
        }
        if (years < 1e3) {
            return `${Math.floor(years)} years`;
        }
        if (years < 1e6) {
            return `${Math.floor(years / 1e3)}k centuries`;
        }
        
        return "Practically Infinite";
    }

    // =====================================================
    // 2. PRIVATE TELEMETRY HELPERS
    // =====================================================

    /**
     * Instantiates a diagnostic message and pushes it into the pipeline collection.
     * @private
     */
    static #addMessage(messages, code, titleData = null, data = null) {
        messages.push(new Message({ code: code, data: data, titleData: titleData, catalog: Catalog }));
    }

    /**
     * Evaluates the active character set found inside the string to compute R dynamically.
     * Supports both Latin and Greek alphabets.
     * @private
     * @param {string} value - Raw input string.
     * @returns {number} The detected pool size.
     */
    static #detectPoolSize(value) {
        let pool = 0;
        
        // Latin Alphabet
        if (/[a-z]/.test(value)) pool += 26;
        if (/[A-Z]/.test(value)) pool += 26;
        
        // 🔥 Greek Alphabet (πεζά, κεφαλαία, τονισμένα και τελικό σίγμα)
        if (/[α-ωά-ώόίύήέύϊϋΐΰς]/.test(value)) pool += 24;
        if (/[Α-ΩΆ-ΏΌΊΎΉΈΎΪΫ]/.test(value)) pool += 24;
        
        // Numbers
        if (/[0-9]/.test(value)) pool += 10;
        
        // Spaces
        if (/[\s]/.test(value)) pool += 1; 
        
        // Special Symbols
        if (/[~`!@#$%^&*()_\-+={[}\]|\\:;"'<,>.?\/]/.test(value)) pool += 32;

        return pool === 0 ? 1 : pool;
    }

    /**
     * Runs advanced static heuristic pattern checks to penalize human password logic.
     * @private
     */
    static #applyPatternPenalties(value, currentEntropy, messages) {
        let penalty = 0;
        const lowerInput = value.toLowerCase();

        // 1. Check for identical repeating characters (e.g., aaaaaa)
        const consecutiveRepeatRegex = /(.)\1{3,}/g;
        if (consecutiveRepeatRegex.test(lowerInput)) {
            penalty += 12;
            nEntropy.#addMessage(messages, Codes.PATTERN_REPETITIVE_CHARS);
        }

        // 2. Dynamic Sequence Detection (ASCII math for 23456, bcdef, 4321, etc.)
        let sequenceLength = 1;
        let maxSequenceFound = 0;
        let detectedSeq = "";

        for (let i = 1; i < lowerInput.length; i++) {
            const prevCharCode = lowerInput.charCodeAt(i - 1);
            const currCharCode = lowerInput.charCodeAt(i);
            
            const isSequentialAhead = (currCharCode === prevCharCode + 1);
            const isSequentialBack = (currCharCode === prevCharCode - 1);

            if (isSequentialAhead || isSequentialBack) {
                sequenceLength++;
                if (sequenceLength >= 4) {
                    maxSequenceFound = Math.max(maxSequenceFound, sequenceLength);
                    detectedSeq = lowerInput.substring(i - sequenceLength + 1, i + 1);
                }
            } else {
                sequenceLength = 1;
            }
        }

        if (maxSequenceFound >= 4) {
            penalty += 15;
            nEntropy.#addMessage(messages, Codes.PATTERN_SEQUENTIAL_FOUND, `: "${detectedSeq}"`);
        }

        // 3. Match against the central static dictionary pattern registry
        for (const word of nEntropy.commonPatterns) {
            if (lowerInput.includes(word)) {
                penalty += 15;
                nEntropy.#addMessage(messages, Codes.PATTERN_SEQUENTIAL_FOUND, `: "${word}"`);
                break; // Stop at the first match to avoid stacking duplicate penalties
            }
        }

        return Math.max(0, currentEntropy - penalty);
    }

    /**
     * Sanitizes and extracts metadata packages from incoming raw text frames.
     * @private
     */
    static #normalize(value, options) {
        const result = {
            valid: true,
            processedText: value,
            poolSize: 0,
            guessesPerSecond: options.guessesPerSecond || 1e10,
            searchMode: options.searchMode || "exhaustive",
            messages: []
        };

        if (typeof value !== "string") {
            result.valid = false;
            nEntropy.#addMessage(result.messages, Codes.INPUT_NOT_STRING);
            return result;
        }

        // Trim leading and trailing spaces if requested via configuration options
        if (options.trimSpaces === true) {
            result.processedText = value.trim();
        }

        if (result.processedText.length === 0) {
            result.valid = false;
            nEntropy.#addMessage(result.messages, Codes.INPUT_EMPTY);
            return result;
        }

        if (options.poolOverride && options.poolOverride !== "auto") {
            result.poolSize = parseInt(options.poolOverride, 10);
            nEntropy.#addMessage(result.messages, Codes.POOL_OVERRIDE_ACTIVE, `: R=${result.poolSize}`);
        } else {
            result.poolSize = nEntropy.#detectPoolSize(result.processedText);
            nEntropy.#addMessage(result.messages, Codes.POOL_AUTO_DETECTED, `: R=${result.poolSize}`);
        }

        return result;
    }

    // =====================================================
    // 3. MAIN UI ANALYTICAL ENGINE Entry Point
    // =====================================================

    /**
     * Comprehensive structural diagnostic method designed for rich telemetry UI output.
     * @param {string} value - Raw string token or password to analyze.
     * @param {Object} [options={}] - Configuration parameter adjustments block.
     * @returns {Object} Complete analytical output payload execution block.
     */
    static analyze(value, options = {}) {
        
        const normalization = nEntropy.#normalize(value, options);
        
        const result = {
            valid: normalization.valid,
            entropyBits: 0,
            poolSize: normalization.poolSize,
            stringLength: 0,
            crackTimeFormatted: "—",
            messages: normalization.messages
        };

        if (!normalization.valid) {
            return result;
        }

        // Calculate string metrics based on the core normalized text length
        result.stringLength = normalization.processedText.length;
        
        let finalEntropy = nEntropy.calculateRawBits(result.stringLength, normalization.poolSize);

        if (normalization.searchMode === "smart") {
            nEntropy.#addMessage(result.messages, Codes.SMART_MODE_ACTIVE);
            finalEntropy = nEntropy.#applyPatternPenalties(normalization.processedText, finalEntropy, result.messages);
        } else {
            nEntropy.#addMessage(result.messages, Codes.EXHAUSTIVE_MODE_ACTIVE);
        }

        result.entropyBits = Math.max(0, finalEntropy);
        
        // Calculate the formatted estimated brute-force runtime threshold
        result.crackTimeFormatted = nEntropy.formatCrackTime(result.entropyBits, normalization.guessesPerSecond);

        // Append final status evaluation insights
        if (result.entropyBits >= 80) {
            nEntropy.#addMessage(result.messages, Codes.STATUS_BULLETPROOF);
        } else if (result.entropyBits >= 60) {
            nEntropy.#addMessage(result.messages, Codes.STATUS_STRONG);
        } else if (result.entropyBits >= 40) {
            nEntropy.#addMessage(result.messages, Codes.STATUS_WEAK);
        } else {
            nEntropy.#addMessage(result.messages, Codes.STATUS_CRITICAL);
        }

        return result;
    }
}