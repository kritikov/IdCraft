import Message from "./Messages/Message.js";
import Severity from "./Messages/Severity.js";
import Catalog from "./Messages/MessageCatalog.js";
import Codes from "./Messages/MessageCodes.js";

/**
 * Cryptographically Secure Universally Unique Identifier (UUID v4 & v7) Engine.
 * Supports deep inspection analysis for v1, v4, v7 and full rich telemetry pipeline integration.
 */
export default class nUUID {
    
    // Static state for UUID v7 Monotonicity Guard
    static #lastTimestamp = 0;
    static #sequence = 0;

    /**
     * Instantiates an inspection payload block for a given UUID string.
     * @param {string} clean - A strict 32-character hexadecimal clean string representation.
     */
    constructor(clean) {
        if (!nUUID.#isValid(clean)) {
            throw new Error("UUID constructor expects a valid 32-char hex string");
        }

        this.clean = clean;

        // Route parsing based on the UUID version bit
        this.v1 = this.version === 1 ? this.#parseV1() : null;
        this.v4 = this.version === 4 ? { note: "Random UUID" } : null;
        this.v7 = this.version === 7 ? this.#parseV7() : null;

        // 🎯 Πλέον επιστρέφει array από επίσημα Message instances
        this.warnings = this.#getWarnings();
    }

    // =====================================================
    // INSTANCE METHODS (INSPECTION LOGIC)
    // =====================================================

    getInformation() {
        let explanation = `This is a UUID v${this.version}. `;

        if (this.version === 4) {
            explanation += "It is randomly generated and contains no embedded metadata.";
        }
        if (this.version === 7) {
            explanation += "It is time-ordered and includes a timestamp.";
            if (this.v7?.iso) {
                explanation += ` Generated around ${this.v7.iso}.`;
            }
        }
        if (this.version === 1) {
            explanation += "It is time-based and may include node (MAC-like) information.";
        }

        return explanation;
    }

    /**
     * Returns the UUID in the standard canonical 8-4-4-4-12 hyphenated format.
     */
    get canonical() {
        return (
            this.clean.slice(0, 8) + "-" +
            this.clean.slice(8, 12) + "-" +
            this.clean.slice(12, 16) + "-" +
            this.clean.slice(16, 20) + "-" +
            this.clean.slice(20)
        );
    }

    /**
     * Extracts the version from the 13th character (4 bits).
     */
    get version() {
        return parseInt(this.clean[12], 16);
    }

    /**
     * Extracts the variant from the 17th character to determine the UUID layout type.
     */
    get variant() {
        const nibble = parseInt(this.clean[16], 16);

        if ((nibble & 0x8) === 0x0) return "NCS";
        if ((nibble & 0xc) === 0x8) return "RFC4122";
        if ((nibble & 0xe) === 0xc) return "Microsoft";
        return "Future";
    }

    #parseV7() {
        const timeHex = this.clean.slice(0, 12);
        const timestamp = parseInt(timeHex, 16);

        return {
            timestamp,
            iso: new Date(timestamp).toISOString(),
            relativeTime: nUUID.#formatRelativeTime(timestamp)
        };
    }

    #parseV1() {
        const timeLow = this.clean.slice(0, 8);
        const timeMid = this.clean.slice(8, 12);
        const timeHi = this.clean.slice(12, 16);

        const timeHiClean = (parseInt(timeHi, 16) & 0x0fff).toString(16).padStart(3, "0");
        const timestampHex = timeHiClean + timeMid + timeLow;
        const timestamp100ns = BigInt("0x" + timestampHex);

        const timestampMs = timestamp100ns / 10000n;
        const UUID_EPOCH_OFFSET = 12219292800000n;
        const unixMs = timestampMs - UUID_EPOCH_OFFSET;
        const unixMsNumber = Number(unixMs);

        return {
            timestamp: unixMsNumber,
            iso: new Date(unixMsNumber).toISOString(),
            relativeTime: nUUID.#formatRelativeTime(unixMsNumber),
            node: this.clean.slice(20)
        };
    }

    #getWarnings() {
        const warnings = [];

        if (![1, 4, 7].includes(this.version)) {
            warnings.push(nUUID.#warn(Codes.UUID_VERSION_UNSUPPORTED));
        }

        switch (this.version) {
            case 1:
                warnings.push(...nUUID.#getV1Warnings(this.v1));
                break;
            case 4:
                warnings.push(...nUUID.#getV4Warnings(this.clean));
                break;
            case 7:
                warnings.push(...nUUID.#getV7Warnings(this.clean));
                break;
        }

        return warnings;
    }

    // =====================================================
    // CORE STATIC GENERATION ENGINE & TELEMETRY PIPELINE
    // =====================================================

    static generateMany(options = {}) {
        const {
            count = 1,
            format = "lowercase",
            withHyphens = false,
            braces = "none",
            version = "v4"
        } = options;

        const result = {
            valid: true,
            uuids: [],
            messages: []
        };

        if (typeof count !== "number" || count < 1 || count > 100) {
            result.valid = false;
            nUUID.#addMessage(result.messages, Codes.INPUT_INVALID_COUNT);
            return result;
        }

        if (version !== "v4" && version !== "v7") {
            result.valid = false;
            nUUID.#addMessage(result.messages, Codes.INPUT_EMPTY);
            return result;
        }

        let cryptoFallbackTriggered = false;
        let v7MonotonicUsed = false;

        for (let i = 0; i < count; i++) {
            let generatorState;

            if (version === "v4") {
                generatorState = nUUID.#generateUUIDv4();
            } else {
                generatorState = nUUID.#generateUUIDv7();
                if (generatorState.monotonicTriggered) {
                    v7MonotonicUsed = true;
                }
            }

            if (generatorState.reliability === "weak") {
                cryptoFallbackTriggered = true;
            }

            let finalToken = withHyphens ? generatorState.uuid.canonical : generatorState.uuid.clean;

            if (format === "uppercase") {
                finalToken = finalToken.toUpperCase();
            } else {
                finalToken = finalToken.toLowerCase();
            }

            if (braces === "curly") {
                finalToken = `{${finalToken}}`;
            }

            result.uuids.push(finalToken);
        }

        nUUID.#addMessage(result.messages, Codes.GENERATION_SUCCESS);

        if (version === "v7") {
            if (v7MonotonicUsed) {
                nUUID.#addMessage(result.messages, Codes.ULID_MONOTONIC_GUARD_ACTIVE);
            } else {
                nUUID.#addMessage(result.messages, Codes.ULID_STANDARD_GENERATION_ACTIVE);
            }
        }

        if (cryptoFallbackTriggered) {
            nUUID.#addMessage(result.messages, Codes.CRYPTO_FALLBACK_WARNING);
        } else {
            nUUID.#addMessage(result.messages, Codes.CSPRNG_CONTEXT_SECURE);
        }

        return result;
    }

    static #generateUUIDv4() {
        const hasCrypto = typeof crypto !== "undefined";
        let reliability = "secure";
        let clean = "";

        if (hasCrypto && crypto.randomUUID) {
            clean = crypto.randomUUID().replace(/-/g, "");
        } else if (hasCrypto && crypto.getRandomValues) {
            const bytes = crypto.getRandomValues(new Uint8Array(16));
            bytes[6] = (bytes[6] & 0x0f) | 0x40;
            bytes[8] = (bytes[8] & 0x3f) | 0x80;
            clean = Array.from(bytes, b => b.toString(16).padStart(2, "0")).join("");
        } else {
            reliability = "weak";
            clean = "xxxxxxxxxxxx4xxxyxxxxxxxxxxxxxxx".replace(/[xy]/g, c => {
                const r = Math.random() * 16 | 0;
                return (c === "x" ? r : (r & 0x3 | 0x8)).toString(16);
            });
        }

        return { reliability, uuid: new nUUID(clean) };
    }

    static #generateUUIDv7() {
        const hasCrypto = typeof crypto !== "undefined" && !!crypto.getRandomValues;
        const reliability = hasCrypto ? "secure" : "weak";
        
        let now = Date.now();
        let monotonicTriggered = false;

        // Handle same millisecond OR clock regression (NTP adjustment, VM resume, etc.)
        if (now === nUUID.#lastTimestamp || now < nUUID.#lastTimestamp) {
            monotonicTriggered = true;
            nUUID.#sequence++;
            
            // Overflow protection: if 12-bit counter exceeds 4095, force timestamp forward
            if (nUUID.#sequence > 0xfff) {
                nUUID.#lastTimestamp++;
                nUUID.#sequence = 0;
            }
        } else {
            nUUID.#lastTimestamp = now;
            nUUID.#sequence = 0;
        }

        // CRITICAL: Use nUUID.#lastTimestamp for the UUID generation, 
        // because it might have been advanced forward by the overflow protection.
        const timeHex = BigInt(nUUID.#lastTimestamp).toString(16).padStart(12, "0");

        // 12-bit monotonic counter -> exactly 3 hex chars (rand_a field)
        const counterHex = nUUID.#sequence.toString(16).padStart(3, "0");

        // 8 fresh random bytes: 1 for the variant byte, 7 for the remaining rand_b tail
        const randBytes = new Uint8Array(8);
        if (hasCrypto) {
            crypto.getRandomValues(randBytes);
        } else {
            for (let i = 0; i < randBytes.length; i++) {
                randBytes[i] = Math.floor(Math.random() * 256);
            }
        }

        // Variant bits come from an independent random byte, never from the counter
        const variantByte = (randBytes[0] & 0x3f) | 0x80;
        const variantHex = variantByte.toString(16).padStart(2, "0");
        const tailHex = Array.from(randBytes.slice(1), b => b.toString(16).padStart(2, "0")).join("");

        const versionNibble = "7";
        const clean = timeHex + versionNibble + counterHex + variantHex + tailHex;

        return { reliability, monotonicTriggered, uuid: new nUUID(clean) };
    }

    // =====================================================
    // STATIC INPUT VALIDATION & PARSING HELPERS
    // =====================================================

    static isValidInput(input) {
        const normalized = nUUID.#normalize(input);
        if (!normalized) return { valid: false, error: "Empty or invalid input" };

        const clean = nUUID.#toClean(normalized);
        if (!clean || !nUUID.#isValid(clean)) return { valid: false, error: "Invalid UUID format" };

        return { valid: true, normalized, clean };
    }

    static #normalize(input) {
        if (!input || typeof input !== "string") return null;
        return input.trim().replace(/[{}]/g, "").toLowerCase();
    }

    static #toClean(normalized) {
        if (!normalized) return null;
        return normalized.replace(/-/g, "");
    }

    static #isValid(clean) {
        return /^[0-9a-f]{32}$/.test(clean);
    }

    static #addMessage(messages, code, titleData = null, data = null) {
        messages.push(new Message({ code: code, data: data, titleData: titleData, catalog: Catalog }));
    }

    // 🎯 ΕΝΟΠΟΙΗΣΗ: Η #warn πλέον κατασκευάζει κανονικό Message instance μέσω του Catalog
    static #warn(code, titleData = null, data = null) {
        return new Message({ code: code, data: data, titleData: titleData, catalog: Catalog });
    }

    static #formatRelativeTime(ts) {
        if (!Number.isFinite(ts)) return "invalid time";
        const diff = Date.now() - ts;

        if (diff < 0) {
            const sec = Math.floor(Math.abs(diff) / 1000);
            if (sec < 60) return "in a few seconds";
            return "in the future";
        }

        const sec = Math.floor(diff / 1000);
        const min = Math.floor(sec / 60);
        const hr = Math.floor(min / 60);
        const day = Math.floor(hr / 24);

        if (sec < 10) return "just now";
        if (sec < 60) return `${sec} seconds ago`;
        if (min < 60) return `${min} minutes ago`;
        if (hr < 24) return `${hr} hours ago`;
        return `${day} days ago`;
    }

    static #getV1Warnings(parsed) {
        const warnings = [];
        const now = Date.now();

        if (parsed.timestamp > now + 5 * 60 * 1000) warnings.push(nUUID.#warn(Codes.UUID_TIMESTAMP_FUTURE));
        if (parsed.timestamp < 946684800000) warnings.push(nUUID.#warn(Codes.UUID_TIMESTAMP_ANCIENT));
        if (/^0+$/.test(parsed.node)) warnings.push(nUUID.#warn(Codes.UUID_V1_ZERO_NODE));

        return warnings;
    }

    static #getV4Warnings(clean) {
        return nUUID.#getEntropyWarnings(clean);
    }

    static #getV7Warnings(clean) {
        const warnings = [];
        const timestamp = parseInt(clean.slice(0, 12), 16);
        const now = Date.now();

        if (timestamp > now + 5 * 60 * 1000) warnings.push(nUUID.#warn(Codes.UUID_TIMESTAMP_FUTURE));
        if (timestamp < 946684800000) warnings.push(nUUID.#warn(Codes.UUID_TIMESTAMP_ANCIENT));

        warnings.push(...nUUID.#getEntropyWarnings(clean.slice(12)));
        return warnings;
    }

    static #getEntropyWarnings(clean) {
        const warnings = [];
        if (/^([0-9a-f])\1+$/.test(clean)) {
            warnings.push(nUUID.#warn(Codes.UUID_CRITICAL_LOW_ENTROPY));
            return warnings;
        }

        const uniqueChars = new Set(clean).size;
        if (uniqueChars <= 4) warnings.push(nUUID.#warn(Codes.UUID_LOW_CHARACTER_DIVERSITY));
        
        return warnings;
    }
}