
export default class UUID {
    static #lastTimestamp = 0;
	static #sequence = 0;
    
    constructor(clean) {

        if (!UUID.#isValid(clean)) {
            throw new Error("UUID constructor expects a valid 32-char hex string");
        }

        this.clean = clean;

        // Route parsing based on the UUID version bit
        this.v1 = this.version === 1 ? this.#parseV1() : null;
        this.v4 = this.version === 4 ? { note: "Random UUID" } : null;
        this.v7 = this.version === 7 ? this.#parseV7() : null;

        this.warnings = this.#getWarnings();
    }


    // ===== PUBLIC =====

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
     * Returns the UUID in the standard 8-4-4-4-12 format.
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
    get version (){
        return parseInt(this.clean[12], 16);
    }

    /**
     * Extracts the variant from the 17th character to determine the UUID layout type.
     */
    get variant (){
        const nibble = parseInt(this.clean[16], 16);

        if ((nibble & 0x8) === 0x0) return "NCS";
        if ((nibble & 0xc) === 0x8) return "RFC4122";
        if ((nibble & 0xe) === 0xc) return "Microsoft";
        return "Future";
    }
    

    // ===== PRIVATE =====

    /**
     * Parses v7 UUID: The first 48 bits are a Unix timestamp in milliseconds.
     */
    #parseV7() {
        const timeHex = this.clean.slice(0, 12);
        const timestamp = parseInt(timeHex, 16);

        return {
            timestamp,
            iso: new Date(timestamp).toISOString(),
            relativeTime: UUID.#formatRelativeTime(timestamp)
        };
    }

    /**
     * Parses v1 UUID: A complex layout based on 100-nanosecond intervals 
     * since the Gregorian calendar began (Oct 15, 1582).
     */
    #parseV1() {
        const timeLow = this.clean.slice(0, 8);
        const timeMid = this.clean.slice(8, 12);
        const timeHi = this.clean.slice(12, 16);

        // Remove the 4-bit version prefix from the timeHi part
        const timeHiClean = (parseInt(timeHi, 16) & 0x0fff).toString(16).padStart(3, "0");

        // Reconstruct the timestamp from low, mid, and high segments
        const timestampHex = timeHiClean + timeMid + timeLow;
        const timestamp100ns = BigInt("0x" + timestampHex);

        // Convert 100ns intervals to milliseconds
        const timestampMs = timestamp100ns / 10000n;

        // Offset between UUID Epoch (1582) and Unix Epoch (1970)
        const UUID_EPOCH_OFFSET = 12219292800000n;

        const unixMs = timestampMs - UUID_EPOCH_OFFSET;
        const unixMsNumber = Number(unixMs);    // The last 12 hex chars (usually a MAC address)

        return {
            timestamp: unixMsNumber,
            iso: new Date(unixMsNumber).toISOString(),
            relativeTime: UUID.#formatRelativeTime(unixMsNumber),
            node: this.clean.slice(20)
        };
    }

    #getWarnings() {
        const warnings = [];

        // 🔴 unsupported version
        if (![1, 4, 7].includes(this.version)) {
            warnings.push(
                UUID.#warn(
                    "MEDIUM",
                    `Version v${this.version} is not explicitly supported (limited analysis available)`,
                )
            );
        }

        // 🔍 vversion-specific heuristics
        switch (this.version) {
            case 1:
                warnings.push(...UUID.#getV1Warnings(this.v1));
                break;
            case 4:
                warnings.push(...UUID.#getV4Warnings(this.clean));
                break;
            case 7:
                warnings.push(...UUID.#getV7Warnings(this.clean));
                break;
        }

        return warnings;
    }


    // ===== STATIC =====

    /**
     * Main entry point for generating batches of UUIDs.
     */
    static generateMany(options = {}) {
		const {
			count = 1,
			format = "lowercase",   // lowercase | uppercase
			withHyphens = false,
			braces = "none",        // none, curly
			version = "v4"          // v4, v7
		} = options;

		const uuids = [];

		let source = "";
		let reliability = "";
		for (let i = 0; i < count; i++) {
			let results;

			if (version === "v4"){
				results = UUID.generateUUIDv4();
			}
			else if (version === "v7"){
				results = UUID.generateUUIDv7();
			}
            else {
                throw new Error(`Unsupported UUID version: ${version}`);
            }

            let uuid = withHyphens
                ? results.uuid.canonical
                : results.uuid.clean;

            uuid = format === "uppercase"
                ? uuid.toUpperCase()
                : uuid.toLowerCase();

			if (braces === "curly") {
				uuid = `{${uuid}}`;
			}

			uuids.push(uuid);
			source = results.source;
			reliability = results.reliability;
		}

		return {
			uuids,
			source: source,
			reliability: reliability
		};
	}

    /**
     * Generates a random-based UUID (v4).
     */
    static generateUUIDv4(){
		const hasCrypto = typeof crypto !== "undefined";
		let source = "";
		let reliability = "";
		let clean = "";

		if (hasCrypto && crypto.randomUUID) {
			source = "native";
			reliability = "native";
			clean = crypto.randomUUID().replace(/-/g, "");
		}
		else if (hasCrypto && crypto.getRandomValues) {
			source = "crypto";
			reliability = "secure";

			const bytes = crypto.getRandomValues(new Uint8Array(16));

			/// Set version to 4 (0100 binary)
		    bytes[6] = (bytes[6] & 0x0f) | 0x40;

		    // Set variant to RFC4122 (10xx binary)
		    bytes[8] = (bytes[8] & 0x3f) | 0x80;

			clean = Array.from(
                bytes,
                b => b.toString(16).padStart(2, "0")
            ).join("");
		}
		else{
            // Fallback for environments without the Web Crypto API
			source = "fallback";
			reliability = "weak";
			clean = "xxxxxxxxxxxx4xxxyxxxxxxxxxxxxxxx".replace(/[xy]/g, c => {
                const r = Math.random() * 16 | 0;
                const v = c === "x"
                    ? r
                    : (r & 0x3 | 0x8);

                return v.toString(16);
            });
		}

        const uuid = new UUID(clean);

		return {
			source: source,
			reliability: reliability,
			uuid: uuid
		};
	}

    /**
     * Generates a time-ordered UUID (v7).
     * Good for database keys due to sequential sorting.
     */
	static generateUUIDv7(){
		const hasCrypto = typeof crypto !== "undefined";
		const source = hasCrypto ? "crypto" : "fallback";
		const reliability = hasCrypto ? "secure" : "weak";

		const now = Date.now();

        // Monotonicity: if generated in the same millisecond, increment sequence to avoid collisions.
		if (now === UUID.#lastTimestamp) {
			UUID.#sequence = (UUID.#sequence + 1) & 0xffff;
		} else {
			UUID.#lastTimestamp = now;
			UUID.#sequence = 0;
		}

        // 48-bit Unix timestamp in milliseconds
		const timeHex = BigInt(now).toString(16).padStart(12, "0");
		const bytes = new Uint8Array(10);

		if (hasCrypto) {
			crypto.getRandomValues(bytes);
		} else {
			for (let i = 0; i < 10; i++) {
				bytes[i] = Math.floor(Math.random() * 256);
			}
		}

        // Inject the sequence into the first 2 bytes of the random part
		bytes[0] = (UUID.#sequence >> 8) & 0xff;
		bytes[1] = UUID.#sequence & 0xff;

		const rand = Array.from(bytes, b => b.toString(16).padStart(2, "0")).join("");

        // version 7
        const versionNibble = "7";

        // variant RFC4122
        const variantNibble = ((parseInt(rand[3], 16) & 0x3) | 0x8).toString(16);

        const clean =
            timeHex +
            versionNibble +
            rand.slice(0, 3) +
            variantNibble +
            rand.slice(4, 19);

        const uuid = new UUID(clean);

        return {
            source,
            reliability,
            uuid
        };
	}

    // validate the input string and return an object with validity status, normalized form, and clean hex if valid, 
    // or error message if invalid. This method is crucial to ensure that only properly formatted UUIDs are processed 
    // by the constructor.
    static isValidInput(input) {
        const normalized = UUID.#normalize(input);

        if (!normalized) {
            return {
                valid: false,
                error: "Empty or invalid input"
            };
        }

        const clean = UUID.#toClean(normalized);

        if (!clean) {
            return {
                valid: false,
                error: "Failed to parse UUID"
            };
        }

        if (!UUID.#isValid(clean)) {
            return {
                valid: false,
                error: "Invalid UUID format"
            };
        }

        return {
            valid: true,
            normalized,
            clean
        };
    }

    /**  Converts any user input UUID into a normalized string:
    * removes braces, trims whitespace, and forces lowercase.
    */
    static #normalize(input) {
        if (!input || typeof input !== "string") return null;

        return input
            .trim()
            .replace(/[{}]/g, "")
            .toLowerCase();
    }

    /** Removes hyphens from a normalized UUID to get a raw 32-char hex string. */
    static #toClean(normalized) {
        if (!normalized) return null;
        return normalized.replace(/-/g, "");
    }

    /** Validates that the string is a proper 32-character hexadecimal UUID body. */
    static #isValid(clean) {
        return /^[0-9a-f]{32}$/.test(clean);
    }

    /** Formats a timestamp into a human-readable relative time string (e.g., "5 minutes ago").*/
    static #formatRelativeTime(ts) {
        if (!Number.isFinite(ts)) return "invalid time";

        const now = Date.now();
        const diff = now - ts;

        // 🚨 future
        if (diff < 0) {
            const futureDiff = Math.abs(diff);

            const sec = Math.floor(futureDiff / 1000);
            const min = Math.floor(sec / 60);
            const hr = Math.floor(min / 60);
            const day = Math.floor(hr / 24);

            if (sec < 60) return "in a few seconds";
            if (min < 60) return `in ${min} minutes`;
            if (hr < 24) return `in ${hr} hours`;
            if (day < 365) return `in ${day} days`;

            return "far in the future";
        }

        const sec = Math.floor(diff / 1000);
        const min = Math.floor(sec / 60);
        const hr = Math.floor(min / 60);
        const day = Math.floor(hr / 24);
        const year = Math.floor(day / 365);

        // 🚨 υπερβολικά παλιά
        if (year > 50) return "a long time ago";

        if (sec < 10) return "just now";
        if (sec < 60) return `${sec} seconds ago`;
        if (min < 60) return `${min} minutes ago`;
        if (hr < 24) return `${hr} hours ago`;
        if (day < 365) return `${day} days ago`;

        return `${year} years ago`;
    }

    /** A helper method to create structured warning objects with type, severity, message, and weight 
    * for scoring purposes.
    */
    static #warn(severity, message) {
        return { severity, message };
    }

    /** Checks v1 UUIDs for signs of potential issues, such as a node field that is all zeros 
    * (which may indicate a fake MAC address) or a locally administered MAC address. It returns a list 
    *  of warnings that can help identify UUIDs that may not be trustworthy.
    */
    static #getV1Warnings(parsed) {
        const warnings = [];

        const now = Date.now();

        // 🚨 future timestamp
        if (parsed.timestamp > now + 5 * 60 * 1000) {
            warnings.push(UUID.#warn("HIGH", "Timestamp is in the future (possibly manipulated UUID)"));
        }

        // 🚨 too old (π.χ. πριν το 2000)
        if (parsed.timestamp < 946684800000) {
            warnings.push(UUID.#warn("MEDIUM", "Timestamp is unusually old (before year 2000)"));
        }

        // 🚨 invalid timestamp
        if (parsed.timestamp <= 0 || !Number.isFinite(parsed.timestamp)) {
            warnings.push(UUID.#warn("HIGH", "Invalid timestamp (corrupted UUID v1)"));
        }

        // ===== NODE =====
        const node = parsed.node;

        // 🚨 πιθανό fake MAC
        if (/^0+$/.test(node)) {
            warnings.push(UUID.#warn("HIGH", "Node (MAC) is all zeros (possibly invalid)"));
        }

        // 🚨 locally administered MAC
        const firstByte = parseInt(node.slice(0, 2), 16);
        if ((firstByte & 0x02) === 0x02) {
            warnings.push(UUID.#warn("MEDIUM", "Node uses locally administered MAC address"));
        }

        // weak pattern repetition (light heuristic)
        if (/^([0-9a-f]{2})\1+$/.test(node)) {
            warnings.push(UUID.#warn("LOW", "Node shows repetitive pattern (possibly synthetic)"));
        }

        return warnings;
    }

    /** For v4 UUIDs, we can check for very low entropy patterns, such as all characters being the same,
    * which may indicate a non-random UUID. This method returns warnings if such patterns are detected.
    */
    static #getV4Warnings(clean) {
        const warnings = [];

        return UUID.#getEntropyWarnings(clean);
    }

    /** Analyzes a v7 UUID for potential anomalies, such as future timestamps or low entropy in the random part, 
    * and returns a list of warnings. This can help identify UUIDs that may have been manipulated or generated 
    * with weak randomness.
    */
    static #getV7Warnings(clean) {
        const warnings = [];

        const timeHex = clean.slice(0, 12);
        const timestamp = parseInt(timeHex, 16);
        const now = Date.now();

        // 🚨 future timestamp
        if (timestamp > now + 5 * 60 * 1000) {
            warnings.push(UUID.#warn("HIGH", "Timestamp is in the future (possibly manipulated UUID)"));
        }

        // 🚨 too old (π.χ. πριν το 2000)
        if (timestamp < 946684800000) {
            warnings.push(UUID.#warn("MEDIUM", "Timestamp is unusually old (before year 2000)"));
        }

        // 🚨 unrealistic far past (negative or broken parse)
        if (timestamp <= 0) {
            warnings.push(UUID.#warn("HIGH", "Invalid timestamp (<= 0)"));
        }

        warnings.push(...UUID.#getEntropyWarnings(clean.slice(12)));

        return warnings;
    }

    /** A helper method to analyze the entropy of a UUID string by checking for patterns that indicate low randomness, 
    * such as all characters being the same, low character diversity, or repeated blocks. It returns a list of 
    * warnings if any suspicious patterns are detected.
    */
    static #getEntropyWarnings(clean) {
        const warnings = [];

        // 1. all same
        if (/^([0-9a-f])\1+$/.test(clean)) {
            warnings.push(UUID.#warn("HIGH", "Extremely low entropy (all characters identical)"));
            return warnings;
        }

        // 2. character diversity
        const uniqueChars = new Set(clean).size;

        if (uniqueChars <= 4) {
            warnings.push(UUID.#warn("MEDIUM", "Very low character diversity (suspicious entropy)"));
        } else if (uniqueChars <= 6) {
            warnings.push(UUID.#warn("LOW", "Low character diversity"));
        }

        // 3. repeated blocks (4-char chunks)
        const chunks = clean.match(/.{4}/g) || [];
        const uniqueChunks = new Set(chunks).size;

        if (uniqueChunks <= 3) {
            warnings.push(UUID.#warn("MEDIUM", "Repeated pattern detected in UUID structure"));
        }

        return warnings;
    }
}
