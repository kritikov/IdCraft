import MessageCodes from "./MessageCodes.js";
import Severity from "./Severity.js";

export default class MessageCatalog {

    static map = {

        // =========================================================
        // INPUT VALIDATION
        // =========================================================

        [MessageCodes.INPUT_NOT_STRING]: {
            severity: Severity.CRITICAL,
            title: "Invalid input format",
            details: "The value provided for entropy evaluation is not a standard text string. The analytical core requires a continuous string layout to accurately map character pool density and bit weight.",
            category: "validation"
        },

        [MessageCodes.INPUT_EMPTY]: {
            severity: Severity.CRITICAL,
            title: "Empty sequence",
            details: "The evaluation target contains absolutely zero characters. Cryptographic information entropy calculations require at least one token slot to establish mathematical unpredictability.",
            category: "validation"
        },

        [MessageCodes.INPUT_INVALID_COUNT]: {
            severity: Severity.CRITICAL,
            title: "Invalid token count",
            details: "The requested generation batch count is invalid. The execution engine requires a positive non-zero integer to allocate structural loops for token minting.",
            category: "validation"
        },

        // =========================================================
        // CONFIGURATION SETUP / METRICS
        // =========================================================

        [MessageCodes.POOL_AUTO_DETECTED]: {
            severity: Severity.INFO,
            title: "Dynamic pool detection active",
            details: "The analyzer is actively scanning the input text to measure unique character diversity. The character pool size (R) is computed dynamically based on the active detection of lowercase, uppercase, digits, and printable symbols.",
            category: "configuration"
        },

        [MessageCodes.POOL_OVERRIDE_ACTIVE]: {
            severity: Severity.INFO,
            title: "Character pool override enforced",
            details: "A fixed structural character boundaries limit has been hard-coded by the user options. The engine skips regex diversity tracking and evaluates the string under specific architectural rules (e.g., standard Hexadecimal or Base64 spaces).",
            category: "configuration"
        },

        [MessageCodes.EXHAUSTIVE_MODE_ACTIVE]: {
            severity: Severity.INFO,
            title: "Pure brute-force strategy",
            details: "The analysis assumes the string is a pure machine-generated random entity. Permutations are treated with equal mathematical probability, making this mode ideal for analyzing API keys, salts, tokens, and cryptographic seeds.",
            category: "strategy"
        },

        [MessageCodes.SMART_MODE_ACTIVE]: {
            severity: Severity.INFO,
            title: "Smart password strategy active",
            details: "The analyzer has enabled password heuristics logic to account for human predictability. The final entropy metrics will include algorithmic penalties if common dictionary patterns, sequences, or character repetitions are discovered.",
            category: "strategy"
        },

        // =========================================================
        // HEURISTIC PATTERNS (SMART MODE PENALTIES)
        // =========================================================

        [MessageCodes.PATTERN_REPETITIVE_CHARS]: {
            severity: Severity.WARNING,
            title: "Low-variance sequence detected",
            details: "The target string contains continuous blocks of identical repeating characters (e.g., 'aaaa'). While simple math counts these slots linearly, smart dictionary attacks bypass them instantly, reducing the real cryptographic strength.",
            category: "heuristics"
        },

        [MessageCodes.PATTERN_SEQUENTIAL_FOUND]: {
            severity: Severity.WARNING,
            title: "Predictable pattern penalty applied",
            details: "A standard numerical, alphabetical, or common keyboard layout sequence (such as '123456' or 'qwerty') was identified inside the input text. This structural flaw drastically lowers the password's security threshold against rule-based attacks.",
            category: "heuristics"
        },

        // =========================================================
        // RANDOM STRING GENERATOR (nString SPECIFIC)
        // =========================================================

        [MessageCodes.INVALID_STRING_LENGTH]: {
            severity: Severity.CRITICAL,
            title: "Invalid target length constraint",
            details: "The requested generation length parameter falls outside the secure architectural boundaries of the generator engine (must be an integer between 1 and 128 characters).",
            category: "validation"
        },

        [MessageCodes.INSUFFICIENT_CHARSET_POOL]: {
            severity: Severity.CRITICAL,
            title: "Insufficient character pool",
            details: "The configured character generation space contains too few symbols. To avoid generating highly predictable tokens, the resolved character pool must provide a minimum of 4 unique character vectors.",
            category: "configuration"
        },

        [MessageCodes.FILTER_SIMILAR_ACTIVE]: {
            severity: Severity.INFO,
            title: "Similar characters excluded",
            details: "The generation pool has successfully excluded visually look-alike characters (e.g., 'O', '0', 'I', 'l', '1') to maximize readability and eliminate human transcription errors.",
            category: "filter"
        },

        [MessageCodes.FILTER_AMBIGUOUS_ACTIVE]: {
            severity: Severity.INFO,
            title: "Ambiguous characters filtered",
            details: "Special characters prone to syntax breaking or escaping issues (such as quotes, backticks, and backslashes) have been intentionally purged from the available generation pool.",
            category: "filter"
        },

        [MessageCodes.GENERATION_GUARANTEE_FAILED]: {
            severity: Severity.CRITICAL,
            title: "Group guarantee exhaustion",
            details: "The generator exceeded its execution window without satisfying all character group distribution constraints. This typically happens when extreme filter exclusions conflict with a short target length.",
            category: "generation"
        },

        [MessageCodes.GENERATION_SUCCESS]: {
            severity: Severity.SUCCESS,
            title: "Cryptographic token generated",
            details: "A secure, cryptographically strong random string has been successfully minted. The generation pool satisfies all requested structural entropy constraints and character distributions.",
            category: "generation"
        },

        // =========================================================
        // UNIVERSALLY UNIQUE LEXICOGRAPHICALLY SORTABLE ID (nULID SPECIFIC)
        // =========================================================

        [MessageCodes.ULID_MONOTONIC_GUARD_ACTIVE]: {
            severity: Severity.WARNING,
            title: "Monotonicity Guard Active (Strict Order)",
            details: "Multiple tokens were requested within the exact same millisecond frame. The engine successfully engaged the Monotonicity Guard, applying a bitwise monotonic increment to the entropy component to guarantee strict chronological sortability across the batch.",
            category: "generation"
        },

        [MessageCodes.ULID_STANDARD_GENERATION_ACTIVE]: {
            severity: Severity.SUCCESS,
            title: "Standard Sortable Minting Active",
            details: "The generation clock advanced cleanly across distinct millisecond frames. Each minted identifier received a completely fresh cryptographic entropy vector alongside its timestamp payload.",
            category: "generation"
        },

        [MessageCodes.CSPRNG_CONTEXT_SECURE]: {
            severity: Severity.SUCCESS,
            title: "Cryptographically Secure (Web Crypto API)",
            details: "The runtime engine successfully fetched entropy from the client's native Web Crypto API (crypto.getRandomValues). High-chaos cryptographic hardware noise verified, ensuring maximum generation security.",
            category: "security"
        },

        [MessageCodes.CRYPTO_FALLBACK_WARNING]: {
            severity: Severity.WARNING,
            title: "Insecure Pseudo-Random Fallback Active",
            details: "The browser context lacks a native Web Crypto API block. The execution engine was forced to seed entropy fields utilizing pseudo-random routines (Math.random). This state is not cryptographically secure and is not recommended for critical production environments.",
            category: "security"
        },

        // =========================================================
        // FINAL EVALUATION STATUS
        // =========================================================

        [MessageCodes.STATUS_CRITICAL]: {
            severity: Severity.CRITICAL,
            title: "Critical safety risk",
            details: "The computed information entropy falls below 40 bits. Sequences in this bracket offer zero defense against automated brute-force scripts and standard consumer hardware clusters, making them highly vulnerable.",
            category: "status"
        },

        [MessageCodes.STATUS_WEAK]: {
            severity: Severity.LOW,
            title: "Moderate vulnerability signature",
            details: "The entropy sits in the 40-59 bits range. While acceptable for quick, transient sessions or short-lived online rate-limited endpoints, it lacks the cryptographic depth needed to resist modern offline GPU dictionary decryption rigs.",
            category: "status"
        },

        [MessageCodes.STATUS_STRONG]: {
            severity: Severity.SUCCESS,
            title: "Strong security posture",
            details: "The string achieves an entropy score between 60 and 79 bits. This layout provides an excellent baseline defensive framework for high-security user credentials, standard API keys, and enterprise identity management systems.",
            category: "status"
        },

        [MessageCodes.STATUS_BULLETPROOF]: {
            severity: Severity.SUCCESS,
            title: "Cryptographically bulletproof",
            details: "The entropy score exceeds the 80 bits safety threshold. This string possesses an exceptional amount of mathematical unpredictability, making it practically immune to modern or foreseeable future distributed brute-force computational attacks.",
            category: "status"
        },

        // =========================================================
        // UUID DEEP INSPECTION ANALYSIS (nUUID SPECIFIC)
        // =========================================================

        [MessageCodes.UUID_TIMESTAMP_FUTURE]: {
            severity: Severity.CRITICAL,
            title: "Timestamp is in the future (possibly manipulated UUID) ",
            details: "The embedded binary timestamp points to a chronological execution execution frame ahead of the current runtime clock. This signature indicates significant system clock drift or intentional structural spoofing during the ID generation process.",
            category: "inspection"
        },

        [MessageCodes.UUID_TIMESTAMP_ANCIENT]: {
            severity: Severity.WARNING,
            title: "Timestamp is unusually old",
            details: "The identifier contains an unusually obsolete timestamp mapping to an era prior to the year 2000. While syntactically legal, utilizing ancient anchors reduces operational relevance and may flag index sorting degradation.",
            category: "inspection"
        },

        [MessageCodes.UUID_V1_ZERO_NODE]: {
            severity: Severity.WARNING,
            title: "Nullified hardware node field",
            details: "The 48-bit spatial node field consists entirely of hexadecimal zeros. In v1 architectures, this breaks physical device traceability, meaning the identifier was minted using a privacy mask or an anonymous software fallback layer.",
            category: "inspection"
        },

        [MessageCodes.UUID_VERSION_UNSUPPORTED]: {
            severity: Severity.WARNING,
            title: "Non-standard version signature",
            details: "The layout exhibits an unmapped or experimental version bit configuration. The inspector will proceed with baseline structural parsing, but advanced metadata reconstruction arrays are disabled for this sub-type.",
            category: "inspection"
        },

        [MessageCodes.UUID_CRITICAL_LOW_ENTROPY]: {
            severity: Severity.CRITICAL,
            title: "Catastrophic entropy collapse",
            details: "The pseudorandom or clock payload displays zero variance, with identical characters repeating continuously across byte blocks. This exposes the ID to immediate structural collisions and predictability exploits.",
            category: "inspection"
        },

        [MessageCodes.UUID_LOW_CHARACTER_DIVERSITY]: {
            severity: Severity.WARNING,
            title: "Deficient character distribution",
            details: "The binary payload registers a tight clustering of unique characters, falling below normal randomized token expectations. This mathematical signature implies a weak entropy source or faulty generation state mechanics.",
            category: "inspection"
        }
    };
}