export default class MessageCodes {

    // =========================================================
    // INPUT VALIDATION
    // =========================================================
    static INPUT_NOT_STRING = "INPUT_NOT_STRING";
    static INPUT_EMPTY = "INPUT_EMPTY";
    static INPUT_INVALID_COUNT = "INPUT_INVALID_COUNT"; 
    
    // =========================================================
    // CONFIGURATION SETUP / METRICS
    // =========================================================
    static POOL_AUTO_DETECTED = "POOL_AUTO_DETECTED";
    static POOL_OVERRIDE_ACTIVE = "POOL_OVERRIDE_ACTIVE";
    static EXHAUSTIVE_MODE_ACTIVE = "EXHAUSTIVE_MODE_ACTIVE";
    static SMART_MODE_ACTIVE = "SMART_MODE_ACTIVE";

    // =========================================================
    // HEURISTIC PATTERNS (SMART MODE PENALTIES)
    // =========================================================
    static PATTERN_REPETITIVE_CHARS = "PATTERN_REPETITIVE_CHARS";
    static PATTERN_SEQUENTIAL_FOUND = "PATTERN_SEQUENTIAL_FOUND";

    // =========================================================
    // RANDOM STRING GENERATOR (nString SPECIFIC)
    // =========================================================
    static INVALID_STRING_LENGTH = "INVALID_STRING_LENGTH";
    static INSUFFICIENT_CHARSET_POOL = "INSUFFICIENT_CHARSET_POOL";
    static FILTER_SIMILAR_ACTIVE = "FILTER_SIMILAR_ACTIVE";
    static FILTER_AMBIGUOUS_ACTIVE = "FILTER_AMBIGUOUS_ACTIVE";
    static GENERATION_GUARANTEE_FAILED = "GENERATION_GUARANTEE_FAILED";
    static GENERATION_SUCCESS = "GENERATION_SUCCESS";

    // =========================================================
    // UNIVERSALLY UNIQUE LEXICOGRAPHICALLY SORTABLE ID (nULID SPECIFIC)
    // =========================================================
    static ULID_MONOTONIC_GUARD_ACTIVE = "ULID_MONOTONIC_GUARD_ACTIVE"; 
    static ULID_STANDARD_GENERATION_ACTIVE = "ULID_STANDARD_GENERATION_ACTIVE"; 
    static CSPRNG_CONTEXT_SECURE = "CSPRNG_CONTEXT_SECURE"; 
    static CRYPTO_FALLBACK_WARNING = "CRYPTO_FALLBACK_WARNING"; 

    // =========================================================
    // FINAL EVALUATION STATUS
    // =========================================================
    static STATUS_CRITICAL = "STATUS_CRITICAL";
    static STATUS_WEAK = "STATUS_WEAK";
    static STATUS_STRONG = "STATUS_STRONG";
    static STATUS_BULLETPROOF = "STATUS_BULLETPROOF";

    // =========================================================
    // UUID DEEP INSPECTION ANALYSIS (nUUID SPECIFIC)
    // =========================================================
    static UUID_TIMESTAMP_FUTURE = "UUID_TIMESTAMP_FUTURE";
    static UUID_TIMESTAMP_ANCIENT = "UUID_TIMESTAMP_ANCIENT";
    static UUID_V1_ZERO_NODE = "UUID_V1_ZERO_NODE";
    static UUID_VERSION_UNSUPPORTED = "UUID_VERSION_UNSUPPORTED";
    static UUID_CRITICAL_LOW_ENTROPY = "UUID_CRITICAL_LOW_ENTROPY";
    static UUID_LOW_CHARACTER_DIVERSITY = "UUID_LOW_CHARACTER_DIVERSITY";
    
}