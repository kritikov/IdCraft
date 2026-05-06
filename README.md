# 🛠️ IdCraft.js

**IdCraft.js** is a professional-grade JavaScript toolkit designed for crafting and inspecting cryptographically strong identifiers. It provides a unified interface for **NanoID** and **UUID (v1, v4, v7)**, with built-in metadata analysis.

[![License: GPL v3](https://img.shields.io/badge/License-GPLv3-blue.svg)](https://www.gnu.org/licenses/gpl-3.0)
![Size: Tiny](https://img.shields.io/badge/Size-Tiny-blue)
![Security: CSPRNG](https://img.shields.io/badge/Security-CSPRNG-green)

---

## ✨ Key Features

* **NanoID Generation**: Customizable, URL-friendly IDs with built-in protection against modulo bias.
* **UUID Generation**:
    * **v4**: Secure random identifiers. Uses native `crypto.randomUUID()` when available for maximum performance.
    * **v7**: Modern, time-ordered IDs—optimized for database primary keys and sequential indexing.
* **Deep Inspection (v1, v4, v7)**: Powerful analysis tools to "decode" existing UUIDs. Extract **timestamps**, **ISO dates**, **relative time** (e.g., "5 mins ago"), and even **Node (MAC)** information from v1 strings.
* **Cryptographically Secure**: Leverages the Web Crypto API (`crypto.getRandomValues`) for maximum entropy.
* **Zero Dependencies**: Pure JavaScript. Lightweight, fast, and dependency-free.

---

## 🚀 Installation

You can include IdCraft in your project by importing it:

```javascript
import IdCraft from './IdCraft.js';
```
---

## 📖 Usage Guide

### 1. Generating NanoIDs

Create short, secure, and customizable IDs.

```JavaScript
const result = IdCraft.generateNanoIds({
    length: 12,
    numbers: true,
    uppercase: true,
    prefix: "user_"
});

console.log(result.nanoIds); // ["user_A1b2C3d4E5f6"]
```

### 2. Generating UUIDs

Generate standard v4 (random) or the new v7 (time-ordered) UUIDs.

```JavaScript
// Generate 5 time-ordered UUIDs (v7)
const batch = IdCraft.generateUUIDs({
    version: "v7",
    count: 5,
    withHyphens: true
});

console.log(batch.uuids);
```

### 3. Inspecting UUIDs

One of IdCraft's features is the ability to "deconstruct" a UUID string to see its origin.

```JavaScript
const inspection = IdCraft.inspectUUID("018f4a12-b7e1-7abc-8d2f-4a5b6c7d8e9f");

if (inspection.valid) {
    console.log(inspection.uuid.version);      // 7
    console.log(inspection.uuid.getInformation()); 
    // Output: "This is a UUID v7. It is time-ordered and includes a timestamp. Generated around 2024-05-05T12:00:00.000Z."
    
    console.log(inspection.uuid.v7.relativeTime); // e.g., "just now"
}
```

---

## 🛡️ Security & Performance

### Native Speed

For UUID v4, IdCraft automatically detects if the environment supports the native crypto.randomUUID() method.
If available, it uses the browser/runtime's optimized implementation. If not, it falls back to a secure crypto.getRandomValues()
buffer implementation.

### Modulo Bias Protection

Most simple ID generators use Math.random() % charset.length, which creates a subtle
statistical bias. IdCraft eliminates this by calculating a maxValid threshold, ensuring that
every character in your alphabet has a mathematically equal chance of being selected.

---

## 🛠️ API Reference

### `IdCraft.generateUUIDs(options)`

| Option | Default | Description |
| :--- | :--- | :--- |
| `count` | `1` | Number of IDs to generate |
| `version` | `"v4"` | `"v4"` or `"v7"` |
| `withHyphens` | `false` | Returns `xxxxxxxx-xxxx...` if true |
| `format` | `"lowercase"` | `"lowercase"` or `"uppercase"` |



### `IdCraft.generateNanoIds(options)`

| Option | Default | Description |
| :--- | :--- | :--- |
| `length` | `21` | ID length of the random part |
| `lowercase` | `true` | Include `a-z` |
| `numbers` | `false` | Include `0-9` |
| `extra` | `""` | Add custom characters |

### `IdCraft.inspectUUIDs(uuids)`

| Option | Type | Description |
| :--- | :--- | :--- |
| `uuids` | `string[]` | An array of UUID strings to be inspected |

**Returns:** An array of objects, where each object contains:
* `valid`: (boolean) Whether the specific UUID is valid.
* `uuid`: (UUID Instance) The analyzed UUID object (only if valid).
* `error`: (string) Error message (only if invalid).

### `IdCraft.inspectUUID(uuid)`

| Parameter | Type | Description |
| :--- | :--- | :--- |
| `input` | `string` | The UUID string to analyze (supports hyphens, braces, and mixed case) |

**Returns:** An inspection object containing:
* `valid`: (boolean) True if the input is a valid 32-character hex string.
* `uuid`: (UUID instance) Access to metadata methods like `getInformation()`, `version`, `variant`, and `v7.iso`.
* `error`: (string) Detailed error message if the validation fails.

**Example:**
```javascript
const result = IdCraft.inspectUUID("{018f4a12-b7e1-7abc-8d2f-4a5b6c7d8e9f}");
if (result.valid) {
    console.log(result.uuid.v7.iso); // Returns the creation date
}

---

## 📜 License

This project is licensed under the GNU GPL v3.0 or later - see the LICENSE file for details.
