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

You can include IdCraft.js in your project by importing it:

```javascript
import IdCraft from './IdCraft.js';
```
---

## 📖 Usage Guide

### 1. Generating NanoIDs

Create short, secure, and customizable IDs.

```JavaScript
const result = IdCraft.generateNanoIds({
   count: 10,
   length: 12,
   lowercase: true,
   uppercase: true,
   numbers: true,
   symbols: true,
   extra: "",
   prefix: "user_",
   suffix: ""
});

console.log(result.nanoIds); // ["user_A1b2C3d4E5f6"]
```

### 2. Generating UUIDs

Generate standard v4 (random) or the new v7 (time-ordered) UUIDs.

```JavaScript
// Generate 5 time-ordered UUIDs (v7)
const batch = IdCraft.generateUUIDs({
   count: 5,
   version: "v7",         // v4, v7
   format: "lowercase",   // lowercase | uppercase
   withHyphens: true,
   braces: "none",       // none, curly
});

console.log(batch.uuids);
```

### 3. Inspecting UUIDs

One of IdCraft's features is the ability to "deconstruct" a UUID string to see its origin.

```JavaScript
// Example: Inspecting multiple IDs at once
const items = [
    "018f4a12-b7e1-7abc-8d2f-4a5b6c7d8e9f", // valid v7
    "48507851-419b-4654-9337-1836f32e9206", // valid v4
    "invalid-id-123"                         // invalid
];

const results = IdCraft.inspectUUIDs(items);

results.forEach((inspection, index) => {
    if (inspection.valid) {
        console.log(`Item ${index} is a valid v${inspection.uuid.version}`);
        console.log(inspection.uuid.getInformation());
        
        // Access relative time if it's a time-based UUID (v1 or v7)
        const timeInfo = inspection.uuid.v7?.relativeTime || inspection.uuid.v1?.relativeTime;
        if (timeInfo) console.log(`Generated: ${timeInfo}`);
    } else {
        console.error(`Item ${index} error: ${inspection.error}`);
    }
});
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

## 🛡️ View online
You can view the usage of library online at:

https://nkode.gr/GR/tools/uuid-generator
<img width="645" height="761" alt="image" src="https://github.com/user-attachments/assets/b30938cd-9a32-4c20-9d41-df9d4c5a6db9" />

---

https://nkode.gr/EN/tools/uuid-inspector
<img width="636" height="811" alt="image" src="https://github.com/user-attachments/assets/7b2c6837-2bcb-4324-8404-701de7708d17" />

---

https://nkode.gr/EN/tools/nano-id-generator
<img width="644" height="809" alt="image" src="https://github.com/user-attachments/assets/49562692-b77a-4b50-b031-15a94aea204d" />

---

## 📜 License

This project is licensed under the GNU GPL v3.0 or later - see the LICENSE file for details.
