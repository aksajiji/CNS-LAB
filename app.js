
const ABC = "ABCDEFGHIJKLMNOPQRSTUVWXYZ";
const HISTORY_STORAGE_KEY = "crypto-playground-history-v3";

let els = {};
let activeMode = null;
let historyItems = [];

const ALGORITHM_OPTIONS = [
  {
    group: "Classical Substitution Ciphers",
    items: [
      ["caesar", "Caesar Cipher / Shift Cipher"],
      ["mono", "Monoalphabetic Cipher"],
      ["affine", "Affine Cipher"],
      ["playfair", "Playfair Cipher"],
      ["vigenere", "Vigenère Cipher"],
      ["hill", "Hill Cipher"]
    ]
  },
  {
    group: "Transposition Ciphers",
    items: [
      ["railfence", "Rail Fence Cipher"],
      ["columnar", "Columnar Transposition Cipher"]
    ]
  },
  {
    group: "Modern Symmetric Encryption",
    items: [
      ["des", "DES"],
      ["tripledes", "3DES"],
      ["aes", "AES"],
      ["rc4", "RC4"]
    ]
  },
  {
    group: "Public Key Cryptography",
    items: [
      ["rsa", "RSA"]
    ]
  }
];



const FIELD_CONFIG = {
  caesar: {
    placeholder: "Enter text for Caesar encryption/decryption...",
    fields: [
      { id: "shift", label: "Shift Value", type: "number", default: 3, min: 0, max: 25 }
    ]
  },
  mono: {
    placeholder: "Enter plaintext or ciphertext for monoalphabetic substitution...",
    fields: [
      {
        id: "alphabet",
        label: "Substitution Alphabet",
        type: "text",
        default: "QWERTYUIOPASDFGHJKLZXCVBNM",
        hint: "Provide 26 unique letters mapping A-Z to cipher letters.",
        full: true
      }
    ]
  },
  affine: {
    placeholder: "Enter text for Affine cipher...",
    fields: [
      { id: "a", label: "Value a", type: "number", default: 5 },
      { id: "b", label: "Value b", type: "number", default: 8 }
    ]
  },
  playfair: {
    placeholder: "Enter text for Playfair cipher...",
    fields: [
      {
        id: "keyword",
        label: "Keyword",
        type: "text",
        default: "MONARCHY",
        hint: "I/J are merged in the 5x5 matrix."
      }
    ]
  },
  vigenere: {
    placeholder: "Enter text for Vigenère cipher...",
    fields: [
      { id: "keyword", label: "Keyword", type: "text", default: "KEY" }
    ]
  },
  hill: {
    placeholder: "Enter text for Hill cipher. Only A-Z are processed.",
    fields: [
      {
        id: "matrix",
        label: "Key Matrix (2x2 or 3x3)",
        type: "textarea",
        default: "3 3\n2 5",
        hint: "Example 2x2:\n3 3\n2 5\n\nExample 3x3:\n6 24 1\n13 16 10\n20 17 15",
        full: true
      }
    ]
  },
  railfence: {
    placeholder: "Enter text for Rail Fence cipher...",
    fields: [
      { id: "rails", label: "Number of Rails", type: "number", default: 3, min: 2 }
    ]
  },
  columnar: {
    placeholder: "Enter text for Columnar Transposition. Only A-Z are used.",
    fields: [
      { id: "keyword", label: "Keyword", type: "text", default: "ZEBRA" },
      {
        id: "padChar",
        label: "Padding Character",
        type: "text",
        default: "X",
        hint: "Used to fill the last row so the grid has no unexplained empty cells."
      }
    ]
  },
  des: modernFields("DESKey12", "12345678"),
  tripledes: modernFields("TripleDESKeyExample123456", "12345678"),
  aes: modernFields("AESDemoSecretKey", "1234567890ABCDEF"),
  rc4: {
    placeholder: "Enter plaintext to encrypt or ciphertext to decrypt with RC4...",
    fields: [
      { id: "secretKey", label: "Secret Key", type: "text", default: "streamkey" },
      ...formatFields()
    ]
  },
  rsa: {
    placeholder: "Encrypt plaintext or decrypt space-separated RSA integers using textbook RSA.",
    fields: [
      { id: "e", label: "Public Key e", type: "text", default: "17", hint: "Used for encryption." },
      { id: "n", label: "Modulus n", type: "text", default: "3233", hint: "Keep n > 255 in this educational demo." },
      { id: "d", label: "Private Key d", type: "text", default: "2753", hint: "Used for decryption." }
    ]
  }
};

function modernFields(key, iv) {
  return {
    placeholder: "Enter data for encryption/decryption...",
    fields: [
      { id: "secretKey", label: "Secret Key", type: "text", default: key },
      {
        id: "mode",
        label: "Mode",
        type: "select",
        default: "ECB",
        options: [
          { value: "ECB", label: "ECB" },
          { value: "CBC", label: "CBC" }
        ]
      },
      { id: "iv", label: "IV", type: "text", default: iv, hint: "Used only in CBC mode." },
      ...formatFields()
    ]
  };
}

function formatFields() {
  return [
    {
      id: "inputFormat",
      label: "Input Format",
      type: "select",
      default: "utf8",
      options: [
        { value: "utf8", label: "UTF-8" },
        { value: "hex", label: "Hex" },
        { value: "base64", label: "Base64" }
      ]
    },
    {
      id: "outputFormat",
      label: "Output Format",
      type: "select",
      default: "base64",
      options: [
        { value: "utf8", label: "UTF-8" },
        { value: "hex", label: "Hex" },
        { value: "base64", label: "Base64" }
      ]
    }
  ];
}

const THEORY = {
  caesar: {
    name: "Caesar Cipher",
    type: "Monoalphabetic Substitution Cipher",
    category: "Classical Cryptography",
    keyType: "Single integer shift k",
    inventor: "Traditionally attributed to Julius Caesar",
    year: "c. 1st century BCE",
    explanation:
      "The Caesar cipher is a substitution cipher in which each plaintext letter is shifted by a fixed number of positions in the alphabet. If letters are mapped to numbers 0 through 25, encryption is performed using modular addition. Because the same shift is applied to every letter, the cipher preserves language frequency patterns and is extremely easy to break by brute force. It is historically important but secure only as an educational example.",
    formula:
      "Encryption: E(x) = (x + k) mod 26\nDecryption: D(x) = (x - k) mod 26",
    example: {
      plaintext: "HELLO",
      key: "k = 3",
      ciphertext: "KHOOR"
    },
    securityLevel: "Very Weak",
    keySize: "1 integer shift",
    blockSize: "N/A",
    status: "Educational Use Only"
  },

  mono: {
    name: "Monoalphabetic Cipher",
    type: "Substitution Cipher",
    category: "Classical Cryptography",
    keyType: "Permutation of the alphabet",
    inventor: "Classical method",
    year: "Ancient",
    explanation:
      "A monoalphabetic substitution cipher replaces each plaintext letter with a fixed corresponding ciphertext letter according to a full substitution alphabet. Unlike the Caesar cipher, the mapping is not restricted to a uniform shift and may be any permutation of A–Z. However, because the same plaintext letter always maps to the same ciphertext letter, statistical properties of the language remain visible. As a result, the cipher is vulnerable to frequency analysis and is not considered secure.",
    formula:
      "Encryption: E(x) = π(x), where π is a permutation of A–Z\nDecryption: D(y) = π⁻¹(y)",
    example: {
      plaintext: "HELLO",
      key: "QWERTYUIOPASDFGHJKLZXCVBNM",
      ciphertext: "ITSSG"
    },
    securityLevel: "Very Weak",
    keySize: "26-letter substitution alphabet",
    blockSize: "N/A",
    status: "Breakable by Frequency Analysis"
  },

  affine: {
    name: "Affine Cipher",
    type: "Substitution Cipher",
    category: "Classical Cryptography",
    keyType: "Two integers a and b, with gcd(a, 26) = 1",
    inventor: "Classical mathematical cipher",
    year: "Classical era",
    explanation:
      "The Affine cipher generalizes the Caesar cipher by combining multiplication and addition in modular arithmetic. Each plaintext letter x is mapped to a ciphertext letter using the transformation ax + b mod 26. For decryption to be possible, the multiplicative key a must be coprime with 26 so that a modular inverse exists. Although mathematically richer than Caesar, the Affine cipher is still weak and can be broken with classical cryptanalysis.",
    formula:
      "Encryption: E(x) = (ax + b) mod 26\nDecryption: D(y) = a⁻¹(y - b) mod 26, where a⁻¹ is the modular inverse of a mod 26",
    example: {
      plaintext: "HELLO",
      key: "a = 5, b = 8",
      ciphertext: "RCLLA"
    },
    securityLevel: "Very Weak",
    keySize: "Two integers",
    blockSize: "N/A",
    status: "Educational Use Only"
  },

  playfair: {
    name: "Playfair Cipher",
    type: "Digraph Substitution Cipher",
    category: "Classical Cryptography",
    keyType: "Keyword generating a 5x5 matrix",
    inventor: "Charles Wheatstone; promoted by Lyon Playfair",
    year: "1854",
    explanation:
      "The Playfair cipher encrypts pairs of letters rather than individual letters, making it stronger than simple monoalphabetic substitution. A 5x5 matrix is constructed from a keyword, with I and J usually combined into a single cell. Encryption depends on whether the two letters of a pair lie in the same row, the same column, or form the corners of a rectangle. Although historically significant, the cipher is not secure by modern standards and can be broken with sufficient ciphertext.",
    formula:
      "Encryption:\n• Same row: replace each letter with the letter to its right (wrapping around)\n• Same column: replace each letter with the letter below it (wrapping around)\n• Rectangle: replace each letter with the letter in the same row but the other letter’s column\nDecryption:\n• Same row: replace each letter with the letter to its left\n• Same column: replace each letter with the letter above\n• Rectangle: same rectangle rule as encryption",
    example: {
      plaintext: "HIDE",
      key: "MONARCHY",
      ciphertext: "BFCK"
    },
    securityLevel: "Weak",
    keySize: "Keyword / 5x5 matrix",
    blockSize: "2 characters",
    status: "Historical / Educational"
  },

  vigenere: {
    name: "Vigenère Cipher",
    type: "Polyalphabetic Substitution Cipher",
    category: "Classical Cryptography",
    keyType: "Keyword",
    inventor: "Often associated with Blaise de Vigenère; based on earlier work by Bellaso",
    year: "16th century",
    explanation:
      "The Vigenère cipher applies a sequence of Caesar shifts determined by a repeating keyword. This means that the same plaintext letter may encrypt to different ciphertext letters at different positions, reducing the effectiveness of simple frequency analysis. However, repeated-key patterns still leak structure, and the cipher can be broken with classical techniques such as Kasiski examination and index-of-coincidence analysis. It is important educationally but not secure for real use.",
    formula:
      "Encryption: E(xᵢ) = (xᵢ + kᵢ) mod 26\nDecryption: D(yᵢ) = (yᵢ - kᵢ) mod 26\nwhere kᵢ is the ith keyword letter value repeated cyclically",
    example: {
      plaintext: "HELLO",
      key: "KEY",
      ciphertext: "RIJVS"
    },
    securityLevel: "Weak",
    keySize: "Depends on keyword length",
    blockSize: "N/A",
    status: "Educational Classical Cipher"
  },

  hill: {
    name: "Hill Cipher",
    type: "Polygraphic Substitution Cipher",
    category: "Classical Cryptography",
    keyType: "Invertible matrix modulo 26",
    inventor: "Lester S. Hill",
    year: "1929",
    explanation:
      "The Hill cipher encrypts blocks of letters using matrix multiplication modulo 26. The plaintext is divided into vectors, and each vector is multiplied by a key matrix to produce ciphertext. Decryption requires the inverse of the key matrix modulo 26, so only matrices with invertible determinants modulo 26 are valid. The cipher is valuable pedagogically because it connects cryptography with linear algebra, but it is not secure against known-plaintext attacks.",
    formula:
      "Encryption: C = K·P mod 26\nDecryption: P = K⁻¹·C mod 26\nwhere K is the key matrix and K⁻¹ is its inverse modulo 26",
    example: {
      plaintext: "HELP",
      key: "[[3,3],[2,5]]",
      ciphertext: "HIAT"
    },
    securityLevel: "Weak",
    keySize: "2x2 or 3x3 invertible matrix",
    blockSize: "2 or 3 characters",
    status: "Educational / Mathematical Demonstration"
  },

  railfence: {
    name: "Rail Fence Cipher",
    type: "Transposition Cipher",
    category: "Classical Cryptography",
    keyType: "Number of rails",
    inventor: "Classical method",
    year: "Classical era",
    explanation:
      "The Rail Fence cipher rearranges letters by writing them in a zig-zag pattern across a fixed number of rails and then reading row by row. Because it changes only the positions of letters and not the letters themselves, letter frequencies remain unchanged. Its simplicity makes it useful for teaching the concept of transposition, but it offers very little security. It is therefore best regarded as a historical or classroom cipher.",
    formula:
      "Encryption: write plaintext in a zig-zag across r rails, then read each rail row by row\nDecryption: reconstruct the zig-zag pattern and read characters along the rail path",
    example: {
      plaintext: "HELLO",
      key: "rails = 3",
      ciphertext: "HOELL"
    },
    securityLevel: "Very Weak",
    keySize: "1 integer",
    blockSize: "N/A",
    status: "Educational Use Only"
  },

  columnar: {
    name: "Columnar Transposition Cipher",
    type: "Transposition Cipher",
    category: "Classical Cryptography",
    keyType: "Keyword",
    inventor: "Classical method",
    year: "Classical era",
    explanation:
      "In a columnar transposition cipher, plaintext is written row by row into a grid whose number of columns is determined by a keyword. The columns are then read in the alphabetical order of the keyword letters, producing the ciphertext. Since letters are not substituted, frequency patterns remain intact, but their positions are scrambled. The cipher is historically important but not secure against modern or even classical analytical methods.",
    formula:
      "Encryption: write plaintext row-wise under the keyword, then read columns in sorted keyword order\nDecryption: reconstruct columns in sorted order, then read the grid row-wise",
    example: {
      plaintext: "HELLO",
      key: "ZEBRA, pad = X",
      ciphertext: "OXLEHX"
    },
    securityLevel: "Very Weak",
    keySize: "Keyword length dependent",
    blockSize: "N/A",
    status: "Historical / Educational"
  },

  des: {
    name: "DES",
    type: "Symmetric Block Cipher",
    category: "Modern Cryptography",
    keyType: "Secret key",
    inventor: "IBM; standardized by NIST",
    year: "1977",
    explanation:
      "DES is a symmetric block cipher based on a 16-round Feistel network. It operates on 64-bit blocks and uses a 56-bit effective key, which was once considered practical but is now far too small for modern security requirements. DES played a major role in the history of commercial cryptography, but exhaustive key search has rendered it obsolete. It is included here only for study and historical comparison.",
    formula:
      "Encryption: 16-round Feistel network on 64-bit blocks using a 56-bit effective key\nDecryption: same Feistel structure with subkeys applied in reverse order",
    example: {
      plaintext: "HELLO",
      key: "56-bit secret key",
      ciphertext: "Binary / encoded block output"
    },
    securityLevel: "Weak",
    keySize: "56 bits",
    blockSize: "64 bits",
    status: "Deprecated"
  },

  tripledes: {
    name: "3DES",
    type: "Symmetric Block Cipher",
    category: "Modern Cryptography",
    keyType: "Secret key bundle",
    inventor: "Derived from DES",
    year: "Late 20th century",
    explanation:
      "Triple DES strengthens DES by applying the DES algorithm three times, usually in Encrypt-Decrypt-Encrypt (EDE) form. It significantly improves resistance to brute force compared with single DES, but it is much slower than AES and still uses a 64-bit block size. For these reasons, 3DES is now considered a legacy algorithm and is being phased out of modern systems. It remains useful mainly for compatibility and historical study.",
    formula:
      "Encryption: C = E(K3, D(K2, E(K1, P)))\nDecryption: P = D(K1, E(K2, D(K3, C)))",
    example: {
      plaintext: "HELLO",
      key: "112 / 168-bit key bundle",
      ciphertext: "Binary / encoded block output"
    },
    securityLevel: "Moderate",
    keySize: "112 / 168 bits",
    blockSize: "64 bits",
    status: "Legacy / Being Phased Out"
  },

  aes: {
    name: "AES",
    type: "Symmetric Block Cipher",
    category: "Modern Cryptography",
    keyType: "Secret key",
    inventor: "Joan Daemen and Vincent Rijmen",
    year: "2001",
    explanation:
      "AES is the modern standard for symmetric encryption and is based on the Rijndael design. It operates on 128-bit blocks and supports 128-bit, 192-bit, and 256-bit keys. AES is widely used in secure communication, storage, and network protocols because it is efficient, well studied, and currently considered secure when implemented properly. In practical systems, the choice of block mode, IV handling, padding, and authentication are all important to overall security.",
    formula:
      "Encryption: repeated rounds of SubBytes, ShiftRows, MixColumns, and AddRoundKey\nDecryption: repeated rounds of InvShiftRows, InvSubBytes, InvMixColumns, and AddRoundKey",
    example: {
      plaintext: "HELLO",
      key: "128-bit secret key",
      ciphertext: "Binary / encoded block output"
    },
    securityLevel: "Very Strong",
    keySize: "128 / 192 / 256 bits",
    blockSize: "128 bits",
    status: "Current Standard"
  },

  rc4: {
    name: "RC4",
    type: "Symmetric Stream Cipher",
    category: "Modern Cryptography",
    keyType: "Secret key",
    inventor: "Ron Rivest",
    year: "1987",
    explanation:
      "RC4 is a stream cipher that generates a pseudorandom keystream from a secret key and XORs it with plaintext bytes. It was once extremely popular because it was simple and fast, especially in software. However, statistical biases in the keystream led to practical attacks, and RC4 is now considered insecure for modern use. It should be studied only as a historical algorithm and not used in real systems.",
    formula:
      "Encryption: C = P ⊕ KS\nDecryption: P = C ⊕ KS\nwhere KS is the keystream generated from the secret key",
    example: {
      plaintext: "HELLO",
      key: "streamkey",
      ciphertext: "Encoded stream output"
    },
    securityLevel: "Weak",
    keySize: "Variable",
    blockSize: "N/A",
    status: "Deprecated / Insecure"
  },

  rsa: {
    name: "RSA",
    type: "Asymmetric Cipher",
    category: "Modern Cryptography",
    keyType: "Public key (e, n), private key (d, n)",
    inventor: "Rivest, Shamir, Adleman",
    year: "1977",
    explanation:
      "RSA is a public-key cryptosystem based on modular exponentiation and the computational difficulty of factoring large composite integers. In secure real-world systems, RSA is used with large key sizes and modern padding schemes such as OAEP or PSS. This playground uses a simplified textbook version for educational purposes, typically encrypting one character at a time. As a teaching tool it is valuable, but textbook RSA without padding must never be used for actual security.",
    formula:
      "Encryption: C = M^e mod n\nDecryption: M = C^d mod n",
    example: {
      plaintext: "A",
      key: "e = 17, d = 2753, n = 3233",
      ciphertext: "2790"
    },
    securityLevel: "Strong",
    keySize: "2048+ bits in practice; small demo keys in this playground",
    blockSize: "N/A",
    status: "Widely Used with Proper Padding"
  }
};

const HANDLERS = {
  caesar: {
    encrypt: (text, keys) => caesarTransform(text, Number(keys.shift)),
    decrypt: (text, keys) => caesarTransform(text, -Number(keys.shift))
  },
  mono: {
    encrypt: (text, keys) => monoEncrypt(text, keys.alphabet),
    decrypt: (text, keys) => monoDecrypt(text, keys.alphabet)
  },
  affine: {
    encrypt: (text, keys) => affineTransform(text, Number(keys.a), Number(keys.b), true),
    decrypt: (text, keys) => affineTransform(text, Number(keys.a), Number(keys.b), false)
  },
  playfair: {
    encrypt: (text, keys) => playfairProcess(text, keys.keyword, true),
    decrypt: (text, keys) => playfairProcess(text, keys.keyword, false)
  },
  vigenere: {
    encrypt: (text, keys) => vigenereTransform(text, keys.keyword, true),
    decrypt: (text, keys) => vigenereTransform(text, keys.keyword, false)
  },
  hill: {
    encrypt: (text, keys) => hillProcess(text, keys.matrix, true),
    decrypt: (text, keys) => hillProcess(text, keys.matrix, false)
  },
  railfence: {
    encrypt: (text, keys) => railFenceEncrypt(text, Number(keys.rails)),
    decrypt: (text, keys) => railFenceDecrypt(text, Number(keys.rails))
  },
  columnar: {
    encrypt: (text, keys) => columnarEncrypt(text, keys.keyword, keys.padChar),
    decrypt: (text, keys) => columnarDecrypt(text, keys.keyword, keys.padChar)
  },
  des: {
    encrypt: (text, keys) => modernBlockEncrypt("DES", text, keys),
    decrypt: (text, keys) => modernBlockDecrypt("DES", text, keys)
  },
  tripledes: {
    encrypt: (text, keys) => modernBlockEncrypt("TripleDES", text, keys),
    decrypt: (text, keys) => modernBlockDecrypt("TripleDES", text, keys)
  },
  aes: {
    encrypt: (text, keys) => modernBlockEncrypt("AES", text, keys),
    decrypt: (text, keys) => modernBlockDecrypt("AES", text, keys)
  },
  rc4: {
    encrypt: (text, keys) => rc4Encrypt(text, keys),
    decrypt: (text, keys) => rc4Decrypt(text, keys)
  },
  rsa: {
    encrypt: (text, keys) => rsaEncrypt(text, keys.e, keys.n),
    decrypt: (text, keys) => rsaDecrypt(text, keys.d, keys.n)
  }
};

window.addEventListener("DOMContentLoaded", init);

function init() {
  els = {
    algorithmSelect: document.getElementById("algorithmSelect"),
    algorithmMeta: document.getElementById("algorithmMeta"),
    mainInput: document.getElementById("mainInput"),
    keyFields: document.getElementById("keyFields"),
    encryptBtn: document.getElementById("encryptBtn"),
    decryptBtn: document.getElementById("decryptBtn"),
    clearBtn: document.getElementById("clearBtn"),
    copyBtn: document.getElementById("copyBtn"),
    outputText: document.getElementById("outputText"),
    status: document.getElementById("status"),
    visualization: document.getElementById("visualization"),
    theoryPanel: document.getElementById("theoryPanel"),
    securityPanel: document.getElementById("securityPanel"),
    comparisonInput: document.getElementById("comparisonInput"),
    compareBtn: document.getElementById("compareBtn"),
    comparisonResults: document.getElementById("comparisonResults"),
    historyList: document.getElementById("historyList"),
    clearHistoryBtn: document.getElementById("clearHistoryBtn"),
    themeToggle: document.getElementById("themeToggle"),
    tabButtons: Array.from(document.querySelectorAll(".tab-btn")),
    tabPanels: Array.from(document.querySelectorAll(".tab-panel"))
  };

  buildAlgorithmSelect();
  bindEvents();
  applySavedTheme();
  loadHistory();
  renderKeyFields();
  updateInfoPanels();
  updateLearningTools();
  renderHistory();
}

function bindEvents() {
  els.algorithmSelect.addEventListener("change", () => {
    renderKeyFields();
    updateInfoPanels();
    updateLearningTools();
    autoRefresh();
  });

  els.encryptBtn.addEventListener("click", () => runCipher("encrypt", true));
  els.decryptBtn.addEventListener("click", () => runCipher("decrypt", true));

  els.clearBtn.addEventListener("click", () => {
    els.mainInput.value = "";
    els.outputText.value = "";
    els.visualization.innerHTML = `<p class="muted">Run encryption or decryption to inspect the internal process.</p>`;
    setStatus("", "");
    activeMode = null;
    updateLearningTools();
  });

  els.copyBtn.addEventListener("click", async () => {
    if (!els.outputText.value) return;
    try {
      await navigator.clipboard.writeText(els.outputText.value);
      setStatus("Output copied to clipboard.", "success");
    } catch {
      setStatus("Could not copy output.", "error");
    }
  });

  els.mainInput.addEventListener("input", () => {
    updateLearningTools();
    autoRefresh();
  });

  els.compareBtn.addEventListener("click", runComparison);

  els.comparisonInput.addEventListener("input", () => {
    if (els.comparisonInput.value.trim()) runComparison();
    else els.comparisonResults.innerHTML = "";
  });

  els.clearHistoryBtn.addEventListener("click", clearHistory);

  els.historyList.addEventListener("click", handleHistoryActions);

  els.themeToggle.addEventListener("click", toggleTheme);

  els.tabButtons.forEach(btn => {
    btn.addEventListener("click", () => activateTab(btn.dataset.tab));
  });
}

function activateTab(tabId) {
  els.tabButtons.forEach(btn => btn.classList.toggle("active", btn.dataset.tab === tabId));
  els.tabPanels.forEach(panel => panel.classList.toggle("active", panel.id === `tab-${tabId}`));
}

function buildAlgorithmSelect() {
  els.algorithmSelect.innerHTML = ALGORITHM_OPTIONS.map(group => `
    <optgroup label="${group.group}">
      ${group.items.map(([value, label]) => `<option value="${value}">${label}</option>`).join("")}
    </optgroup>
  `).join("");
}

function renderKeyFields() {
  const selected = els.algorithmSelect.value;
  const config = FIELD_CONFIG[selected];
  els.mainInput.placeholder = config.placeholder;

  let html = config.fields.map(field => {
    const id = `key-${field.id}`;
    const cls = field.full ? "field full" : "field";
    const hint = field.hint ? `<small>${escapeHtml(field.hint)}</small>` : "";

    if (field.type === "textarea") {
      return `
        <label class="${cls}">
          <span>${field.label}</span>
          <textarea id="${id}" rows="5">${field.default ?? ""}</textarea>
          ${hint}
        </label>
      `;
    }

    if (field.type === "select") {
      return `
        <label class="${cls}">
          <span>${field.label}</span>
          <select id="${id}">
            ${field.options.map(opt => `
              <option value="${opt.value}" ${opt.value === field.default ? "selected" : ""}>${opt.label}</option>
            `).join("")}
          </select>
          ${hint}
        </label>
      `;
    }

    return `
      <label class="${cls}">
        <span>${field.label}</span>
        <input id="${id}" type="${field.type}" value="${field.default ?? ""}"
          ${field.min !== undefined ? `min="${field.min}"` : ""}
          ${field.max !== undefined ? `max="${field.max}"` : ""} />
        ${hint}
      </label>
    `;
  }).join("");

  if (selected === "rsa") {
    html += `
      <div class="field full">
        <span>RSA Tools</span>
        <div class="button-row">
          <button type="button" id="generateRSAKeysBtn" class="btn btn-secondary">Generate Demo RSA Keys</button>
        </div>
        <small>Creates small educational RSA keys in the browser. Not secure for real-world use.</small>
      </div>
    `;
  }

  els.keyFields.innerHTML = html;

  els.keyFields.querySelectorAll("input, textarea, select").forEach(node => {
    node.addEventListener("input", () => {
      updateModeFieldState();
      autoRefresh();
    });
    node.addEventListener("change", () => {
      updateModeFieldState();
      autoRefresh();
    });
  });

  const rsaBtn = document.getElementById("generateRSAKeysBtn");
  if (rsaBtn) {
    rsaBtn.addEventListener("click", generateRSAKeysIntoFields);
  }

  updateModeFieldState();
}

function updateModeFieldState() {
  const modeEl = document.getElementById("key-mode");
  const ivEl = document.getElementById("key-iv");
  if (!modeEl || !ivEl) return;

  const wrapper = ivEl.closest(".field");
  if (modeEl.value === "ECB") {
    ivEl.disabled = true;
    wrapper.classList.add("disabled");
  } else {
    ivEl.disabled = false;
    wrapper.classList.remove("disabled");
  }
}

function updateInfoPanels() {
  const id = els.algorithmSelect.value;
  const t = THEORY[id];

  els.algorithmMeta.innerHTML = `
    <span class="pill">${t.type}</span>
    <span class="pill">${t.category}</span>
    <span class="pill ${securityClass(t.securityLevel)}">${t.securityLevel}</span>
  `;

  els.theoryPanel.innerHTML = `
    <div class="meta-grid">
      <div class="meta-item"><span class="meta-label">Cipher Name</span><strong>${t.name}</strong></div>
      <div class="meta-item"><span class="meta-label">Type</span><strong>${t.type}</strong></div>
      <div class="meta-item"><span class="meta-label">Category</span><strong>${t.category}</strong></div>
      <div class="meta-item"><span class="meta-label">Key Type</span><strong>${t.keyType}</strong></div>
      <div class="meta-item"><span class="meta-label">Inventor</span><strong>${t.inventor}</strong></div>
      <div class="meta-item"><span class="meta-label">Year</span><strong>${t.year}</strong></div>
    </div>

    <div class="formula-box" style="margin-top:14px;">
      <strong>Explanation</strong>
      <p style="margin:8px 0 0; line-height:1.6;">${t.explanation}</p>
    </div>

    <div class="formula-box" style="margin-top:14px;">
      <strong>Encryption Formula</strong>
      <p style="margin:8px 0 0;"><code>${escapeHtml(t.formula)}</code></p>
    </div>

    <div class="example-box" style="margin-top:14px;">
      <strong>Example</strong>
      <p style="margin:10px 0 0;"><b>Plaintext:</b> ${escapeHtml(t.example.plaintext)}</p>
      <p style="margin:6px 0 0;"><b>Key:</b> ${escapeHtml(t.example.key)}</p>
      <p style="margin:6px 0 0;"><b>Ciphertext:</b> ${escapeHtml(t.example.ciphertext)}</p>
    </div>
  `;

  els.securityPanel.innerHTML = `
    <div class="security-rows">
      <div class="security-row">
        <div class="label">Key Size</div>
        <div class="value">${escapeHtml(t.keySize)}</div>
      </div>
      <div class="security-row">
        <div class="label">Block Size</div>
        <div class="value">${escapeHtml(t.blockSize || "N/A")}</div>
      </div>
      <div class="security-row">
        <div class="label">Security Level</div>
        <div class="value">${escapeHtml(t.securityLevel)}</div>
      </div>
      <div class="security-row">
        <div class="label">Current Status</div>
        <div class="value">${escapeHtml(t.status)}</div>
      </div>
    </div>
  `;
}

function autoRefresh() {
  if (activeMode) runCipher(activeMode, false);
}

function runCipher(mode, userTriggered) {
  const input = els.mainInput.value;
  const algorithm = els.algorithmSelect.value;

  if (userTriggered) activeMode = mode;

  if (!input.trim()) {
    els.outputText.value = "";
    els.visualization.innerHTML = `<p class="muted">Enter input text to generate output and visualization.</p>`;
    setStatus("", "");
    updateLearningTools();
    return;
  }

  try {
    const keys = readKeys(algorithm);
    const result = HANDLERS[algorithm][mode](input, keys);
    els.outputText.value = result.output;
    els.visualization.innerHTML = result.visualization || `<p class="muted">No visualization available.</p>`;
    if (userTriggered) {
      setStatus(`${capitalize(mode)}ion complete.`, "success");
      addHistory({
        algorithm,
        mode,
        input,
        output: result.output,
        keys
      });
    } else {
      setStatus("", "");
    }
  } catch (err) {
    els.outputText.value = "";
    els.visualization.innerHTML = `<p class="muted">Adjust the input or keys to view the internal steps.</p>`;
    if (userTriggered || input.trim()) setStatus(err.message || "Operation failed.", "error");
  }

  updateLearningTools();
}

function readKeys(algorithm) {
  const config = FIELD_CONFIG[algorithm];
  const obj = {};
  config.fields.forEach(field => {
    const el = document.getElementById(`key-${field.id}`);
    obj[field.id] = el ? el.value : "";
  });
  return obj;
}

function setStatus(message, type) {
  els.status.textContent = message;
  els.status.className = "status";
  if (type) els.status.classList.add(type);
}

function updateLearningTools() {
  const algo = els.algorithmSelect.value;
  const showFreq = TOOL_RULES.frequency.includes(algo);
  const showBrute = TOOL_RULES.bruteforce.includes(algo);

  els.learningCard.classList.toggle("hidden", !showFreq && !showBrute);
  els.freqTool.classList.toggle("hidden", !showFreq);
  els.bruteTool.classList.toggle("hidden", !showBrute);

  if (showFreq) renderFrequency();
  else els.frequencyPanel.innerHTML = "";

  if (showBrute) renderBruteForce();
  else els.bruteforcePanel.innerHTML = "";
}

function runComparison() {
  const text = (els.comparisonInput.value || els.mainInput.value).trim();
  if (!text) {
    els.comparisonResults.innerHTML = "";
    return;
  }

  const comparisons = [
    { name: "Caesar", key: "shift = 3", fn: () => caesarTransform(text, 3).output },
    { name: "Affine", key: "a = 5, b = 8", fn: () => affineTransform(text, 5, 8, true).output },
    { name: "Vigenère", key: "KEY", fn: () => vigenereTransform(text, "KEY", true).output },
    { name: "Playfair", key: "MONARCHY", fn: () => playfairProcess(text, "MONARCHY", true).output },
    { name: "Rail Fence", key: "rails = 3", fn: () => railFenceEncrypt(text, 3).output },
    { name: "Columnar", key: "ZEBRA / X", fn: () => columnarEncrypt(text, "ZEBRA", "X").output },
    {
      name: "AES",
      key: "AESDemoSecretKey / ECB / Base64",
      fn: () => modernBlockEncrypt("AES", text, {
        secretKey: "AESDemoSecretKey",
        mode: "ECB",
        iv: "",
        inputFormat: "utf8",
        outputFormat: "base64"
      }).output
    }
  ];

  els.comparisonResults.innerHTML = comparisons.map(c => {
    let result = "";
    try {
      result = c.fn();
    } catch (e) {
      result = `Error: ${e.message}`;
    }
    return `
      <article class="compare-card">
        <h4>${c.name}</h4>
        <small>Key: ${escapeHtml(c.key)}</small>
        <code>${escapeHtml(result)}</code>
      </article>
    `;
  }).join("");
}

/* -----------------------------
   History
------------------------------ */

function addHistory(item) {
  historyItems.unshift({
    id: cryptoRandomId(),
    timestamp: new Date().toISOString(),
    ...item
  });
  historyItems = historyItems.slice(0, 25);
  saveHistory();
  renderHistory();
}

function renderHistory() {
  if (!historyItems.length) {
    els.historyList.innerHTML = `<p class="muted">No history yet. Run encryption or decryption to store operations here.</p>`;
    return;
  }

  els.historyList.innerHTML = `
    <div class="history-list">
      ${historyItems.map(item => `
        <div class="history-item">
          <div class="history-head">
            <div>
              <strong>${escapeHtml(THEORY[item.algorithm].name)}</strong>
              <small>${capitalize(item.mode)} • ${formatTimestamp(item.timestamp)}</small>
            </div>
            <div class="history-actions">
              <button class="btn btn-secondary" data-action="restore" data-id="${item.id}">Restore</button>
            </div>
          </div>
          <div class="history-body">
            <div><b>Keys:</b> <code>${escapeHtml(summarizeKeys(item.algorithm, item.keys))}</code></div>
            <div><b>Input:</b> <code>${escapeHtml(truncate(item.input, 180))}</code></div>
            <div><b>Output:</b> <code>${escapeHtml(truncate(item.output, 180))}</code></div>
          </div>
        </div>
      `).join("")}
    </div>
  `;
}

function handleHistoryActions(e) {
  const btn = e.target.closest("button[data-action]");
  if (!btn) return;

  const id = btn.dataset.id;
  const item = historyItems.find(x => x.id === id);
  if (!item) return;

  if (btn.dataset.action === "restore") {
    restoreHistoryItem(item);
  }
}

function restoreHistoryItem(item) {
  els.algorithmSelect.value = item.algorithm;
  renderKeyFields();
  updateInfoPanels();
  updateLearningTools();

  Object.entries(item.keys || {}).forEach(([key, value]) => {
    const el = document.getElementById(`key-${key}`);
    if (el) el.value = value;
  });

  updateModeFieldState();

  els.mainInput.value = item.input;
  activeMode = item.mode;
  runCipher(item.mode, false);
  activateTab("workbench");
  setStatus("History item restored.", "success");
}

function saveHistory() {
  localStorage.setItem(HISTORY_STORAGE_KEY, JSON.stringify(historyItems));
}

function loadHistory() {
  try {
    historyItems = JSON.parse(localStorage.getItem(HISTORY_STORAGE_KEY) || "[]");
  } catch {
    historyItems = [];
  }
}

function clearHistory() {
  historyItems = [];
  saveHistory();
  renderHistory();
}

/* -----------------------------
   RSA Key Generation
------------------------------ */

function generateRSAKeysIntoFields() {
  try {
    const keys = generateEducationalRSAKeys();
    document.getElementById("key-e").value = keys.e;
    document.getElementById("key-n").value = keys.n;
    document.getElementById("key-d").value = keys.d;
    setStatus(`Generated demo RSA keys (p=${keys.p}, q=${keys.q}).`, "success");
    autoRefresh();
  } catch (e) {
    setStatus(e.message || "Could not generate RSA keys.", "error");
  }
}

function generateEducationalRSAKeys() {
  const primes = [
    101n, 103n, 107n, 109n, 113n, 127n, 131n, 137n, 139n, 149n,
    151n, 157n, 163n, 167n, 173n, 179n, 181n, 191n, 193n, 197n,
    199n, 211n, 223n, 227n, 229n, 233n, 239n, 241n, 251n, 257n,
    263n, 269n, 271n, 277n, 281n, 283n, 293n, 307n, 311n, 313n
  ];

  let p = pick(primes);
  let q = pick(primes);
  while (q === p) q = pick(primes);

  const n = p * q;
  const phi = (p - 1n) * (q - 1n);
  const candidates = [65537n, 257n, 17n, 5n, 3n];
  let e = candidates.find(x => x < phi && gcdBigInt(x, phi) === 1n);
  if (!e) throw new Error("Unable to find valid RSA exponent.");

  const d = modInvBigInt(e, phi);

  return {
    p: p.toString(),
    q: q.toString(),
    e: e.toString(),
    d: d.toString(),
    n: n.toString()
  };
}

/* -----------------------------
   Learning Tools
------------------------------ */

function renderFrequency() {
  const clean = sanitizeLetters(els.mainInput.value);
  if (!clean) {
    els.frequencyPanel.innerHTML = `<p class="muted">Type some text to see A-Z frequency distribution.</p>`;
    return;
  }

  const counts = Array(26).fill(0);
  for (const ch of clean) counts[alphaIndex(ch)]++;

  const total = clean.length;
  const top = counts.map((count, i) => ({ letter: ABC[i], count }))
    .sort((a, b) => b.count - a.count)
    .slice(0, 5);

  const bars = counts.map((count, i) => {
    const pct = total ? (count / total) * 100 : 0;
    return `
      <div class="freq-col">
        <div class="bar-box"><div class="bar-fill" style="height:${pct}%"></div></div>
        <strong>${ABC[i]}</strong>
        <small>${count}<br>${pct.toFixed(1)}%</small>
      </div>
    `;
  }).join("");

  els.frequencyPanel.innerHTML = `
    <div class="freq-wrap">
      <div class="sub-card">
        <strong>Total letters:</strong> ${total}<br>
        <strong>Top letters:</strong> ${top.map(x => `${x.letter} (${x.count})`).join(", ")}
      </div>
      <div class="freq-bars">${bars}</div>
    </div>
  `;
}

function renderBruteForce() {
  const text = els.mainInput.value;
  if (!text.trim()) {
    els.bruteforcePanel.innerHTML = `<p class="muted">Enter text to try all 26 Caesar shifts.</p>`;
    return;
  }

  els.bruteforcePanel.innerHTML = `
    <div class="bruteforce-list">
      ${Array.from({ length: 26 }, (_, shift) => `
        <div class="bf-row">
          <strong>Shift ${shift}</strong>
          <code>${escapeHtml(caesarTransform(text, -shift).output)}</code>
        </div>
      `).join("")}
    </div>
  `;
}

/* -----------------------------
   Helpers
------------------------------ */

function escapeHtml(str = "") {
  return String(str).replace(/[&<>"']/g, m => ({
    "&": "&amp;",
    "<": "&lt;",
    ">": "&gt;",
    '"': "&quot;",
    "'": "&#39;"
  }[m]));
}

function capitalize(str) {
  return str.charAt(0).toUpperCase() + str.slice(1);
}

function securityClass(text) {
  const v = text.toLowerCase();
  if (v.includes("strong")) return "strong";
  if (v.includes("moderate")) return "moderate";
  return "weak";
}

function formatTimestamp(iso) {
  return new Date(iso).toLocaleString();
}

function truncate(str = "", len = 140) {
  return str.length > len ? `${str.slice(0, len)}…` : str;
}

function cryptoRandomId() {
  return Math.random().toString(36).slice(2) + Date.now().toString(36);
}

function pick(arr) {
  return arr[Math.floor(Math.random() * arr.length)];
}

function summarizeKeys(algorithm, keys) {
  if (!keys) return "";
  switch (algorithm) {
    case "caesar": return `shift=${keys.shift}`;
    case "mono": return `alphabet=${truncate(keys.alphabet, 40)}`;
    case "affine": return `a=${keys.a}, b=${keys.b}`;
    case "playfair":
    case "vigenere":
    case "columnar": return `keyword=${keys.keyword}${keys.padChar ? `, pad=${keys.padChar}` : ""}`;
    case "hill": return `matrix=${keys.matrix.replace(/\n/g, "; ")}`;
    case "railfence": return `rails=${keys.rails}`;
    case "des":
    case "tripledes":
    case "aes":
      return `key=${truncate(keys.secretKey, 18)}, mode=${keys.mode}, in=${keys.inputFormat}, out=${keys.outputFormat}`;
    case "rc4":
      return `key=${truncate(keys.secretKey, 18)}, in=${keys.inputFormat}, out=${keys.outputFormat}`;
    case "rsa":
      return `e=${keys.e}, n=${keys.n}, d=${keys.d}`;
    default:
      return JSON.stringify(keys);
  }
}

function mod(n, m) {
  return ((n % m) + m) % m;
}

function gcd(a, b) {
  a = Math.abs(Number(a));
  b = Math.abs(Number(b));
  while (b) [a, b] = [b, a % b];
  return a;
}

function modInv(a, m) {
  a = mod(a, m);
  for (let x = 1; x < m; x++) {
    if (mod(a * x, m) === 1) return x;
  }
  throw new Error(`No modular inverse exists for ${a} mod ${m}.`);
}

function gcdBigInt(a, b) {
  while (b !== 0n) [a, b] = [b, a % b];
  return a;
}

function egcd(a, b) {
  if (b === 0n) return [a, 1n, 0n];
  const [g, x1, y1] = egcd(b, a % b);
  return [g, y1, x1 - (a / b) * y1];
}

function modInvBigInt(a, m) {
  const [g, x] = egcd(a, m);
  if (g !== 1n) throw new Error("No modular inverse for RSA exponent.");
  return ((x % m) + m) % m;
}

function alphaIndex(ch) {
  return ABC.indexOf(ch.toUpperCase());
}

function isLetter(ch) {
  return /^[A-Za-z]$/.test(ch);
}

function sanitizeLetters(text) {
  return (text || "").toUpperCase().replace(/[^A-Z]/g, "");
}

function shiftChar(ch, shift) {
  if (!isLetter(ch)) return ch;
  const base = ch === ch.toLowerCase() ? 97 : 65;
  return String.fromCharCode(base + mod(ch.charCodeAt(0) - base + shift, 26));
}

function renderSimpleStepGrid(steps) {
  return steps.length
    ? `<div class="step-grid">${steps.join("")}</div>`
    : `<p class="muted">Add more input to see the step-by-step transformation.</p>`;
}

function matrixTableHTML(matrix, headers = null) {
  const head = headers
    ? `<thead><tr>${headers.map(h => `<th>${escapeHtml(String(h))}</th>`).join("")}</tr></thead>`
    : "";
  return `
    <div class="table-wrap">
      <table class="matrix-table">
        ${head}
        <tbody>
          ${matrix.map(row => `<tr>${row.map(cell => `<td>${escapeHtml(String(cell))}</td>`).join("")}</tr>`).join("")}
        </tbody>
      </table>
    </div>
  `;
}

function visibleCellChar(ch) {
  if (!ch) return "·";
  if (ch === " ") return "␠";
  return escapeHtml(ch);
}

/* -----------------------------
   Caesar
------------------------------ */

function caesarTransform(text, shift) {
  if (!Number.isFinite(shift)) throw new Error("Shift must be a number.");
  let output = "";
  const steps = [];

  for (const ch of text) {
    const result = shiftChar(ch, shift);
    output += result;

    if (isLetter(ch) && steps.length < 12) {
      steps.push(`
        <div class="step-chip">
          <code>${escapeHtml(ch)}</code> → <code>${escapeHtml(result)}</code>
          <small>${alphaIndex(ch)} ${shift >= 0 ? "+" : "-"} ${Math.abs(shift)} ≡ ${alphaIndex(result)} (mod 26)</small>
        </div>
      `);
    }
  }

  return { output, visualization: renderSimpleStepGrid(steps) };
}

/* -----------------------------
   Monoalphabetic
------------------------------ */

function validateMonoAlphabet(key) {
  const clean = sanitizeLetters(key);
  if (clean.length !== 26) throw new Error("Monoalphabetic key must contain exactly 26 letters.");
  if (new Set(clean).size !== 26) throw new Error("Monoalphabetic key must contain 26 unique letters.");
  return clean;
}

function monoEncrypt(text, alphabet) {
  const key = validateMonoAlphabet(alphabet);
  let output = "";
  const steps = [];

  for (const ch of text) {
    if (!isLetter(ch)) {
      output += ch;
      continue;
    }
    const idx = alphaIndex(ch);
    let mapped = key[idx];
    if (ch === ch.toLowerCase()) mapped = mapped.toLowerCase();
    output += mapped;

    if (steps.length < 12) {
      steps.push(`
        <div class="step-chip">
          <code>${escapeHtml(ch)}</code> → <code>${escapeHtml(mapped)}</code>
          <small>${ABC[idx]} maps to ${key[idx]}</small>
        </div>
      `);
    }
  }

  return {
    output,
    visualization: `${matrixTableHTML([["Plain", ...ABC.split("")], ["Cipher", ...key.split("")]])}<div style="height:14px;"></div>${renderSimpleStepGrid(steps)}`
  };
}

function monoDecrypt(text, alphabet) {
  const key = validateMonoAlphabet(alphabet);
  const inverse = {};
  key.split("").forEach((ch, i) => inverse[ch] = ABC[i]);

  let output = "";
  const steps = [];

  for (const ch of text) {
    if (!isLetter(ch)) {
      output += ch;
      continue;
    }
    const upper = ch.toUpperCase();
    let mapped = inverse[upper];
    if (!mapped) throw new Error("Invalid character for monoalphabetic decryption.");
    if (ch === ch.toLowerCase()) mapped = mapped.toLowerCase();
    output += mapped;

    if (steps.length < 12) {
      steps.push(`
        <div class="step-chip">
          <code>${escapeHtml(ch)}</code> → <code>${escapeHtml(mapped)}</code>
          <small>${upper} maps back to ${mapped.toUpperCase()}</small>
        </div>
      `);
    }
  }

  return {
    output,
    visualization: `${matrixTableHTML([["Cipher", ...key.split("")], ["Plain", ...ABC.split("")]])}<div style="height:14px;"></div>${renderSimpleStepGrid(steps)}`
  };
}

/* -----------------------------
   Affine
------------------------------ */

function affineTransform(text, a, b, encrypt = true) {
  if (!Number.isInteger(a) || !Number.isInteger(b)) throw new Error("Affine keys a and b must be integers.");
  if (gcd(a, 26) !== 1) throw new Error("Value 'a' must be coprime with 26.");

  const invA = encrypt ? null : modInv(a, 26);
  let output = "";
  const steps = [];

  for (const ch of text) {
    if (!isLetter(ch)) {
      output += ch;
      continue;
    }
    const x = alphaIndex(ch);
    const y = encrypt ? mod(a * x + b, 26) : mod(invA * (x - b), 26);
    const mapped = ch === ch.toLowerCase() ? ABC[y].toLowerCase() : ABC[y];
    output += mapped;

    if (steps.length < 12) {
      steps.push(`
        <div class="step-chip">
          <code>${escapeHtml(ch)}</code> → <code>${escapeHtml(mapped)}</code>
          <small>${encrypt ? `(${a}×${x}+${b}) mod 26 = ${y}` : `${invA}×(${x}-${b}) mod 26 = ${y}`}</small>
        </div>
      `);
    }
  }

  return { output, visualization: renderSimpleStepGrid(steps) };
}

/* -----------------------------
   Vigenère
------------------------------ */

function vigenereTransform(text, keyword, encrypt = true) {
  const key = sanitizeLetters(keyword);
  if (!key) throw new Error("Keyword is required.");

  let output = "";
  let k = 0;
  const steps = [];

  for (const ch of text) {
    if (!isLetter(ch)) {
      output += ch;
      continue;
    }
    const keyChar = key[k % key.length];
    const shift = alphaIndex(keyChar);
    const result = shiftChar(ch, encrypt ? shift : -shift);
    output += result;

    if (steps.length < 12) {
      steps.push(`
        <div class="step-chip">
          <code>${escapeHtml(ch)}</code> + <code>${keyChar}</code> → <code>${escapeHtml(result)}</code>
          <small>Shift ${encrypt ? "+" : "-"}${shift}</small>
        </div>
      `);
    }
    k++;
  }

  return { output, visualization: renderSimpleStepGrid(steps) };
}

/* -----------------------------
   Playfair
------------------------------ */

function buildPlayfairMatrix(keyword) {
  const clean = sanitizeLetters(keyword).replace(/J/g, "I");
  const seen = new Set();
  const sequence = [];

  for (const ch of (clean + ABC.replace("J", "")).split("")) {
    const c = ch === "J" ? "I" : ch;
    if (!seen.has(c)) {
      seen.add(c);
      sequence.push(c);
    }
  }

  const matrix = [];
  const pos = {};
  for (let i = 0; i < 5; i++) matrix.push(sequence.slice(i * 5, i * 5 + 5));
  matrix.forEach((row, r) => row.forEach((ch, c) => pos[ch] = { r, c }));
  return { matrix, pos };
}

function preparePlayfairPairs(text) {
  const clean = sanitizeLetters(text).replace(/J/g, "I");
  const pairs = [];
  let i = 0;

  while (i < clean.length) {
    const a = clean[i];
    let b = clean[i + 1];
    if (!b) {
      b = "X";
      i += 1;
    } else if (a === b) {
      b = "X";
      i += 1;
    } else {
      i += 2;
    }
    pairs.push([a, b]);
  }
  return pairs;
}

function chunkPairs(text) {
  let clean = sanitizeLetters(text).replace(/J/g, "I");
  if (clean.length % 2 !== 0) clean += "X";
  const pairs = [];
  for (let i = 0; i < clean.length; i += 2) pairs.push([clean[i], clean[i + 1]]);
  return pairs;
}

function playfairPair(pair, matrix, pos, encrypt = true) {
  const [a, b] = pair;
  const p1 = pos[a];
  const p2 = pos[b];

  if (p1.r === p2.r) {
    return {
      out: matrix[p1.r][mod(p1.c + (encrypt ? 1 : -1), 5)] + matrix[p2.r][mod(p2.c + (encrypt ? 1 : -1), 5)],
      rule: "Same row"
    };
  }

  if (p1.c === p2.c) {
    return {
      out: matrix[mod(p1.r + (encrypt ? 1 : -1), 5)][p1.c] + matrix[mod(p2.r + (encrypt ? 1 : -1), 5)][p2.c],
      rule: "Same column"
    };
  }

  return {
    out: matrix[p1.r][p2.c] + matrix[p2.r][p1.c],
    rule: "Rectangle swap"
  };
}

function playfairProcess(text, keyword, encrypt = true) {
  const { matrix, pos } = buildPlayfairMatrix(keyword);
  const pairs = encrypt ? preparePlayfairPairs(text) : chunkPairs(text);

  let output = "";
  const steps = [];

  for (const pair of pairs) {
    const transformed = playfairPair(pair, matrix, pos, encrypt);
    output += transformed.out;
    if (steps.length < 12) {
      steps.push(`
        <div class="step-chip">
          <strong>${pair.join("")}</strong> → <strong>${transformed.out}</strong>
          <small>${transformed.rule}</small>
        </div>
      `);
    }
  }

  return {
    output,
    visualization: `<div class="sub-card"><strong>5x5 Key Matrix</strong></div>${matrixTableHTML(matrix)}<div style="height:14px;"></div>${renderSimpleStepGrid(steps)}`
  };
}

/* -----------------------------
   Hill
------------------------------ */

function parseHillMatrix(input) {
  const rows = input.trim().split(/\n|;/).map(r => r.trim()).filter(Boolean).map(r => r.split(/[\s,]+/).map(Number));
  const n = rows.length;
  if (![2, 3].includes(n)) throw new Error("Hill cipher requires a 2x2 or 3x3 matrix.");
  if (rows.some(row => row.length !== n || row.some(Number.isNaN))) throw new Error("Matrix must be a valid square 2x2 or 3x3 matrix.");
  return rows;
}

function determinant(matrix) {
  if (matrix.length === 2) return matrix[0][0] * matrix[1][1] - matrix[0][1] * matrix[1][0];
  return (
    matrix[0][0] * (matrix[1][1] * matrix[2][2] - matrix[1][2] * matrix[2][1]) -
    matrix[0][1] * (matrix[1][0] * matrix[2][2] - matrix[1][2] * matrix[2][0]) +
    matrix[0][2] * (matrix[1][0] * matrix[2][1] - matrix[1][1] * matrix[2][0])
  );
}

function minor3(m, row, col) {
  const sub = m.filter((_, r) => r !== row).map(r => r.filter((_, c) => c !== col));
  return sub[0][0] * sub[1][1] - sub[0][1] * sub[1][0];
}

function inverseMatrixMod26(matrix) {
  const det = determinant(matrix);
  const invDet = modInv(mod(det, 26), 26);

  if (matrix.length === 2) {
    const adj = [
      [matrix[1][1], -matrix[0][1]],
      [-matrix[1][0], matrix[0][0]]
    ];
    return adj.map(row => row.map(v => mod(v * invDet, 26)));
  }

  const cof = Array.from({ length: 3 }, () => Array(3).fill(0));
  for (let r = 0; r < 3; r++) {
    for (let c = 0; c < 3; c++) {
      cof[r][c] = ((r + c) % 2 === 0 ? 1 : -1) * minor3(matrix, r, c);
    }
  }
  const adj = cof[0].map((_, c) => cof.map(row => row[c]));
  return adj.map(row => row.map(v => mod(v * invDet, 26)));
}

function multiplyMatrixVector(matrix, vector) {
  return matrix.map(row => mod(row.reduce((sum, v, i) => sum + v * vector[i], 0), 26));
}

function hillProcess(text, matrixText, encrypt = true) {
  const originalMatrix = parseHillMatrix(matrixText);
  const usedMatrix = encrypt ? originalMatrix : inverseMatrixMod26(originalMatrix);
  const size = usedMatrix.length;
  let clean = sanitizeLetters(text);
  while (clean.length % size !== 0) clean += "X";

  let output = "";
  const steps = [];
  for (let i = 0; i < clean.length; i += size) {
    const block = clean.slice(i, i + size);
    const vector = block.split("").map(alphaIndex);
    const resultVec = multiplyMatrixVector(usedMatrix, vector);
    const resultBlock = resultVec.map(n => ABC[n]).join("");
    output += resultBlock;

    if (steps.length < 10) {
      steps.push(`
        <div class="step-chip">
          <strong>${block}</strong> → <strong>${resultBlock}</strong>
          <small>K × [${vector.join(", ")}] mod 26 = [${resultVec.join(", ")}]</small>
        </div>
      `);
    }
  }

  return {
    output,
    visualization: `<div class="sub-card"><strong>${encrypt ? "Key Matrix" : "Inverse Key Matrix (mod 26)"}</strong></div>${matrixTableHTML(usedMatrix)}<div style="height:14px;"></div>${renderSimpleStepGrid(steps)}`
  };
}

/* -----------------------------
   Rail Fence
------------------------------ */

function buildRailFence(text, rails) {
  const fence = Array.from({ length: rails }, () => Array(text.length).fill(""));
  let rail = 0;
  let dir = 1;
  for (let i = 0; i < text.length; i++) {
    fence[rail][i] = text[i];
    if (rail === 0) dir = 1;
    else if (rail === rails - 1) dir = -1;
    rail += dir;
  }
  return fence;
}

function railFenceTable(fence) {
  return `
    <div class="table-wrap">
      <table class="matrix-table">
        <tbody>
          ${fence.map(row => `<tr>${row.map(ch => `<td>${visibleCellChar(ch)}</td>`).join("")}</tr>`).join("")}
        </tbody>
      </table>
    </div>
  `;
}

function railFenceEncrypt(text, rails) {
  if (!Number.isInteger(rails) || rails < 2) throw new Error("Rails must be at least 2.");
  const fence = buildRailFence(text, rails);
  return { output: fence.map(row => row.filter(Boolean).join("")).join(""), visualization: railFenceTable(fence) };
}

function railFenceDecrypt(text, rails) {
  if (!Number.isInteger(rails) || rails < 2) throw new Error("Rails must be at least 2.");

  const pattern = Array.from({ length: rails }, () => Array(text.length).fill(""));
  let rail = 0;
  let dir = 1;
  for (let i = 0; i < text.length; i++) {
    pattern[rail][i] = "*";
    if (rail === 0) dir = 1;
    else if (rail === rails - 1) dir = -1;
    rail += dir;
  }

  let idx = 0;
  for (let r = 0; r < rails; r++) {
    for (let c = 0; c < text.length; c++) {
      if (pattern[r][c] === "*") pattern[r][c] = text[idx++];
    }
  }

  let output = "";
  rail = 0;
  dir = 1;
  for (let i = 0; i < text.length; i++) {
    output += pattern[rail][i];
    if (rail === 0) dir = 1;
    else if (rail === rails - 1) dir = -1;
    rail += dir;
  }

  return { output, visualization: railFenceTable(pattern) };
}

/* -----------------------------
   Columnar
------------------------------ */

function validateKeyword(keyword) {
  const key = sanitizeLetters(keyword);
  if (!key) throw new Error("Keyword is required.");
  return key;
}

function normalizePadChar(ch) {
  const clean = sanitizeLetters(ch || "");
  return clean[0] || "X";
}

function sortedKeyColumns(keyword) {
  return keyword.split("").map((ch, index) => ({ ch, index }))
    .sort((a, b) => a.ch.localeCompare(b.ch) || a.index - b.index);
}

function keyRanks(keyword) {
  const sorted = sortedKeyColumns(keyword);
  const ranks = Array(keyword.length);
  sorted.forEach((item, i) => ranks[item.index] = i + 1);
  return ranks;
}

function columnarTableHTML(matrix, keyword, fillerIndexes = new Set()) {
  const ranks = keyRanks(keyword);
  return `
    <div class="table-wrap">
      <table class="matrix-table">
        <thead>
          <tr>${keyword.split("").map(ch => `<th>${escapeHtml(ch)}</th>`).join("")}</tr>
          <tr>${ranks.map(x => `<th>${x}</th>`).join("")}</tr>
        </thead>
        <tbody>
          ${matrix.map((row, r) => `
            <tr>
              ${row.map((cell, c) => `<td class="${fillerIndexes.has(`${r}-${c}`) ? "pad-cell" : ""}">${escapeHtml(cell)}</td>`).join("")}
            </tr>
          `).join("")}
        </tbody>
      </table>
    </div>
  `;
}

function columnarEncrypt(text, keyword, padChar) {
  const key = validateKeyword(keyword);
  const pad = normalizePadChar(padChar);
  const clean = sanitizeLetters(text);
  if (!clean) return { output: "", visualization: `<p class="muted">Only A-Z are used in this implementation.</p>` };

  const cols = key.length;
  const rows = Math.ceil(clean.length / cols);
  const matrix = Array.from({ length: rows }, () => Array(cols).fill(pad));
  const fillerIndexes = new Set();

  let idx = 0;
  for (let r = 0; r < rows; r++) {
    for (let c = 0; c < cols; c++) {
      if (idx < clean.length) matrix[r][c] = clean[idx++];
      else fillerIndexes.add(`${r}-${c}`);
    }
  }

  const sorted = sortedKeyColumns(key);
  let output = "";
  const steps = [];

  sorted.forEach((col, orderIndex) => {
    let chunk = "";
    for (let r = 0; r < rows; r++) chunk += matrix[r][col.index];
    output += chunk;
    steps.push(`
      <div class="step-chip">
        <strong>Order ${orderIndex + 1}</strong>
        <small>Read column <b>${escapeHtml(col.ch)}</b> (position ${col.index + 1}) → ${escapeHtml(chunk)}</small>
      </div>
    `);
  });

  return {
    output,
    visualization: `
      <div class="sub-card"><strong>Grid Construction</strong><br>Final row is padded with <span class="inline-code">${pad}</span>.</div>
      <div style="height:14px;"></div>
      ${columnarTableHTML(matrix, key, fillerIndexes)}
      <div style="height:14px;"></div>
      ${renderSimpleStepGrid(steps)}
    `
  };
}

function columnarDecrypt(text, keyword, padChar) {
  const key = validateKeyword(keyword);
  const pad = normalizePadChar(padChar);
  const clean = sanitizeLetters(text);
  if (!clean) return { output: "", visualization: `<p class="muted">Only A-Z are used in this implementation.</p>` };

  const cols = key.length;
  if (clean.length % cols !== 0) throw new Error("Ciphertext length must be divisible by keyword length in this padded implementation.");

  const rows = clean.length / cols;
  const matrix = Array.from({ length: rows }, () => Array(cols).fill(""));
  const sorted = sortedKeyColumns(key);

  let idx = 0;
  const steps = [];
  sorted.forEach((col, orderIndex) => {
    let chunk = "";
    for (let r = 0; r < rows; r++) {
      matrix[r][col.index] = clean[idx];
      chunk += clean[idx++];
    }
    steps.push(`
      <div class="step-chip">
        <strong>Order ${orderIndex + 1}</strong>
        <small>Place ${escapeHtml(chunk)} into column <b>${escapeHtml(col.ch)}</b> (position ${col.index + 1})</small>
      </div>
    `);
  });

  let output = "";
  for (let r = 0; r < rows; r++) {
    for (let c = 0; c < cols; c++) output += matrix[r][c];
  }

  return {
    output,
    visualization: `
      <div class="sub-card"><strong>Recovered Grid</strong><br>Read row by row. Plaintext may end with padding character <span class="inline-code">${pad}</span>.</div>
      <div style="height:14px;"></div>
      ${columnarTableHTML(matrix, key)}
      <div style="height:14px;"></div>
      ${renderSimpleStepGrid(steps)}
    `
  };
}

/* -----------------------------
   Modern Crypto with format toggles
------------------------------ */

function parseWordArrayByFormat(text, format) {
  switch (format) {
    case "utf8":
      return CryptoJS.enc.Utf8.parse(text);
    case "hex": {
      const clean = text.replace(/\s+/g, "");
      if (!clean || clean.length % 2 !== 0 || /[^0-9a-f]/i.test(clean)) throw new Error("Invalid hex input.");
      return CryptoJS.enc.Hex.parse(clean);
    }
    case "base64": {
      const clean = text.replace(/\s+/g, "");
      if (!clean) throw new Error("Base64 input is empty.");
      return CryptoJS.enc.Base64.parse(clean);
    }
    default:
      throw new Error("Unsupported input format.");
  }
}

function wordArrayToFormat(wordArray, format) {
  switch (format) {
    case "utf8": return CryptoJS.enc.Utf8.stringify(wordArray);
    case "hex": return CryptoJS.enc.Hex.stringify(wordArray);
    case "base64": return CryptoJS.enc.Base64.stringify(wordArray);
    default: throw new Error("Unsupported output format.");
  }
}

function normalizeKey(str, bytes) {
  return String(str || "").padEnd(bytes, "0").slice(0, bytes);
}

function cryptoConfig(algo, secretKey, mode, iv) {
  const keyStr = String(secretKey || "");
  if (!keyStr) throw new Error("Secret key is required.");

  let keyBytes = 16;
  let blockBytes = 16;

  if (algo === "DES") {
    keyBytes = 8;
    blockBytes = 8;
  } else if (algo === "TripleDES") {
    keyBytes = 24;
    blockBytes = 8;
  } else if (algo === "AES") {
    keyBytes = keyStr.length <= 16 ? 16 : keyStr.length <= 24 ? 24 : 32;
    blockBytes = 16;
  }

  const normalizedKey = normalizeKey(keyStr, keyBytes);
  const normalizedIv = mode === "CBC" ? normalizeKey(iv || "", blockBytes) : "";
  const cfg = {
    mode: mode === "CBC" ? CryptoJS.mode.CBC : CryptoJS.mode.ECB,
    padding: CryptoJS.pad.Pkcs7
  };

  if (mode === "CBC") cfg.iv = CryptoJS.enc.Utf8.parse(normalizedIv);

  return {
    key: CryptoJS.enc.Utf8.parse(normalizedKey),
    cfg,
    normalizedKey,
    normalizedIv,
    keyBits: keyBytes * 8,
    blockBits: blockBytes * 8
  };
}

function modernBlockViz(name, meta, mode, inFmt, outFmt, op) {
  return `
    <div class="meta-grid">
      <div class="meta-item"><span class="meta-label">Algorithm</span><strong>${name}</strong></div>
      <div class="meta-item"><span class="meta-label">Operation</span><strong>${capitalize(op)}</strong></div>
      <div class="meta-item"><span class="meta-label">Mode</span><strong>${mode}</strong></div>
      <div class="meta-item"><span class="meta-label">Input Format</span><strong>${inFmt.toUpperCase()}</strong></div>
      <div class="meta-item"><span class="meta-label">Output Format</span><strong>${outFmt.toUpperCase()}</strong></div>
      <div class="meta-item"><span class="meta-label">Normalized Key</span><strong>${escapeHtml(meta.normalizedKey)}</strong></div>
      <div class="meta-item"><span class="meta-label">IV</span><strong>${escapeHtml(meta.normalizedIv || "Not used in ECB")}</strong></div>
      <div class="meta-item"><span class="meta-label">Key Size</span><strong>${meta.keyBits} bits</strong></div>
      <div class="meta-item"><span class="meta-label">Block Size</span><strong>${meta.blockBits} bits</strong></div>
    </div>
    <div class="formula-box" style="margin-top:14px;">
      <strong>Format Handling</strong>
      <p style="margin:8px 0 0; line-height:1.6;">
        For ${capitalize(op)}, the playground interprets the main input as <b>${inFmt.toUpperCase()}</b> data and converts the result to <b>${outFmt.toUpperCase()}</b>.
      </p>
    </div>
  `;
}

function modernBlockEncrypt(algo, text, keys) {
  const mode = keys.mode || "ECB";
  const inputFormat = keys.inputFormat || "utf8";
  const outputFormat = keys.outputFormat || "base64";
  const meta = cryptoConfig(algo, keys.secretKey, mode, keys.iv);
  const plaintextWA = parseWordArrayByFormat(text, inputFormat);
  const encrypted = CryptoJS[algo].encrypt(plaintextWA, meta.key, meta.cfg);
  const output = wordArrayToFormat(encrypted.ciphertext, outputFormat);

  return {
    output,
    visualization: modernBlockViz(algo, meta, mode, inputFormat, outputFormat, "encrypt")
  };
}

function modernBlockDecrypt(algo, text, keys) {
  const mode = keys.mode || "ECB";
  const inputFormat = keys.inputFormat || "base64";
  const outputFormat = keys.outputFormat || "utf8";
  const meta = cryptoConfig(algo, keys.secretKey, mode, keys.iv);
  const ciphertextWA = parseWordArrayByFormat(text.trim(), inputFormat);
  const cipherParams = CryptoJS.lib.CipherParams.create({ ciphertext: ciphertextWA });
  const decrypted = CryptoJS[algo].decrypt(cipherParams, meta.key, meta.cfg);
  const output = wordArrayToFormat(decrypted, outputFormat);

  return {
    output,
    visualization: modernBlockViz(algo, meta, mode, inputFormat, outputFormat, "decrypt")
  };
}

function rc4Encrypt(text, keys) {
  if (!keys.secretKey) throw new Error("Secret key is required.");
  const inputFormat = keys.inputFormat || "utf8";
  const outputFormat = keys.outputFormat || "base64";
  const plaintextWA = parseWordArrayByFormat(text, inputFormat);
  const keyWA = CryptoJS.enc.Utf8.parse(keys.secretKey);
  const encrypted = CryptoJS.RC4.encrypt(plaintextWA, keyWA);

  return {
    output: wordArrayToFormat(encrypted.ciphertext, outputFormat),
    visualization: `
      <div class="meta-grid">
        <div class="meta-item"><span class="meta-label">Algorithm</span><strong>RC4</strong></div>
        <div class="meta-item"><span class="meta-label">Input Format</span><strong>${inputFormat.toUpperCase()}</strong></div>
        <div class="meta-item"><span class="meta-label">Output Format</span><strong>${outputFormat.toUpperCase()}</strong></div>
        <div class="meta-item"><span class="meta-label">Secret Key</span><strong>${escapeHtml(keys.secretKey)}</strong></div>
      </div>
    `
  };
}

function rc4Decrypt(text, keys) {
  if (!keys.secretKey) throw new Error("Secret key is required.");
  const inputFormat = keys.inputFormat || "base64";
  const outputFormat = keys.outputFormat || "utf8";
  const ciphertextWA = parseWordArrayByFormat(text.trim(), inputFormat);
  const keyWA = CryptoJS.enc.Utf8.parse(keys.secretKey);
  const cipherParams = CryptoJS.lib.CipherParams.create({ ciphertext: ciphertextWA });
  const decrypted = CryptoJS.RC4.decrypt(cipherParams, keyWA);

  return {
    output: wordArrayToFormat(decrypted, outputFormat),
    visualization: `
      <div class="meta-grid">
        <div class="meta-item"><span class="meta-label">Algorithm</span><strong>RC4</strong></div>
        <div class="meta-item"><span class="meta-label">Input Format</span><strong>${inputFormat.toUpperCase()}</strong></div>
        <div class="meta-item"><span class="meta-label">Output Format</span><strong>${outputFormat.toUpperCase()}</strong></div>
        <div class="meta-item"><span class="meta-label">Secret Key</span><strong>${escapeHtml(keys.secretKey)}</strong></div>
      </div>
    `
  };
}

/* -----------------------------
   RSA
------------------------------ */

function parseBigInt(value, label) {
  try {
    return BigInt(String(value).trim());
  } catch {
    throw new Error(`${label} must be a valid integer.`);
  }
}

function modPow(base, exp, modn) {
  let result = 1n;
  base %= modn;
  while (exp > 0n) {
    if (exp & 1n) result = (result * base) % modn;
    base = (base * base) % modn;
    exp >>= 1n;
  }
  return result;
}

function rsaEncrypt(text, eVal, nVal) {
  const e = parseBigInt(eVal, "Public exponent e");
  const n = parseBigInt(nVal, "Modulus n");
  if (n <= 255n) throw new Error("For this educational RSA, modulus n must be greater than 255.");

  const nums = [];
  const steps = [];

  for (const ch of text) {
    const m = BigInt(ch.charCodeAt(0));
    if (m >= n) throw new Error(`Character "${ch}" has code ${m}, which must be smaller than n.`);
    const c = modPow(m, e, n);
    nums.push(c.toString());

    if (steps.length < 10) {
      steps.push(`
        <div class="step-chip">
          <strong>${escapeHtml(ch)}</strong> → <strong>${c}</strong>
          <small>${m}^${e} mod ${n} = ${c}</small>
        </div>
      `);
    }
  }

  return { output: nums.join(" "), visualization: renderSimpleStepGrid(steps) };
}

function rsaDecrypt(text, dVal, nVal) {
  const d = parseBigInt(dVal, "Private exponent d");
  const n = parseBigInt(nVal, "Modulus n");
  const parts = text.trim().split(/[\s,]+/).filter(Boolean);
  if (!parts.length) return { output: "", visualization: `<p class="muted">Enter space-separated RSA integers to decrypt.</p>` };

  let output = "";
  const steps = [];

  for (const part of parts) {
    const c = parseBigInt(part, "Ciphertext block");
    const m = modPow(c, d, n);
    const ch = String.fromCharCode(Number(m));
    output += ch;

    if (steps.length < 10) {
      steps.push(`
        <div class="step-chip">
          <strong>${c}</strong> → <strong>${escapeHtml(ch)}</strong>
          <small>${c}^${d} mod ${n} = ${m}</small>
        </div>
      `);
    }
  }

  return { output, visualization: renderSimpleStepGrid(steps) };
}

/* -----------------------------
   Theme
------------------------------ */

function toggleTheme() {
  document.body.classList.toggle("dark");
  localStorage.setItem("crypto-theme", document.body.classList.contains("dark") ? "dark" : "light");
}

function applySavedTheme() {
  const saved = localStorage.getItem("crypto-theme");
  if (saved === "dark") document.body.classList.add("dark");
}
