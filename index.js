import cryp from 'crypto'

const txtencoder = new TextEncoder();

// Base Namespace
const NSB = "com.omnipass";
// The namespace used in calculateMasterKey
const KeyNS   = `${NSB}.key`;
// The namespaces used in calculateSubKey
const SubKeyNS   = `${NSB}.subkey`;

const charsets = Object.freeze({
  V: "AEIOU",
  v: "aeiou",
  C: "BCDFGHJKLMNPQRSTVWXYZ",
  c: "bcdfghjklmnpqrstvwxyz",
  n: "0123456789",
  o: "@&%?,=[]_:-+*$#!'^~;()/.",
  get A() {
    return `${this.C}${this.V}`
  },
  get a() {
    return `${this.c}${this.v}`
  },
  get x() {
    return `${this.A}${this.a}${this.n}${this.o}`
  },
  get X() {
    return `${this.A}${this.a}${this.n}${this.o}`
  },
  get N() {
    return this.n
  },
  get O() {
    return this.o
  },
  " ": " ",
})

const specials = [
  '-',
  '[',
  ']',
  '/',
  '{',
  '}',
  '(',
  ')',
  '*',
  '+',
  '?',
  '.',
  '\\',
  '^',
  '$',
  '|',
]

function escapeRegex(string) {
  return string.replace(RegExp(`[${specials.join('\\')}]`, 'g'), '\\$&')
}

function getCharsetProfile({
  charset = 'X',
  exclude = '',
  required = 'Aano',
}) {
  if (!charset || !charset.length || typeof charset !== 'string') {
    throw Error('Argument charset not valid');
  }
  if (typeof required !== 'string') {
    throw Error('Argument required not valid');
  }
  if (typeof exclude !== 'string') {
    throw Error('Argument exclude not valid');
  }
  charset = new Set(charset + required);
  required = new Set(required);
  const requires = [];
  let chars = new Set();
  for (let char of charset) {
    let set = charsets[char]
    if (!set) throw Error('Argument charset not valid')
    set = set.replace(RegExp(`[${escapeRegex(exclude)}]`, 'g'), '')
    if (required.has(char)) requires.push(set)
    chars = new Set([...chars, ...set.split('')])
  }
  return {
    chars: [...chars].join(''),
    requires
  }
}

function divmod(a,b) {
  return [Math.floor(a / b), a % b]
}

// calculateMasterKey takes ~ 1450.000ms to complete
async function calculateMasterKey(password, {ID, keylen = 64}) {
  if (!ID || !ID.length) {
    throw Error("Argument ID not present");
  }
  if (!password || !password.length) {
    throw Error("Argument password not present");
  }

  try {

    // Convert password string to a Uint8Array w/ UTF-8
    password = txtencoder.encode(password);

    // Convert ID string to a Uint8Array w/ UTF-8
    ID = txtencoder.encode(ID);

    // Convert KeyNS string to a Uint8Array w/ UTF-8
    let NS = txtencoder.encode(KeyNS);

    // Create salt array and a DataView representing it
    let salt = new Uint8Array(
      NS.length
      + 4/*sizeof(uint32)*/ + ID.length
    );
    let saltView = new DataView(salt.buffer, salt.byteOffset, salt.byteLength);
    let i = 0;

    // Set salt[0,] to NS
    salt.set(NS, i); i += NS.length;

    // Set salt[i,i+4] to ID.length UINT32 in big-endian form
    saltView.setUint32(i, ID.length, false/*big-endian*/); i += 4/*sizeof(uint32)*/;

    // Set salt[i,] to ID
    salt.set(ID, i); i += ID.length;
    // Derive the master key w/ scrypt
    // why is buflen 64*8==512 and not 32*8==256 ?
    return new Promise((resolve, reject) => {
      cryp.scrypt(password, salt, keylen, {
        N: 32768,
        r: 8,
        p: 2,
        maxmem: 64*1024*1024
      }, (error, key) => {
        if (error) reject(error)
        else resolve(key)
      })
    })

  } catch (e) {
    return Promise.reject(e);
  }
}

// calculateSubKey takes ~ 3.000ms to complete
async function calculateSubKey(masterKey, {name, counter = 1}, context = null) {
  if (!name) {
    throw Error("Argument name not present");
  }

  if (counter < 1 || counter > Math.pow(2, 32) - 1) {
    throw Error("Argument counter out of range");
  }

  try {

    // Convert salt string to a Uint8Array w/ UTF-8
    name = txtencoder.encode(name);

    // Convert NS string to a Uint8Array w/ UTF-8
    const NS = txtencoder.encode(SubKeyNS);

    if (context) {
      // Convert context string to a Uint8Array w/ UTF-8
      context = txtencoder.encode(context);
    }

    // Create seed array and a seedView representing it
    const seed = new Uint8Array(
      NS.length
      + 4/*sizeof(uint32)*/ + name.length
      + 4/*sizeof(int32)*/
      + (context
        ? 4/*sizeof(uint32)*/ + context.length
        : 0)
    );
    const seedView = new DataView(seed.buffer, seed.byteOffset, seed.byteLength);
    let i = 0;

    // Set seed[0,] to NS
    seed.set(NS, i); i += NS.length;

    // Set seed[i,i+4] to name.length UINT32 in big-endian form
    seedView.setUint32(i, name.length, false/*big-endian*/); i += 4/*sizeof(uint32)*/;

    // Set seed[i,] to name
    seed.set(name, i); i += name.length;

    // Set seed[i,i+4] to counter INT32 in big-endian form
    seedView.setInt32(i, counter, false/*big-endian*/); i += 4/*sizeof(int32)*/;

    if (context) {
      // Set seed[i,i+4] to context.length UINT32 in big-endian form
      seedView.setUint32(i, context.length, false/*big-endian*/); i += 4/*sizeof(uint32)*/;

      // Set seed[i,] to context
      seed.set(context, i); i += context.length;
    }

    const hmac = cryp.createHmac('sha256', seed);
    hmac.update(masterKey)
    return parseInt(hmac.digest('hex'), 16)
  } catch (e) {
    return Promise.reject(e);
  }
}

async function calculateEntropy(password, config = {}, context = null) {
  const masterKey = await calculateMasterKey(password, config)
  return calculateSubKey(masterKey, config, context)
}

function render(entropy, charset, length, pass = '') {
  if (pass.length >= length) return [pass, entropy]
  const [q, r] = divmod(entropy, charset.length)
  return render(q, charset, length, pass.concat(charset[r]))
}

export async function generate(
  password,
  {
    length = 14,
    ...config
  } = {},
  context = null
) {

  const {
    chars,
    requires
  } = getCharsetProfile(config)

  if (length < 1 || length > 36) {
    throw Error("Argument length out of range");
  }

  let pass = ''
  let entropy = null

  entropy = await calculateEntropy(password, config, context);
  [pass, entropy] = render(
    entropy,
    chars,
    length - requires.length,
  )

  pass = pass.split('')
  requires.forEach((set) => {
    const [char, char_entropy] = render(entropy, set, 1)
    const [q, r] = divmod(char_entropy, pass.length)
    pass.splice(r, 0, char)
    entropy = q
  })
  return pass.join('')
}
