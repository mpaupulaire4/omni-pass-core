import cryp from 'crypto'
import { getCharsetProfile } from './charset'
import { render } from './renderPassword'

// Base Namespace
const NSB = "com.omnipass";
// The namespace used in calculateMasterKey
const KeyNS   = `${NSB}.key`;
// The namespaces used in calculateSubKey
const SubKeyNS   = `${NSB}.subkey`;

// calculateMasterKey takes ~ 1450.000ms to complete
async function calculateMasterKey(password, { ID }) {
  if (!ID || !ID.length) {
    throw Error("Argument ID not present");
  }

  if (!password || !password.length) {
    throw Error("Argument password not present");
  }

  return new Promise((resolve, reject) => {
    cryp.scrypt(password, `${KeyNS}.${ID.length}.${ID}`, 64, {
      N: 32768,
      r: 8,
      p: 2,
      maxmem: 64*1024*1024
    }, (error, key) => {
      if (error) reject(error)
      else resolve(key)
    })
  })
}

// calculateSubKey takes ~ 3.000ms to complete
async function calculateSubKey(masterKey, {name, counter = 1, length}, context = 'password') {
  if (!name || typeof name !== 'string') {
    throw Error("Argument name not present");
  }

  if (!context || typeof context !== 'string') {
    throw Error("Argument context not present");
  }

  if (typeof counter !== 'number' || counter < 1 || counter > Math.pow(2, 32) - 1) {
    throw Error("Argument counter out of range");
  }

  const salt = `${SubKeyNS}.${name.length}.${name}.${context.length}.${context}.${counter}`
  return new Promise((resolve, reject) => {
    cryp.pbkdf2(
      masterKey,
      salt,
      10000,
      64,
      'sha256',
      (e, key) => {
        if (e) reject(e)
        else resolve(key)
      }
    );
  })
}

async function calculateEntropy(password, config = {}, context) {
  const masterKey = await calculateMasterKey(password, config)
  const subKey = await calculateSubKey(masterKey, config, context)
  return subKey
}

export async function generate(
  password,
  {
    length = 14,
    ...config
  } = {},
  context
) {

  const {
    chars,
    requires
  } = getCharsetProfile(config)

  if (length < 1 || length > 36) {
    throw Error("Argument length out of range");
  }

  const entropy = await calculateEntropy(password, config, context);
  const [pass] = render(
    entropy,
    chars,
    length,
    requires
  )

  return pass
}
