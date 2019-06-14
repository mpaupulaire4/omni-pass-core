const { pbkdf2 } = require('pbkdf2')
const { Buffer } = require('safe-buffer')
const scrypt = require('scrypt-js')
const { render } = require('./renderPassword')

// Base Namespace
const NSB = "com.omnipass";
// The namespace used in calculateMasterKey
const KeyNS   = `${NSB}.key`;
// The namespaces used in calculateSubKey
const SubKeyNS   = `${NSB}.subkey`;

const DefaultConfig = Object.freeze({
  name: 'password',
  counter: 1,
  rounds: 10000,
  length: 16,
  charset: 'X',
  exclude: '',
  required: 'Aano',
})

// calculateMasterKey takes ~ 1450.000ms to complete
async function calculateMasterKey(username, password) {
  if (!username || !username.length) {
    throw Error("Argument username not present");
  }

  if (!password || !password.length) {
    throw Error("Argument password not present");
  }

  // TODO either normaliza password and salt or restrict the posibilities /^[A-Za-z0-9!@#$%^&*()]+$/
  return new Promise((resolve, reject) => {
    return scrypt(
      Buffer.from(password.normalize('NFKC')),
      Buffer.from(`${KeyNS}.${username.length}.${username}`.normalize('NFKC')),
      32768,
      8,
      2,
      64,
      (e, p, key) => {
        if (e) reject(e)
        else if (key) resolve(Buffer.from(key))
      }
    )
  })
}

// calculateSubKey takes ~ 3.000ms to complete
async function calculateEntropy(masterKey, config) {
  const { context, name, counter, rounds, length } = { ...DefaultConfig, ...config }
  if (!name || typeof name !== 'string') {
    throw Error("Argument name not present");
  }

  if (!context || typeof context !== 'string') {
    throw Error("Argument context not present");
  }

  if (typeof counter !== 'number' || counter < 1 || counter > Math.pow(2, 32) - 1) {
    throw Error("Argument counter out of range");
  }

  const salt = `${SubKeyNS}.${context.length}.${context}.${name.length}.${name}.${counter}`
  return new Promise((resolve, reject) => {
    pbkdf2(
      masterKey,
      salt,
      rounds,
      Math.max(64, length),
      'sha256',
      (e, key) => {
        if (e) reject(e)
        else resolve(key)
      }
    );
  })
}

async function generate(
  username,
  password,
  config
) {
  config = {...DefaultConfig, ...config}

  const entropy = await calculateEntropy(
    await calculateMasterKey(username, password),
    config,
  );

  const [pass] = render(
    entropy,
    config
  )

  return pass
}

async function generateFromMasterKey(
  masterKey,
  config
) {
  config = {...DefaultConfig, ...config}

  const entropy = await calculateEntropy(
    masterKey,
    config,
  );

  const [pass] = render(
    entropy,
    config
  )

  return pass
}

module.exports = {
  calculateMasterKey,
  DefaultConfig,
  generate,
  generateFromMasterKey
}
