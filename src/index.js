const crypo = require('crypto')
const scrypt = require('scrypt-js')
const { getCharsetProfile } = require('./charset')
const { render } = require('./renderPassword')

// Base Namespace
const NSB = "com.omnipass";
// The namespace used in calculateMasterKey
const KeyNS   = `${NSB}.key`;
// The namespaces used in calculateSubKey
const SubKeyNS   = `${NSB}.subkey`;

// calculateMasterKey takes ~ 1450.000ms to complete
async function calculateMasterKey(username, password) {
  if (!username || !username.length) {
    throw Error("Argument username not present");
  }

  if (!password || !password.length) {
    throw Error("Argument password not present");
  }

  return new Promise((resolve, reject) => {
    // TODO either normaliza password and salt or restrict the posibilities /^[A-Za-z0-9!@#$%^&*()]+$/
    scrypt(
      Buffer.from(password.normalize('NFKC')),
      Buffer.from(`${KeyNS}.${username.length}.${username}`.normalize('NFKC')),
      32768,
      8,
      2,
      64,
      (error, progress, key) => {
      if (error) reject(error)
      else if (key) resolve(Buffer.from(key))
    })
  })
}

// calculateSubKey takes ~ 3.000ms to complete
async function calculateEntropy(masterKey, {context, name = 'password', counter = 1, rounds = 10000, digest = 'sha256'}) {
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
    crypo.pbkdf2(
      masterKey,
      salt,
      rounds,
      64,
      digest,
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

  const {
    chars,
    requires
  } = getCharsetProfile(config)

  const entropy = await calculateEntropy(
    await calculateMasterKey(username, password),
    config,
  );
  const [pass] = render(
    entropy,
    chars,
    config.length,
    requires
  )

  return pass
}

module.exports = {
  generate,
  calculateMasterKey,
  calculateEntropy,
}
