const { escapeRegex } = require('./utils')

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
  S: " ",
  s: " ",
})

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

module.exports = {
  charsets,
  getCharsetProfile
}