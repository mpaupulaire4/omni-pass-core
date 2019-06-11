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

module.exports = {
  escapeRegex,
}
