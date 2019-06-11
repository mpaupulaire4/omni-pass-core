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

export function escapeRegex(string) {
  return string.replace(RegExp(`[${specials.join('\\')}]`, 'g'), '\\$&')
}

module.exports = {
  escapeRegex,
}
