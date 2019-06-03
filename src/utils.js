// 24*#SLZs@%VNgj

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

export function divmod(a,b) {
  return [Math.floor(a / b), a % b]
}
