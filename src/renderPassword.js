import { escapeRegex } from './utils'
import { charsets } from './charset';

export function render([rand, ...entropy], charset, length, requires = [], pass = []) {
  // recursive end case
  if (pass.length >= length - requires.length) {
    // for each unmet requirement add a prandom char at a prandom index
    requires.forEach((set) => {
      const r = rand % pass.length
      const [char, char_entropy] = render(entropy, set, 1)
      pass.splice(r, 0, char)
      rand = char_entropy.shift()
      entropy = char_entropy
    })
    return [pass.join(''), [rand, ...entropy]]
  }

  // make sure there is a number to work with
  if (typeof rand !== 'number') throw Error('Render Error')

  // get the pseudorandom char
  const char = charset[rand % charset.length]

  // check if a requirement is met. If so remove the requirement
  const i = requires.findIndex((set) => RegExp(`[${escapeRegex(set)}]`).test(char))
  if ( i !== -1) requires.splice(i, 1)

  // next step
  return render(entropy, charset, length, requires, pass.concat(char))
}

export function renderFromTemplate(entropy, template = '') {
  if (typeof template !== 'string') throw Error('Invalid template parameter')
  const pass = []
  for (const temp of template) {
    const chars = charsets[temp]
    if (!chars) throw Error('Invalid template parameter')

    const [char, char_entropy] = render(entropy, chars, 1)
    pass.push(char)
    entropy = char_entropy
  }
  return [pass.join(''), entropy]
}