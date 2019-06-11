const test = require('tape');
const {
  generate,
  calculateMasterKey,
  calculateEntropy
} = require('../src');

test('Calculate Master Key', async (t) => {
  t.plan(4)

  t.deepEqual(
    [...(await calculateMasterKey('username', 'password'))],
    [ 215,3,247,51,86,243,70,223,201,26,16,30,19,215,254,181,19,129,197,228,192,83,124,120,33,161,164,219,195,220,100,159,99,58,88,151,218,138,246,42,101,74,184,115,248,179,13,194,3,83,17,194,195,36,129,210,0,210,38,201,255,114,103,62 ],
    'Should always generate the same key'
  )

  t.deepEqual(
    [...(await calculateMasterKey('username', 'password'))],
    [...(await calculateMasterKey('username', 'password'))],
    'Should generate the same key given the same inputs'
  )

  t.notDeepEqual(
    [...(await calculateMasterKey('username', 'password'))],
    [...(await calculateMasterKey('username', 'password1'))],
    'Should generate different key given same username but different password'
  )

  t.notDeepEqual(
    [...(await calculateMasterKey('username', 'password'))],
    [...(await calculateMasterKey('username1', 'password'))],
    'Should generate different key given same password but different username'
  )
})

test('Calculate Entropy', async (t) => {
  t.plan(4)

  t.deepEqual(
    [...(await calculateEntropy(Buffer.from([1,2,3,4]), {
      name: 'some.site.com'
    }))],
    [ 231, 230, 47, 147, 153, 98, 129, 10, 17, 238, 46, 254, 236, 97, 91, 237, 102, 209, 201, 242, 24, 30, 13, 76, 45, 172, 64, 128, 241, 242, 222, 127, 216, 160, 122, 161, 133, 126, 105, 88, 57, 146, 123, 173, 10, 32, 72, 136, 30, 116, 79, 136, 87, 215, 89, 210, 81, 59, 231, 192, 107, 200, 125, 65 ],
    'Defaults Should always generate the same prandom bits'
  )

  t.deepEqual(
    [...(await calculateEntropy('username', { name: 'some.sute.com'}))],
    [...(await calculateEntropy('username', { name: 'some.sute.com'}))],
    'Should generate the same bits given the same inputs'
  )

  t.notDeepEqual(
    [...(await calculateEntropy('username', {
      name: 'some.site.come',
      counter: 1
    }))],
    [...(await calculateEntropy('username', {
      name: 'some.site.come',
      counter: 2
    }))],
    'Should generate different bits given a different counter'
  )

  t.notDeepEqual(
    [...(await calculateEntropy('username', {
      name: 'some.site.come',
    }, 'one'))],
    [...(await calculateEntropy('username', {
      name: 'some.site.come',
    }, 'two'))],
    'Should generate different bits given a different context'
  )

})