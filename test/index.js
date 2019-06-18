const tap = require('tap');
const {
  generate,
  calculateMasterKey,
  calculateEntropy
} = require('../src');

tap.test('Calculate Master Key', async (t) => {
  t.matchSnapshot(
    await calculateMasterKey('username', 'password'),
    'Should always generate the same key'
  )

  t.deepEqual(
    await calculateMasterKey('username', 'password'),
    await calculateMasterKey('username', 'password'),
    'Should generate the same key given the same inputs'
  )

  t.notDeepEqual(
    await calculateMasterKey('username', 'password'),
    await calculateMasterKey('username', 'password1'),
    'Should generate different key given same username but different password'
  )

  t.notDeepEqual(
    await calculateMasterKey('username', 'password'),
    await calculateMasterKey('username1', 'password'),
    'Should generate different key given same password but different username'
  )
})

tap.test('Generate', async (t) => {

  t.matchSnapshot(
    await generate('username', 'password', {
      context: 'some.site.com'
    }),
    'Defaults Should always generate the same '
  )

  t.deepEqual(
    await generate('username', 'password', { context: 'some.sute.com'}),
    await generate('username', 'password', { context: 'some.sute.com'}),
    'Should generate the same string given the same inputs'
  )

  t.notDeepEqual(
    await generate('username', 'password', {
      context: 'some.site.come',
      counter: 1
    }),
    await generate('username', 'password', {
      context: 'some.site.come',
      counter: 2
    }),
    'Should generate different string given a different counter'
  )

  t.notDeepEqual(
    await generate('username', 'password', {
      name: 'one',
      context: 'some.site.come',
    }),
    await generate('username', 'password', {
      context: 'some.site.come',
      name: 'two'
    }),
    'Should generate different string given a different context'
  )
})