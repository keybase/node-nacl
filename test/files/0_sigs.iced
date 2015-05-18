
main = require '../../'
{rng} = require 'crypto'

tweak = (x) ->
  x[x.length-1] ^= 0x1

msg = new Buffer """The vision of a rock where lightnings whirl'd
  Bruising the darkness with their carkling light ;""", "utf8"

test_attached = (T,signer,verifier,cb) ->
  sig = signer.sign { payload: msg, detached : false }
  [err, payload] = verifier.verify { payload : msg, detached : false, sig }
  T.no_error err
  cb()

test_detached = (T,sign,verify,cb) ->
  cb()

exports.test_sodium_sodium = (T, cb) ->
  sodium = main.alloc { force_js : false }
  sodium.genFromSeed { seed : rng(main.sign.seedLength) }
  await test_attached T, sodium, sodium, defer err
  cb err
