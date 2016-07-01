main = require('../../')
util = require('../../src/util.iced')
nonce = require('../../src/nonce.iced')
base = require('../../src/base.iced')
{prng} = require('crypto')

msg = new Buffer('If you please--draw me a sheep!')

test_encrypt_decrypt = (T, encryptor, decryptor, nonce, cb) ->
  ciphertext = encryptor.lib.js.box(msg, nonce, decryptor.publicKey, encryptor.secretKey)
  plaintext = base.u2b(decryptor.lib.js.box.open(ciphertext, nonce, encryptor.publicKey, decryptor.secretKey))
  success = util.bufeq_secure(msg, plaintext)
  T.assert(success?, "inconsistency detected: msg=#{msg}, ciphertext=#{ciphertext}, plaintext=#{plaintext}")
  cb()

exports.test_tweetnacl_tweetnacl_encrypt_decrypt = (T, cb) ->
  tweetnacl = main.alloc({force_js : true})
  tweetnacl.genBoxPair()
  await test_encrypt_decrypt(T, tweetnacl, tweetnacl, nonce.nonceForChunkSecretBox(1), defer())
  cb()
