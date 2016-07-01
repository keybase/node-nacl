main = require('../../')
util = require('../../src/util.iced')
nonce = require('../../src/nonce.iced')
{prng} = require('crypto')

msg = new Buffer('If you please--draw me a sheep!')

test_encrypt_decrypt = (T, encryptor, decryptor, nonce, cb) ->
  ciphertext = encryptor.encrypt({plaintext : msg, nonce : nonce, pubkey : decryptor.publicKey})
  console.log(ciphertext.toString('base64'))
  plaintext = decryptor.decrypt({ciphertext : ciphertext, nonce: nonce, pubkey : encryptor.publicKey})
  success = util.bufeq_secure(msg, plaintext)
  T.assert(success?, "inconsistency detected: msg=#{msg}, ciphertext=#{ciphertext}, plaintext=#{plaintext}")
  cb()

exports.test_tweetnacl_tweetnacl_consistency = (T, cb) ->
  tweetnacl = main.alloc({force_js : true})
  tweetnacl.genBoxPair()
  await test_encrypt_decrypt(T, tweetnacl, tweetnacl, nonce.nonceForChunkSecretBox(1), defer())
  cb()

exports.test_libsodium_libsodium_consistency = (T, cb) ->
  sodium = main.alloc({force_js : false})
  sodium.genBoxPair()
  await test_encrypt_decrypt(T, sodium, sodium, nonce.nonceForChunkSecretBox(1), defer())
  cb()
