{prng} = require('crypto')
main = require('../../')
util = require('../../src/util.iced')
nonce = require('../../src/nonce.iced')

msg = prng((1024**2)*20)

test_encrypt_decrypt = (T, encryptor, decryptor, nonce, cb) ->
  ciphertext = encryptor.encrypt({plaintext : msg, nonce : nonce, pubkey : decryptor.publicKey})
  plaintext = decryptor.decrypt({ciphertext : ciphertext, nonce: nonce, pubkey : encryptor.publicKey})
  T.assert(util.bufeq_secure(msg, plaintext)?, "inconsistency detected: msg=#{msg}, ciphertext=#{ciphertext}, plaintext=#{plaintext}")
  cb()

test_encrypt_encrypt = (T, tweetnacl, sodium, nonce, recipient, cb) ->
  twncl_ctext = tweetnacl.encrypt({plaintext : msg, nonce : nonce, pubkey : recipient.publicKey})
  sodium_ctext = sodium.encrypt({plaintext : msg, nonce : nonce, pubkey : recipient.publicKey})
  T.assert(util.bufeq_secure(twncl_ctext, sodium_ctext)?, "ciphertexts differ: tweetnacl=#{twncl_ctext}, sodium=#{sodium_ctext}")
  cb()

exports.test_tweetnacl_consistency = (T, cb) ->
  tweetnacl = main.alloc({force_js : true})
  tweetnacl.genBoxPair()
  await test_encrypt_decrypt(T, tweetnacl, tweetnacl, nonce.nonceForChunkSecretBox(1), defer())
  cb()

exports.test_libsodium_consistency = (T, cb) ->
  sodium = main.alloc({force_js : false})
  sodium.genBoxPair()
  await test_encrypt_decrypt(T, sodium, sodium, nonce.nonceForChunkSecretBox(1), defer())
  cb()

exports.test_cross_consistency = (T, cb) ->
  sodium = main.alloc({force_js : false})
  sodium.genBoxPair()
  tweetnacl = main.alloc({force_js : true})
  tweetnacl.genBoxPair()
  await test_encrypt_decrypt(T, sodium, tweetnacl, nonce.nonceForChunkSecretBox(1), defer())
  await test_encrypt_decrypt(T, tweetnacl, sodium, nonce.nonceForChunkSecretBox(1), defer())
  cb()

exports.test_ciphertext_output = (T, cb) ->
  tweetnacl = main.alloc({force_js : true})
  tweetnacl.genBoxPair()
  sodium = main.alloc({force_js : false})
  sodium.secretKey = tweetnacl.secretKey
  sodium.publicKey = tweetnacl.publicKey
  recipient = main.alloc({force_js : true})
  recipient.genBoxPair()
  await test_encrypt_encrypt(T, tweetnacl, sodium, nonce.nonceForChunkSecretBox(1), recipient, defer())
  cb()
