main = require('../../')
{rng} = require('crypto')

msg = new Buffer('If you please--draw me a sheep!')

test_encrypt_decrypt = (T, encryptor, decryptor, nonce, cb) ->
  ciphertext = encryptor.box(msg, nonce, decryptor.get_public_key(), encryptor.get_secret_key())
  plaintext = decryptor.decrypt(ciphertext, nonce, encryptor.get_public_key(), decryptor.get_secret_key())
  success = main.util.bufeq_secure(msg, plaintext)
  T.assert(success?, "inconsistency detected: msg=#{msg}, ciphertext=#{ciphertext}, plaintext=#{plaintext}")

exports.test_tweetnacl_tweetnacl_encrypt_decrypt = (T, cb) ->
  tweetnacl = main.alloc({force_js : true})
  tweetnacl.genFromSeed({seed : rng(main.sign.seedLength)})
  await test_encrypt(T, tweetnacl, tweetnacl), defer(err)
  cb(err)
