{bufeq_secure} = require './util'
{Base} = require './base'

#================================================================

# 
# @class Sodium
#
#  A C-based implemenation using the libsodium library
#
exports.Sodium = class Sodium extends Base

  #------

  _detach : (sig) ->
    l = @lib.c.crypto_sign_BYTES
    { sig: sig[0...l], payload : sig[l...] }

  #------
  
  #
  # @method verify
  #
  # Verify a signature, given a public key, the signature, and the payload
  # (if it's not alread attached).
  #
  # @param {Bool} detached If this is a detached signature or not.
  # @param {Buffer} payload The payload to verify. Optional, might be attached.
  # @param {Buffer} sig The signature to verify.
  # @return {List<Error,Buffer>} error on a failure, or nil on success. On sucess,
  #   also return the payload from the buffer.
  #
  verify : ({payload, sig, detached}) ->
    if detached and not payload?
      err = new Error "in detached mode, you must supply a payload"
      return [ err, null ]
    msg = if detached then Buffer.concat([sig, payload]) else sig

    r_payload = @lib.c.crypto_sign_open msg, @publicKey

    if not r_payload?
      err = new Error "Signature failed to verify"
    else if detached then # noop
    else if not payload? then payload = r_payload
    else if not bufeq_secure r_payload, payload
      err = new Error "got unexpected payload"
    if err? then payload = null
    return [ err, payload ]

  #
  # @method sign
  #
  # Generate a signature
  #
  # @param {Buffer} payload The message to sign
  # @param {Boolean} detached Whether this is a detached message or not
  #
  sign : ({detached, payload}) ->
    sig = @lib.c.crypto_sign payload, @secretKey
    if detached then @_detach(sig).sig else sig

  #
  # @method encrypt
  # Encrypt a given plaintext
  # @param {Buffer} plaintext The plaintext to encrypt
  # @param {Buffer} nonce The nonce
  # @param {Buffer} pubkey The public key to encrypt for
  # @return {Buffer} The encrypted plaintext
  encrypt : ({plaintext, nonce, pubkey}) ->
    return @lib.c.crypto_box(plaintext, nonce, pubkey, @secretKey)[16...]

  #
  # @method secretbox
  # Secretbox a given plaintext
  # @param {Buffer} plaintext The plaintext to encrypt
  # @param {Buffer} nonce The nonce
  # @return {Buffer} The encrypted plaintext
  secretbox : ({plaintext, nonce}) ->
    return @lib.c.crypto_secretbox(plaintext, nonce, @secretKey)[16...]

  #
  # @method decrypt
  # 
  # @param {Buffer} ciphertext The ciphertext to decrypt
  # @param {Buffer} nonce The nonce 
  # @param {Buffer} pubkey The public key that was used for encryption
  # @return {Buffer} The decrypted plaintext
  decrypt : ({ciphertext, nonce, pubkey}) ->
    return @lib.c.crypto_box_open(Buffer.concat([Buffer.alloc(16), ciphertext]), nonce, pubkey, @secretKey)

  #
  # @method secretbox_open
  # Decrypt a given secretbox
  # @param {Buffer} ciphertext The ciphertext to decrypt
  # @param {Buffer} nonce The nonce
  # @return {Buffer} The decrypted plaintext
  secretbox_open : ({ciphertext, nonce}) ->
    return @lib.c.crypto_secretbox_open(Buffer.concat([Buffer.alloc(16), ciphertext]), nonce, @secretKey)

#================================================================
