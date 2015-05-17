
nacl_js = require 'tweetnacl/nacl-fast'
nacl_c = null 

try
  nacl_c = require('sodium').api
catch e
  # noop

exports.publicKeyLength = nacl_js.publicKeyLength
exports.secretKeyLength = nacl_js.secretKeyLength
exports.b2u = b2u = (b) -> new Uint8Array(b)
exports.u2b = u2b = (u) -> new Buffer u

#---------------------------------------------------------
# Constant-time buffer comparison
#
bufeq_secure = (x,y) ->
  ret = if not x? and not y? then true
  else if not x? or not y? then false
  else if x.length isnt y.length then false
  else
    check = 0
    for i in [0...x.length]
      check |= (x.readUInt8(i) ^ y.readUInt8(i))
    (check is 0)
  return ret

#================================================================
#
# fromSeed
#
# Generate an EdDSA keypair from a deterministic seed.
#
# @param {Buffer} seed The seed
# @return {Object} Contained `publicKey`, `secretKey` buffers
# 
# 
exports.fromSeed = ({seed}) ->

  # As of sodium@1.0.13, there is no wrapper for crypto_sign_seed_keypair,
  # so use TweetNaCl's for all.
  {secretKey, publicKey} = nalc_js.sign.keyPair.fromSeed b2u seed

  # Note that the tweetnacl library deals with Uint8Arrays,
  # and internally, we like node-style Buffers.
  return {
    secretKey : u2b secretKey,
    publicKey : u2b publicKey
  }


#================================================================
#
# verify
#
# Verify a signature, given a public key, the signature, and the payload
# (if it's not alread attached).
#
# @param {Bool} detached If this is a detached signature or not.
# @param {Buffer} payload The payload to verify. Optional, might be attached.
# @param {Buffer} sig The signature to verify.
# @param {Buffer} publicKey The public key to verify with.
# @return {List<Error,Buffer>} error on a failure, or nil on success. On sucess,
#   also return the payload from the buffer.
#
exports.verify = ({payload, sig, detached, publicKey}) ->
  f = if nacl_c? then verify_c else verify_js
  f { payload, sig, detached, publicKey }

#----------------------------

verify_js = ({payload, sig, detached, publicKey}) ->
  # "Attached" signatures in NaCl are just a concatenation of the signature
  # in front of the message.
  err = null
  if detached
    payload = new Buffer [] if not payload?
    if not nacl_js.sign.detached.verify b2u(payload), b2u(sig), b2u(publicKey)
      err = new Error "signature didn't verify"
  else if not (r_payload = nacl_js.sign.open b2u(sig), b2u(publicKey))?
    err = new Error "signature didn't verify"
  else if not (r_payload = u2b r_payload)?
    err = new Error "failed to convert from a Uint8Array to a buffer"
  else if payload? and not bufeq_secure(r_payload, payload)
    err = new Error "got unexpected payload"
  else
    payload = r_payload
  return [ err, payload ]

#----------------------------

verify_c = ({payload, sig, detached, publicKey}) ->
  if detached and not payload?
    err = new Error "in detached mode, you must supply a payload"
    return [ err, null ]
  msg = if detached then Buffer.concat [ sig, payload ] else sig
  err = nalc_c.cyrpto_sign_open msg, publicKey

#================================================================
