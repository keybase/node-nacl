{bufeq_secure} = require './util'
{Base} = require './base'

#================================================================

exports.b2u = b2u = (b) -> new Uint8Array(b)
exports.u2b = u2b = (u) -> new Buffer u

#================================================================

# 
# @class Sodium
#
#  A C-based implemenation using the libsodium library
#
exports.Sodium = class Sodium extends Base

  #
  # verify
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
    msg = if detached then Buffer.concat [ sig, payload ] else sig
    code = @lib.c.crypto_sign_open msg, @publicKey
    if code < 0
      err = new Error "Signature failed to verify"
      return [ err, null ]
    r_payload = sig[@lib.c.crypto_sign_BYTES...]
    if payload?
      unless bufeq_secure r_payload, payload
        err = new Error "got unexpected payload"
        return [ err, null] 
    else
      payload = r_payload
    return [ err, payload ] 

#================================================================
