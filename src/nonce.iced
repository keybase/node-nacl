nonceBytes = 24
sigNonceBytes = 16
{prng} = require('crypto')
uint64be = require('uint64be')

exports.nonceForSenderKeySecretBox = () -> return new Buffer('saltpack_sender_key_sbox')

exports.nonceForPayloadKeyBox = () -> return new Buffer('saltpack_payload_key_box')

exports.nonceForMACKeyBox = (headerHash) ->
  if headerHash.length isnt 64 then return new Error('Header hash shorter than expected')
  return new Buffer(headerHash[0...nonceBytes])

exports.nonceForChunkSecretBox = (encryptionBlockNumber) ->
  nonce = new Buffer('saltpack_ploadsb')
  return Buffer.concat([nonce, uint64be.encode(encryptionBlockNumber)])

exports.sigNonce = () -> return prng(sigNonceBytes)
