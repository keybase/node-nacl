nonceBytes = 24
{rng} = require('crypto')

nonceForSenderKeySecretBox = () -> return new Buffer('saltpack_sender_key_sbox')

nonceForPayloadKeyBox = () -> return new Buffer('saltpack_payload_key_box')

nonceForMACKeyBox = (headerHash) ->
  if headerHash.length isnt 64 then return new Error('Header hash shorter than expected')
  return new Buffer(headerHash[0...nonceBytes])

nonceForChunkSecretBox = (encryptionBlockNumber) ->
  nonce = new Buffer('saltpack_ploadsb')
  return Buffer.concat([nonce, uint64be.encode(encryptionBlockNumber)])
