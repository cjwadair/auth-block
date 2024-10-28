require "scrypt"
require "openssl/hmac"
require "msgpack"
require "monocypher"
require "ed25519"

# TODO: Write documentation for `Auth::Block`
module Auth::Block
  
  VERSION = "0.1.0"

  include MessagePack::Serializable

  # This is a proof of concept for the Seitan Token Exchange protocol
  # Inviting Side
  # 1. Generate a random string 17 chars in length to use as the invitation key
  # 2. Stretch the key to 32 chars using scrypt
  # 3. Generate Invitation ID
  # 4. Generate the EdDSA keypair
  # 5. Sign the invitation ID with the signing key
  # 6. Sign a Hash with the expected response values in a predetermined format
  #   - This could be done by sending a message to a second trusted device (ie - phone and email), by signing using information about the person being invited that only they would know, etc
  # 7. Package and save the invitation ID, expected response. Can be encrypted if needed
  # 
  # Accepting Side
  # 1. Receives the iKey via an external channel from the Inviting side
  # 2. Stretch the iKey to 32 chars using scrypt
  # 3. Generate the invitation ID
  # 4. Generate the EdDSA keypair
  # 5. Generate the expected response and sign it wih the signing key generated in step 4
  # 6 Submit the signed response and the invitation ID to the Inviting side
  # 
  # Inviting Side
  # 1. Decrypt the stored invitation ID and expected response
  # 2. Use the stored public key generated on the inviting side to verify the signature of the response submitted by the accepting side
  # 3. If the signature is valid, compare the original signed signature to the signed version that the accepting side submitted. If the key elements match, the accepting side is verified. 


  # STEP 1 :: Generate a random string  17 chars in length to use as the invitation key
  # 
  def self.generate_iKey
    Random::Secure.urlsafe_base64(16, padding:true).gsub(/[-_=]/, nil)[0..16]
  end


  # STEP 2 :: Stretch the key to 32 chars using scrypt
  # IMPORTANT -- need to verify that these are correct parameters
  def self.compute_stretched_ikey(iKey)
    Scrypt::Engine.crypto_scrypt(iKey, "", 2**10, 8, 1, 32)
  end


  # STEP 3 :: Generate Invitation ID
  def self.generate_invitation_id(s_iKey, msg)
    OpenSSL::HMAC.hexdigest(:sha512, s_iKey, msg)[0..15]
  end


  # STEP 4A Generate a 32-byte random seed using the s_iKey and a message
  def self.generate_seed(s_iKey, msg)
    OpenSSL::HMAC.digest(:sha512, s_iKey, msg)[0..31]
  end 


  # STEP 4B - Generate a signing key from the seed, and a verify key from the signing key
  def self.generate_keys(seed)
    signing_key = Ed25519::SigningKey.new(seed)
    verify_key = signing_key.verify_key
    return signing_key, verify_key
  end


  # STEP 5 :: Sign the invitation ID with the signing key
  def self.sign_message(signing_key, msg)
    signing_key.sign(msg)
  end

  # Check the validity of a signature (for proof of concept)
  def self.verify_signature(verify_key, signature, msg)
    verify_key.verify(signature, msg)
  end


end
