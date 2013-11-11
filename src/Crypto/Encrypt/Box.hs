{-# LANGUAGE EmptyDataDecls           #-}
{-# LANGUAGE ForeignFunctionInterface #-}
-- |
-- Module      : Crypto.Encrypt.Box
-- Copyright   : (c) Austin Seipp 2011-2013
-- License     : MIT
--
-- Maintainer  : aseipp@pobox.com
-- Stability   : experimental
-- Portability : portable
--
-- Authenticated public-key encryption.
--
-- The underlying encryption primitive is known as
-- @curve25519xsalsa20poly1305@, a particular combination of
-- Curve25519, Salsa20, and Poly1305. See the specification,
-- \"Cryptography in NaCl\":
-- <http://cr.yp.to/highspeed/naclcrypto-20090310.pdf>
--
-- This module is intended to be imported @qualified@ to avoid name
-- clashes with other cryptographic primitives, e.g.
--
-- > import qualified Crypto.Encrypt.Box as Box
--
module Crypto.Encrypt.Box
       ( -- * Security model
         -- $securitymodel

         -- * Types
         Box           -- :: *
       , createKeypair -- :: IO (PublicKey Box, SecretKey Box)

         -- * Encrypting messages
       , encrypt -- :: Nonce Box -> ByteString -> PublicKey Box -> SecretKey Box ->  ByteString
       , decrypt -- :: Nonce Box -> ByteString -> PublicKey Box -> SecretKey Box -> Maybe ByteString

         -- * Precomputation interface
         -- $precomp
       , NM        -- :: *
       , createNM  -- :: PublicKey Box -> SecretKey Box -> NM
       , encryptNM -- :: NM -> Nonce Box -> ByteString -> ByteString
       , decryptNM -- :: NM -> Nonce Box -> ByteString -> Maybe ByteString
       ) where
import           Data.Word
import           Foreign.C.Types
import           Foreign.ForeignPtr       (withForeignPtr)
import           Foreign.Ptr

import           System.IO.Unsafe         (unsafePerformIO)

import           Data.ByteString          as S
import           Data.ByteString.Internal as SI
import           Data.ByteString.Unsafe   as SU

import           Crypto.Key
import           Crypto.Nonce

-- $securitymodel
--
-- The @'encrypt'@ function is designed to meet the standard notions
-- of privacy and third-party unforgeability for a public-key
-- authenticated-encryption scheme using nonces. For formal
-- definitions see, e.g., Jee Hea An, "Authenticated encryption in the
-- public-key setting: security notions and analyses,"
-- <http://eprint.iacr.org/2001/079>.
--
-- Distinct messages between the same {sender, receiver} set are
-- required to have distinct nonces. For example, the
-- lexicographically smaller public key can use nonce 1 for its first
-- message to the other key, nonce 3 for its second message, nonce 5
-- for its third message, etc., while the lexicographically larger
-- public key uses nonce 2 for its first message to the other key,
-- nonce 4 for its second message, nonce 6 for its third message,
-- etc. Nonces are long enough that randomly generated nonces have
-- negligible risk of collision.
--
-- There is no harm in having the same nonce for different messages if
-- the {sender, receiver} sets are different. This is true even if the
-- sets overlap. For example, a sender can use the same nonce for two
-- different messages if the messages are sent to two different public
-- keys.
--
-- The @'encrypt'@ function is not meant to provide
-- non-repudiation. On the contrary: the @'encrypt'@ function
-- guarantees repudiability. A receiver can freely modify a boxed
-- message, and therefore cannot convince third parties that this
-- particular message came from the sender. The sender and receiver
-- are nevertheless protected against forgeries by other parties. In
-- the terminology of
-- <http://groups.google.com/group/sci.crypt/msg/ec5c18b23b11d82c>,
-- @'encrypt'@ uses \"public-key authenticators\" rather than
-- \"public-key signatures.\"
--
-- Users who want public verifiability (or receiver-assisted public
-- verifiability) should instead use signatures (or signcryption).

-- | A phantom type for representing types related to authenticated,
-- public-key encryption.
data Box

instance Nonces Box where
  nonceSize _ = boxNONCEBYTES

-- | The @'createKeypair'@ function randomly generates a @'SecretKey'@
-- and a corresponding @'PublicKey'@.
createKeypair :: IO (PublicKey Box, SecretKey Box)
createKeypair = do
  pk <- SI.mallocByteString boxPUBLICKEYBYTES
  sk <- SI.mallocByteString boxSECRETKEYBYTES

  _ <- withForeignPtr pk $ \ppk -> do
    _ <- withForeignPtr sk $ \psk -> do
      _ <- c_crypto_box_keypair ppk psk
      return ()
    return ()

  return (PublicKey $ SI.fromForeignPtr pk 0 boxPUBLICKEYBYTES,
          SecretKey $ SI.fromForeignPtr sk 0 boxSECRETKEYBYTES)

-- | The @'encrypt'@ function encrypts and authenticates a message @m@
-- using a sender's @'SecretKey'@ @sk@, the receiver's @'PublicKey'@
-- @pk@, and a @'Nonce'@ @n@.
--
-- This function produces ciphertext compatible with the NaCl
-- @crypto_box@ function.
encrypt :: Nonce Box
        -- ^ Nonce
        -> ByteString
        -- ^ Message
        -> PublicKey Box
        -- ^ Recievers @'PublicKey'@
        -> SecretKey Box
        -- ^ Senders @'SecretKey'@
        -> ByteString
        -- ^ Ciphertext
encrypt (Nonce n) msg (PublicKey pk) (SecretKey sk) = unsafePerformIO $ do
  -- inputs to crypto_box must be padded
  let m    = S.replicate boxZEROBYTES 0x0 `S.append` msg
      mlen = S.length m
      clen = S.length msg + boxBOXZEROBYTES
  c <- SI.mallocByteString clen

  -- as you can tell, this is unsafe
  _ <- withForeignPtr c $ \pc ->
    SU.unsafeUseAsCString m $ \pm ->
      SU.unsafeUseAsCString n $ \pn ->
        SU.unsafeUseAsCString pk $ \ppk ->
          SU.unsafeUseAsCString sk $ \psk ->
            c_crypto_box pc pm (fromIntegral mlen) pn ppk psk
  return $! SI.fromForeignPtr c 0 clen
{-# INLINE encrypt #-}

-- | The @'decrypt'@ function verifies and decrypts a ciphertext @c@
-- using the receiver's @'SecretKey'@ @sk@, the sender's @'PublicKey'@
-- @pk@ and a @'Nonce'@ @n@.
--
-- Like @'encrypt'@, @'decrypt'@ takes ciphertext that is compatible
-- with the NaCl C @crypto_box@ and @crypto_boxopen@ functions.
decrypt :: Nonce Box
        -- ^ Nonce
        -> ByteString
        -- ^ Input ciphertext
        -> PublicKey Box
        -- ^ Senders @'PublicKey'@
        -> SecretKey Box
        -- ^ Recievers @'SecretKey'@
        -> Maybe ByteString -- ^ Ciphertext
decrypt (Nonce n) cipher (PublicKey pk) (SecretKey sk) = unsafePerformIO $ do
  let c    = cipher
      clen = S.length c
      mlen = (clen - boxBOXZEROBYTES) + boxZEROBYTES
  m <- SI.mallocByteString mlen

  -- as you can tell, this is unsafe
  r <- withForeignPtr m $ \pm ->
    SU.unsafeUseAsCString c $ \pc ->
      SU.unsafeUseAsCString n $ \pn ->
        SU.unsafeUseAsCString pk $ \ppk ->
          SU.unsafeUseAsCString sk $ \psk ->
            c_crypto_box_open pm pc (fromIntegral mlen) pn ppk psk
  return $! if r /= 0 then Nothing
            else
              let bs = SI.fromForeignPtr m 0 mlen
              in Just $ SU.unsafeDrop boxZEROBYTES bs
{-# INLINE decrypt #-}

-- $precomp
--
-- If you send many messages to the same receiver, or receive many
-- messages from the same sender, you can gain speed increases by
-- instead using the following precomputation interface, which splits
-- the encryption and decryption steps into two parts.
--
-- For encryption, you first create an @'NM'@ by using @'createNM'@,
-- using the senders @'SecretKey'@, and receivers @'PublicKey'@. You
-- can then use @'encryptNM'@ to encrypt data.
--
-- For decryption, you first create an @'NM'@ by using @'createNM'@,
-- using the recievers @'SecretKey'@, and the senders
-- @'PublicKey'@. You can then use @'decryptNM'@ to decrypt data.


-- | An @'NM'@ is intermediate data computed by @'createNM'@ given a
-- public and private key which can be used to encrypt/decrypt
-- information via @'encryptNM'@ or @'decryptNM'@.
--
-- An @'NM'@ can be re-used between two communicators for any number
-- of messages.
--
-- Its name is not particularly enlightening as to its purpose, it is
-- merely the same identifier used in the NaCl source code for this
-- interface.
newtype NM = NM ByteString deriving (Eq, Show)

-- | Creates an intermediate piece of @'NM'@ data for
-- sending/receiving messages to/from the same person. The resulting
-- @'NM'@ can be used for any number of messages between
-- client/server.
createNM :: PublicKey Box -- ^ Sender/receiver @'PublicKey'@
         -> SecretKey Box -- ^ Sender/receiver @'SecretKey'@
         -> NM            -- ^ Precomputation box
createNM (PublicKey pk) (SecretKey sk) = unsafePerformIO $ do
  nm <- SI.mallocByteString boxBEFORENMBYTES
  _ <- withForeignPtr nm $ \pnm ->
    SU.unsafeUseAsCString pk $ \ppk ->
      SU.unsafeUseAsCString sk $ \psk ->
        c_crypto_box_beforenm pnm ppk psk
  return $! NM $ SI.fromForeignPtr nm 0 boxBEFORENMBYTES
{-# INLINE createNM #-}

-- | Encrypt data from a specific sender to a specific receiver with
-- some precomputed @'NM'@ data.
encryptNM :: NM -> Nonce Box -> ByteString -> ByteString
encryptNM (NM nm) (Nonce n) msg = unsafePerformIO $ do
  -- inputs to crypto_box must be padded
  let m    = S.replicate boxZEROBYTES 0x0 `S.append` msg
      mlen = S.length m
      clen = S.length msg + boxBOXZEROBYTES
  c <- SI.mallocByteString clen

  -- as you can tell, this is unsafe
  _ <- withForeignPtr c $ \pc ->
    SU.unsafeUseAsCString m $ \pm ->
      SU.unsafeUseAsCString n $ \pn ->
        SU.unsafeUseAsCString nm $ \pnm ->
          c_crypto_box_afternm pc pm (fromIntegral mlen) pn pnm
  return $! SI.fromForeignPtr c 0 clen
{-# INLINE encryptNM #-}

-- | Decrypt data from a specific sender for a specific receiver with
-- some precomputed @'NM'@ data.
decryptNM :: NM -> Nonce Box -> ByteString -> Maybe ByteString
decryptNM (NM nm) (Nonce n) cipher = unsafePerformIO $ do
  let c    = cipher
      clen = S.length c
      mlen = (clen - boxBOXZEROBYTES) + boxZEROBYTES
  m <- SI.mallocByteString mlen

  -- as you can tell, this is unsafe
  r <- withForeignPtr m $ \pm ->
    SU.unsafeUseAsCString c $ \pc ->
      SU.unsafeUseAsCString n $ \pn ->
        SU.unsafeUseAsCString nm $ \pnm ->
          c_crypto_box_open_afternm pm pc (fromIntegral mlen) pn pnm
  return $! if r /= 0 then Nothing
            else
              let bs = SI.fromForeignPtr m 0 mlen
              in Just $ SU.unsafeDrop boxZEROBYTES bs
{-# INLINE decryptNM #-}

--
-- FFI bindings
--

boxPUBLICKEYBYTES :: Int
boxPUBLICKEYBYTES = 32

boxSECRETKEYBYTES :: Int
boxSECRETKEYBYTES = 32

boxNONCEBYTES :: Int
boxNONCEBYTES = 24

boxZEROBYTES :: Int
boxZEROBYTES = 32

boxBOXZEROBYTES :: Int
boxBOXZEROBYTES = 16

boxBEFORENMBYTES :: Int
boxBEFORENMBYTES = 32

foreign import ccall unsafe "curve25519xsalsa20poly1305_box_keypair"
  c_crypto_box_keypair :: Ptr Word8 -> Ptr Word8 -> IO Int

foreign import ccall unsafe "curve25519xsalsa20poly1305_box"
  c_crypto_box :: Ptr Word8 -> Ptr CChar -> CULLong ->
                  Ptr CChar -> Ptr CChar -> Ptr CChar -> IO Int

foreign import ccall unsafe "curve25519xsalsa20poly1305_box_open"
  c_crypto_box_open :: Ptr Word8 -> Ptr CChar -> CULLong ->
                       Ptr CChar -> Ptr CChar -> Ptr CChar -> IO Int

foreign import ccall unsafe "curve25519xsalsa20poly1305_box_beforenm"
  c_crypto_box_beforenm :: Ptr Word8 -> Ptr CChar -> Ptr CChar -> IO Int

foreign import ccall unsafe "curve25519xsalsa20poly1305_box_afternm"
  c_crypto_box_afternm :: Ptr Word8 -> Ptr CChar -> CULLong ->
                          Ptr CChar -> Ptr CChar -> IO Int

foreign import ccall unsafe "curve25519xsalsa20poly1305_box_open_afternm"
  c_crypto_box_open_afternm :: Ptr Word8 -> Ptr CChar -> CULLong ->
                               Ptr CChar -> Ptr CChar -> IO Int
