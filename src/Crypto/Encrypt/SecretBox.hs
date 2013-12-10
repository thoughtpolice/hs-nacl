{-# LANGUAGE EmptyDataDecls           #-}
{-# LANGUAGE ForeignFunctionInterface #-}
-- |
-- Module      : Crypto.Encrypt.SecretBox
-- Copyright   : (c) Austin Seipp 2011-2013
-- License     : BSD3
--
-- Maintainer  : aseipp@pobox.com
-- Stability   : experimental
-- Portability : portable
--
-- Authenticated secret-key encryption.
--
-- The selected underlying primitive used is
-- @crypto_secretbox_xsalsa20poly1305@, a particular combination of
-- XSalsa20 and Poly1305. See the specification, \"Cryptography in
-- NaCl\": <http://cr.yp.to/highspeed/naclcrypto-20090310.pdf>
--
-- This module is intended to be imported @qualified@ to avoid name
-- clashes with other cryptographic primitives, e.g.
--
-- > import qualified Crypto.Encrypt.SecretBox as SecretBox
--
module Crypto.Encrypt.SecretBox
       ( -- * Security model
         -- $securitymodel

         -- * Types
         SecretBox -- :: *

         -- * Key creation
       , randomKey -- :: IO (SecretKey SecretBox)

         -- * Encrypting messages
       , encrypt -- :: Nonce SecretBox -> ByteString -> SecretKey SecretBox -> ByteString
       , decrypt -- :: Nonce SecretBox -> ByteString -> SecretKey SecretBox -> Maybe ByteString
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
import           System.Crypto.Random

-- $securitymodel
--
-- The @'encrypt'@ function is designed to meet the standard notions
-- of privacy and authenticity for a secret-key
-- authenticated-encryption scheme using nonces. For formal
-- definitions see, e.g., Bellare and Namprempre, \"Authenticated
-- encryption: relations among notions and analysis of the generic
-- composition paradigm,\" Lecture Notes in Computer Science 1976
-- (2000), 531–545, <http://www-cse.ucsd.edu/~mihir/papers/oem.html>.
--
-- Note that the length is not hidden. Note also that it is the
-- caller's responsibility to ensure the uniqueness of nonces—for
-- example, by using nonce 1 for the first message, nonce 2 for the
-- second message, etc. Nonces are long enough that randomly generated
-- nonces have negligible risk of collision.

-- | A phantom type for representing types related to authenticated,
-- secret-key encryption.
data SecretBox

instance Nonces SecretBox where
  nonceSize _ = nonceBYTES

-- | Generate a random key for performing encryption.
randomKey :: IO (SecretKey SecretBox)
randomKey = SecretKey `fmap` randombytes keyBYTES

-- | The @'encrypt'@ function encrypts and authenticates a message @m@
-- using a secret @'SecretKey'@ @k@, and a @'Nonce'@ @n@.
encrypt :: Nonce SecretBox
        -- ^ Nonce
        -> ByteString
        -- ^ Input
        -> SecretKey SecretBox
        -- ^ Shared @'SecretKey'@
        -> ByteString
        -- ^ Ciphertext
encrypt (Nonce n) msg (SecretKey k) = unsafePerformIO $ do
  -- inputs to crypto_box must be padded
  let m    = S.replicate zeroBYTES 0x0 `S.append` msg
      mlen = S.length m
  c <- SI.mallocByteString mlen

  -- as you can tell, this is unsafe
  _ <- withForeignPtr c $ \pc ->
    SU.unsafeUseAsCString m $ \pm ->
      SU.unsafeUseAsCString n $ \pn ->
        SU.unsafeUseAsCString k $ \pk ->
          c_crypto_secretbox pc pm (fromIntegral mlen) pn pk
  return $! SI.fromForeignPtr c boxZEROBYTES (mlen - boxZEROBYTES)
{-# INLINE encrypt #-}

-- | The @'decrypt'@ function verifies and decrypts a ciphertext @c@
-- using a secret @'Key'@ @k@, and a @'Nonce'@ @n@.
decrypt :: Nonce SecretBox
        -- ^ Nonce
        -> ByteString
        -- ^ Input
        -> SecretKey SecretBox
        -- ^ Shared @'SecretKey'@
        -> Maybe ByteString
        -- ^ Ciphertext
decrypt (Nonce n) cipher (SecretKey k) = unsafePerformIO $ do
  let c    = S.replicate boxZEROBYTES 0x0 `S.append` cipher
      clen = S.length c
  m <- SI.mallocByteString clen

  -- as you can tell, this is unsafe
  r <- withForeignPtr m $ \pm ->
    SU.unsafeUseAsCString c $ \pc ->
      SU.unsafeUseAsCString n $ \pn ->
        SU.unsafeUseAsCString k $ \pk ->
          c_crypto_secretbox_open pm pc (fromIntegral clen) pn pk

  return $! if r /= 0 then Nothing
            else Just $ SI.fromForeignPtr m zeroBYTES (clen - zeroBYTES)

keyBYTES :: Int
keyBYTES = 32

nonceBYTES :: Int
nonceBYTES = 24

zeroBYTES :: Int
zeroBYTES = 32

boxZEROBYTES :: Int
boxZEROBYTES = 16

foreign import ccall unsafe "xsalsa20poly1305_secretbox"
  c_crypto_secretbox :: Ptr Word8 -> Ptr CChar -> CULLong ->
                        Ptr CChar -> Ptr CChar -> IO Int

foreign import ccall unsafe "xsalsa20poly1305_secretbox_open"
  c_crypto_secretbox_open :: Ptr Word8 -> Ptr CChar -> CULLong ->
                             Ptr CChar -> Ptr CChar -> IO Int
