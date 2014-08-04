{-# LANGUAGE EmptyDataDecls           #-}
{-# LANGUAGE ForeignFunctionInterface #-}
-- |
-- Module      : Crypto.Encrypt.Stream
-- Copyright   : (c) Austin Seipp 2011-2013
-- License     : BSD3
--
-- Maintainer  : aseipp@pobox.com
-- Stability   : experimental
-- Portability : portable
--
-- Fast streaming encryption. The underlying primitive is
-- @crypto_stream_xsalsa20@, a particular cipher specified in,
-- \"Cryptography in NaCl\":
-- <http://cr.yp.to/highspeed/naclcrypto-20090310.pdf>
--
-- This module is intended to be imported @qualified@ to avoid name
-- clashes with other cryptographic primitives, e.g.
--
-- > import qualified Crypto.Encrypt.Stream as Stream
--
module Crypto.Encrypt.Stream
       ( -- * Security model
         -- $securitymodel

         -- * Types
         Stream    -- :: *

         -- * Key creation
       , randomKey -- :: IO (SecretKey Stream)

         -- * Encrypting messages
         -- ** Example usage
         -- $example
       , stream    -- :: Nonce Stream -> Int -> SecretKey Stream -> ByteString
       , encrypt   -- :: Nonce Stream -> ByteString -> SecretKey Stream -> ByteString
       , decrypt   -- :: Nonce Stream -> ByteString -> SecretKey Stream -> ByteString
       ) where
import           Data.Word
import           Foreign.C.Types
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
-- The @'stream'@ function, viewed as a function of the nonce for a
-- uniform random key, is designed to meet the standard notion of
-- unpredictability (\"PRF\"). For a formal definition see, e.g.,
-- Section 2.3 of Bellare, Kilian, and Rogaway, \"The security of the
-- cipher block chaining message authentication code,\" Journal of
-- Computer and System Sciences 61 (2000), 362–399;
-- <http://www-cse.ucsd.edu/~mihir/papers/cbc.html>.
--
-- This means that an attacker cannot distinguish this function from a
-- uniform random function. Consequently, if a series of messages is
-- encrypted by @'encrypt'@ with a different nonce for each message,
-- the ciphertexts are indistinguishable from uniform random strings
-- of the same length.
--
-- Note that the length is not hidden. Note also that it is the
-- caller's responsibility to ensure the uniqueness of nonces—for
-- example, by using nonce 1 for the first message, nonce 2 for the
-- second message, etc. Nonces are long enough that randomly generated
-- nonces have negligible risk of collision.
--
-- NaCl does not make any promises regarding the resistance of
-- @'stream'@ to \"related-key attacks.\" It is the caller's
-- responsibility to use proper key-derivation functions.

-- $setup
-- >>> :set -XOverloadedStrings

-- | A phantom type for representing types related to secret-key
-- streaming encryption.
data Stream

instance Nonces Stream where
  nonceSize _ = xsalsa20NONCEBYTES

-- | Generate a random key for performing encryption.
--
-- Example usage:
--
-- >>> key <- randomKey
randomKey :: IO (SecretKey Stream)
randomKey = SecretKey `fmap` randombytes xsalsa20KEYBYTES

-- | Given a @'Nonce'@ @n@, size @s@ and @'Key'@ @k@, @'stream' n s k@
-- generates a cryptographic stream of length @s@.
--
-- Example usage:
--
-- >>> nonce <- randomNonce :: IO (Nonce Stream)
-- >>> key <- randomKey
-- >>> let ks = stream nonce 256 key
stream :: Nonce Stream
       -- ^ Nonce
       -> Int
       -- ^ Size
       -> SecretKey Stream
       -- ^ Key
       -> ByteString
       -- ^ Resulting crypto stream
stream (Nonce n) sz (SecretKey sk)
  = unsafePerformIO . SI.create sz $ \out ->
    SU.unsafeUseAsCString n $ \pn ->
      SU.unsafeUseAsCString sk $ \psk -> do
        _ <- c_xsalsa20_crypto_stream out (fromIntegral sz) pn psk
        return ()

-- | Given a @'Nonce'@ @n@, plaintext @p@ and @'Key'@ @k@, @encrypt n
-- p k@ encrypts the message @p@ using @'Key'@ @k@ and returns the
-- result.
--
-- @'encrypt'@ guarantees the resulting ciphertext is the plaintext
-- bitwise XOR'd with the result of @'stream'@. As a result,
-- @'encrypt'@ can also be used to decrypt messages.
encrypt :: Nonce Stream
        -- ^ Nonce
        -> ByteString
        -- ^ Input plaintext
        -> SecretKey Stream
        -- ^ Key
        -> ByteString
        -- ^ Ciphertext
encrypt (Nonce n) msg (SecretKey sk)
  = let l = S.length msg
    in unsafePerformIO . SI.create l $ \out ->
    SU.unsafeUseAsCString msg $ \cstr ->
    SU.unsafeUseAsCString n $ \pn ->
    SU.unsafeUseAsCString sk $ \psk -> do
      _ <- c_xsalsa20_crypto_stream_xor out cstr (fromIntegral l) pn psk
      return ()
{-# INLINE encrypt #-}

-- | Simple alias for @'encrypt'@.
decrypt :: Nonce Stream
        -- ^ Nonce
        -> ByteString
        -- ^ Input ciphertext
        -> SecretKey Stream
        -- ^ Key
        -> ByteString
        -- ^ Plaintext
decrypt = encrypt
{-# INLINE decrypt #-}

-- $example
-- >>> nonce <- randomNonce :: IO (Nonce Stream)
-- >>> key <- randomKey
-- >>> let cipherText = encrypt nonce "Hello" key
-- >>> let recoveredText = decrypt nonce cipherText key
-- >>> recoveredText == "Hello"
-- True

xsalsa20KEYBYTES :: Int
xsalsa20KEYBYTES   = 32

xsalsa20NONCEBYTES :: Int
xsalsa20NONCEBYTES = 24

foreign import ccall unsafe "xsalsa20_stream"
  c_xsalsa20_crypto_stream :: Ptr Word8 -> CULLong -> Ptr CChar ->
                              Ptr CChar -> IO Int

foreign import ccall unsafe "xsalsa20_stream_xor"
  c_xsalsa20_crypto_stream_xor :: Ptr Word8 -> Ptr CChar ->
                                  CULLong -> Ptr CChar -> Ptr CChar -> IO Int
