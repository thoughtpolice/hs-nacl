{-# LANGUAGE EmptyDataDecls           #-}
{-# LANGUAGE ForeignFunctionInterface #-}
-- |
-- Module      : Crypto.Encrypt.Stream.ChaCha20
-- Copyright   : (c) Austin Seipp 2011-2014
-- License     : BSD3
--
-- Maintainer  : aseipp@pobox.com
-- Stability   : experimental
-- Portability : portable
--
-- Fast streaming encryption. The underlying primitive is
-- @crypto_stream_chacha20@, a particular cipher specified in,
-- \"ChaCha, a variant of Salsa20\":
-- <http://cr.yp.to/chacha/chacha-20080128.pdf>
--
-- This module is intended to be imported @qualified@ to avoid name
-- clashes with other cryptographic primitives, e.g.
--
-- > import qualified Crypto.Encrypt.Stream.ChaCha20 as ChaCha20
--
module Crypto.Encrypt.Stream.ChaCha20
       ( -- * Security model
         -- $securitymodel

         -- * Types
         ChaCha20    -- :: *

         -- * Key creation
       , randomKey -- :: IO (SecretKey ChaCha20)

         -- * Encrypting messages
         -- ** Example usage
         -- $example
       , stream    -- :: Nonce ChaCha20 -> Int -> SecretKey ChaCha20 -> ByteString
       , encrypt   -- :: Nonce ChaCha20 -> ByteString -> SecretKey ChaCha20 -> ByteString
       , decrypt   -- :: Nonce ChaCha20 -> ByteString -> SecretKey ChaCha20 -> ByteString
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
data ChaCha20

instance Nonces ChaCha20 where
  nonceSize _ = chacha20NONCEBYTES

-- | Generate a random key for performing encryption.
--
-- Example usage:
--
-- >>> key <- randomKey
randomKey :: IO (SecretKey ChaCha20)
randomKey = SecretKey `fmap` randombytes chacha20KEYBYTES

-- | Given a @'Nonce'@ @n@, size @s@ and @'Key'@ @k@, @'stream' n s k@
-- generates a cryptographic stream of length @s@.
--
-- Example usage:
--
-- >>> nonce <- randomNonce :: IO (Nonce ChaCha20)
-- >>> key <- randomKey
-- >>> let ks = stream nonce 256 key
stream :: Nonce ChaCha20
       -- ^ Nonce
       -> Int
       -- ^ Size
       -> SecretKey ChaCha20
       -- ^ Key
       -> ByteString
       -- ^ Resulting crypto stream
stream (Nonce n) sz (SecretKey sk)
  = unsafePerformIO . SI.create sz $ \out ->
    SU.unsafeUseAsCString n $ \pn ->
      SU.unsafeUseAsCString sk $ \psk -> do
        _ <- c_crypto_stream_chacha20 out (fromIntegral sz) pn psk
        return ()

-- | Given a @'Nonce'@ @n@, plaintext @p@ and @'Key'@ @k@, @encrypt n
-- p k@ encrypts the message @p@ using @'Key'@ @k@ and returns the
-- result.
--
-- @'encrypt'@ guarantees the resulting ciphertext is the plaintext
-- bitwise XOR'd with the result of @'stream'@. As a result,
-- @'encrypt'@ can also be used to decrypt messages.
encrypt :: Nonce ChaCha20
        -- ^ Nonce
        -> ByteString
        -- ^ Input plaintext
        -> SecretKey ChaCha20
        -- ^ Key
        -> ByteString
        -- ^ Ciphertext
encrypt (Nonce n) msg (SecretKey sk)
  = let l = S.length msg
    in unsafePerformIO . SI.create l $ \out ->
    SU.unsafeUseAsCString msg $ \cstr ->
    SU.unsafeUseAsCString n $ \pn ->
    SU.unsafeUseAsCString sk $ \psk -> do
      _ <- c_crypto_stream_chacha20_xor out cstr (fromIntegral l) pn psk
      return ()
{-# INLINE encrypt #-}

-- | Simple alias for @'encrypt'@.
decrypt :: Nonce ChaCha20
        -- ^ Nonce
        -> ByteString
        -- ^ Input ciphertext
        -> SecretKey ChaCha20
        -- ^ Key
        -> ByteString
        -- ^ Plaintext
decrypt = encrypt
{-# INLINE decrypt #-}

-- $example
-- >>> nonce <- randomNonce :: IO (Nonce ChaCha20)
-- >>> key <- randomKey
-- >>> let cipherText = encrypt nonce "Hello" key
-- >>> let recoveredText = decrypt nonce cipherText key
-- >>> recoveredText == "Hello"
-- True

chacha20KEYBYTES :: Int
chacha20KEYBYTES   = 32

chacha20NONCEBYTES :: Int
chacha20NONCEBYTES = 8

foreign import ccall unsafe "crypto_stream_chacha20"
  c_crypto_stream_chacha20 :: Ptr Word8 -> CULLong -> Ptr CChar ->
                              Ptr CChar -> IO Int

foreign import ccall unsafe "crypto_stream_chacha20_xor"
  c_crypto_stream_chacha20_xor :: Ptr Word8 -> Ptr CChar ->
                                  CULLong -> Ptr CChar -> Ptr CChar -> IO Int
