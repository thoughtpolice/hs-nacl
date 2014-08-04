{-# LANGUAGE ForeignFunctionInterface #-}
-- |
-- Module      : Crypto.Hash.BLAKE2
-- Copyright   : (c) Austin Seipp 2013
-- License     : BSD3
--
-- Maintainer  : aseipp@pobox.com
-- Stability   : experimental
-- Portability : portable
--
-- BLAKE2b\/2bp and BLAKE2s\/2sp hashes.
--
-- For more information visit <https://blake2.net/>.
--
-- This module is intended to be imported @qualified@ to avoid name
-- clashes with other cryptographic primitives, e.g.
--
-- > import qualified Crypto.Hash.BLAKE2 as BLAKE2
--
module Crypto.Hash.BLAKE2
       ( -- * Introduction
         -- $intro

         -- * Security model
         -- $securitymodel

         -- * Hashing primitives
         -- ** BLAKE2s
         blake2s  -- :: ByteString -> ByteString
       , blake2sp -- :: ByteString -> ByteString
         -- ** BLAKE2b
       , blake2b  -- :: ByteString -> ByteString
       , blake2bp -- :: ByteString -> ByteString
       ) where
import           Data.Word
import           Foreign.C.Types
import           Foreign.Ptr
import           System.IO.Unsafe         (unsafePerformIO)

import           Data.ByteString          (ByteString)
import qualified Data.ByteString          as B
import           Data.ByteString.Internal (create)
import           Data.ByteString.Unsafe   (unsafeUseAsCStringLen)

-- $intro
--
-- BLAKE2 is a fast hash function designed as the successor to
-- BLAKE. It has two main variants:
--
--  * BLAKE2b/BLAKE2bp which is optimized for 64 bit platforms.
--
--  * BLAKE2s/BLAKE2sp which is optimized for 32 bit platforms.
--
-- The \"p\" variants are parallel and can transparently use OpenMP
-- for multicore support, so they're good if you plan on hashing lots
-- of data in one go.
--
-- Note: all of these functions produce -different- output (including
-- the parallel variants.) You should benchmark them for your specific
-- deployment to see which is optimal.

-- $securitymodel
--
-- The hash functions here are designed to be usable as a strong
-- component of DSA, RSA-PSS, key derivation, hash-based
-- message-authentication codes, hash-based ciphers, and various other
-- common applications. \"Strong\" means that the security of these
-- applications, when instantiated with a given hash below, is the
-- same as the security of the applications against generic
-- attacks. In particular, the hash function is designed to make
-- finding collisions difficult.
--

-- $setup
-- >>> :set -XOverloadedStrings
-- >>> import Data.ByteString.Base16

-- | Compute a 256-bit (32 byte) digest of an input string.
--
-- Example usage:
--
-- >>> encode $ blake2s "Hello"
-- "f73a5fbf881f89b814871f46e26ad3fa37cb2921c5e8561618639015b3ccbb71"
blake2s :: ByteString -> ByteString
blake2s = hasher c_blake2s 32 B.empty
{-# INLINE blake2s #-}

-- | Compute a 256-bit (32 byte) digest of an input string.
--
-- Example usage:
--
-- >>> encode $ blake2sp "Hello"
-- "0d6bae0db99f99183d060f7994bb94b45c6490b2a0a628b8b1346ebea8ec1d66"
blake2sp :: ByteString -> ByteString
blake2sp = hasher c_blake2sp 32 B.empty
{-# INLINE blake2sp #-}

-- | Compute a 512-bit (64 byte) digest of an input string.
--
-- Example usage:
--
-- >>> encode $ blake2b "Hello"
-- "ef15eaf92d5e335345a3e1d977bc7d8797c3d275717cc1b10af79c93cda01aeb2a0c59bc02e2bdf9380fd1b54eb9e1669026930ccc24bd49748e65f9a6b2ee68"
blake2b :: ByteString -> ByteString
blake2b = hasher c_blake2b 64 B.empty
{-# INLINE blake2b #-}

-- | Compute a 512-bit (64 byte) digest of an input string.
--
-- Example usage:
--
-- >>> encode $ blake2bp "Hello"
-- "10510f3c750e0dac793a46de7b6976a8ab08fe16d529a8a040eadf4bfd54b1754b7b09304839b2593b81234bccd1249abf6611f1f6c8117dcbd934136eb2e57e"
blake2bp :: ByteString -> ByteString
blake2bp = hasher c_blake2bp 64 B.empty
{-# INLINE blake2bp #-}

hasher :: Hash -> Int -> ByteString -> ByteString -> ByteString
hasher k outlen key xs =
  unsafePerformIO . create outlen $ \out ->
    unsafeUseAsCStringLen xs $ \(cstr,clen) ->
      let outlen' = fromIntegral outlen
          clen'   = fromIntegral clen
      in case B.null key of
        True  -> k out cstr nullPtr outlen' clen' 0 >> return ()
        False -> unsafeUseAsCStringLen key $ \(kstr,klen) ->
          k out cstr kstr outlen' clen' (fromIntegral klen) >> return ()
{-# INLINE hasher #-}

--
-- FFI hash binding
--

type Hash = Ptr Word8 -> Ptr CChar -> Ptr CChar
         -> Word8 -> Word64 -> Word8 -> IO CInt

foreign import ccall unsafe "blake2s"  c_blake2s  :: Hash
foreign import ccall unsafe "blake2sp" c_blake2sp :: Hash
foreign import ccall unsafe "blake2b"  c_blake2b  :: Hash
foreign import ccall unsafe "blake2bp" c_blake2bp :: Hash
