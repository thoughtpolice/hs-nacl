{-# LANGUAGE ForeignFunctionInterface #-}
-- |
-- Module      : Crypto.Hash.BLAKE2
-- Copyright   : (c) Austin Seipp 2013
-- License     : MIT
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

-- | Compute a 256-bit (32 byte) digest of an input string.
blake2s :: ByteString -> ByteString
blake2s = hasher c_blake2s 32 B.empty
{-# INLINE blake2s #-}

-- | Compute a 256-bit (32 byte) digest of an input string.
blake2sp :: ByteString -> ByteString
blake2sp = hasher c_blake2sp 32 B.empty
{-# INLINE blake2sp #-}

-- | Compute a 512-bit (64 byte) digest of an input string.
blake2b :: ByteString -> ByteString
blake2b = hasher c_blake2b 64 B.empty
{-# INLINE blake2b #-}

-- | Compute a 512-bit (64 byte) digest of an input string.
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
