{-# LANGUAGE ForeignFunctionInterface #-}
-- |
-- Module      : Crypto.Hash.SHA
-- Copyright   : (c) Austin Seipp 2013
-- License     : BSD3
--
-- Maintainer  : aseipp@pobox.com
-- Stability   : experimental
-- Portability : portable
--
-- SHA-256 and SHA-512 hashes. The underlying implementation uses the
-- @ref@ code of @sha256@ and @sha512@ from SUPERCOP, and should be
-- relatively fast.
--
-- This module is intended to be imported @qualified@ to avoid name
-- clashes with other cryptographic primitives, e.g.
--
-- > import qualified Crypto.Hash.SHA as SHA
--
module Crypto.Hash.SHA
       ( -- * Security model
         -- $securitymodel

         -- * Hashing primitives
         sha256 -- :: ByteString -> ByteString
       , sha512 -- :: ByteString -> ByteString
       ) where
import           Data.Word
import           Foreign.C.Types
import           Foreign.Ptr
import           System.IO.Unsafe         (unsafePerformIO)

import           Data.ByteString          (ByteString)
import           Data.ByteString.Internal (create)
import           Data.ByteString.Unsafe   (unsafeUseAsCStringLen)

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

-- | Compute a 256-bit (32 byte) digest of an input string.
sha256 :: ByteString -> ByteString
sha256 xs =
  -- SHA256 has 32 bytes of output
  unsafePerformIO . create 32 $ \out ->
    unsafeUseAsCStringLen xs $ \(cstr,clen) ->
      c_sha256 out cstr (fromIntegral clen) >> return ()
{-# INLINE sha256 #-}

-- | Compute a 512-bit (64 byte) digest of an input string.
sha512 :: ByteString -> ByteString
sha512 xs =
  -- The default primitive of SHA512 has 64 bytes of output.
  unsafePerformIO . create 64 $ \out ->
    unsafeUseAsCStringLen xs $ \(cstr,clen) ->
      c_sha512 out cstr (fromIntegral clen) >> return ()
{-# INLINE sha512 #-}

--
-- FFI hash binding
--

foreign import ccall unsafe "sha256"
  c_sha256 ::Ptr Word8 -> Ptr CChar -> CULLong -> IO CInt

foreign import ccall unsafe "sha512"
  c_sha512 ::Ptr Word8 -> Ptr CChar -> CULLong -> IO CInt
