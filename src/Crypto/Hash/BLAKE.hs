{-# LANGUAGE ForeignFunctionInterface #-}
-- |
-- Module      : Crypto.Hash.BLAKE
-- Copyright   : (c) Austin Seipp 2013
-- License     : BSD3
--
-- Maintainer  : aseipp@pobox.com
-- Stability   : experimental
-- Portability : portable
--
-- BLAKE-256 and BLAKE-512 hashes. The underlying implementation uses
-- the @ref@ code of @blake256@ and @blake512@ from SUPERCOP, and
-- should be relatively fast.
--
-- For more information visit <https://131002.net/blake/>.
--
-- This module is intended to be imported @qualified@ to avoid name
-- clashes with other cryptographic primitives, e.g.
--
-- > import qualified Crypto.Hash.BLAKE as BLAKE
--
module Crypto.Hash.BLAKE
       ( -- * Security model
         -- $securitymodel

         -- * Hashing primitives
         blake256 -- :: ByteString -> ByteString
       , blake512 -- :: ByteString -> ByteString
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
blake256 :: ByteString -> ByteString
blake256 xs =
  unsafePerformIO . create 32 $ \out ->
    unsafeUseAsCStringLen xs $ \(cstr,clen) ->
      c_blake256 out cstr (fromIntegral clen) >> return ()
{-# INLINE blake256 #-}

-- | Compute a 512-bit (64 byte) digest of an input string.
blake512 :: ByteString -> ByteString
blake512 xs =
  unsafePerformIO . create 64 $ \out ->
    unsafeUseAsCStringLen xs $ \(cstr,clen) ->
      c_blake512 out cstr (fromIntegral clen) >> return ()
{-# INLINE blake512 #-}

--
-- FFI hash binding
--

foreign import ccall unsafe "blake256"
  c_blake256 ::Ptr Word8 -> Ptr CChar -> CULLong -> IO CInt

foreign import ccall unsafe "blake512"
  c_blake512 ::Ptr Word8 -> Ptr CChar -> CULLong -> IO CInt
