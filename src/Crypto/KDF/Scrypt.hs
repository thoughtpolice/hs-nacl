{-# LANGUAGE NamedFieldPuns           #-}
-- |
-- Module      : Crypto.KDF.Scrypt
-- Copyright   : (c) Copyright 2011-2013 Falko Peters, Austin Seipp 2013
-- License     : BSD3
--
-- Maintainer  : aseipp@pobox.com
-- Stability   : experimental
-- Portability : GHC
--
-- Scrypt is a sequential memory-hard key derivation function. This
-- module provides a way to use scrypt for /key stretching/: turning a
-- low-entropy source (like a user password) into a suitable source
-- for use as a cryptographic key.
--
-- This implementation is based on a variant of scrypt known as
-- @scrypt-jane@ with customizable mixing and hash functions for the
-- underlying KDF. It is a combination of BLAKE512 for hashing and
-- ChaCha20/8 for mixing.
--
-- For further information see
-- <http://www.tarsnap.com/scrypt.html>. The homepage of @scrypt-jane@
-- is at <https://github.com/floodyberry/scrypt-jane>.
--
module Crypto.KDF.Scrypt
       ( -- * Key stretching
         -- $key-stretching
         -- ** Types
         Salt(..) -- :: *
         -- ** Parameters
         -- $params
       , ScryptParams
       , defaultParams
       , scryptParams
         -- ** Stretching
       , newSalt  -- :: *
       , stretch  -- :: ScryptParams -> Int -> Salt -> ByteString -> ByteString
       , stretch' -- :: Int -> Salt -> ByteString -> ByteString
       ) where
import           Data.ByteString        (ByteString)

import           Crypto.Internal.Scrypt
import           System.Crypto.Random   (randombytes)

------------------------------------------------------------------------------
-- $params
--
-- Scrypt takes three tuning parameters: @N@, @r@ and @p@. They affect running
-- time and memory usage:
--
-- /Memory usage/ is approximately @128*r*N@ bytes. Note that the
-- 'scryptParams' function takes @log_2(N)@ as a parameter. As an example,
-- the 'defaultParams'
--
-- >   log_2(N) = 14, r = 8 and p = 1
--
-- lead to 'scrypt' using @128 * 8 * 2^14 = 16M@ bytes of memory.
--
-- /Running time/ is proportional to all of @N@, @r@ and @p@. Since it's
-- influence on memory usage is small, @p@ can be used to independently tune
-- the running time.

-- | Create a new @'Salt'@, primarily for use when stretching a key.
newSalt :: IO Salt
newSalt = Salt `fmap` randombytes 32

-- | @'stretch' n salt buf@ performs key stretching with scrypt: the
-- given value @buf@ will be stretched to be an @n@ byte long key with
-- the given @salt@. This is useful for turning something like a
-- password into a cryptographic key for encryption.
stretch :: ScryptParams -- ^ Scrypt parameters
        -> Integer      -- ^ Length of resulting buffer.
        -> Salt         -- ^ The salt to use.
        -> ByteString   -- ^ Input buffer.
        -> ByteString   -- ^ Resulting key.
stretch p n salt key = getHash (scrypt (p { bufLen = n }) salt (Pass key))

-- | Equivalent to @'stretch' 'defaultParams' n salt key@
stretch' :: Integer      -- ^ Length of resulting buffer.
         -> Salt         -- ^ The salt to use.
         -> ByteString   -- ^ Input buffer.
         -> ByteString   -- ^ Resulting key.
stretch' = stretch defaultParams
