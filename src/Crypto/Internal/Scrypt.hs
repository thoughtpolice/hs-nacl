{-# LANGUAGE ForeignFunctionInterface #-}
{-# LANGUAGE NamedFieldPuns           #-}
{-# LANGUAGE RecordWildCards          #-}
-- |
-- Module      : Crypto.Internal.Scrypt
-- Copyright   : (c) Copyright 2011-2013 Falko Peters, Austin Seipp 2013
-- License     : BSD3
--
-- Maintainer  : aseipp@pobox.com
-- Stability   : experimental
-- Portability : GHC
--
-- Internal low-level scrypt bindings and types.
--
module Crypto.Internal.Scrypt
       ( -- * Types
         Pass(..)
       , Salt(..)
       , PassHash(..)
       , ScryptParams(..)
         -- * Low-level utilities and settings.
       , scryptParams
       , scryptParamsLen
       , defaultParams
       , getParams
       , scrypt
       , scrypt'
       ) where

import           Control.Applicative
import qualified Data.ByteString.Char8 as B
import           Data.Maybe
import           Foreign               (Ptr, Word32, Word64, Word8, allocaBytes,
                                        castPtr)
import           Foreign.C
import           System.IO.Unsafe      (unsafePerformIO)

newtype Pass          = Pass     { getPass :: B.ByteString } deriving (Show, Eq)
newtype PassHash      = PassHash { getHash :: B.ByteString } deriving (Show, Eq)

-- | A @'Salt'@ ...
newtype Salt          = Salt     { getSalt :: B.ByteString } deriving (Show, Eq)


-- |Encapsulates the three tuning parameters to the 'scrypt' function: @N@,
-- @r@ and @p@ (see above) as well as the length of the derived key.
--
data ScryptParams = Params { logN, r, p, bufLen :: Integer} deriving (Eq, Show)

-- |Constructor function for 'ScryptParams' with default derived-key-length of
--  64 bytes.
scryptParams
    :: Integer
    -- ^ @log_2(N)@. Scrypt's @N@ parameter must be a power of two greater
    --   than one, thus it's logarithm to base two must be greater than zero.
    --   @128*r*N@ must be smaller than the available memory address space.
    -> Integer
    -- ^ @r@, must be greater than zero.
    -> Integer
    -- ^ @p@, must be greater than zero. @r@ and @p@
    --   must satisfy @r*p < 2^30@.
    -> Maybe ScryptParams
    -- ^ Returns 'Just' the parameter object for valid arguments,
    --   otherwise 'Nothing'.
    --
scryptParams logN r p = scryptParamsLen logN r p 64

-- |Constructor function for 'ScryptParams' with an additional parameter to
--  control the length of the derived key. Only use this function if you are
--  sure you need control over the length of the derived key. Use 'scryptParams'
--  instead.
--
scryptParamsLen
    :: Integer -- ^ @log_2(N)@,
    -> Integer -- ^ @r@,
    -> Integer -- ^ @p@,
    -> Integer
    -- ^ Length of the derived key (the output of 'scrypt') in bytes.
    --   Must be greater than zero and less than or equal to @(2^32-1)*32@.
    -> Maybe ScryptParams
scryptParamsLen logN r p bufLen
    | valid     = Just Params { logN, r, p, bufLen }
    | otherwise = Nothing
  where
    valid = and [ logN > 0, r > 0, p > 0
                , r*p < 2^(30 :: Int)
                , bufLen > 0, bufLen <= 2^(32 :: Int)-1 * 32
                -- allocation fits into (virtual) memory
                , 128*r*2^logN <= fromIntegral (maxBound :: CSize)
                ]

-- |Default parameters as recommended in the scrypt paper:
--
--  >   N = 2^14, r = 8, p = 1
--
--  Equivalent to @'fromJust' ('scryptParams' 14 8 1)@.
--
defaultParams :: ScryptParams
defaultParams = fromJust (scryptParams 14 8 1)

getParams :: ScryptParams -> (Integer, Integer, Integer, Integer)
getParams Params{..} = (logN, r, p, bufLen)

-- |Calculates a hash from the given password, salt and parameters.
--
scrypt :: ScryptParams -> Salt -> Pass -> PassHash
scrypt Params{..} (Salt salt) (Pass pass) =
    PassHash <$> unsafePerformIO $
        B.useAsCStringLen salt $ \(saltPtr, saltLen) ->
        B.useAsCStringLen pass $ \(passPtr, passLen) ->
        allocaBytes (fromIntegral bufLen) $ \bufPtr -> do
            throwErrnoIfMinus1_ "crypto_scrypt" $ crypto_scrypt
                (castPtr passPtr) (fromIntegral passLen)
                (castPtr saltPtr) (fromIntegral saltLen)
                (2^logN) (fromIntegral r) (fromIntegral p)
                bufPtr (fromIntegral bufLen)
            B.packCStringLen (castPtr bufPtr, fromIntegral bufLen)

foreign import ccall unsafe "crypto_scrypt" crypto_scrypt
    :: Ptr Word8 -> CSize         -- password
    -> Ptr Word8 -> CSize         -- salt
    -> Word64 -> Word32 -> Word32 -- N, r, p
    -> Ptr Word8 -> CSize         -- result buffer
    -> IO CInt

-- |Note the prime symbol (\'). Calls 'scrypt' with 'defaultParams'.
--
scrypt' :: Salt -> Pass -> PassHash
scrypt' = scrypt defaultParams
