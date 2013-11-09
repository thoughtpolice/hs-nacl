{-# LANGUAGE ForeignFunctionInterface #-}
-- |
-- Module      : System.Crypto.Random
-- Copyright   : (c) Austin Seipp 2011-2013
-- License     : MIT
--
-- Maintainer  : aseipp@pobox.com
-- Stability   : experimental
-- Portability : portable
--
-- Cross-platform access to cryptographically sure randomness. Use
-- 'randombytes' to generate nonces or secret keys.
--
-- On Unix machines, this uses the @\/dev\/urandom@ device. On
-- Windows, it uses the @CryptGenRandom@ API.
--
module System.Crypto.Random
       ( randombytes -- :: Int -> IO ByteString
       ) where
import           Data.Word
import           Foreign.C.Types
import           Foreign.Ptr

import           Data.ByteString          (ByteString)
import           Data.ByteString.Internal (create)

-- | Generate a random @'ByteString'@ from your system entropy source.
randombytes :: Int -> IO ByteString
randombytes n
  | n < 0     = error "Crypto.NaCl.Random.randomBytes: invalid length"
  | otherwise = create n $ \out ->
      c_randombytes out (fromIntegral n) >> return ()

foreign import ccall unsafe "randombytes"
  c_randombytes :: Ptr Word8 -> CULLong -> IO Int
