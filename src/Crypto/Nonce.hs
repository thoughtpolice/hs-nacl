{-# LANGUAGE ForeignFunctionInterface #-}
{-# LANGUAGE ScopedTypeVariables      #-}
-- |
-- Module      : Crypto.Nonce
-- Copyright   : (c) Austin Seipp 2011-2013
-- License     : MIT
--
-- Maintainer  : aseipp@pobox.com
-- Stability   : experimental
-- Portability : GHC (ScopedTypeVariables)
--
-- An interface for cryptographic nonces.
--
module Crypto.Nonce
       ( -- * Nonces
         Nonce(..)

         -- * Nonce interface
       , Nonces(..)
       , incBS
       ) where
import           Data.Word
import           Foreign.C.Types
import           Foreign.Ptr

import           Data.ByteString          as S
import           Data.ByteString.Internal as SI
import           Data.ByteString.Unsafe   as SU

import           System.Crypto.Random

-- | A @'Nonce' t@ is a @'ByteString'@ parameterized by some type @t@,
-- which designates what interface the @'Nonce'@ is used for. This
-- provides more type-safety to ensure you don't confuse them when
-- performing encryption.
newtype Nonce t = Nonce { unNonce :: ByteString }
  deriving (Eq, Show)

-- | A common interface for different nonces.
class Nonces t where
  -- | The size of a given @'Nonce'@.
  nonceSize :: t -> Int

  -- | Create a random @'Nonce'@ for the given API.
  randomNonce :: IO (Nonce t)
  randomNonce = Nonce `fmap` randombytes l
    where l = nonceSize (undefined :: t)

  -- | Increment a @'Nonce'@ by one.
  incNonce :: Nonce t -> Nonce t
  incNonce (Nonce n) = Nonce $! incBS n

  -- | Create a @'Nonce'@ from a @'ByteString'@.
  fromByteString :: ByteString -> Maybe (Nonce t)
  fromByteString xs
    | S.length xs /= nonceSize (undefined :: t) = Nothing
    | otherwise = Just (Nonce xs)

-- | Utility function that performs an increment operation like
-- @'incNonce'@, but on @'ByteString'@s
incBS :: ByteString -> ByteString
incBS n =
  SI.unsafeCreate (S.length n) $ \out -> do
    SU.unsafeUseAsCStringLen n $ \(b,blen) ->
      SI.memcpy out (castPtr b) (fromIntegral blen)
    c_incnonce out (fromIntegral (S.length n))
{-# INLINE incBS #-}

--
-- FFI
--

foreign import ccall unsafe "nacl_incnonce"
  c_incnonce :: Ptr Word8 -> CSize -> IO ()
