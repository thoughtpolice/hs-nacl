{-# LANGUAGE ForeignFunctionInterface #-}
{-# LANGUAGE ScopedTypeVariables      #-}
-- |
-- Module      : Crypto.Nonce
-- Copyright   : (c) Austin Seipp 2011-2013
-- License     : BSD3
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
       , randomNonce
       , incNonce
       , fromByteString
       , incBS
       ) where
import           Data.Word
import           Foreign.C.Types
import           Foreign.Ptr

import           Data.ByteString          as S
import           Data.ByteString.Internal as SI
import           Data.ByteString.Unsafe   as SU
import           Numeric
import           System.Crypto.Random
import           Text.Printf              (printf)

-- | A @'Nonce' t@ is a @'ByteString'@ parameterized by some type @t@,
-- which designates what interface the @'Nonce'@ is used for. This
-- provides more type-safety to ensure you don't confuse them when
-- performing encryption.
newtype Nonce t = Nonce { unNonce :: ByteString }
  deriving Eq

instance Show (Nonce t) where
  show (Nonce xs) = writeBytes xs

instance Read (Nonce t) where
  readsPrec _ xs = [(Nonce $ readBytes xs, "")]

-- | A common interface for different nonces.
class Nonces t where
  -- | The size of a given @'Nonce'@.
  nonceSize :: t -> Int

-- | Create a random @'Nonce'@ for the given API.
randomNonce :: forall t. Nonces t => IO (Nonce t)
randomNonce = Nonce `fmap` randombytes l
  where l = nonceSize (undefined :: t)
{-# INLINE randomNonce #-}

-- | Increment a @'Nonce'@ by one.
incNonce :: forall t. Nonces t => Nonce t -> Nonce t
incNonce (Nonce n) = Nonce (incBS n)
{-# INLINE incNonce #-}

-- | Create a @'Nonce'@ from a @'ByteString'@.
fromByteString :: forall t. Nonces t => ByteString -> Maybe (Nonce t)
fromByteString xs
  | S.length xs /= nonceSize (undefined :: t) = Nothing
  | otherwise = Just (Nonce xs)
{-# INLINE fromByteString #-}

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
-- Utilities
--

writeBytes :: ByteString -> String
writeBytes = Prelude.concatMap (printf "%02x") . S.unpack

readBytes :: String -> ByteString
readBytes = S.pack . Prelude.map reader . chunk 2
  where reader :: String -> Word8
        reader x = case readHex x of
          [(a, "")] -> a
          _         -> error "invalid key bytes in readBytes"

        chunk :: Int -> [a] -> [[a]]
        chunk _ [] = []
        chunk n xs = y1 : chunk n y2
          where (y1, y2) = Prelude.splitAt n xs

--
-- FFI
--

foreign import ccall unsafe "nacl_incnonce"
  c_incnonce :: Ptr Word8 -> CSize -> IO ()
