-- |
-- Module      : Crypto.Key
-- Copyright   : (c) Austin Seipp 2011-2013
-- License     : BSD3
--
-- Maintainer  : aseipp@pobox.com
-- Stability   : experimental
-- Portability : GHC (ScopedTypeVariables)
--
-- Minimal cryptographic key API.
--
module Crypto.Key
       ( SecretKey(..)        -- :: *
       , PublicKey(..)        -- :: *
       ) where
import           Data.ByteString (ByteString)
import qualified Data.ByteString as B
import           Data.Word
import           Numeric         (readHex)
import           Text.Printf     (printf)

-- | A @'SecretKey'@ created by @'createKeypair'@. Be sure to keep
-- this safe!
newtype SecretKey t = SecretKey { unSecretKey :: ByteString }
        deriving (Eq, Ord)

instance Show (SecretKey t) where
  show (SecretKey xs) = writeBytes xs

instance Read (SecretKey t) where
  readsPrec _ xs = [(SecretKey $ readBytes xs, "")]

-- | A @'PublicKey'@ created by @'createKeypair'@.
newtype PublicKey t = PublicKey { unPublicKey :: ByteString }
        deriving (Eq, Ord)

instance Show (PublicKey t) where
  show (PublicKey xs) = writeBytes xs

instance Read (PublicKey t) where
  readsPrec _ xs = [(PublicKey $ readBytes xs, "")]

--
-- Utilities
--

writeBytes :: ByteString -> String
writeBytes = concatMap (printf "%02x") . B.unpack

readBytes :: String -> ByteString
readBytes = B.pack . map reader . chunk 2
  where reader :: String -> Word8
        reader x = case readHex x of
          [(a, "")] -> a
          _         -> error "invalid key bytes in readBytes"

        chunk :: Int -> [a] -> [[a]]
        chunk _ [] = []
        chunk n xs = y1 : chunk n y2
          where (y1, y2) = splitAt n xs
