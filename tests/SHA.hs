module SHA
       ( tests -- :: Int -> Tests
       ) where
import           Data.ByteString (ByteString)
import qualified Data.ByteString as S

import           Crypto.Hash.SHA

import           Test.QuickCheck
import           Util

--------------------------------------------------------------------------------
-- Hashing

pure256 :: ByteString -> Bool
pure256 xs = sha256 xs == sha256 xs

pure512 :: ByteString -> Bool
pure512 xs = sha512 xs == sha512 xs

length256 :: ByteString -> Bool
length256 xs = S.length (sha256 xs) == 32

length512 :: ByteString -> Bool
length512 xs = S.length (sha512 xs) == 64


tests :: Int -> Tests
tests ntests =
  [ ("sha256 purity", wrap pure256)
  , ("sha256 length", wrap length256)
  , ("sha512 purity", wrap pure512)
  , ("sha512 length", wrap length512)
  ]
  where
    wrap :: Testable prop => prop -> IO (Bool, Int)
    wrap = mktest ntests
