module BLAKE2
       ( tests -- :: Int -> Tests
       ) where
import           Data.ByteString    (ByteString)
import qualified Data.ByteString    as S

import           Crypto.Hash.BLAKE2

import           Test.QuickCheck
import           Util

--------------------------------------------------------------------------------
-- Hashing

pure2s, length2s, pure2sp, length2sp, pure2b, length2b, pure2bp, length2bp
  :: ByteString -> Bool

pure2s   xs = blake2s xs == blake2s xs
length2s xs = S.length (blake2s xs) == 32

pure2sp   xs = blake2sp xs == blake2sp xs
length2sp xs = S.length (blake2sp xs) == 32

pure2b   xs = blake2b xs == blake2b xs
length2b xs = S.length (blake2b xs) == 64

pure2bp   xs = blake2bp xs == blake2bp xs
length2bp xs = S.length (blake2bp xs) == 64


tests :: Int -> Tests
tests ntests =
  [ ("blake2s  purity", wrap pure2s)
  , ("blake2s  length", wrap length2s)
  , ("blake2sp purity", wrap pure2sp)
  , ("blake2sp length", wrap length2sp)
  , ("blake2b  purity", wrap pure2b)
  , ("blake2b  length", wrap length2b)
  , ("blake2bp purity", wrap pure2bp)
  , ("blake2bp length", wrap length2bp)
  ]
  where
    wrap :: Testable prop => prop -> IO (Bool, Int)
    wrap = mkArgTest ntests
