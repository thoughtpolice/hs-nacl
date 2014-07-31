{-# OPTIONS_GHC -fno-warn-orphans #-}
module Curve25519
       ( tests -- :: Int -> Tests
       ) where
import           Control.Monad

import           Crypto.DH.Curve25519
import           Crypto.Key

import           Test.QuickCheck
import           Util

--------------------------------------------------------------------------------
-- Diffie-Hellman key exchange

type KP = (PublicKey Curve25519, SecretKey Curve25519)

keypairProp :: (KP -> KP -> Bool) -> Property
keypairProp k = ioProperty $ liftM2 k createKeypair createKeypair

roundtrip :: Property
roundtrip = keypairProp $ \(p1,s2) (p2,s1) ->
  curve25519 s1 p1 == curve25519 s2 p2

tests :: Int -> [(String, IO (Bool,Int))]
tests ntests =
  [ ("curve25519 roundtrip",            wrap roundtrip)
  ]
  where
    wrap :: Testable prop => prop -> IO (Bool, Int)
    wrap = mkArgTest ntests
