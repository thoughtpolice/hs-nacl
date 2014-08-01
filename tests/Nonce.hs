{-# LANGUAGE ScopedTypeVariables #-}
module Nonce
       ( tests -- :: Int -> Tests
       ) where
import           Control.Monad

import           Crypto.Encrypt.Box       (Box)
import           Crypto.Nonce

import           Test.QuickCheck
import           Util

--------------------------------------------------------------------------------
-- Signatures

nonceProp :: Nonces t => (Nonce t -> Bool) -> Property
nonceProp k = ioProperty $ k `liftM` randomNonce

incPure1 :: Property
incPure1 = nonceProp $ \(n :: Nonce Box) -> incNonce n == incNonce n

tests :: Int -> Tests
tests ntests =
  [ ("pure incNonce #1", wrap incPure1)
  ]
  where
    wrap :: Testable prop => prop -> IO (Bool, Int)
    wrap = mkArgTest ntests
