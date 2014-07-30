{-# OPTIONS_GHC -fno-warn-orphans #-}
{-# LANGUAGE CPP #-}
module Util
       ( Test, Tests
       , driver
       , mktest
       ) where

#include "../dist/build/autogen/cabal_macros.h"

import           Control.Monad
import           Data.ByteString    (ByteString)
import qualified Data.ByteString    as S

import           System.Environment (getArgs)
import           Test.QuickCheck
import           Text.Printf

--------------------------------------------------------------------------------
-- Orphans

instance Arbitrary ByteString where
  arbitrary = S.pack `liftM` arbitrary

type Test  = (String, IO (Bool,Int))
type Tests = [Test]

driver :: (Int -> Tests) -> IO ()
driver tests = do
  args <- getArgs
  let n = if null args then 100 else read (head args) :: Int
  (results, passed) <- runTests (tests n)
  _ <- printf "Passed %d tests!\n" (sum passed)
  unless (and results) (fail "Not all tests passed!")

runTests :: Tests -> IO ([Bool], [Int])
runTests tests = fmap unzip . forM tests $ \(s, a) ->
  printf "%-45s: " s >> a

mktest :: Testable prop => Int -> prop -> IO (Bool, Int)
mktest ntests prop = do
  r <- quickCheckWithResult stdArgs{maxSuccess=ntests,maxSize=ntests} prop
  case r of
    Success n _ _           -> return (True, n)
    GaveUp  n _ _           -> return (True, n)
#if MIN_VERSION_QuickCheck(2,6,0)
    Failure n _ _ _ _ _ _ _ -> return (False, n)
#else
    Failure n _ _ _ _ _ _   -> return (False, n)
#endif
    _                       -> return (False, 0)
