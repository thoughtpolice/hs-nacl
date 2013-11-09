#!/usr/bin/env runghc
import           Data.List
import           System.Cmd

main :: IO ()
main = do
  system $ "rm -rf benchmarks/*.html"
  system $ "cabal clean"
  system $ "cabal configure --enable-benchmarks"
  system $ "cabal build"
  system $ "dist/build/bench/bench -o benchmarks/report.html"
  return ()
