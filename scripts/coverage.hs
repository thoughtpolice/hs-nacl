#!/usr/bin/env runghc
import           Data.List
import           System.Cmd

main :: IO ()
main = do
  system $ "rm -rf *.tix hpc_out"
  system $ "cabal clean"
  system $ "cabal configure --enable-tests --enable-library-coverage"
  system $ "cabal build"
  system $ "dist/build/properties/properties"
  system $ hpc "markup" ["--destdir=hpc_out"]
  system $ hpc "report" []
  return ()

hpc :: String -> [String] -> String
hpc cmd args = unwords [ "hpc", cmd, hpcdir, exclusions
                       , unwords args, "properties" ]

hpcdir :: String
hpcdir = "--hpcdir=dist/hpc/mix/nacl-0.0.0.0"

exclusions :: String
exclusions = concat . intersperse " " $ map ("--exclude="++)
             [ "BLAKE"
             , "BLAKE2"
             , "Box"
             , "Curve25519"
             , "Ed25519"
             , "HMACSHA512"
             , "Nonce"
             , "Poly1305"
             , "SHA"
             , "SecretBox"
             , "Siphash2448"
             , "Stream"
             , "Util"
             , "Main" ]
