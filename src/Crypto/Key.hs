-- |
-- Module      : Crypto.Key
-- Copyright   : (c) Austin Seipp 2011-2013
-- License     : MIT
--
-- Maintainer  : aseipp@pobox.com
-- Stability   : experimental
-- Portability : GHC (ScopedTypeVariables)
--
-- The Networking and Cryptography library.
--
module Crypto.Key
       ( SecretKey(..) -- :: *
       , PublicKey(..) -- :: *
       ) where
import           Data.ByteString

-- | A @'SecretKey'@ created by @'createKeypair'@. Be sure to keep
-- this safe!
newtype SecretKey t = SecretKey { unSecretKey :: ByteString }
        deriving (Eq, Show, Ord)

-- | A @'PublicKey'@ created by @'createKeypair'@.
newtype PublicKey t = PublicKey { unPublicKey :: ByteString }
        deriving (Eq, Show, Ord)
