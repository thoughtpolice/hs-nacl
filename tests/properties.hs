module Main
       ( main  -- :: IO ()
       ) where
import           Util        (driver)

import           BLAKE       (tests)
import           BLAKE2      (tests)
import           Box         (tests)
import           ChaCha20    (tests)
import           Curve25519  (tests)
import           Ed25519     (tests)
import           HMACSHA512  (tests)
import           Nonce       (tests)
import           Poly1305    (tests)
import           SecretBox   (tests)
import           SHA         (tests)
import           Siphash2448 (tests)
import           Stream      (tests)

main :: IO ()
main = driver $ \n -> BLAKE.tests n
                   ++ BLAKE2.tests n
                   ++ Box.tests n
                   ++ Curve25519.tests n
                   ++ Ed25519.tests n
                   ++ HMACSHA512.tests n
                   ++ Nonce.tests n
                   ++ Poly1305.tests n
                   ++ SecretBox.tests n
                   ++ SHA.tests n
                   ++ Siphash2448.tests n
                   ++ Stream.tests n
                   ++ ChaCha20.tests n
