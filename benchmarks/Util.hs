{-# OPTIONS_GHC -fno-warn-orphans #-}
{-# LANGUAGE CPP #-}
module Util where
#include "../dist/build/autogen/cabal_macros.h"
#if !MIN_VERSION_bytestring(0,10,0)
import           Control.DeepSeq
import           Data.ByteString (ByteString)
import qualified Data.ByteString as B
#endif

--------------------------------------------------------------------------------
-- Orphans

#if !MIN_VERSION_bytestring(0,10,0)
instance NFData B.ByteString
#endif
