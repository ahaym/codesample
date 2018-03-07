import System.Environment
import Network.Pcap
import Data.Binary.Get
import Control.Monad
import Data.Word
import Text.Printf
import qualified Data.ByteString as B
import qualified Data.ByteString.Lazy as BL
import qualified Data.ByteString.Lazy.Char8 as CL
import qualified Data.ByteString.Char8 as C

qstart = CL.pack "B6034"
delayUs = 3000000

data PacketContents = NotQuote | QuotePacket {
    issueCode :: String,

    bid1 :: String,
    bq1 :: String,

    bid2 :: String,
    bq2 :: String,

    bid3 :: String,
    bq3 :: String,

    bid4 :: String,
    bq4 :: String,

    bid5 :: String,
    bq5 :: String,

    ask1 :: String,
    aq1 :: String,

    ask2 :: String,
    aq2 :: String,

    ask3 :: String,
    aq3 :: String,

    ask4 :: String,
    aq4 :: String,

    ask5 :: String,
    aq5 :: String,

    pktTime :: Word32,
    acceptTime :: Word32
    }

instance Show PacketContents where
  show NotQuote = "NotQuote"
  show QuotePacket{
    issueCode = issueCode,
    bid1 = bid1,
    bq1 =  bq1,
    bid2 = bid2,
    bq2 = bq2,
    bid3 = bid3,
    bq3 = bq3,
    bid4 = bid4,
    bq4 = bq4,
    bid5 = bid5,
    bq5 = bq5,
    ask1 = ask1,
    aq1 = aq1,
    ask2 = ask2,
    aq2 = aq2,
    ask3 = ask3,
    aq3 = aq3,
    ask4 = ask4,
    aq4 = aq4,
    ask5 = ask5,
    aq5 = aq5,
    pktTime = packtime,
    acceptTime =  acceptTime
} = printf "%d %d %s %s@%s %s@%s %s@%s %s@%s %s@%s %s@%s %s@%s %s@%s %s@%s %s@%s"
      packtime acceptTime issueCode bq5 bid5 bq4 bid4 bq3 bid3 bq2 bid2 bq1 bid1
      aq1 ask1 aq2 ask2 aq3 ask3 aq4 ask4 aq5 ask5  

--Extract the quote from the body of the Packet
--We add in packtime from the pcap header
getQuote :: Word32 -> Get PacketContents
getQuote packtime = do
  skip 5 --B6034
  issueCode <- getByteString 12
  skip 12 --3 + 2 + 7

  bid1 <- getByteString 5
  bq1 <- getByteString 7
  bid2 <- getByteString 5
  bq2 <- getByteString 7
  bid3 <- getByteString 5
  bq3 <- getByteString 7
  bid4 <- getByteString 5
  bq4 <- getByteString 7
  bid5 <- getByteString 5
  bq5 <- getByteString 7

  skip 7

  ask1 <- getByteString 5
  aq1 <- getByteString 7
  ask2 <- getByteString 5
  aq2 <- getByteString 7
  ask3 <- getByteString 5
  aq3 <- getByteString 7
  ask4 <- getByteString 5
  aq4 <- getByteString 7
  ask5 <- getByteString 5
  aq5 <- getByteString 7
  
  skip 50

  acceptTime <- getByteString 8

  return QuotePacket {
    issueCode = C.unpack issueCode,

    bid1 = C.unpack bid1,
    bq1 = C.unpack bq1,

    bid2 = C.unpack bid2,
    bq2 = C.unpack bq2,

    bid3 = C.unpack bid3,
    bq3 = C.unpack bq3,

    bid4 = C.unpack bid4,
    bq4 = C.unpack bq4,

    bid5 = C.unpack bid5,
    bq5 = C.unpack bq5,

    ask1 = C.unpack ask1,
    aq1 = C.unpack aq1,

    ask2 = C.unpack ask2,
    aq2 = C.unpack aq2,

    ask3 = C.unpack ask3,
    aq3 = C.unpack aq3,

    ask4 = C.unpack ask4,
    aq4 = C.unpack aq4,

    ask5 = C.unpack ask5,
    aq5 = C.unpack aq5,

    pktTime = packtime,
    acceptTime = read (C.unpack acceptTime) :: Word32

    }

parsePacket :: PktHdr -> BL.ByteString -> PacketContents
parsePacket header bytes
  | packlen < 5 = NotQuote 
  | BL.take 5 body /= qstart = NotQuote
  | otherwise = runGet (getQuote packtime) body
  where
    PktHdr{hdrCaptureLength = packlen, hdrUseconds = packtime} = header
    (_,body) = BL.splitAt 42 bytes --I have NO idea why a 42 byte split works
                                   --0 and 16 both spit out a bunch of header
                                   --May work differently on other platforms?
                                   --Using 64-bit Linux

printUnsorted :: PktHdr -> B.ByteString -> IO ()
printUnsorted hdr bytes = do
  let quote = parsePacket hdr (CL.fromStrict bytes) --fromStrict is O(1)
  case quote of
    NotQuote -> return ()
    _ -> print quote

runUnsorted :: PcapHandle -> IO ()
runUnsorted handle = do dispatchBS handle (-1) printUnsorted
                        return ()

runSorted :: PcapHandle -> IO ()
runSorted handle = putStrLn "The Sorted Output" 

main = do
  args <- getArgs
  let rflag = "-r" `elem` args
  case filter ("-r"/=) args of
    [] -> error "too few arguments!"
    [file] -> do handle <- openOffline file
                 if rflag then runSorted handle
                 else runUnsorted handle
    _ -> error "too many arguments!"
