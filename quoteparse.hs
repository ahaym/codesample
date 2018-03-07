import System.Environment
import Network.Pcap
import Data.Binary.Get
import Control.Monad
import Data.Word
import Text.Printf
import qualified Data.Heap as H
import qualified Data.ByteString as B
import qualified Data.ByteString.Lazy as BL
import qualified Data.ByteString.Char8 as C
import qualified Data.ByteString.Lazy.Char8 as CL

qstart = CL.pack "B6034"
delayUs = 3000000
delaySecs = 3

data PacketContents = NotQuote | QuotePacket {
    issueCode :: String,
    --would alias the five-string tuple but ran into invalid test error
    --making these lists of strings would remove boilerplate, but introduce ambiguity
    bprice :: (String, String, String, String, String), 
    bqty :: (String, String, String, String, String),
    aprice :: (String, String, String, String, String),
    aqty :: (String, String, String, String, String),
    pktTime :: Word32,
    acceptTime :: Word32
    } deriving (Eq, Ord)

instance Show PacketContents where
  show NotQuote = "NotQuote"
  show QuotePacket{
    issueCode = issueCode,
    bprice = (bid1, bid2, bid3, bid4, bid5),
    bqty = (bq1, bq2, bq3, bq4, bq5),
    aprice = (ask1, ask2, ask3, ask4, ask5),
    aqty = (aq1, aq2, aq3, aq4, aq5),
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

  bid1_ <- getByteString 5
  bq1_ <- getByteString 7
  bid2_ <- getByteString 5
  bq2_ <- getByteString 7
  bid3_ <- getByteString 5
  bq3_ <- getByteString 7
  bid4_ <- getByteString 5
  bq4_ <- getByteString 7
  bid5_ <- getByteString 5
  bq5_ <- getByteString 7

  skip 7

  ask1_ <- getByteString 5
  aq1_ <- getByteString 7
  ask2_ <- getByteString 5
  aq2_ <- getByteString 7
  ask3_ <- getByteString 5
  aq3_ <- getByteString 7
  ask4_ <- getByteString 5
  aq4_ <- getByteString 7
  ask5_ <- getByteString 5
  aq5_ <- getByteString 7
  
  skip 50

  acceptTime <- getByteString 8
  
  let [bid1, bid2, bid3, bid4, bid5] = map C.unpack [bid1_, bid2_, bid3_, bid4_, bid5_]
      [bq1, bq2, bq3, bq4, bq5] = map C.unpack [bq1_, bq2_, bq3_, bq4_, bq5_]
      [ask1, ask2, ask3, ask4, ask5] = map C.unpack [ask1_, ask2_, ask3_, ask4_, ask5_]
      [aq1, aq2, aq3, aq4, aq5] = map C.unpack [aq1_, aq2_, aq3_, aq4_, aq5_]

  return QuotePacket {
    issueCode = C.unpack issueCode,
    pktTime = packtime,
    acceptTime = read (C.unpack acceptTime) :: Word32,
    bprice = (bid1, bid2, bid3, bid4, bid5),
    bqty = (bq1, bq2, bq3, bq4, bq5),
    aprice = (ask1, ask2, ask3, ask4, ask5),
    aqty = (aq1, aq2, aq3, aq4, aq5)
    }

parsePacket :: PktHdr -> BL.ByteString -> PacketContents
parsePacket header bytes
  | packlen < 5 = NotQuote 
  | BL.take 5 body /= qstart = NotQuote
  | otherwise = runGet (getQuote packtime) body
  where
    PktHdr{hdrCaptureLength = packlen, hdrSeconds = packtime} = header
    (_,body) = BL.splitAt 42 bytes --I have no idea why a 42 byte split works
                                   --0,16,16+24 both spit out a bunch of header
                                   --May work differently on other systems?
                                   --Padding issue? Using 64-bit Linux

printUnsorted :: PktHdr -> B.ByteString -> IO ()
printUnsorted hdr bytes = do
  let quote = parsePacket hdr (CL.fromStrict bytes) --fromStrict is O(1)
  case quote of
    NotQuote -> return ()
    _ -> print quote

type AcceptTime = Word32
type PackTime = Word32
type QuoteHeap = H.MinHeap (AcceptTime, PackTime, PacketContents)

printSorted :: PcapHandle -> QuoteHeap -> IO ()
printSorted handle qh = do
  (hdr, bytes) <- nextBS handle
  let quote = parsePacket hdr (CL.fromStrict bytes)
  if B.null bytes then printRest qh --no more packets, print the whole heap
    else case quote of
        NotQuote -> printSorted handle qh
        QuotePacket{acceptTime=atime, pktTime=ptime} -> do
          let newEntry = (atime, ptime, quote)
              newH = H.insert newEntry qh
          newH' <- printPred ptime newH
          printSorted handle newH'

--TODO
third (_, _, x3) = x3

printRest :: QuoteHeap -> IO ()
--prints the contents of the quoteheap
printRest qh = mapM_ (print . third) $ H.toAscList qh

printPred :: Word32 -> QuoteHeap -> IO QuoteHeap
--prints and removes all packets in the queue dated at least 3 seconds earlier
--should guarantee sorted order without having all packets in memory
printPred packTime qh = do mapM_ (print . third) safeQuotes
                           return newHeap
                        where (safeQuotes, newHeap) = H.span safeToPrint qh
                              safeToPrint item = packTime - snd item > delaySecs
                              snd (_, x2, _) = x2

runUnsorted :: PcapHandle -> IO ()
runUnsorted handle = do dispatchBS handle (-1) printUnsorted
                        return ()

runSorted :: PcapHandle -> IO ()
runSorted handle = printSorted handle H.empty

main = do
  args <- getArgs
  let rflag = "-r" `elem` args
  case filter ("-r"/=) args of
    [] -> error "too few arguments!"
    [file] -> do handle <- openOffline file
                 if rflag then runSorted handle
                 else runUnsorted handle
    _ -> error "too many arguments!"
