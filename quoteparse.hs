import System.Environment
import Network.Pcap
import Data.Binary.Get
import Control.Monad
import Data.Word
import qualified Data.Heap as H
import qualified Data.ByteString as B
import qualified Data.ByteString.Lazy as BL
import qualified Data.ByteString.Char8 as C
import qualified Data.ByteString.Lazy.Char8 as CL

{-
 Market Data Feed Parser/Tsuru Capital Code Sample
 Mark Hay, 2018, mah6@williams.edu

 The general idea, ignoring packet ordering, is straightforward: recieve a packet from
 the dump file via Network.Pcap, parse its body as a Quote if it has the correct size and 
 opening bytes,then print it.
 
 When packets must be ordered, a heap is used to take advantage of the fact that packet
 and accept time are no more than three seconds apart. Instead of printing a packet as
 soon as it is recieved, the packet (if it is a quote) is inserted in a (functional) heap,
 ordered by quote accept time, then packet time. After any packet is recieved, the heap is
 popped and printed until the heap head's time is within three seconds of the newest
 packet's packet time. Once the last packet is recieved, the remaining heap is then
 printed. The packets can therefore be printed in sorted order without having more than
 three seconds' worth of trading data in memory at any given time.
 -}

quoteStart = C.pack "B6034" --Start of relevant packet messages
quotePacketSize = 257 --Length of quote packets, from wireshark
dataOffset = 42 --Distance from start of packet to data, also from wireshark

delaySecs = 3 --max distance between packet time and quote accept time in seconds

data Qp = Qp String String deriving (Eq, Ord) --quantity and price
instance Show Qp where show (Qp q p) = q ++ "@" ++ p

data Quote = Quote {
    issueCode :: String,
    bids :: (Qp, Qp, Qp, Qp, Qp), 
    asks :: (Qp, Qp, Qp, Qp, Qp),
    pktTime :: Word32,
    acceptTime :: Word32
    } deriving (Eq, Ord)

instance Show Quote where
  show Quote{
    issueCode = issueCode,
    bids = bids,
    asks = asks,
    pktTime = packtime,
    acceptTime =  acceptTime
} = unwords [show packtime, show acceptTime, issueCode, printDescQps bids, printAscQps asks]
    where printAscQps (x1, x2, x3, x4, x5) = unwords $ map show [x1, x2, x3, x4, x5]
          printDescQps (x1, x2, x3, x4, x5) = unwords $ map show [x5, x4, x3, x2, x1]

{-
--prints just the accept times; for checking correctness of -r 
instance Show Quote where
  show Quote{acceptTime = acceptTime} = show acceptTime
-}

--Extract quote from the body of a valid quote Packet
--We add in packtime from the pcap header
getQuote :: Word32 -> Get Quote
getQuote packtime = do
  let getPriceQuantity = (,) <$> getByteString 5 <*> getByteString 7 
  skip 5 --B6034
  issueCode <- getByteString 12
  skip 12 --3 + 2 + 7

  bids_ <- replicateM 5 getPriceQuantity
  skip 7
  asks_ <- replicateM 5 getPriceQuantity
  
  skip 50

  acceptTime <- getByteString 8
  
  let [bid1, bid2, bid3, bid4, bid5] = map unpackQp bids_
      [ask1, ask2, ask3, ask4, ask5] = map unpackQp asks_
      unpackQp (p, q) = Qp (C.unpack p) (C.unpack q)

  return Quote {
    issueCode = C.unpack issueCode,
    pktTime = packtime,
    acceptTime = read (C.unpack acceptTime) :: Word32,
    bids = (bid1, bid2, bid3, bid4, bid5),
    asks = (ask1, ask2, ask3, ask4, ask5)
    }

parsePacket :: PktHdr -> B.ByteString -> Maybe Quote
parsePacket header bytes
  | packlen /= quotePacketSize = Nothing --packet must be the correct size
  | B.take 5 body /= quoteStart = Nothing --packet must start with correct message
  | otherwise = Just $ runGet (getQuote packtime) (CL.fromStrict body) --fromStrict is O(1)
  where
    PktHdr{hdrCaptureLength = packlen, hdrSeconds = packtime} = header
    (_,body) = B.splitAt dataOffset bytes

printUnsorted :: PktHdr -> B.ByteString -> IO ()
printUnsorted hdr bytes = do
  let packet = parsePacket hdr bytes 
  forM_ packet print 

type QuoteHeap = H.MinHeap (Word32, Word32, Quote) --(Accept Time, Pack Time, Quote)

printSorted :: PcapHandle -> QuoteHeap -> IO ()
printSorted handle qh = do
  (hdr, bytes) <- nextBS handle
  let packet = parsePacket hdr bytes
      PktHdr{hdrSeconds = packtime} = hdr
  if B.null bytes then printRest qh --no more packets, print the whole heap
    else do
          newH <- printPred packtime qh --print elements 3 seconds younger than packtime
          case packet of --if the new packet is a quote, add it to the heap
            Just quote@Quote{acceptTime=atime} ->
              printSorted handle (H.insert newEntry newH)
              where newEntry = (atime, packtime, quote)
            Nothing -> printSorted handle newH

third (_, _, x3) = x3

printRest :: QuoteHeap -> IO ()
--prints the contents of the quoteheap
printRest qh = mapM_ (print . third) $ H.toAscList qh

printPred :: Word32 -> QuoteHeap -> IO QuoteHeap
--pops and prints all packets in the heap recieved least 3 seconds earlier
--should guarantee sorted order without needing all packets in memory
printPred packTime qh = do mapM_ (print . third) safeQuotes
                           return newHeap
                        where (safeQuotes, newHeap) = H.span safeToPrint qh
                              safeToPrint item = packTime - snd item > delaySecs
                              snd (_, x2, _) = x2

main = do
  args <- getArgs
  let rflag = "-r" `elem` args
  case filter ("-r"/=) args of
    [] -> error "too few arguments!"
    [file] -> do handle <- openOffline file
                 if rflag then runSorted handle
                 else runUnsorted handle
    _ -> error "too many arguments!"
  where runUnsorted handle = void $ dispatchBS handle (-1) printUnsorted
        runSorted handle = printSorted handle H.empty
