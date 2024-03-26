import Control.Monad
import Data.Binary as B
import Data.Binary.Get as B
import Data.Binary.Put as B
import Data.Binary.Builder as BB
import Data.Bits ((.&.), (.>>.))
import qualified Data.Map as M
import qualified Data.ByteString.Lazy as BS
import qualified Data.ByteString.Lazy.Char8 as BSC
import Data.Either
import Data.Maybe
import Text.Printf (PrintfType, PrintfArg, printf)

import qualified Debug.Trace as D

type RawElfFile = BS.ByteString

readElfFile :: String -> IO RawElfFile
readElfFile = BS.readFile

data Elf64EHeader = Elf64EHeader {
  ehEntry         :: !Word64,
  ehPrgHdrOff     :: !Word64,
  ehSecHdrOff     :: !Word64,
  ehFlags         :: !Word32,
  ehPrgHdrNum     :: !Word16,
  ehSecHdrNum     :: !Word16,
  ehSecStrSecIdx  :: !Word16
}

forShow :: Show b => (a -> b) -> a -> String
forShow = (show .)

hexShow :: PrintfArg b => (a -> b) -> a -> String
hexShow f a = (printf "0x%x" $ f a)

showTable :: [(String, a -> String)] -> a -> String
showTable xs a = concat $ map (showItem . (withSnd $ \f -> f a)) xs
  where showItem (n, s) = n ++ ":\t" ++ s ++ "\n"
        withSnd f (a, b) = (a, f b)

instance Show Elf64EHeader where
  show = showTable [
    ("EntryPoint", hexShow ehEntry),
    ("Program Header Offset", forShow ehPrgHdrOff),
    ("Section Header Offset", forShow ehSecHdrOff),
    ("Flags", hexShow ehFlags),
    ("Program header Number", forShow ehPrgHdrNum),
    ("Section header Number", forShow ehSecHdrNum),
    ("Section Name String Table Index", forShow ehSecStrSecIdx) ]

getElf64EHeader :: B.Get Elf64EHeader
getElf64EHeader = do
  B.skip $ 16 + 2 + 2 + 4
  entry     <- B.getWord64le
  prgHrdOff <- B.getWord64le
  secHrdOff <- B.getWord64le
  flags     <- B.getWord32le
  B.skip $ 2 + 2
  prgHrdNum <- B.getWord16le
  B.skip 2
  secHrdNum <- B.getWord16le
  secStrSecIdx <- B.getWord16le
  return $ Elf64EHeader entry prgHrdOff secHrdOff flags prgHrdNum secHrdNum
                        secStrSecIdx

parseBinary :: B.Get a -> BS.ByteString -> Either String a
parseBinary g s = case runGetOrFail g s of
  Left  (_, _, e) -> Left e
  Right (_, _, a) -> Right a

parseElf64EHeader :: BS.ByteString -> Either String Elf64EHeader
parseElf64EHeader = parseBinary getElf64EHeader

data Elf64SHeader = Elf64SHeader {
  shNameOff     :: !Word32,
  shType        :: !Word32,
  shFlags       :: !Word64,
  shAddr        :: !Word64,
  shOff         :: !Word64,
  shSize        :: !Word64,
  shLink        :: !Word32,
  shInfo        :: !Word32,
  shAlign       :: !Word64
}

instance Show Elf64SHeader where
  show = showTable [
    ("Name Offset in .shstrstab", hexShow shNameOff),
    ("Type", hexShow shType),
    ("Flags", hexShow shFlags),
    ("Address", hexShow shAddr),
    ("Offset", hexShow shOff),
    ("Size", hexShow shSize),
    ("Info", hexShow shInfo),
    ("Link", hexShow shLink),
    ("Address Alignement", hexShow shAlign) ]

getElf64SHeader :: B.Get Elf64SHeader
getElf64SHeader = do
  nameOff       <- getWord32le
  t             <- getWord32le
  flags         <- getWord64le
  addr          <- getWord64le
  off           <- getWord64le
  size          <- getWord64le
  link          <- getWord32le
  info          <- getWord32le
  align         <- getWord64le
  return $ Elf64SHeader nameOff t flags addr off size info link align

parseElf64SHeader :: BS.ByteString -> Either String Elf64SHeader
parseElf64SHeader = parseBinary getElf64SHeader

offset :: (Integral a, Integral b, Integral c) =>
          a -> b -> BS.ByteString -> c -> BS.ByteString
offset b s xs n = BS.drop ((fromIntegral b) +
                           (fromIntegral n) * (fromIntegral s)) xs
peekArray = offset 0
offset1 :: (Integral a) => a -> BS.ByteString -> BS.ByteString
offset1 addr = flip (offset addr 0) 0
sizedChunk :: (Integral a, Integral b) => a -> b -> BS.ByteString ->
                                          BS.ByteString
sizedChunk a b = BS.take $ (fromIntegral a) * (fromIntegral b)
sizedChunk1 = sizedChunk 1

parseElf64SHeaders :: Elf64EHeader -> BS.ByteString ->
                      Either String ([Elf64SHeader])
parseElf64SHeaders eh ef = mapM parse [0 .. (ehSecHdrNum eh) - 1]
  where parse = parseElf64SHeader . secHdr ef
        secHdr = offset (ehSecHdrOff eh) 64

getSecData :: Elf64SHeader -> BS.ByteString -> BS.ByteString
getSecData sh ef = sizedChunk1 (shSize sh) $ offset1 (shOff sh) ef

type ElfStrTab = BS.ByteString
parseElfStrTab :: [Elf64SHeader] -> Elf64EHeader -> BS.ByteString ->
                    ElfShStrTab
parseElfStrTab hs eh ef =
  getSecData hdr ef
  where hdr = hs !! (fromIntegral $ ehSecStrSecIdx eh)

parseElfShStrTab = parseElfStrTab

type ElfShStrTab = ElfStrTab
peekNullTermStr :: BS.ByteString -> BS.ByteString
peekNullTermStr = BS.takeWhile (/= 0)

type ElfName = BS.ByteString
getElfName :: (Integral a) => ElfStrTab -> a -> ElfName
getElfName tab off = peekNullTermStr $ offset1 (fromIntegral off) tab

data Elf64PHeader = Elf64PHeader {
  epType        :: !Word32,
  epFlags       :: !Word32,
  epOffset      :: !Word64,
  epVAddr       :: !Word64,
  epPAddr       :: !Word64,
  epFileSize    :: !Word64,
  epMemSize     :: !Word64,
  epAlign       :: !Word64
}

instance Show Elf64PHeader where
  show = showTable [
    ("Type", hexShow epType),
    ("Flags", hexShow epFlags),
    ("Offset", hexShow epOffset),
    ("Virtual Address", hexShow epVAddr),
    ("Physical Address", hexShow epPAddr),
    ("Size in File", forShow epFileSize),
    ("Size in Memory", forShow epMemSize),
    ("Alignment", hexShow epAlign) ]

data Elf64Sym = Elf64Sym {
  esNameOff     :: !Word32,
  esInfo        :: !Word8,
  esOther       :: !Word8,
  esSecHdrIdx   :: !Word16,
  esValue       :: !Word64,
  esSize        :: !Word64
}

instance Show Elf64Sym where
  show = showTable [
    ("Name", forShow esNameOff),
    ("Info", hexShow esInfo),
    ("Other", hexShow esOther),
    ("Section Header Index", forShow esSecHdrIdx),
    ("Value", hexShow esValue),
    ("Size", hexShow esSize) ]

getElf64Sym :: B.Get Elf64Sym
getElf64Sym = do
  name          <- B.getWord32le
  info          <- B.getWord8
  other         <- B.getWord8
  secHdrIdx     <- B.getWord16le
  value         <- B.getWord64le
  size          <- B.getWord64le
  return $ Elf64Sym name info other secHdrIdx value size

parseElf64Sym :: BS.ByteString -> Either String Elf64Sym
parseElf64Sym = parseBinary getElf64Sym

parseElf64SymTab :: BS.ByteString -> Either String [Elf64Sym]
parseElf64SymTab raw =
  mapM (parseElf64Sym . offset 0 24 raw) [0..(n - 1)]
  where n = (BS.length raw) `div` 24

getElf64SymNames :: [Elf64Sym] -> BS.ByteString -> [BS.ByteString]
getElf64SymNames ss tab = map ((getElfName tab) . esNameOff) ss

-- Elf64_Rel and Elf64_Rela is represented as the same type
data Elf64Rel = Elf64Rel {
  erOffset      :: !Word64,
  erInfo        :: !Word64,
  erAddend      :: !Word64
} deriving (Show)

erType :: Elf64Rel -> Word64
erType = (.&. 0xffffffff) . erInfo

erIndex :: Elf64Rel -> Word64
erIndex = (.>>. 32) . erInfo

getElf64Rel :: B.Get Elf64Rel
getElf64Rel = do
  offset <- B.getWord64le
  info   <- B.getWord64le
  return $ Elf64Rel offset info 0

getElf64Rela :: B.Get Elf64Rel
getElf64Rela = do
  offset <- B.getWord64le
  info   <- B.getWord64le
  addend <- B.getWord64le
  return $ Elf64Rel offset info addend

parseElf64Rel = parseBinary getElf64Rel
parseElf64Rela = parseBinary getElf64Rela

parseElf64Rels :: Elf64SHeader -> BS.ByteString -> Either String [Elf64Rel]
parseElf64Rels h p =
  mapM (parseElf64Rel . offset start 16 p) [0 .. (n - 1)]
  where n     = (shSize h) `div` (fromIntegral 16)
        start = shOff h

parseElf64Relas :: Elf64SHeader -> BS.ByteString -> Either String [Elf64Rel]
parseElf64Relas h p =
  mapM (parseElf64Rela . offset start 24 p) [0 .. (n - 1)]
  where n     = (shSize h) `div` (fromIntegral 24)
        start = shOff h

newtype ElfLayout = ElfLayout {
  elSecStart    :: Word64
}

data Relocator = Relocator8  (ElfLayout -> Elf64Rel -> Elf64Sym -> Word8)
               | Relocator16 (ElfLayout -> Elf64Rel -> Elf64Sym -> Word16)
               | Relocator32 (ElfLayout -> Elf64Rel -> Elf64Sym -> Word32)
               | Relocator64 (ElfLayout -> Elf64Rel -> Elf64Sym -> Word64)

rel32S el r sym = fromIntegral $ (esValue sym) + (erAddend r) + s
  where s = fromIntegral $ elSecStart el

relocators = [
  (11, Relocator32 rel32S) ]

relocate :: [Elf64Sym] -> ElfLayout -> Elf64Rel -> BS.ByteString
relocate symTab el r =
  case relocator of
    Relocator32 f -> B.encode $ f el r sym
  where relocator = fromJust $ lookup (erType r) relocators
        sym       = symTab !! (fromIntegral $ erIndex r)


fromRight' = fromRight undefined

main = do
  p  <- readElfFile "test.o"
  let eh = fromRight' $ parseElf64EHeader p
  putStrLn "==== Program Header ===="
  putStr $ show eh
  let shs = fromRight' $ parseElf64SHeaders eh p
  putStrLn "==== Header No. 1 ===="
  putStr $ show $ shs !! 1
  let sst = parseElfShStrTab shs eh p
  putStrLn "==== Section String Table ===="
  putStrLn $ show sst
  let secNames = map ((getElfName sst) . shNameOff) shs
  putStrLn "==== All Section Names ===="
  mapM_ (putStrLn . show) secNames
  let shs' = zip secNames shs
      hStrTab = fromJust $ lookup (BSC.pack ".strtab") shs'
      strTab = getSecData hStrTab p
      hSymTab = fromJust $ lookup (BSC.pack ".symtab") shs'
      rawSymTab = getSecData hSymTab p
      symTab = fromRight' $ parseElf64SymTab rawSymTab
      symNames = getElf64SymNames symTab strTab
  putStrLn "==== String Table ===="
  putStrLn $ show strTab
  putStrLn "==== Symbol Table ===="
  putStrLn $ show symTab
  putStrLn "==== Symbol Names ===="
  mapM_ (putStrLn . show) symNames

  let shRela = fromJust $ lookup (BSC.pack ".rela.text") shs'
  let rels   = fromRight' $ parseElf64Relas shRela p
  putStrLn "==== Relocs ===="
  mapM_ (putStrLn . show) rels

  let layout  = ElfLayout 0x400000
  let rels'   = map (relocate symTab layout) rels
  putStrLn "==== Relocation result ===="
  mapM_ (putStrLn . hexShow (B.decode :: BS.ByteString -> Word32)) rels'
