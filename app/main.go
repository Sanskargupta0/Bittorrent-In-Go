package main

import (
	"crypto/sha1"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"strconv"
	"strings"
	"sync"

	netUrl "net/url"

	"github.com/codecrafters-io/bittorrent-starter-go/app/bencode"
	"github.com/codecrafters-io/bittorrent-starter-go/app/magnet"
	"github.com/codecrafters-io/bittorrent-starter-go/app/utils"
)

// Ensures gofmt doesn't remove the "os" encoding/json import (feel free to remove this!)
var _ = json.Marshal

const BITFIELD = 5
const INTERESTED = 2
const UNCHOKE = 1
const REQUEST = 6
const PIECE = 7
const BLOCK_LENGTH = 16 * 1024

var pieces_map map[int][]byte
var pieces_lock sync.Mutex

func WaitForSpecificExtensionMsg(conn net.Conn, msgId uint8) ([]byte, error) {
	for {
		rcvdMsgId, payload, err := GetExtensionReqMessaage(conn)
		//fmt.Println("received msg with id: " + strconv.Itoa(int(rcvdMsgId)))
		if err != nil {
			return nil, err
		}
		if rcvdMsgId == msgId {
			return payload, nil
		}
	}
}

func WaitForSpecificPeerMessage(conn net.Conn, msgId uint8) ([]byte, error) {
	for {
		rcvdMsgId, payload, err := GetPeerMessage(conn)
		//fmt.Println("received msg with id: " + strconv.Itoa(int(rcvdMsgId)))
		if err != nil {
			return nil, err
		}
		if rcvdMsgId == msgId {
			return payload, nil
		}
	}
}

func SendRequestMsg(conn net.Conn, index uint32, begin uint32, length uint32) {
	payload := make([]byte, 0)
	payload = binary.BigEndian.AppendUint32(payload, index)
	payload = binary.BigEndian.AppendUint32(payload, begin)
	payload = binary.BigEndian.AppendUint32(payload, length)

	SendPeerMessage(conn, REQUEST, payload)
}

func SendPeerMessage(conn net.Conn, msgId uint8, payload []byte) {
	data := make([]byte, 0)
	// append msg length
	messageLengthBytes := make([]byte, 0)
	messageLengthBytes = binary.BigEndian.AppendUint32(messageLengthBytes, uint32(len(payload)+1))
	data = append(data, messageLengthBytes...)

	// append msgId
	data = append(data, byte(msgId))

	// append payload
	data = append(data, payload...)

	// send msg
	//fmt.Println("sending peer msg with msgId: " + strconv.Itoa(int(msgId)))
	conn.Write(data)
}

func getPieceLength(index int, pieceLength int, totalLength int) int {
	if (pieceLength * (index + 1)) < totalLength {
		return pieceLength
	}
	return totalLength - (pieceLength * index)
}
func GetPeerMessage(conn net.Conn) (uint8, []byte, error) {
	messageLengthBytes := make([]byte, 4)
	messageIdBytes := make([]byte, 1)
	//fmt.Println("starting reading peer msg")

	_, err := conn.Read(messageLengthBytes)
	if err != nil {
		log.Fatalf("%s error reading msg length", err.Error())
		return 0, nil, err
	}

	messageLength := binary.BigEndian.Uint32(messageLengthBytes)
	//log.Println("retrieved msg with msglength: " + strconv.Itoa(int(messageLength)))

	_, err = conn.Read(messageIdBytes)
	if err != nil {
		log.Fatalf("%s error reading msg id", err.Error())
		return 0, nil, err
	}

	//log.Println("retrieved msg with id: " + strconv.Itoa(int(messageIdBytes[0])))

	payload := make([]byte, messageLength-1)

	_, err = io.ReadFull(conn, payload)

	if err != nil {
		log.Fatalf("%s error payload", err.Error())
		return 0, nil, err
	}

	return uint8(messageIdBytes[0]), payload, nil
}

func GetExtensionReqMessaage(conn net.Conn) (uint8, []byte, error) {
	messageLengthBytes := make([]byte, 4)
	messageIdBytes := make([]byte, 1)
	//fmt.Println("starting reading peer msg")

	_, err := conn.Read(messageLengthBytes)
	if err != nil {
		log.Fatalf("%s error reading msg length", err.Error())
		return 0, nil, err
	}

	messageLength := binary.BigEndian.Uint32(messageLengthBytes)
	//log.Println("retrieved msg with msglength: " + strconv.Itoa(int(messageLength)))

	_, err = conn.Read(messageIdBytes)
	if err != nil {
		log.Fatalf("%s error reading msg id", err.Error())
		return 0, nil, err
	}

	//log.Println("retrieved msg with id: " + strconv.Itoa(int(messageIdBytes[0])))

	payload := make([]byte, messageLength-1)

	_, err = io.ReadFull(conn, payload)

	if err != nil {
		log.Fatalf("%s error payload", err.Error())
		return 0, nil, err
	}

	return uint8(messageIdBytes[0]), payload, nil
}

func DiscoverPeers(trackerUrl string, infoHash string, length int) ([]string, error) {
	infoBtes, _ := hex.DecodeString(infoHash)
	var urlBuilder strings.Builder
	urlBuilder.WriteString(trackerUrl)
	urlBuilder.WriteString("?info_hash=" + netUrl.QueryEscape(string(infoBtes)))
	urlBuilder.WriteString("&peer_id=" + utils.GetPeerId())
	urlBuilder.WriteString("&port=6881")
	urlBuilder.WriteString("&uploaded=0")
	urlBuilder.WriteString("&downloaded=0")
	urlBuilder.WriteString(fmt.Sprintf("&left=%s", strconv.Itoa(length)))
	urlBuilder.WriteString("&compact=1")

	resp, err := http.Get(urlBuilder.String())
	if err != nil {
		log.Fatalf("peer error %s", err.Error())
		return nil, err
	}
	defer resp.Body.Close()
	// Read the response body
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		log.Fatalf("error reading body of get %s", err.Error())
		return nil, fmt.Errorf("error reading body of get")
	}
	decodedMap, _, err := bencode.DecodeBencode(string(body), 0)
	if err != nil {
		log.Fatalf("error decoding %s", err.Error())
		return nil, err
	}
	m := decodedMap.(map[string]interface{})
	peers, _ := utils.DecodePeers([]byte(bencode.ConvToString(m["peers"])))

	return peers, nil
}

func GetHandshakeBytes(infoHash []byte) ([]byte, error) {
	data := make([]byte, 0)
	// Write length
	data = append(data, byte(19))

	// Write protocol string
	data = append(data, []byte("BitTorrent protocol")...)
	for i := 0; i < 8; i++ {
		data = append(data, byte(0))
	}

	// Write hash
	data = append(data, infoHash...)

	// Write peer id
	peerId := make([]byte, 0)
	for i := 0; i < 20; i++ {
		peerId = append(peerId, byte(1))
	}
	data = append(data, peerId...)
	return data, nil
}

func StartPeerConnectionNaive(torrentInfo map[string]interface{}, peerIp string, piecesChannel chan int, freePeer chan string) error {
	info, _ := ReadInfo(torrentInfo)
	for {
		pieceIndex, ok := <-piecesChannel
		if !ok {
			log.Println("piece channel not ok")
			break
		}
		//log.Printf("piece Id: %s got for peer Ip %s", strconv.Itoa(pieceIndex), peerIp)

		piece, err := DownloadPieceWithPeerIp(torrentInfo, pieceIndex, peerIp)
		if err != nil {
			log.Print("error dll piece")
			return err
		}

		//log.Println("verify piece")
		sum := sha1.Sum(piece)
		pieces := GetPiecesHash(info)
		if string(sum[:]) != pieces[pieceIndex] {
			log.Fatalf("hash not matching")
		} else {
			pieces_lock.Lock()
			pieces_map[pieceIndex] = piece
			pieces_lock.Unlock()
			log.Println(peerIp + " is free")
			freePeer <- peerIp
		}
	}
	return nil
}

func StartPeerConnectionNaiveForMagnet(torrentInfo magnet.MagnetInfo, peerIp string, piecesChannel chan int, freePeer chan string) error {
	for {
		pieceIndex, ok := <-piecesChannel
		if !ok {
			log.Println("piece channel not ok")
			break
		}
		//log.Printf("piece Id: %s got for peer Ip %s", strconv.Itoa(pieceIndex), peerIp)

		piece, err := DownloadPieceWithPeerIpForMagnet(torrentInfo, pieceIndex, peerIp)
		if err != nil {
			log.Print("error dll piece")
			return err
		}

		//log.Println("verify piece")
		sum := sha1.Sum(piece)
		pieces := torrentInfo.Pieces
		if string(sum[:]) != pieces[pieceIndex] {
			log.Fatalf("hash not matching")
		} else {
			pieces_lock.Lock()
			pieces_map[pieceIndex] = piece
			pieces_lock.Unlock()
			log.Println(peerIp + " is free")
			freePeer <- peerIp
		}
	}
	return nil
}

func DownloadFile(torrentInfo map[string]interface{}) ([]byte, error) {
	pieces_map = make(map[int][]byte)
	pieces_lock = sync.Mutex{}

	info, _ := ReadInfo(torrentInfo)
	peers, err := DiscoverPeers(bencode.ConvToString(torrentInfo["announce"]), HashInfo(info), info["length"].(int))
	if err != nil {
		return nil, err
	}

	numPieces := len(GetPiecesHash(info))
	piecesQueue := make([]int, numPieces)
	for i := 0; i < numPieces; i++ {
		piecesQueue[i] = i
	}

	freePeers := peers
	freePeerChan := make(chan string)
	peerToChan := make(map[string]chan int)
	for i := 0; i < len(peers); i++ {
		peerChan := make(chan int)
		peerToChan[peers[i]] = peerChan
		log.Println("starting peer conn " + peers[i])
		go StartPeerConnectionNaive(torrentInfo, peers[i], peerChan, freePeerChan)
	}

	for len(piecesQueue) > 0 {
		pieceId := piecesQueue[0]
		if len(freePeers) > 0 {
			peer := freePeers[0]
			freePeers = freePeers[1:]
			log.Println("requesting piece " + strconv.Itoa(pieceId))
			peerToChan[peer] <- pieceId
			piecesQueue = piecesQueue[1:]
		} else {
			//log.Println("waiting for free peer to send piece to " + strconv.Itoa(pieceId))
			peer := <-freePeerChan
			freePeers = append(freePeers, peer)
		}
		//
	}

	for len(pieces_map) < numPieces {
	}

	log.Println("closing peer channels")
	for _, chann := range peerToChan {
		close(chann)
	}
	log.Printf("pieces map size: %s", strconv.Itoa(len(pieces_map)))
	log.Println("closing free peer channels")
	//close(freePeerChan)

	file := make([]byte, 0)
	for i := 0; i < len(pieces_map); i++ {
		file = append(file, pieces_map[i]...)
	}
	return file, nil
}

func DownloadFileForMagnet(torrentInfo magnet.MagnetInfo) ([]byte, error) {
	pieces_map = make(map[int][]byte)
	pieces_lock = sync.Mutex{}

	numPieces := len(torrentInfo.Pieces)
	piecesQueue := make([]int, numPieces)
	for i := 0; i < numPieces; i++ {
		piecesQueue[i] = i
	}

	freePeers := torrentInfo.PeerIps
	freePeerChan := make(chan string)
	peerToChan := make(map[string]chan int)
	for i := 0; i < len(torrentInfo.PeerIps); i++ {
		peerChan := make(chan int)
		peerToChan[torrentInfo.PeerIps[i]] = peerChan
		log.Println("starting peer conn " + torrentInfo.PeerIps[i])
		go StartPeerConnectionNaiveForMagnet(torrentInfo, torrentInfo.PeerIps[i], peerChan, freePeerChan)
	}

	for len(piecesQueue) > 0 {
		pieceId := piecesQueue[0]
		if len(freePeers) > 0 {
			peer := freePeers[0]
			freePeers = freePeers[1:]
			log.Println("requesting piece " + strconv.Itoa(pieceId))
			peerToChan[peer] <- pieceId
			piecesQueue = piecesQueue[1:]
		} else {
			//log.Println("waiting for free peer to send piece to " + strconv.Itoa(pieceId))
			peer := <-freePeerChan
			freePeers = append(freePeers, peer)
		}
		//
	}

	for len(pieces_map) < numPieces {
	}

	log.Println("closing peer channels")
	for _, chann := range peerToChan {
		close(chann)
	}
	log.Printf("pieces map size: %s", strconv.Itoa(len(pieces_map)))
	log.Println("closing free peer channels")
	//close(freePeerChan)

	file := make([]byte, 0)
	for i := 0; i < len(pieces_map); i++ {
		file = append(file, pieces_map[i]...)
	}
	return file, nil
}

func DownloadPiece(torrentInfo map[string]interface{}, pieceIndex int) ([]byte, error) {
	info, _ := ReadInfo(torrentInfo)
	peers, err := DiscoverPeers(bencode.ConvToString(torrentInfo["announce"]), HashInfo(info), info["length"].(int))
	if err != nil {
		log.Fatalf("error discovering peers")
		return nil, err
	}

	peerIp := peers[0]
	return DownloadPieceWithPeerIp(torrentInfo, pieceIndex, peerIp)
}

func DownloadPieceWithPeerIpForMagnet(magInfo magnet.MagnetInfo, pieceIndex int, peerIp string) ([]byte, error) {
	conn, err := utils.MakeConnection(peerIp)
	if err != nil {
		log.Fatalf("error with handshake")
		return nil, err
	}

	hashBytes, _ := hex.DecodeString(magInfo.InfoHash)
	handshake, err := GetHandshakeBytes(hashBytes)
	if err != nil {
		log.Fatalf("error with handshake")
		return nil, err
	}
	conn.Write(handshake)

	buf := make([]byte, 68)
	_, err = conn.Read(buf)
	if err != nil {
		log.Fatalf("error read")
		return nil, err
	}

	//peerId := buf[len(buf)-20:]
	//log.Println("Peer ID: " + hex.EncodeToString(peerId))
	//log.Println("waiting for bitfeld msg")
	_, err = WaitForSpecificPeerMessage(conn, BITFIELD)
	if err != nil {
		log.Fatalf("error retrieving bitfield msg")
		return nil, err
	}

	// Send interested msg
	//log.Println("sending interested msg")
	SendPeerMessage(conn, 2, make([]byte, 0))

	// Wait for unchoke msg
	//log.Println("waiting for unchoke msg")
	_, err = WaitForSpecificPeerMessage(conn, UNCHOKE)
	if err != nil {
		log.Fatalf("error retrieving unchoke msg")
		return nil, err
	}
	//log.Println("received unchoke msg")
	piece_length := getPieceLength(pieceIndex, magInfo.PieceLength, magInfo.Length)
	//log.Print("piece length: " + strconv.Itoa(piece_length))
	piece_data := make([]byte, piece_length)
	for beginOffset := 0; beginOffset < piece_length; beginOffset = beginOffset + BLOCK_LENGTH {
		//log.Println("sending request msg with begin: " + strconv.Itoa(beginOffset))
		var blockLength int
		if (beginOffset + BLOCK_LENGTH) < piece_length {
			blockLength = BLOCK_LENGTH
		} else {
			blockLength = piece_length - beginOffset
		}

		SendRequestMsg(conn, uint32(pieceIndex), uint32(beginOffset), uint32(blockLength))
	}

	for beginOffset := 0; beginOffset < piece_length; beginOffset = beginOffset + BLOCK_LENGTH {
		//log.Println("waiting for download msg")
		block, err := WaitForSpecificPeerMessage(conn, PIECE)
		//log.Println("rcvd download msg")
		if err != nil {
			log.Fatalf("error piece msg")
			return nil, err
		}

		rcvdPieceIndex := binary.BigEndian.Uint32(block[0:4])
		if rcvdPieceIndex != uint32(pieceIndex) {
			log.Fatalf("rcvd piece index different")
			os.Exit(1)
		}

		begin := binary.BigEndian.Uint32(block[4:8])
		for bi := 8; bi < len(block); bi++ {
			piece_data[begin] = block[bi]
			begin = begin + 1
		}
	}
	//log.Println("verify piece")
	sum := sha1.Sum(piece_data)
	if string(sum[:]) != magInfo.Pieces[pieceIndex] {
		log.Fatalf("piece hash incorrect")
	}
	defer conn.Close()
	return piece_data, nil
}

func DownloadPieceWithPeerIp(torrentInfo map[string]any, pieceIndex int, peerIp string) ([]byte, error) {
	info, err := ReadInfo(torrentInfo)
	if err != nil {
		log.Fatalf("Issue with info")
		return nil, err
	}

	conn, err := utils.MakeConnection(peerIp)
	if err != nil {
		log.Fatalf("error with handshake")
		return nil, err
	}

	hashBytes, _ := hex.DecodeString(HashInfo(info))
	handshake, err := GetHandshakeBytes(hashBytes)
	if err != nil {
		log.Fatalf("error with handshake")
		return nil, err
	}
	conn.Write(handshake)

	buf := make([]byte, 68)
	_, err = conn.Read(buf)
	if err != nil {
		log.Fatalf("error read")
		return nil, err
	}

	//peerId := buf[len(buf)-20:]
	//log.Println("Peer ID: " + hex.EncodeToString(peerId))
	//log.Println("waiting for bitfeld msg")
	_, err = WaitForSpecificPeerMessage(conn, BITFIELD)
	if err != nil {
		log.Fatalf("error retrieving bitfield msg")
		return nil, err
	}

	// Send interested msg
	//log.Println("sending interested msg")
	SendPeerMessage(conn, 2, make([]byte, 0))

	// Wait for unchoke msg
	//log.Println("waiting for unchoke msg")
	_, err = WaitForSpecificPeerMessage(conn, UNCHOKE)
	if err != nil {
		log.Fatalf("error retrieving unchoke msg")
		return nil, err
	}
	//log.Println("received unchoke msg")
	piece_length := getPieceLength(pieceIndex, info["piece length"].(int), info["length"].(int))
	//log.Print("piece length: " + strconv.Itoa(piece_length))
	piece_data := make([]byte, piece_length)
	for beginOffset := 0; beginOffset < piece_length; beginOffset = beginOffset + BLOCK_LENGTH {
		//log.Println("sending request msg with begin: " + strconv.Itoa(beginOffset))
		var blockLength int
		if (beginOffset + BLOCK_LENGTH) < piece_length {
			blockLength = BLOCK_LENGTH
		} else {
			blockLength = piece_length - beginOffset
		}

		SendRequestMsg(conn, uint32(pieceIndex), uint32(beginOffset), uint32(blockLength))
	}

	for beginOffset := 0; beginOffset < piece_length; beginOffset = beginOffset + BLOCK_LENGTH {
		//log.Println("waiting for download msg")
		block, err := WaitForSpecificPeerMessage(conn, PIECE)
		//log.Println("rcvd download msg")
		if err != nil {
			log.Fatalf("error piece msg")
			return nil, err
		}

		rcvdPieceIndex := binary.BigEndian.Uint32(block[0:4])
		if rcvdPieceIndex != uint32(pieceIndex) {
			log.Fatalf("rcvd piece index different")
			os.Exit(1)
		}

		begin := binary.BigEndian.Uint32(block[4:8])
		for bi := 8; bi < len(block); bi++ {
			piece_data[begin] = block[bi]
			begin = begin + 1
		}
	}
	//log.Println("verify piece")
	sum := sha1.Sum(piece_data)
	pieces := GetPiecesHash(info)
	if string(sum[:]) != pieces[pieceIndex] {
		log.Fatalf("piece hash incorrect")
	}
	defer conn.Close()
	return piece_data, nil
}

func GetMagnetInfo(magnetLink string) (magnet.MagnetInfo, error) {
	magInfo := magnet.MagnetInfo{}
	parsed, err := magnet.ParseMagnetLink(magnetLink)
	if err != nil {
		log.Fatal(err.Error())
	}

	log.Println("parsed magnet link")
	trackerUrl, err := magnet.GetTrackerUrl(parsed)
	if err != nil {
		log.Print(err.Error())
		return magInfo, err
	}

	infoHash, err := magnet.GetInfoHash(parsed)
	if err != nil {
		log.Print(err.Error())
		return magInfo, err
	}

	peers, err := magnet.DiscoverPeers(trackerUrl, infoHash)
	if err != nil {
		log.Print(err.Error())
		return magInfo, err
	}
	log.Println("discovered peers")
	peerIp := peers[0]
	conn, err := utils.MakeConnection(peerIp)
	if err != nil {
		fmt.Println("error with making connection")
		return magInfo, err
	}

	hashBytes, _ := hex.DecodeString(infoHash)
	handshake, err := magnet.GetHandshakeBytesForMagnet(hashBytes)
	if err != nil {
		log.Print("error with handshake")
		return magInfo, err
	}
	conn.Write(handshake)

	buf := make([]byte, 68)
	_, err = conn.Read(buf)
	if err != nil {
		log.Print("error read")
		return magInfo, err
	}

	peerId := buf[len(buf)-20:]
	// TODO: send & receive bitfeld msg
	log.Println("rcving bitfield msg")
	_, err = WaitForSpecificPeerMessage(conn, BITFIELD)
	if err != nil {
		log.Print("error rcv bitfield")
		return magInfo, err
	}

	magnetBytes, err := magnet.GetHandshakeBytesForMagnetExtension2()
	if err != nil {
		log.Print(err.Error())
		return magInfo, err
	}
	if buf[25] == 16 {
		log.Println("sending extension handshake")
		conn.Write(magnetBytes)
	}

	log.Println("start receiving magnet extension handshake")
	msgLength := make([]byte, 4)
	_, err = conn.Read(msgLength)
	if err != nil {
		log.Print("error reading msglength")
		return magInfo, err
	}
	msgLengthInt := binary.BigEndian.Uint32(msgLength)
	log.Println("length: " + strconv.Itoa(int(msgLengthInt)))
	magPayload := make([]byte, msgLengthInt)
	_, err = io.ReadFull(conn, magPayload)
	if err != nil {
		log.Print("error reading payload")
		return magInfo, err
	}
	defer conn.Close()
	log.Print("magM: " + strconv.Itoa(len(magPayload)))
	magM, _, err := bencode.DecodeBencode(string(magPayload[2:]), 0)
	magMMap := magM.(map[string]any)
	if err != nil {
		log.Print("error decoding")
		return magInfo, err
	}
	m := magMMap["m"].(map[string]any)
	magPeer := bencode.ConvToString(m["ut_metadata"])

	magReqMsgMap := magM.(map[string]any)
	magReqMsgMap["msg_type"] = 0
	magReqMsgMap["piece"] = 0

	magReqMsgMapEncoded, err := bencode.DictToBencode(magReqMsgMap)
	if err != nil {
		log.Print("error encoding")
		return magInfo, err
	}

	peerExtId, err := strconv.Atoi(magPeer)
	if err != nil {
		log.Print("peerid failure " + hex.EncodeToString(peerId))
		return magInfo, err
	}

	magnet.SendExtensionMessage(conn, peerExtId, []byte(magReqMsgMapEncoded))

	reqMsg, err := WaitForSpecificExtensionMsg(conn, 20)
	if err != nil {
		log.Print(err.Error())
		return magInfo, err
	}

	//extensionMsgId := reqMsg[0]
	_, index, err := bencode.DecodeBencode(string(reqMsg[1:]), 0)
	if err != nil {
		log.Print(err.Error())
		return magInfo, err
	}
	extMsg, _, err := bencode.DecodeBencode(string(reqMsg[1+index:]), 0)
	if err != nil {
		log.Print(err.Error())
		return magInfo, err
	}
	extMsgM := extMsg.(map[string]any)

	magInfo.InfoHash = infoHash
	magInfo.PeerIps = peers
	magInfo.PieceLength, _ = strconv.Atoi(bencode.ConvToString(extMsgM["piece length"]))
	magInfo.Length, _ = strconv.Atoi(bencode.ConvToString(extMsgM["length"]))
	magInfo.Pieces = GetPiecesHash(extMsgM)
	magInfo.TrackerUrl = trackerUrl

	return magInfo, nil
}

func main() {
	// You can use print statements as follows for debugging, they'll be visible when running tests.
	fmt.Fprintln(os.Stderr, "Logs from your program will appear here!")

	command := os.Args[1]

	if command == "decode" {
		bencodedValue := os.Args[2]
		jsonOutput, _ := bencode.DecodeBencodeToString(bencodedValue)
		fmt.Println(jsonOutput)
	} else if command == "info" {
		filePath := os.Args[2]
		info, err := DecodeInfo(filePath)
		if err != nil {
			log.Fatalf("Issue with info")
			os.Exit(1)
		}
		fmt.Println(info)
	} else if command == "peers" {
		filePath := os.Args[2]
		m, err := ReadTorrent(filePath)
		if err != nil {
			log.Fatalf("Issue with m")
			os.Exit(1)
		}
		info, err := ReadInfo(m)
		if err != nil {
			log.Fatalf("Issue with info")
			os.Exit(1)
		}

		ans, err := DiscoverPeers(bencode.ConvToString(m["announce"]), HashInfo(info), info["length"].(int))
		if err != nil {
			log.Fatalf("Issue with peer")
			os.Exit(1)
		}
		strAns := strings.Join(ans, "\n")
		fmt.Println(strAns)
	} else if command == "handshake" {
		filePath := os.Args[2]
		m, err := ReadTorrent(filePath)
		if err != nil {
			log.Fatalf("Issue with m")
			os.Exit(1)
		}
		info, err := ReadInfo(m)
		if err != nil {
			log.Fatalf("Issue with info")
			os.Exit(1)
		}

		peerIp := os.Args[3]
		conn, err := utils.MakeConnection(peerIp)
		if err != nil {
			fmt.Println("error with handshake")
			os.Exit(1)
		}

		hashBytes, _ := hex.DecodeString(HashInfo(info))
		handshake, err := GetHandshakeBytes(hashBytes)
		if err != nil {
			log.Fatalf("error with handshake")
			os.Exit(1)
		}
		conn.Write(handshake)

		buf := make([]byte, 68)
		_, err = conn.Read(buf)
		if err != nil {
			log.Fatalf("error read")
			os.Exit(1)
		}

		peerId := buf[len(buf)-20:]
		fmt.Println("Peer ID: " + hex.EncodeToString(peerId))
	} else if command == "download_piece" {
		downPath := os.Args[3]
		filePath := os.Args[4]
		pieceIndex, err := strconv.Atoi(os.Args[5])
		if err != nil {
			log.Fatal("issue decoding args")
		}

		torrentInfo, err := ReadTorrent(filePath)
		if err != nil {
			log.Fatal("issue reading torrent info")
		}
		piece_data, err := DownloadPiece(torrentInfo, pieceIndex)
		if err != nil {
			log.Fatal("issue downloading piece")
		}
		log.Println("writing to file")
		os.WriteFile(downPath, piece_data, 0644)
	} else if command == "download" {
		downPath := os.Args[3]
		filePath := os.Args[4]
		torrentInfo, err := ReadTorrent(filePath)
		if err != nil {
			log.Fatal("issue reading torrent info")
		}
		file, err := DownloadFile(torrentInfo)
		if err != nil {
			log.Fatalf("issue with dll")
		}
		log.Println("writing to file")
		os.WriteFile(downPath, file, 0644)
	} else if command == "magnet_parse" {
		parsed, err := magnet.ParseMagnetLink(os.Args[2])
		if err != nil {
			log.Fatal(err.Error())
		}
		magHash, err := magnet.GetInfoHash(parsed)
		if err != nil {
			log.Fatal(err.Error())
		}

		trackerUrl, err := magnet.GetTrackerUrl(parsed)
		if err != nil {
			log.Fatal(err.Error())
		}
		op := "Tracker URL: " + trackerUrl + "\nInfo Hash: " + magHash
		fmt.Println(op)
	} else if command == "magnet_handshake" {
		magnetLink := os.Args[2]
		parsed, err := magnet.ParseMagnetLink(magnetLink)
		if err != nil {
			log.Fatal(err.Error())
		}

		log.Println("parsed magnet link")
		trackerUrl, err := magnet.GetTrackerUrl(parsed)
		if err != nil {
			log.Fatal(err.Error())
		}

		infoHash, err := magnet.GetInfoHash(parsed)
		if err != nil {
			log.Fatal(err.Error())
		}

		peers, err := magnet.DiscoverPeers(trackerUrl, infoHash)
		if err != nil {
			log.Fatal(err.Error())
		}
		log.Println("discovered peers")
		peerIp := peers[0]
		conn, err := utils.MakeConnection(peerIp)
		if err != nil {
			fmt.Println("error with making connection")
			os.Exit(1)
		}

		hashBytes, _ := hex.DecodeString(infoHash)
		handshake, err := magnet.GetHandshakeBytesForMagnet(hashBytes)
		if err != nil {
			log.Fatalf("error with handshake")
			os.Exit(1)
		}
		conn.Write(handshake)

		buf := make([]byte, 68)
		_, err = conn.Read(buf)
		if err != nil {
			log.Fatalf("error read")
			os.Exit(1)
		}

		peerId := buf[len(buf)-20:]
		// TODO: send & receive bitfeld msg
		log.Println("rcving bitfield msg")
		_, err = WaitForSpecificPeerMessage(conn, BITFIELD)
		if err != nil {
			log.Fatal("error rcv bitfield")
		}

		magnetBytes, err := magnet.GetHandshakeBytesForMagnetExtension2()
		if err != nil {
			log.Fatal(err.Error())
			os.Exit(1)
		}
		if buf[25] == 16 {
			log.Println("sending extension handshake")
			conn.Write(magnetBytes)
		}

		log.Println("start receiving magnet extension handshake")
		msgLength := make([]byte, 4)
		_, err = conn.Read(msgLength)
		if err != nil {
			log.Fatal("error reading msglength")
		}
		msgLengthInt := binary.BigEndian.Uint32(msgLength)
		log.Println("length: " + strconv.Itoa(int(msgLengthInt)))
		magPayload := make([]byte, msgLengthInt)
		_, err = io.ReadFull(conn, magPayload)
		if err != nil {
			log.Fatal("error reading payload")
		}
		log.Print("magM: " + strconv.Itoa(len(magPayload)))
		magM, _, err := bencode.DecodeBencode(string(magPayload[2:]), 0)
		magMMap := magM.(map[string]any)
		if err != nil {
			log.Fatal("error decoding")
		}
		m := magMMap["m"].(map[string]any)
		magPeer := bencode.ConvToString(m["ut_metadata"])
		fmt.Println("Peer ID: " + hex.EncodeToString(peerId))
		fmt.Println("Peer Metadata Extension ID: " + magPeer)
	} else if command == "magnet_info" {
		magnetLink := os.Args[2]
		magInfo, err := GetMagnetInfo(magnetLink)
		piecesS := ""
		for _, v := range magInfo.Pieces {
			piecesS = piecesS + "\n" + hex.EncodeToString([]byte(v))
		}
		op := "Tracker URL: " + magInfo.TrackerUrl
		op = op + "\nLength: " + strconv.Itoa(magInfo.Length)
		op = op + "\nInfo Hash: " + magInfo.InfoHash
		op = op + "\nPiece Length: " + strconv.Itoa(magInfo.PieceLength)
		op = op + "\nPiece Hashes: " + piecesS

		if err != nil {
			log.Fatal(err.Error())
		}
		fmt.Print(op)
	} else if command == "magnet_download_piece" {
		path := os.Args[3]
		magnetLink := os.Args[4]
		pieceIndex := os.Args[5]
		magInfo, err := GetMagnetInfo(magnetLink)
		if err != nil {
			log.Fatal(err.Error())
		}
		pieceIndexInt, err := strconv.Atoi(pieceIndex)
		if err != nil {
			log.Fatal(err.Error())
		}
		data, err := DownloadPieceWithPeerIpForMagnet(magInfo, pieceIndexInt, magInfo.PeerIps[0])
		if err != nil {
			log.Fatal(err.Error())
		}
		os.WriteFile(path, data, 0644)
	} else if command == "magnet_download" {
		path := os.Args[3]
		magnetLink := os.Args[4]
		torrentInfo, err := GetMagnetInfo(magnetLink)
		if err != nil {
			log.Fatal(err.Error())
		}

		data, err := DownloadFileForMagnet(torrentInfo)

		if err != nil {
			log.Fatal(err.Error())
		}
		os.WriteFile(path, data, 0644)
	} else {
		log.Fatalf("Unknown command: %s", command)
		os.Exit(1)
	}
}
