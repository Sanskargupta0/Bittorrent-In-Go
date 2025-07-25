package main

import (
	"bytes"
	"crypto/sha1"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"math"
	"net"
	"net/http"
	"net/url"
	"os"
	"slices"
	"strconv"
	"strings"
	"sync"
	"unicode"

	"github.com/dchest/uniuri"
	bencode "github.com/jackpal/bencode-go"
)

var BLOCK_SIZE = 16384

type Info struct {
	length      int
	pieceLength int
	pieces      [][20]byte
	infoHash    [20]byte
}

type ExtensionMetadata struct {
	length      int
	pieceLength int
	pieces      [][20]byte
	name        string
}

type TorrentFile struct {
	announce string
	info     Info
}

type PeerResponse struct {
	length  int
	id      int
	payload []byte
}

type PieceResponse struct {
	index int
	begin int
	data  []byte
}

type MagnetLink struct {
	trackerUrl  string
	infoHashHex string
	infoHash    [20]byte
}

// Ensures gofmt doesn't remove the "os" encoding/json import (feel free to remove this!)
var _ = json.Marshal

func decodeString(bencodedString string) (string, string, error) {
	var firstColonIndex int

	for i := 0; i < len(bencodedString); i++ {
		if bencodedString[i] == ':' {
			firstColonIndex = i
			break
		}
	}

	lengthStr := bencodedString[:firstColonIndex]

	length, err := strconv.Atoi(lengthStr)
	if err != nil {
		return "", "", err
	}

	rest := bencodedString[firstColonIndex+length+1:]
	return bencodedString[firstColonIndex+1 : firstColonIndex+1+length], rest, nil
}

func decodeInt(bencodedString string) (int, string, error) {
	endIdx := 1
	for bencodedString[endIdx] != 'e' {
		endIdx++
	}
	res, nil := strconv.Atoi(bencodedString[1:endIdx])
	rest := bencodedString[endIdx+1:]
	return res, rest, nil
}

func decodeList(bencodedString string) ([]interface{}, string, error) {
	list := make([]interface{}, 0)

	bencodedString = bencodedString[1:]
	for bencodedString[0] != 'e' {
		res, rest, _ := decodeBencode(bencodedString)
		bencodedString = rest
		list = append(list, res)
	}

	return list, bencodedString[1:], nil
}

func decodeDict(bencodedString string) (map[string]interface{}, string, error) {
	dict := make(map[string]interface{})

	bencodedString = bencodedString[1:]
	for bencodedString[0] != 'e' {
		key, rest1, _ := decodeString(bencodedString)
		value, rest2, _ := decodeBencode(rest1)

		bencodedString = rest2
		dict[string(key)] = value
	}

	return dict, bencodedString[1:], nil
}

func decodeBencode(bencodedString string) (interface{}, string, error) {
	// string decoding
	if unicode.IsDigit(rune(bencodedString[0])) {
		return decodeString(bencodedString)
	}

	// integer decoding
	if bencodedString[0] == 'i' {
		return decodeInt(bencodedString)
	}

	// list decoding
	if bencodedString[0] == 'l' {
		return decodeList(bencodedString)
	}

	// dict decoding
	if bencodedString[0] == 'd' {
		return decodeDict(bencodedString)
	}

	return "", "", fmt.Errorf("only strings and integers are supported at the moment")
}

func formatPiecesString(piecesStr string) [][20]byte {
	piecesBytes := []byte(piecesStr)

	pieces := make([][20]byte, 0)
	for i := 20; i <= len(piecesBytes); i += 20 {
		var chunk [20]byte
		copy(chunk[:], piecesBytes[i-20:i])
		pieces = append(pieces, chunk)
	}

	return pieces
}

func decodeTorrentFile(fileName string) TorrentFile {
	data, _ := os.ReadFile(fileName)

	decoded, _, _ := decodeDict(string(data))
	announce := decoded["announce"].(string)

	info := decoded["info"].(map[string]interface{})

	length := info["length"].(int)
	pieceLength := info["piece length"].(int)

	var buffer bytes.Buffer
	bencode.Marshal(io.Writer(&buffer), info)

	pieces := formatPiecesString(info["pieces"].(string))

	return TorrentFile{
		announce: announce,
		info: Info{
			length:      length,
			pieceLength: pieceLength,
			pieces:      pieces,
			infoHash:    sha1.Sum(buffer.Bytes()),
		},
	}
}

func resolvePeers(torrentFile *TorrentFile) []string {
	query := torrentFile.announce
	query += "?info_hash=" + url.QueryEscape(string(torrentFile.info.infoHash[:]))
	query += "&peer_id=" + uniuri.NewLen(20)
	query += "&port=6881"
	query += "&uploaded=0"
	query += "&downloaded=0"
	query += fmt.Sprintf("&left=%d", torrentFile.info.length)
	query += "&compact=1"

	resp, err := http.Get(query)
	if err != nil {
		fmt.Println("fetch error")
		return make([]string, 0)
	}

	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)

	decodedResp, _, _ := decodeDict(string(body))
	peerBytes := []byte(decodedResp["peers"].(string))

	peers := make([]string, 0)
	for i := 6; i <= len(peerBytes); i += 6 {
		peer := fmt.Sprintf("%d.%d.%d.%d:%d",
			int(peerBytes[i-6]),
			int(peerBytes[i-5]),
			int(peerBytes[i-4]),
			int(peerBytes[i-3]),
			binary.BigEndian.Uint16(peerBytes[i-2:i]))
		peers = append(peers, peer)
	}

	return peers
}

func performHandshake(conn net.Conn, infoHash [20]byte) []byte {
	peerId := sha1.Sum([]byte(uniuri.New()))

	message := make([]byte, 0)
	message = append(message, 19)
	message = append(message, []byte("BitTorrent protocol")...)
	message = append(message, []byte{0, 0, 0, 0, 0, 16, 0, 0}...)
	message = append(message, infoHash[:]...)
	message = append(message, peerId[:]...)

	conn.Write(message)

	res := make([]byte, 68)
	conn.Read(res)

	return res
}

func performExtensionHandshake(conn net.Conn) PeerResponse {
	payload := make(map[string]any)
	payload["m"] = map[string]int{
		"ut_metadata": 15,
	}

	var buffer bytes.Buffer
	bencode.Marshal(io.Writer(&buffer), payload)

	message := make([]byte, 4)
	binary.BigEndian.PutUint32(message[0:4], uint32(2+len(buffer.Bytes())))
	message = append(message, 20) // id
	message = append(message, 0)  // payload id
	message = append(message, buffer.Bytes()...)

	conn.Write(message)

	res, err := readMessage(conn, 20)
	if err != nil {
		panic(err)
	}

	return res
}

func readMessage(conn net.Conn, expectedId uint) (PeerResponse, error) {
	res := make([]byte, 5)
	_, err := io.ReadFull(conn, res)
	if err != nil {
		return PeerResponse{}, err
	}

	msgLength := binary.BigEndian.Uint32(res[:5])

	payload := make([]byte, msgLength-1)
	_, err = io.ReadFull(conn, payload)
	if err != nil {
		return PeerResponse{}, err
	}

	receivedId := uint(res[4])
	if expectedId != receivedId {
		return PeerResponse{}, fmt.Errorf("expected id %d, but reveived %d", expectedId, receivedId)
	}

	return PeerResponse{
		length:  int(binary.BigEndian.Uint32(res[:5])),
		id:      int(res[4]),
		payload: payload,
	}, nil
}

func resolvePieceResonse(msg *PeerResponse) PieceResponse {
	index := int(binary.BigEndian.Uint32(msg.payload[:4]))
	begin := int(binary.BigEndian.Uint32(msg.payload[4:8]))
	data := msg.payload[8:]

	return PieceResponse{
		index: index,
		begin: begin,
		data:  data,
	}
}

func resolveMetadataExtensionId(msg *PeerResponse) int {
	decoded, _, _ := decodeDict(string(msg.payload[1:]))

	m := decoded["m"].(map[string]interface{})
	return m["ut_metadata"].(int)
}

func downloadWorker(conn net.Conn, torrentFile *TorrentFile, pieceIdx <-chan int, fileData *[]byte, wg *sync.WaitGroup) {
	defer wg.Done()

	for idx := range pieceIdx {
		indexPieceLength := min(torrentFile.info.length-idx*torrentFile.info.pieceLength, torrentFile.info.pieceLength)
		pieceData := downloadPiece(conn, indexPieceLength, idx)

		copy((*fileData)[idx*torrentFile.info.pieceLength:], pieceData)
	}
}

func initConnection(peer string, infoHash [20]byte) net.Conn {
	conn, err := net.Dial("tcp", peer)
	if err != nil {
		panic(fmt.Sprintln("dial error:", err))
	}

	performHandshake(conn, infoHash)

	_, err = readMessage(conn, 5)
	if err != nil {
		panic(err)
	}

	sendInterestedMessage(conn)

	return conn
}

func sendInterestedMessage(conn net.Conn) {
	// interested message; length = id (1 byte)
	message := []byte{0, 0, 0, 1, 2}
	conn.Write(message)

	_, err := readMessage(conn, 1)
	if err != nil {
		panic(err)
	}
}

func initMagnetConn(magnetUrl string) (net.Conn, [20]byte, int) {
	magnetLink := parseMagnetLink(magnetUrl)
	torrentFile := TorrentFile{
		announce: magnetLink.trackerUrl,
		info: Info{
			length:      999,
			pieceLength: 0,
			pieces:      make([][20]byte, 0),
			infoHash:    magnetLink.infoHash,
		}}

	peers := resolvePeers(&torrentFile)

	conn, err := net.Dial("tcp", peers[0])
	if err != nil {
		panic(fmt.Sprintln("dial error:", err))
	}
	baseRes := performHandshake(conn, magnetLink.infoHash)

	// read bitfield msg
	_, err = readMessage(conn, 5)
	if err != nil {
		panic(err)
	}

	extensionId := 0
	if baseRes[25] == 16 { // supports extensions
		extensionRes := performExtensionHandshake(conn)
		extensionId = resolveMetadataExtensionId(&extensionRes)
	}

	var peerId [20]byte
	copy(peerId[:], baseRes[len(baseRes)-20:])
	return conn, peerId, extensionId
}

func requestExtensionMetadata(conn net.Conn, metadataExtensionId int) ExtensionMetadata {
	payload := map[string]int{
		"msg_type": 0,
		"piece":    0,
	}

	var buffer bytes.Buffer
	bencode.Marshal(io.Writer(&buffer), payload)

	message := make([]byte, 4)
	binary.BigEndian.PutUint32(message[0:4], uint32(2+len(buffer.Bytes())))
	message = append(message, 20)                        // id
	message = append(message, byte(metadataExtensionId)) // extension peer id
	message = append(message, buffer.Bytes()...)

	conn.Write(message)

	res, err := readMessage(conn, 20)
	if err != nil {
		panic(err)
	}

	_, rest, _ := decodeDict(string(res.payload[1:]))
	decodedMetadata, _, _ := decodeDict(rest)

	return ExtensionMetadata{
		length:      decodedMetadata["length"].(int),
		pieceLength: decodedMetadata["piece length"].(int),
		name:        decodedMetadata["name"].(string),
		pieces:      formatPiecesString(decodedMetadata["pieces"].(string)),
	}
}

func downloadPiece(conn net.Conn, pieceLength int, pieceIdx int) []byte {
	// send block requests
	pieceData := make([]byte, 0)
	blockCount := math.Ceil(float64(pieceLength) / float64(BLOCK_SIZE))
	for i := 0; i < int(blockCount); i += 1 {
		blockLength := min(pieceLength-i*BLOCK_SIZE, BLOCK_SIZE)

		payload := make([]byte, 12)
		binary.BigEndian.PutUint32(payload[0:4], uint32(pieceIdx))
		binary.BigEndian.PutUint32(payload[4:8], uint32(i*BLOCK_SIZE))
		binary.BigEndian.PutUint32(payload[8:], uint32(blockLength))

		// length = id (1 byte) + payload (3*4 bytes)
		message := []byte{0, 0, 0, 13, 6}
		message = append(message, payload...)

		conn.Write(message)

		res, err := readMessage(conn, 7)
		if err != nil {
			fmt.Println(err)
			return []byte{}
		}
		piece := resolvePieceResonse(&res)
		pieceData = slices.Insert(pieceData, piece.begin, piece.data...)
	}

	return pieceData
}

func parseMagnetLink(link string) MagnetLink {
	u, _ := url.Parse(link)
	query, _ := url.ParseQuery(u.RawQuery)

	trackerUrl := query.Get("tr")
	xt := query.Get("xt")
	infoHashHex := strings.Split(xt, ":")[2]

	decodedHash, _ := hex.DecodeString(infoHashHex)
	var infoHash [20]byte
	copy(infoHash[:], decodedHash)

	return MagnetLink{
		trackerUrl:  trackerUrl,
		infoHashHex: infoHashHex,
		infoHash:    infoHash,
	}
}

func main() {
	command := os.Args[1]

	if command == "decode" {
		bencodedValue := os.Args[2]

		decoded, _, err := decodeBencode(bencodedValue)
		if err != nil {
			fmt.Println(err)
			return
		}

		jsonOutput, _ := json.Marshal(decoded)
		fmt.Println(string(jsonOutput))
	} else if command == "info" {
		fileName := os.Args[2]

		torrentFile := decodeTorrentFile(fileName)

		fmt.Println("Tracker URL:", torrentFile.announce)
		fmt.Println("Length:", torrentFile.info.length)
		fmt.Printf("Info Hash: %x\n", torrentFile.info.infoHash)
		fmt.Println("Piece Length:", torrentFile.info.pieceLength)
		fmt.Println("Piece Hashes:")
		for _, hash := range torrentFile.info.pieces {
			fmt.Printf("%x\n", hash)
		}
	} else if command == "peers" {
		fileName := os.Args[2]
		torrentFile := decodeTorrentFile(fileName)

		peers := resolvePeers(&torrentFile)
		for _, peer := range peers {
			fmt.Println(peer)
		}

	} else if command == "handshake" {
		fileName := os.Args[2]
		peerAddr := os.Args[3]

		torrentFile := decodeTorrentFile(fileName)

		conn, err := net.Dial("tcp", peerAddr)
		if err != nil {
			fmt.Println("dial error:", err)
			return
		}
		defer conn.Close()

		res := performHandshake(conn, torrentFile.info.infoHash)

		fmt.Printf("Peer ID: %x\n", res[len(res)-20:])

	} else if command == "download_piece" {
		outPath := os.Args[3]
		fileName := os.Args[4]
		index, _ := strconv.Atoi(os.Args[5])

		torrentFile := decodeTorrentFile(fileName)
		peers := resolvePeers(&torrentFile)

		conn := initConnection(peers[0], torrentFile.info.infoHash)

		indexPieceLength := min(torrentFile.info.length-index*torrentFile.info.pieceLength, torrentFile.info.pieceLength)
		pieceData := downloadPiece(conn, indexPieceLength, index)

		piece_hash := sha1.Sum(pieceData)

		fmt.Printf("%x\n", piece_hash)
		fmt.Printf("%x\n", torrentFile.info.pieces[index])

		os.WriteFile(outPath, pieceData, 0644)

	} else if command == "download" {
		outPath := os.Args[3]
		fileName := os.Args[4]

		torrentFile := decodeTorrentFile(fileName)
		peers := resolvePeers(&torrentFile)

		conns := make([]net.Conn, 0)
		for _, peer := range peers {
			conns = append(conns, initConnection(peer, torrentFile.info.infoHash))
		}

		jobs := make(chan int, len(torrentFile.info.pieces))
		fileData := make([]byte, torrentFile.info.length)

		var wg sync.WaitGroup
		for _, conn := range conns {
			wg.Add(1)
			go downloadWorker(conn, &torrentFile, jobs, &fileData, &wg)
		}

		for idx := range torrentFile.info.pieces {
			jobs <- idx
		}
		close(jobs)
		wg.Wait()

		os.WriteFile(outPath, fileData, 0644)

	} else if command == "magnet_parse" {
		magnetUrl := os.Args[2]

		magnetLink := parseMagnetLink(magnetUrl)

		fmt.Printf("Tracker URL: %s\n", magnetLink.trackerUrl)
		fmt.Printf("Info Hash: %s\n", magnetLink.infoHashHex)

	} else if command == "magnet_handshake" {
		magnetUrl := os.Args[2]

		_, peerId, extensionId := initMagnetConn(magnetUrl)

		fmt.Printf("Peer ID: %x\n", peerId)
		if extensionId != 0 {
			fmt.Printf("Peer Metadata Extension ID: %d\n", extensionId)
		}

	} else if command == "magnet_info" {
		magnetUrl := os.Args[2]
		magnetLink := parseMagnetLink(magnetUrl)

		conn, _, extensionId := initMagnetConn(magnetUrl)
		metadata := requestExtensionMetadata(conn, extensionId)

		fmt.Printf("Tracker URL: %s\n", magnetLink.trackerUrl)
		fmt.Printf("Length: %d\n", metadata.length)
		fmt.Printf("Info Hash: %s\n", magnetLink.infoHashHex)
		fmt.Printf("Piece Length: %d\n", metadata.pieceLength)
		fmt.Println("Piece Hashes:")
		for _, hash := range metadata.pieces {
			fmt.Printf("%x\n", hash)
		}

	} else if command == "magnet_download_piece" {
		outPath := os.Args[3]
		magnetUrl := os.Args[4]
		index, _ := strconv.Atoi(os.Args[5])

		conn, _, extensionId := initMagnetConn(magnetUrl)
		metadata := requestExtensionMetadata(conn, extensionId)

		sendInterestedMessage(conn)

		indexPieceLength := min(metadata.length-index*metadata.pieceLength, metadata.pieceLength)
		pieceData := downloadPiece(conn, indexPieceLength, index)

		piece_hash := sha1.Sum(pieceData)

		fmt.Printf("%x\n", piece_hash)
		fmt.Printf("%x\n", metadata.pieces[index])

		os.WriteFile(outPath, pieceData, 0644)

	} else {
		fmt.Println("Unknown command: " + command)
		os.Exit(1)
	}
}
