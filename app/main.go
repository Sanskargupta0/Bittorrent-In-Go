package main

import (
	"bytes"
	"crypto/rand"
	"crypto/sha1"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"strconv"
	"strings"
	"unicode"
)

// The decoder struct is a representation of the data structure that holds the
// all the information needed through the execution of the program
// TODO: change the name
type decoder struct {
	command    string
	args       []byte
	pos        int
	peerAddr   string
	outputFile string
	pieceIndex int
}

// The PeerMessage struct is a representation of the BitTorrent peer wire
// protocol message
type PeerMessage struct {
	ID      uint8
	Payload []byte
}

// The TorrentInfo contains information about the torrent nedded during
// the execution of the program
type TorrentInfo struct {
	InfoHash    [20]byte
	PieceLength int
	PieceHashes [][20]byte
	TotalLength int
}

type MagnetLink struct {
	trackerUrl string
	infoHash   string
}

// These constants are useful for implementing the BT peer wire protocol
const (
	MsgChoke         = 0
	MsgUnchoke       = 1
	MsgInterested    = 2
	MsgNotInterested = 3
	MsgHave          = 4
	MsgBitfield      = 5
	MsgRequest       = 6
	MsgPiece         = 7
	MsgCancel        = 8
)

const (
	peerId     = "thisisa20charsstring"
	port       = 6881
	uploaded   = 0
	downloaded = 0
	compact    = 1
)

const BlockSize = 16384

func printJson(v interface{}) error {
	encoder := json.NewEncoder(os.Stdout)
	encoder.SetIndent("", "")
	return encoder.Encode(v)
}

func main() {
	cmd := os.Args[1]
	d := &decoder{command: cmd}

	var result interface{}
	var err error

	switch cmd {
	case "decode":
		d.pos = 0
		d.args = []byte(os.Args[2])
		result, err = d.decodeBencode()
	case "info":
		d.args = []byte(os.Args[2])
		result, err = d.info()
	case "peers":
		d.args = []byte(os.Args[2])
		result, err = d.peers()
	case "handshake":
		d.args = []byte(os.Args[2])
		d.peerAddr = os.Args[3]
		result, err = d.handshake()
	case "download_piece":
		d.outputFile = os.Args[3]
		d.args = []byte(os.Args[4])
		d.pieceIndex, _ = strconv.Atoi(os.Args[5])
		result, err = d.download()
	case "download":

		if len(os.Args) < 5 || os.Args[2] != "-o" {
			fmt.Fprintln(os.Stderr, "Usage: download -o <output_file> <torrent_file>")
			os.Exit(1)
		}

		d.outputFile = os.Args[3]
		d.args = []byte(os.Args[4])
		result, err = d.downloadFile()
	case "magnet_parse":
		d.args = []byte(os.Args[2])
		result, err = d.parseMagnetLink()
	case "magnet_handshake":
		d.args = []byte(os.Args[2])
		result, err = d.magnetHandshake()
	default:
		fmt.Fprintln(os.Stderr, "Unknown command:", cmd)
		os.Exit(1)
	}

	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}

	// it's expected that these two commands are printed as string, not JSON
	if cmd == "handshake" || cmd == "info" || cmd == "download_file" || cmd == "download" ||
		cmd == "magnet_parse" || cmd == "magnet_handshake" {
		if str, ok := result.(string); ok {
			fmt.Println(str)
			return
		}
	}

	printJson(result)
}

func (d *decoder) parseMagnetLink() (interface{}, error) {
	u, _ := url.Parse(string(d.args))
	query, _ := url.ParseQuery(u.RawQuery)

	trackerUrl := query.Get("tr")
	xt := query.Get("xt")
	infoHash := strings.Split(xt, ":")[2]

	return fmt.Sprintf("Tracker URL: %s\nInfo Hash: %s\n",
		trackerUrl,
		infoHash,
	), nil
}

func (d *decoder) magnetHandshake() (interface{}, error) {
	u, _ := url.Parse(string(d.args))
	parsedQuery, _ := url.ParseQuery(u.RawQuery)

	trackerUrl := parsedQuery.Get("tr")
	xt := parsedQuery.Get("xt")
	infoHashString := strings.Split(xt, ":")[2]

	peerID := make([]byte, 20)
	// if _, err := io.ReadFull(rand.Reader, peerID); err != nil {
	// 	return nil, fmt.Errorf("failed to generate peer id: %w", err)
	// }

	decoded, err := hex.DecodeString(infoHashString)

	if err != nil {
		return nil, fmt.Errorf("failed to decode info hash from string to byte %w", err)
	}
	var infoHash [20]byte
	copy(infoHash[:], decoded)

	left := 999
	// building the query to communicate with the tracker
	queries := url.Values{}
	queries.Add("info_hash", string(infoHash[:]))
	queries.Add("peer_id", peerId)
	queries.Add("port", strconv.Itoa(port))
	queries.Add("uploaded", strconv.Itoa(uploaded))
	queries.Add("downloaded", strconv.Itoa(downloaded))
	queries.Add("left", strconv.Itoa(left))
	queries.Add("compact", strconv.Itoa(compact))
	query := queries.Encode()

	finalUrl := trackerUrl + "?" + query

	// GET request to the tracker with the final query
	resp, err := http.Get(finalUrl)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	// we parse the answer
	body, err := io.ReadAll(resp.Body)
	if resp.StatusCode != 200 {
		return nil, fmt.Errorf("error getting 200 answer from the tracker")
	}
	if err != nil {
		return nil, err
	}

	respDecoder := &decoder{args: body}
	response, err := respDecoder.decodeDict()
	if err != nil {
		return nil, err
	}

	peersResp, ok := response["peers"].(string)
	if !ok {
		return nil, fmt.Errorf("problem with type assertion of peers field")
	}

	peersData := []byte(peersResp)
	if len(peersData)%6 != 0 { // sanity checking
		return nil, fmt.Errorf("peer data is malformed")
	}

	// we extract the peer information from the answer
	var ipList []string
	for i := 0; i < len(peersData); i += 6 {
		ip := net.IPv4(
			peersData[i],
			peersData[i+1],
			peersData[i+2],
			peersData[i+3],
		)
		port := binary.BigEndian.Uint16(peersData[i+4 : i+6])
		ipList = append(ipList, fmt.Sprintf("%s:%d", ip.String(), port))
	}

	d.peerAddr = ipList[0]

	reserveBytes := make([]byte, 8)
	reserveBytes[5] = byte(16)

	// build the handshake msg
	handshake := new(bytes.Buffer)
	handshake.WriteByte(19)
	handshake.WriteString("BitTorrent protocol")
	handshake.Write(reserveBytes) // resreved bytes with 20th bit set to 1
	handshake.Write(infoHash[:])
	handshake.Write(peerID)

	// connect to peer and send handshake
	conn, err := net.Dial("tcp", d.peerAddr)
	if err != nil {
		return nil, fmt.Errorf("failed to connect to peer: %w", err)
	}
	defer conn.Close()

	if _, err := conn.Write(handshake.Bytes()); err != nil {
		return nil, fmt.Errorf("failed to send handshake: %w", err)
	}

	handshakeResponse := make([]byte, 68) // 68 bytes is the default response
	if _, err := io.ReadFull(conn, handshakeResponse); err != nil {
		return nil, fmt.Errorf("failed to read handshake response: %w", err)
	}

	if handshakeResponse[0] != 19 || string(handshakeResponse[1:20]) != "BitTorrent protocol" {
		return nil, fmt.Errorf("invalid handshake response")
	}

	recvPeerID := handshakeResponse[48:68]

	return fmt.Sprintf("Peer ID: %x", recvPeerID), nil
}

// The decodeBencode function is the main point of entry for data, where we
// select which type of bencoded data we will be dealing with, and dispatch it
// accordingly
func (d *decoder) decodeBencode() (interface{}, error) {

	if d.pos >= len(d.args) { // out-of-bounds check
		return nil, fmt.Errorf("unexpected end of input")
	}

	// the first character determines which type of data we're dealing with.
	// this will get updated as we progress through the input
	firstChar := rune(d.args[d.pos])
	if unicode.IsDigit(firstChar) {
		return d.decodeString()
	}
	if firstChar == 'i' {
		return d.decodeIntegers()
	}
	if firstChar == 'l' {
		return d.decodeList()
	}
	if firstChar == 'd' {
		return d.decodeDict()
	}
	return "", fmt.Errorf("unsupported bencode: %d, %c", d.pos, firstChar)
}

// The decodeString function deals with bencoded strings
func (d *decoder) decodeString() (string, error) {

	var firstColonIndex int

	// we detect and save where the first colon is, as this is the delimiter
	// for bencoded strings
	for i := d.pos; i < len(d.args); i++ {
		if d.args[i] == ':' {
			firstColonIndex = i
			break
		}
	}
	if firstColonIndex == 0 || firstColonIndex <= d.pos { // sanity checking
		return "", fmt.Errorf("problems with string parsing")
	}

	// the string we want to extract
	lengthStr := d.args[d.pos:firstColonIndex]
	// this is to extract the integer that codifies the string
	length, err := strconv.Atoi(string(lengthStr))
	if err != nil {
		return "", err
	}

	// this is the full size of the string
	size := firstColonIndex + length + 1

	decodedString := d.args[firstColonIndex+1 : size]

	// the pos argument is updated with the full size of the string
	d.pos = size

	return string(decodedString), nil
}

// The decodeIntegers function deals with bencoded integers
func (d *decoder) decodeIntegers() (int, error) {

	// We start one char to the right to ignore the delimiter
	start := d.pos + 1
	end := start

	// we detect and save where the end of the integer is
	for ; end < len(d.args); end++ {
		if d.args[end] == 'e' {
			break
		}
	}

	if end >= len(d.args) {
		return 0, fmt.Errorf("malformed integer")
	}

	// the integer is between the start and end parameters
	result := d.args[start:end]

	// convert it to int type
	intResult, err := strconv.Atoi(string(result))
	if err != nil {
		return 0, fmt.Errorf("problem with int parsing: %w", err)
	}

	// move the pos argument one to the right so that we ignore the last char
	d.pos = end + 1

	return intResult, nil
}

// The decodeList function deals with bencoded lists
func (d *decoder) decodeList() ([]interface{}, error) {

	result := make([]interface{}, 0)
	d.pos++ // ignoring the first char

	// while not out of bounds and we haven't found the char, keep going
	for d.pos < len(d.args) && d.args[d.pos] != 'e' {
		// recursively deal with each of the components of the list
		r, err := d.decodeBencode()
		if err != nil {
			return nil, err
		}
		result = append(result, r)
	}

	if d.pos >= len(d.args) { // sanity checking
		return nil, fmt.Errorf("list is malformed")
	}

	// move the pos argument one to the right so that we ignore the last char
	d.pos++
	return result, nil
}

// The decodeDict function deals with dictionaries
func (d *decoder) decodeDict() (map[string]interface{}, error) {

	result := make(map[string]interface{})
	d.pos++ // ignoring the first char

	var lastKey string

	for d.pos < len(d.args) && d.args[d.pos] != 'e' {
		// Keys must be strings
		keyRaw, err := d.decodeString()
		if err != nil {
			return nil, fmt.Errorf("invalid dictionary key: %w", err)
		}

		// Ensure lexicographical key order
		if lastKey != "" && keyRaw < lastKey {
			fmt.Println(fmt.Errorf("dictionary keys not in lex order: %q < %q", keyRaw, lastKey))
		}
		lastKey = keyRaw

		value, err := d.decodeBencode()
		if err != nil {
			return nil, fmt.Errorf("invalid dictionary value for key %q: %w", keyRaw, err)
		}

		result[keyRaw] = value
	}

	// we're out of bounds or we never found the delimiter, so we error out
	if d.pos >= len(d.args) || d.args[d.pos] != 'e' {
		return nil, fmt.Errorf("malformed dictionary")
	}

	d.pos++ // Skip the delimiter
	return result, nil
}

// The infoHash calculates the info hash after decoding the info dictionary
func (d *decoder) infoHash() ([20]uint8, error) {
	var empty [20]uint8

	// ingest the file
	file, err := os.ReadFile(string(d.args))
	if err != nil {
		return empty, err
	}

	// need to figure out where the info dict is
	start := bytes.Index(file, []byte("4:info"))
	if start == -1 {
		return empty, fmt.Errorf("info dict not found")
	}
	start += len("4:info")

	// decode just that data and calculate the hash
	subDec := &decoder{args: file, pos: start}
	startPos := subDec.pos
	_, err = subDec.decodeDict()
	if err != nil {
		return empty, err
	}
	endPos := subDec.pos

	return sha1.Sum(file[startPos:endPos]), nil
}

func (d *decoder) getTorrentInfo() (*TorrentInfo, error) {
	file, err := os.ReadFile(string(d.args))
	if err != nil {
		return nil, err
	}

	decoder := &decoder{args: file}
	decoded, err := decoder.decodeDict()
	if err != nil {
		return nil, err
	}

	infoMap, ok := decoded["info"].(map[string]interface{})
	if !ok {
		return nil, fmt.Errorf("invalid info section")
	}

	pieceLength, ok := infoMap["piece length"].(int)
	if !ok {
		return nil, fmt.Errorf("invalid piece length")
	}

	totalLength, ok := infoMap["length"].(int)
	if !ok {
		return nil, fmt.Errorf("invalid file length")
	}

	piecesStr, ok := infoMap["pieces"].(string)
	if !ok {
		return nil, fmt.Errorf("invalid pieces")
	}

	pieces := []byte(piecesStr)
	var pieceHashes [][20]byte
	for i := 0; i < len(pieces); i += 20 {
		var hash [20]byte
		copy(hash[:], pieces[i:i+20])
		pieceHashes = append(pieceHashes, hash)
	}

	infoHash, err := d.infoHash()
	if err != nil {
		return nil, err
	}

	return &TorrentInfo{
		InfoHash:    infoHash,
		PieceLength: pieceLength,
		PieceHashes: pieceHashes,
		TotalLength: totalLength,
	}, nil
}

// The info function serves as a way to leverage the decodeBencode function to
// extract information from torrent files
func (d *decoder) info() (interface{}, error) {
	torrentInfo, err := d.getTorrentInfo()
	if err != nil {
		return nil, err
	}

	// Parse announce URL from torrent file
	file, err := os.ReadFile(string(d.args))
	if err != nil {
		return nil, err
	}

	decoded, err := (&decoder{args: file}).decodeDict()
	if err != nil {
		return nil, err
	}

	announceURL, ok := decoded["announce"].(string)
	if !ok {
		return nil, fmt.Errorf("invalid announce URL")
	}

	// Convert piece hashes to hex strings for display
	var hashes []string
	for _, hash := range torrentInfo.PieceHashes {
		hashes = append(hashes, hex.EncodeToString(hash[:]))
	}

	return fmt.Sprintf(
		"Tracker URL: %s\nLength: %d\nInfo Hash: %s\nPiece Length: %d\nPieces: %s\n",
		announceURL,
		torrentInfo.TotalLength,
		hex.EncodeToString(torrentInfo.InfoHash[:]),
		torrentInfo.PieceLength,
		hashes,
	), nil
}

// The peers function is responsible for interacting with the bittorrent tracker
// and getting information from it - namely, peers
func (d *decoder) peers() (interface{}, error) {

	const (
		peerId     = "thisisa20charsstring"
		port       = 6881
		uploaded   = 0
		downloaded = 0
		compact    = 1
	)

	// file ingestion
	file, err := os.ReadFile(string(d.args))
	if err != nil {
		return nil, err
	}

	decoded, err := (&decoder{args: file}).decodeDict()
	if err != nil {
		return nil, err
	}

	urlAnnounce, ok := decoded["announce"].(string)
	if !ok {
		return nil, fmt.Errorf("announce field is not a string")
	}

	infoHash, err := d.infoHash()
	if err != nil {
		return nil, err
	}

	subMap, ok := decoded["info"].(map[string]interface{})
	if !ok {
		return nil, fmt.Errorf("problem with type assertion of info field")
	}

	left, ok := subMap["length"].(int)
	if !ok {
		return nil, fmt.Errorf("problem with type assertion of length field")
	}

	// building the query to communicate with the tracker
	queries := url.Values{}
	queries.Add("info_hash", string(infoHash[:]))
	queries.Add("peer_id", peerId)
	queries.Add("port", strconv.Itoa(port))
	queries.Add("uploaded", strconv.Itoa(uploaded))
	queries.Add("downloaded", strconv.Itoa(downloaded))
	queries.Add("left", strconv.Itoa(left))
	queries.Add("compact", strconv.Itoa(compact))
	query := queries.Encode()

	finalUrl := urlAnnounce + "?" + query

	// GET request to the tracker with the final query
	resp, err := http.Get(finalUrl)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	// we parse the answer
	body, err := io.ReadAll(resp.Body)
	if resp.StatusCode != 200 {
		return nil, fmt.Errorf("error getting 200 answer from the tracker")
	}
	if err != nil {
		return nil, err
	}

	respDecoder := &decoder{args: body}
	response, err := respDecoder.decodeDict()
	if err != nil {
		return nil, err
	}

	peersResp, ok := response["peers"].(string)
	if !ok {
		return nil, fmt.Errorf("problem with type assertion of peers field")
	}

	peersData := []byte(peersResp)
	if len(peersData)%6 != 0 { // sanity checking
		return nil, fmt.Errorf("peer data is malformed")
	}

	// we extract the peer information from the answer
	var ipList []string
	for i := 0; i < len(peersData); i += 6 {
		ip := net.IPv4(
			peersData[i],
			peersData[i+1],
			peersData[i+2],
			peersData[i+3],
		)
		port := binary.BigEndian.Uint16(peersData[i+4 : i+6])
		ipList = append(ipList, fmt.Sprintf("%s:%d", ip.String(), port))
	}

	return ipList, nil
}

func (d *decoder) handshake() (interface{}, error) {

	// getting the infoHash
	infoHash, err := d.infoHash()
	if err != nil {
		return nil, err
	}

	// 20 byte random peer id
	peerID := make([]byte, 20)
	if _, err = io.ReadFull(rand.Reader, peerID); err != nil {
		return nil, fmt.Errorf("failed to generate peer id: %w", err)
	}

	// build the handshake msg
	handshake := new(bytes.Buffer)
	handshake.WriteByte(19)
	handshake.WriteString("BitTorrent protocol")
	handshake.Write(make([]byte, 8)) // 8 zero bytes
	handshake.Write(infoHash[:])
	handshake.Write(peerID)

	// connect to peer and send handshake
	conn, err := net.Dial("tcp", d.peerAddr)
	if err != nil {
		return nil, fmt.Errorf("failed to connect to peer: %w", err)
	}
	defer conn.Close()

	if _, err := conn.Write(handshake.Bytes()); err != nil {
		return nil, fmt.Errorf("failed to send handshake: %w", err)
	}

	handshakeResponse := make([]byte, 68) // 68 bytes is the default response
	if _, err := io.ReadFull(conn, handshakeResponse); err != nil {
		return nil, fmt.Errorf("failed to read handshake response: %w", err)
	}

	if handshakeResponse[0] != 19 || string(handshakeResponse[1:20]) != "BitTorrent protocol" {
		return nil, fmt.Errorf("invalid handshake response")
	}

	recvPeerID := handshakeResponse[48:68]

	return fmt.Sprintf("Peer ID: %x", recvPeerID), nil
}

func (d *decoder) connectHandshake(infoHash [20]byte) (net.Conn, error) {
	conn, err := net.Dial("tcp", d.peerAddr)
	if err != nil {
		return nil, err
	}

	_, err = d.performHandshake(conn, infoHash)
	if err != nil {
		conn.Close()
		return nil, err
	}

	return conn, nil
}

func (d *decoder) performHandshake(conn net.Conn, infoHash [20]byte) ([]byte, error) {
	peerID := make([]byte, 20)
	if _, err := io.ReadFull(rand.Reader, peerID); err != nil {
		return nil, fmt.Errorf("failed to generate peer id: %w", err)
	}

	// Build handshake message
	handshake := new(bytes.Buffer)
	handshake.WriteByte(19)
	handshake.WriteString("BitTorrent protocol")
	handshake.Write(make([]byte, 8)) // Reserved bytes
	handshake.Write(infoHash[:])
	handshake.Write(peerID)

	if _, err := conn.Write(handshake.Bytes()); err != nil {
		return nil, fmt.Errorf("failed to send handshake: %w", err)
	}

	response := make([]byte, 68)
	if _, err := io.ReadFull(conn, response); err != nil {
		return nil, fmt.Errorf("failed to read handshake response: %w", err)
	}

	if response[0] != 19 || string(response[1:20]) != "BitTorrent protocol" {
		return nil, fmt.Errorf("invalid handshake response")
	}

	return response[48:68], nil
}

func (d *decoder) sendMessage(conn net.Conn, msg *PeerMessage) error {
	var buf bytes.Buffer

	msgLen := uint32(1 + len(msg.Payload))
	if err := binary.Write(&buf, binary.BigEndian, msgLen); err != nil {
		return err
	}

	buf.WriteByte(msg.ID)

	buf.Write(msg.Payload)

	_, err := conn.Write(buf.Bytes())
	return err
}

// readMessage reads a peer wire protocol message
func (d *decoder) readMessage(conn net.Conn) (*PeerMessage, error) {
	// Read message length
	var msgLen uint32
	if err := binary.Read(conn, binary.BigEndian, &msgLen); err != nil {
		return nil, err
	}

	if msgLen == 0 {
		// Keep-alive message
		return &PeerMessage{}, nil
	}

	// Read message ID
	var msgID uint8
	if err := binary.Read(conn, binary.BigEndian, &msgID); err != nil {
		return nil, err
	}

	// Read payload
	payload := make([]byte, msgLen-1)
	if _, err := io.ReadFull(conn, payload); err != nil {
		return nil, err
	}

	return &PeerMessage{
		ID:      msgID,
		Payload: payload,
	}, nil
}

// hasPiece checks if peer has a specific piece based on bitfield
func (d *decoder) hasPiece(bitfield []byte, pieceIndex int) bool {
	byteIndex := pieceIndex / 8
	bitIndex := pieceIndex % 8

	if byteIndex >= len(bitfield) {
		return false
	}

	return (bitfield[byteIndex] & (1 << (7 - bitIndex))) != 0
}

func (d *decoder) download() (interface{}, error) {
	torrentInfo, err := d.getTorrentInfo()
	if err != nil {
		return nil, fmt.Errorf("problem with torrent parsing: %w", err)
	}

	peers, err := d.peers()
	if err != nil {
		return nil, fmt.Errorf("error getting the peer list: %w", err)
	}

	peerList, ok := peers.([]string)
	if !ok || len(peerList) == 0 {
		return nil, fmt.Errorf("no peers available")
	}

	for _, peer := range peerList {
		d.peerAddr = peer
		pieceData, err := d.downloadFromPeer(torrentInfo, d.pieceIndex)
		if err != nil {
			continue
		}

		expectedHash := torrentInfo.PieceHashes[d.pieceIndex]
		actualHash := sha1.Sum(pieceData)

		if !bytes.Equal(expectedHash[:], actualHash[:]) {
			continue
		}

		if err := os.WriteFile(d.outputFile, pieceData, 0644); err != nil {
			return nil, fmt.Errorf("failed to write data to file: %w", err)
		}

		return fmt.Sprintf("Piece %d downloaded to %s", d.pieceIndex, d.outputFile), nil
	}

	return nil, fmt.Errorf("unable to download piece from any peer")

}

func (d *decoder) downloadFromPeer(tInfo *TorrentInfo, pIndex int) ([]byte, error) {

	conn, err := d.connectHandshake(tInfo.InfoHash)
	if err != nil {
		return nil, err
	}
	defer conn.Close()

	if err := d.sendMessage(conn, &PeerMessage{ID: MsgInterested}); err != nil {
		return nil, err
	}

	for {
		msg, err := d.readMessage(conn)
		if err != nil {
			return nil, err
		}

		if msg.ID == MsgUnchoke {
			break
		}

		if msg.ID == MsgBitfield {
			if !d.hasPiece(msg.Payload, pIndex) {
				return nil, fmt.Errorf("peer doesn't have piece %d", pIndex)
			}
		}
	}

	pieceSize := tInfo.PieceLength
	if pIndex == len(tInfo.PieceHashes)-1 {
		pieceSize = tInfo.TotalLength - (pIndex * tInfo.PieceLength)
	}

	pieceData := make([]byte, pieceSize)
	blocksReceived := make(map[int]bool)
	totalBlocks := (pieceSize + BlockSize - 1) / BlockSize

	for blockIndex := 0; blockIndex < totalBlocks; blockIndex++ {
		begin := blockIndex * BlockSize
		length := BlockSize
		if begin+BlockSize > pieceSize {
			length = pieceSize - begin
		}

		requestMsg := &PeerMessage{
			ID:      MsgRequest,
			Payload: make([]byte, 12),
		}

		binary.BigEndian.PutUint32(requestMsg.Payload[0:4], uint32(pIndex))
		binary.BigEndian.PutUint32(requestMsg.Payload[4:8], uint32(begin))
		binary.BigEndian.PutUint32(requestMsg.Payload[8:12], uint32(length))

		if err := d.sendMessage(conn, requestMsg); err != nil {
			return nil, err
		}
	}

	for len(blocksReceived) < totalBlocks {
		msg, err := d.readMessage(conn)
		if err != nil {
			return nil, err
		}

		if msg.ID == MsgPiece {
			if len(msg.Payload) < 8 {
				continue
			}

			msgPieceIndex := binary.BigEndian.Uint32(msg.Payload[0:4])
			begin := binary.BigEndian.Uint32(msg.Payload[4:8])
			blockData := msg.Payload[8:]

			if msgPieceIndex != uint32(pIndex) {
				continue
			}

			blockIndex := int(begin) / BlockSize
			if !blocksReceived[blockIndex] {
				copy(pieceData[begin:], blockData)
				blocksReceived[blockIndex] = true
			}
		}
	}

	return pieceData, nil
}

func (d *decoder) downloadFile() (interface{}, error) {
	torrentInfo, err := d.getTorrentInfo()
	if err != nil {
		return nil, fmt.Errorf("problem with torrent parsing: %w", err)
	}

	peers, err := d.peers()
	if err != nil {
		return nil, fmt.Errorf("error getting the peer list: %w", err)
	}

	peerList, ok := peers.([]string)
	if !ok || len(peerList) == 0 {
		return nil, fmt.Errorf("no peers available")
	}

	numPieces := len(torrentInfo.PieceHashes)
	fileData := make([]byte, torrentInfo.TotalLength)

	for pieceIndex := 0; pieceIndex < numPieces; pieceIndex++ {
		var pieceData []byte
		var downloadError error

		// Download each piece
		for _, peer := range peerList {
			d.peerAddr = peer
			pieceData, downloadError = d.downloadFromPeer(torrentInfo, pieceIndex)
			if downloadError != nil {
				continue // Try for next peer
			}

			// Verify integrity of the piece
			expectedHash := torrentInfo.PieceHashes[pieceIndex]
			actualHash := sha1.Sum(pieceData)

			if bytes.Equal(expectedHash[:], actualHash[:]) {
				break // successful download
			}

			downloadError = fmt.Errorf("piece %d hash mismatch", pieceIndex)
		}

		if downloadError != nil {
			return nil, fmt.Errorf("failed to download piece %d: %w", pieceIndex, downloadError)
		}

		// Putting the piece at correct position in file
		start := pieceIndex * torrentInfo.PieceLength
		end := start + len(pieceData)
		if end > len(fileData) {
			end = len(fileData)
		}
		copy(fileData[start:end], pieceData)

		fmt.Printf("Downloaded piece %d/%d\n", pieceIndex+1, numPieces)
	}

	// Write the complete file to disk
	if err := os.WriteFile(d.outputFile, fileData, 0644); err != nil {
		return nil, fmt.Errorf("failed to write file to the disk: %w", err)
	}

	return fmt.Sprintf("Downloaded %s\n", d.outputFile), nil

}
