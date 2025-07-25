package main

import (
	"crypto/sha1"
	"encoding/hex"
	"fmt"
	"os"
	"github.com/codecrafters-io/bittorrent-starter-go/app/bencode"
)

// ReadTorrent reads and parses a torrent file
func ReadTorrent(filePath string) (map[string]interface{}, error) {
	data, err := os.ReadFile(filePath)
	if err != nil {
		return nil, fmt.Errorf("failed to read torrent file: %v", err)
	}
	
	decoded, _, err := bencode.DecodeBencode(string(data), 0)
	if err != nil {
		return nil, fmt.Errorf("failed to decode torrent: %v", err)
	}
	
	torrentMap, ok := decoded.(map[string]interface{})
	if !ok {
		return nil, fmt.Errorf("torrent file is not a dictionary")
	}
	
	return torrentMap, nil
}

// ReadInfo extracts the info dictionary from a torrent
func ReadInfo(torrent map[string]interface{}) (map[string]interface{}, error) {
	info, ok := torrent["info"]
	if !ok {
		return nil, fmt.Errorf("no info section in torrent")
	}
	
	infoMap, ok := info.(map[string]interface{})
	if !ok {
		return nil, fmt.Errorf("info section is not a dictionary")
	}
	
	return infoMap, nil
}

// HashInfo calculates the SHA1 hash of the info dictionary
func HashInfo(info map[string]interface{}) string {
	// Convert info dictionary back to bencode
	encoded, err := bencode.DictToBencode(info)
	if err != nil {
		return ""
	}
	
	hash := sha1.Sum([]byte(encoded))
	return hex.EncodeToString(hash[:])
}

// GetPiecesHash extracts piece hashes from info dictionary
func GetPiecesHash(info map[string]interface{}) []string {
	pieces, ok := info["pieces"]
	if !ok {
		return nil
	}
	
	piecesStr, ok := pieces.(string)
	if !ok {
		return nil
	}
	
	var hashes []string
	for i := 0; i < len(piecesStr); i += 20 {
		if i+20 <= len(piecesStr) {
			hashes = append(hashes, piecesStr[i:i+20])
		}
	}
	
	return hashes
}

// DecodeInfo decodes torrent info and returns formatted string
func DecodeInfo(filePath string) (string, error) {
	torrent, err := ReadTorrent(filePath)
	if err != nil {
		return "", err
	}
	
	info, err := ReadInfo(torrent)
	if err != nil {
		return "", err
	}
	
	// Format info output
	result := fmt.Sprintf("Tracker URL: %s\n", bencode.ConvToString(torrent["announce"]))
	result += fmt.Sprintf("Length: %d\n", info["length"])
	result += fmt.Sprintf("Info Hash: %s\n", HashInfo(info))
	result += fmt.Sprintf("Piece Length: %d\n", info["piece length"])
	
	pieces := GetPiecesHash(info)
	result += "Piece Hashes:\n"
	for _, piece := range pieces {
		result += hex.EncodeToString([]byte(piece)) + "\n"
	}
	
	return result, nil
}
