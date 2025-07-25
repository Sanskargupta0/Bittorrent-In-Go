package main

import (
	"crypto/sha1"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"sort"
	"strconv"
	"unicode"

	// bencode "github.com/jackpal/bencode-go" // Available if you need it!
	"bytes"
	"encoding/binary"
	"io"
	"net/http"
	"net/url"
	"strings"
)

// Ensures gofmt doesn't remove the "os" encoding/json import (feel free to remove this!)
var _ = json.Marshal

// Example:
// - 5:hello -> hello
// - 10:hello12345 -> hello12345
func decodeBencode(bencodedString []byte, start int) (any, int, error) {
	rInitial := rune(bencodedString[start])
	var err error
	var out any
	switch {
	case unicode.IsDigit(rInitial):
		out, start, err := decodeBencodeString(bencodedString, start)
		if err != nil {
			return "", start, err
		}
		return out, start, err
	case unicode.IsLetter(rInitial) && rInitial == 'i':
		out, start, err := decodeBencodeInteger(bencodedString, start)
		if err != nil {
			return "", start, err
		}
		return out, start, err
	case unicode.IsLetter(rInitial) && rInitial == 'l':
		out, start, err := decodeBencodeList(bencodedString, start)
		if err != nil {
			return "", start, err
		}
		return out, start, err
	case unicode.IsLetter(rInitial) && rInitial == 'd':
		out, start, err := decodeBencodeDictionary(bencodedString, start)
		if err != nil {
			return "", start, err
		}
		return out, start, err

	}
	// if unicode.IsDigit(rune(bencodedString[0])) {
	// } else {
	// 	return "", fmt.Errorf("Only strings are supported at the moment")
	// }
	//return "", 0, fmt.Errorf("Only strings are supported at the moment")
	return out, start, err
}

func decodeBencodeDictionary(bencodedString []byte, start int) (map[string]any, int, error) {
	pos := start + 1
	output := make([]any, 0)
	outputDict := make(map[string]any, 0)
	orderedOutputDict := make(map[string]any, 0)

OuterLoop:
	for pos <= len(bencodedString) {
		switch rInitial := rune(bencodedString[pos]); {
		case rInitial == 'e':
			break OuterLoop
			// return outputDict, pos + 1, nil
		default:
			out, outPos, err := decodeBencode(bencodedString, pos)
			pos = outPos
			if err != nil {
				return nil, start, err
			}
			output = append(output, out)
		}
	}
	for i := 0; i < len(output); i += 2 {
		outputDict[output[i].(string)] = output[i+1]
	}

	keys := make([]string, 0, len(outputDict))

	for k := range outputDict {
		keys = append(keys, k)
	}
	sort.Strings(keys)

	for _, k := range keys {
		orderedOutputDict[k] = outputDict[k]
	}
	//fmt.Println((orderedOutputDict))
	return orderedOutputDict, pos + 1, nil
}

func decodeBencodeList(bencodedString []byte, start int) ([]any, int, error) {
	pos := start + 1
	output := make([]any, 0)
	for pos <= len(bencodedString) {
		switch rInitial := rune(bencodedString[pos]); {
		case rInitial == 'e':
			return output, pos + 1, nil
		default:
			out, outPos, err := decodeBencode(bencodedString, pos)
			pos = outPos
			if err != nil {
				return nil, start, err
			}
			output = append(output, out)
		}
	}
	return output, pos, nil
}

func decodeBencodeInteger(bencodedString []byte, start int) (any, int, error) {
	finalIndex := 0
	for i := start + 1; i < len(bencodedString); i++ {
		if !(unicode.IsDigit(rune(bencodedString[i])) || rune(bencodedString[i]) == '-') {
			finalIndex = i
			break
		}
	}
	numberString, err := strconv.Atoi(string(bencodedString[start+1 : finalIndex]))
	if err != nil {
		return "", 0, fmt.Errorf("Error here")
	} else {
		return numberString, finalIndex + 1, nil
	}
}

func decodeBencodeString(bencodedString []byte, start int) (any, int, error) {
	var firstColonIndex int
	for i := start; i < len(bencodedString); i++ {
		if bencodedString[i] == ':' {
			firstColonIndex = i
			break
		}
	}
	lengthStr := bencodedString[start:firstColonIndex]
	length, err := strconv.Atoi(string(lengthStr))
	if err != nil {
		return "", 0, err
	}
	return string(bencodedString[firstColonIndex+1 : firstColonIndex+1+length]), firstColonIndex + 1 + length, nil
}

func getInfoDataBytes(bencoded []byte) ([]byte, error) {
	// result, err := calculateSha1(bencoded)
	var result []byte
	for key, val := range bytes.Split(bencoded, []byte("info")) {
		if key == 1 {
			result, err := calculateSha1Bytes(val[0 : len(val)-1])
			if err != nil {
				return nil, err
			}
			return result, nil
		}
	}
	return result, nil
}

func getInfoData(bencoded []byte) (string, error) {
	// result, err := calculateSha1(bencoded)
	var result string
	for key, val := range bytes.Split(bencoded, []byte("info")) {
		if key == 1 {
			result, err := calculateSha1(val[0 : len(val)-1])
			if err != nil {
				return "", err
			}
			return result, nil
		}
	}
	return result, nil
}

func getHashFromPieces(bencoded []byte) ([]string, error) {
	output := make([]string, 0)
	// var hashResult string
	var err error
	var temp []byte
	for key, val := range bencoded {
		temp = append(temp, val)
		if (key+1)%20 == 0 && key > 1 {
			h := fmt.Sprintf("%2x", temp)
			// hashResult, err = calculateSha1(temp)
			output = append(output, h)
			if err != nil {
				return nil, err
			}
			temp = []byte{}
		}
	}
	return output, nil
}

// HexToPct encodes "deadbeef" → "%DE%AD%BE%EF".
func HexToPct(h string) (string, error) {
	b, err := hex.DecodeString(h) // "deadbeef" → []byte{0xDE,0xAD,0xBE,0xEF}
	if err != nil {
		return "", err
	}
	return strings.ToLower(string(b)), nil
}

// info_hash=%D6%9F%91%E6%B2%AELT%24h%D1%07%3Aq%D4%EA%13%87%9A%7F
// info_hash=%D6%9F%EF%BF%BD%E6%B2%AElt%24h%EF%BF%BD%07%3Aq%EF%BF%BD%EF%BF%BD%13%EF%BF%BD%EF%BF%BD%7F
func getTrackerRequest(url string) (*http.Response, error) {
	res, err := http.Get(url)
	if err != nil {
		return nil, err
	}
	return res, nil
}

func encodeRequest(tracker_url string, info_hash []byte, left int) (string, error) {
	u, err := url.Parse(tracker_url)
	if err != nil {
		return "", err
	}
	q := u.Query()
	q.Set("info_hash", string(info_hash))
	q.Set("port", "6881")
	q.Set("peer_id", "01234567890123456789")
	q.Set("uploaded", "0")
	q.Set("downloaded", "0")
	q.Set("left", strconv.Itoa(left))
	q.Set("compact", "1")
	u.RawQuery = q.Encode()
	urlEncoded := u.String()
	return urlEncoded, nil
}

func calculateSha1(bencoded []byte) (string, error) {
	//reducedBytes := (bencoded[1 : len(bencoded)-1])
	h := sha1.Sum(bencoded)
	return fmt.Sprintf("%x", h), nil
}

func calculateSha1Bytes(bencoded []byte) ([]byte, error) {
	//reducedBytes := (bencoded[1 : len(bencoded)-1])
	h := sha1.Sum(bencoded)
	return h[:], nil
}

func convertToIP(peer []byte) (string, error) {
	output := ""
	for i := 0; i < 3; i += 1 {
		output = output + fmt.Sprintf("%d", (peer[i])) + "."
	}
	output = output + fmt.Sprintf("%d", (peer[3]))
	output = output + ":" + fmt.Sprintf("%d", binary.BigEndian.Uint16(peer[4:]))
	return output, nil
}
func getPeersInfo(peersIn []byte) ([]string, error) {

	var output []string
	for i := 0; i < len(peersIn); i += 6 {
		temp, err := convertToIP(peersIn[i : i+6])
		if err != nil {
			return nil, err
		}
		output = append(output, temp)
	}
	return output, nil
}

func getPeers(metadataFile string) (any, error) {
	data, err := os.ReadFile(metadataFile)

	if err != nil {
		return nil, err
	}
	var result any
	dataString := data
	// for key, value := range data {
	// 	fmt.Println(key, string(value))
	// }
	result, _, err = decodeBencode(dataString, 0)
	resultDict := result.(map[string]any)
	resultInfo := resultDict["info"].(map[string]any)
	hash, _ := getInfoDataBytes(data)
	if err != nil {
		return nil, err
	}
	// piecesBytes, _ := json.Marshal(resultInfo["pieces"])
	urlEncoded, _ := encodeRequest(resultDict["announce"].(string), hash, resultInfo["length"].(int))
	res, err := getTrackerRequest(urlEncoded)
	body, err := io.ReadAll(res.Body)
	res.Body.Close()
	final, _, _ := decodeBencode(body, 0)
	temp, ok := final.(map[string]any)
	if !ok {
		return nil, fmt.Errorf("Error")
	}
	salida := (temp["peers"])
	var peers []byte
	// salida := []byte(temp["peers"])
	switch v := salida.(type) {
	case string:
		peers = []byte(v) // convert
	default:
		return nil, fmt.Errorf(`unexpected type %T for peers`, v)
	}
	sal, err := getPeersInfo(peers)
	if err != nil {
		return nil, err
	}

	for _, val := range sal {
		fmt.Println(val)
	}

	// fmt.Println(salida["peers"])
	return nil, err

}

func decodeInfo(metadataFile string) (any, error) {
	data, err := os.ReadFile(metadataFile)
	if err != nil {
		return nil, err
	}
	var result any
	dataString := data
	// for key, value := range data {
	// 	fmt.Println(key, string(value))
	// }
	result, _, err = decodeBencode(dataString, 0)
	resultDict := result.(map[string]any)
	resultInfo := resultDict["info"].(map[string]any)
	resultPieces := []byte(resultInfo["pieces"].(string))
	hash, _ := getInfoData(data)
	if err != nil {
		return nil, err
	}
	fmt.Println("Tracker URL:", resultDict["announce"])
	fmt.Println("Length:", resultInfo["length"])
	fmt.Println("Info Hash:", hash)
	fmt.Println("Piece Length:", resultInfo["piece length"])
	// piecesBytes, _ := json.Marshal(resultInfo["pieces"])
	resultHash, _ := getHashFromPieces(resultPieces)
	fmt.Println("Piece Hashes:")
	stringSlices := strings.Join(resultHash[:], "\n")
	fmt.Print(stringSlices)
	return result, err
}

func main() {
	// You can use print statements as follows for debugging, they'll be visible when running tests.
	//
	command := os.Args[1]

	switch command {
	case "peers":
		metadataFile := os.Args[2]
		getPeers(metadataFile)

	case "info":
		metadataFile := os.Args[2]
		decodeInfo(metadataFile)

	case "decode":
		bencodedValue := os.Args[2]
		decoded, _, err := decodeBencode([]byte(bencodedValue), 0)
		if err != nil {
			fmt.Println(err)
			return
		}
		// fmt.Println("Decoded value:", decoded)
		//output := fmt.Sprintf("%s", decoded)
		// output := fmt.Sprint(decoded)
		// fmt.Println(output)
		jsonOutput, _ := json.Marshal(decoded)
		fmt.Println(string(jsonOutput))
	default:
		fmt.Println("Unknown command: " + command)
		os.Exit(1)
	}
}
