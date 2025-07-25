package main

import (
	"bytes"
	"crypto/sha1"
	"encoding/json"
	"fmt"
	"os"
	"strconv"
	"unicode"

	bencode "github.com/jackpal/bencode-go" // Available if you need it!
)

// Ensures gofmt doesn't remove the "os" encoding/json import (feel free to remove this!)
var _ = json.Marshal

// Example:
// - 5:hello -> hello
// - 10:hello12345 -> hello12345
func decodeBencode(bencodedString string) (interface{}, error) {
	var stk []interface{}
	for i := 0; i < len(bencodedString); {
		if bencodedString[i] == 'l' {
			stk = append(stk, 'l')
			i++
		} else if bencodedString[i] == 'd' {
			stk = append(stk, 'd')
			i++
		} else if bencodedString[i] == 'i' {
			num, adv, err := decodeBencodeInt(bencodedString[i:])
			if err != nil {
				return "", err
			}
			stk = append(stk, num)
			i += adv
		} else if unicode.IsDigit(rune(bencodedString[i])) {
			str, adv, err := decodeBencodeStr(bencodedString[i:])
			if err != nil {
				return "", err
			}
			stk = append(stk, str)
			i += adv
		} else if bencodedString[i] == 'e' {
			listElem := []interface{}{}
			for j := len(stk) - 1; j >= 0; j-- {
				if stk[j] == 'l' {
					reverseList(listElem)
					stk = stk[:len(stk)-1]
					stk = append(stk, listElem)
					break
				}
				if stk[j] == 'd' {
					reverseList(listElem)
					stk = stk[:len(stk)-1]
					dict := make(map[string]interface{})
					for k := 0; k < len(listElem); k += 2 {
						dict[listElem[k].(string)] = listElem[k+1]
					}
					stk = append(stk, dict)
					break
				}
				listElem = append(listElem, stk[j])
				stk = stk[:len(stk)-1]
			}
			i++
		}

	}
	return stk[0], nil
}

func decodeBencodeInt(bencodedString string) (interface{}, int, error) {
	for i := 0; i < len(bencodedString); i++ {
		if bencodedString[i] == 'e' {
			numStr := bencodedString[1:i]
			num, err := strconv.Atoi(numStr)
			if err != nil {
				return "", 0, err
			}
			return num, len(numStr) + 2, nil
		}
	}
	return "", 0, fmt.Errorf("i<number>e is not correctly formatted")
}

func decodeBencodeStr(bencodedString string) (interface{}, int, error) {
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
		return "", 0, err
	}

	return bencodedString[firstColonIndex+1 : firstColonIndex+1+length], len(lengthStr) + 1 + length, nil
}

func reverseList(s []interface{}) {
	for i, j := 0, len(s)-1; i < j; i, j = i+1, j-1 {
		s[i], s[j] = s[j], s[i]
	}
}

func main() {
	// You can use print statements as follows for debugging, they'll be visible when running tests.
	fmt.Fprintln(os.Stderr, "Logs from your program will appear here!")

	command := os.Args[1]

	if command == "decode" {
		// Uncomment this block to pass the first stage
		//
		bencodedValue := os.Args[2]

		decoded, err := decodeBencode(bencodedValue)
		if err != nil {
			fmt.Println(err)
			return
		}

		jsonOutput, _ := json.Marshal(decoded)
		fmt.Println(string(jsonOutput))
	} else if command == "info" {
		data, err := os.ReadFile(os.Args[2])
		if err != nil {
			fmt.Printf("error: read file: %v\n", err)
			os.Exit(1)
		}
		d, err := decodeBencode(string(data))
		if err != nil {
			fmt.Printf("error: decode bencode: %v\n", err)
			os.Exit(1)
		}
		dict, ok := d.(map[string]interface{})
		if !ok {
			fmt.Println("Top-level bencode is not a dictionary")
			return
		}

		fmt.Printf("Tracker URL: %v\n", dict["announce"])

		info, ok := dict["info"].(map[string]interface{})
		if !ok || info == nil {
			fmt.Printf("No info section\n")
			return
		}

		fmt.Printf("Length: %v\n", info["length"])

		var buf bytes.Buffer
		err = bencode.Marshal(&buf, info)
		if err != nil {
			fmt.Print(err)
		}
		infoBytes := buf.Bytes()
		infoHash := sha1.Sum(infoBytes)
		fmt.Printf("Info Hash: %x\n", infoHash)

		fmt.Printf("Piece Length: %v\n", info["piece length"])

		fmt.Printf("Piece Hashes:\n")
		pieces, _ := info["pieces"].(string)
		for i := 0; i < len(pieces); i += 20 {
			fmt.Printf("%02x\n", pieces[i:i+20])
		}
	} else {
		fmt.Println("Unknown command: " + command)
		os.Exit(1)
	}
}
