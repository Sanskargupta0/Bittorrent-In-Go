package bencode

import (
	"encoding/json"
	"fmt"
	"sort"
	"strconv"
	"strings"
)

// DecodeBencode decodes a bencoded string and returns the decoded value and the index after parsing
func DecodeBencode(bencodedString string, index int) (interface{}, int, error) {
	if index >= len(bencodedString) {
		return nil, index, fmt.Errorf("unexpected end of string")
	}

	switch bencodedString[index] {
	case 'i':
		// Integer: i<integer>e
		return decodeInteger(bencodedString, index)
	case 'l':
		// List: l<elements>e
		return decodeList(bencodedString, index)
	case 'd':
		// Dictionary: d<key-value pairs>e
		return decodeDictionary(bencodedString, index)
	case '0', '1', '2', '3', '4', '5', '6', '7', '8', '9':
		// String: <length>:<string>
		return decodeString(bencodedString, index)
	default:
		return nil, index, fmt.Errorf("invalid character at index %d: %c", index, bencodedString[index])
	}
}

func decodeInteger(bencodedString string, index int) (interface{}, int, error) {
	// Skip 'i'
	index++
	endIndex := strings.Index(bencodedString[index:], "e")
	if endIndex == -1 {
		return nil, index, fmt.Errorf("invalid integer format")
	}
	endIndex += index
	
	intStr := bencodedString[index:endIndex]
	num, err := strconv.Atoi(intStr)
	if err != nil {
		return nil, index, fmt.Errorf("invalid integer: %s", intStr)
	}
	
	return num, endIndex + 1, nil
}

func decodeString(bencodedString string, index int) (interface{}, int, error) {
	colonIndex := strings.Index(bencodedString[index:], ":")
	if colonIndex == -1 {
		return nil, index, fmt.Errorf("invalid string format")
	}
	colonIndex += index
	
	lengthStr := bencodedString[index:colonIndex]
	length, err := strconv.Atoi(lengthStr)
	if err != nil {
		return nil, index, fmt.Errorf("invalid string length: %s", lengthStr)
	}
	
	startIndex := colonIndex + 1
	endIndex := startIndex + length
	if endIndex > len(bencodedString) {
		return nil, index, fmt.Errorf("string length exceeds data")
	}
	
	return bencodedString[startIndex:endIndex], endIndex, nil
}

func decodeList(bencodedString string, index int) (interface{}, int, error) {
	// Skip 'l'
	index++
	var list []interface{}
	
	for index < len(bencodedString) && bencodedString[index] != 'e' {
		element, newIndex, err := DecodeBencode(bencodedString, index)
		if err != nil {
			return nil, index, err
		}
		list = append(list, element)
		index = newIndex
	}
	
	if index >= len(bencodedString) {
		return nil, index, fmt.Errorf("unterminated list")
	}
	
	// Skip 'e'
	return list, index + 1, nil
}

func decodeDictionary(bencodedString string, index int) (interface{}, int, error) {
	// Skip 'd'
	index++
	dict := make(map[string]interface{})
	
	for index < len(bencodedString) && bencodedString[index] != 'e' {
		// Decode key (must be string)
		key, newIndex, err := DecodeBencode(bencodedString, index)
		if err != nil {
			return nil, index, err
		}
		keyStr, ok := key.(string)
		if !ok {
			return nil, index, fmt.Errorf("dictionary key must be string")
		}
		index = newIndex
		
		// Decode value
		value, newIndex, err := DecodeBencode(bencodedString, index)
		if err != nil {
			return nil, index, err
		}
		dict[keyStr] = value
		index = newIndex
	}
	
	if index >= len(bencodedString) {
		return nil, index, fmt.Errorf("unterminated dictionary")
	}
	
	// Skip 'e'
	return dict, index + 1, nil
}

// DecodeBencodeToString decodes a bencoded string and returns it as JSON
func DecodeBencodeToString(bencodedString string) (string, error) {
	decoded, _, err := DecodeBencode(bencodedString, 0)
	if err != nil {
		return "", err
	}
	
	jsonBytes, err := json.Marshal(decoded)
	if err != nil {
		return "", err
	}
	
	return string(jsonBytes), nil
}

// ConvToString converts an interface{} to string
func ConvToString(value interface{}) string {
	if str, ok := value.(string); ok {
		return str
	}
	return fmt.Sprintf("%v", value)
}

// DictToBencode encodes a map to bencode format
func DictToBencode(dict map[string]interface{}) (string, error) {
	var result strings.Builder
	result.WriteString("d")
	
	// Sort keys for deterministic output
	keys := make([]string, 0, len(dict))
	for key := range dict {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	
	for _, key := range keys {
		value := dict[key]
		
		// Encode key
		result.WriteString(fmt.Sprintf("%d:%s", len(key), key))
		
		// Encode value
		encoded, err := encodeToBencode(value)
		if err != nil {
			return "", err
		}
		result.WriteString(encoded)
	}
	
	result.WriteString("e")
	return result.String(), nil
}

func encodeToBencode(value interface{}) (string, error) {
	switch v := value.(type) {
	case string:
		return fmt.Sprintf("%d:%s", len(v), v), nil
	case int:
		return fmt.Sprintf("i%de", v), nil
	case []interface{}:
		var result strings.Builder
		result.WriteString("l")
		for _, item := range v {
			encoded, err := encodeToBencode(item)
			if err != nil {
				return "", err
			}
			result.WriteString(encoded)
		}
		result.WriteString("e")
		return result.String(), nil
	case map[string]interface{}:
		return DictToBencode(v)
	default:
		return "", fmt.Errorf("unsupported type: %T", v)
	}
}
