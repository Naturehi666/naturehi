package flagsearch

import (
	"fmt"
	"regexp"
)

func processUserInputString(input string) string {
	// 判断是否为字符串，如果是，则将其转换为正则表达式格式

	quotedInput := regexp.QuoteMeta(input)

	//return fmt.Sprintf("(?i)(?:%s?\\s*[=:])\\s*([\\S]+)|.*%s.*", quotedInput, quotedInput)
	return fmt.Sprintf("(?i)(?:%s?\\s*[=:])\\s*([\\S]+)", quotedInput)
}

func processUserString1(inputList []string) []string {

	for _, input := range inputList {
		regex := processUserInputString(input)
		inputList = append(inputList, regex)
	}

	return inputList
}

func processUserString(inputList []string) []string {

	return inputList
}
