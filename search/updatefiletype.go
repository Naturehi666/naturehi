package search

import "strings"

func UpdateFileTypes(fileTypes map[string]string, fileTypeCategory string, extensions string) {
	// 如果扩展名列表为空，不进行更新
	if extensions == "" {
		return
	}

	// 将用户输入的扩展名字符串拆分为切片
	extensionList := strings.Split(extensions, ",")

	// 将扩展名切片转换为以点号开头的字符串，并添加到映射中
	extensionString := "." + strings.Join(extensionList, ",.") + ","
	fileTypes[fileTypeCategory] = extensionString
}
