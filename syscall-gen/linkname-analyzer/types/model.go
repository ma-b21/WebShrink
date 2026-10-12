package types


// LinknameEntry 表示一个 linkname 映射条目
type LinknameEntry struct {
	DeclFunc   string `json:"decl_func"`    // 声明函数的完全限定名
	ImplFunc   string `json:"impl_func"`    // 实现函数的完全限定名
	DeclPkg    string `json:"decl_pkg"`     // 声明所在包
	ImplPkg    string `json:"impl_pkg"`     // 实现所在包
	SourceFile string `json:"source_file"`  // 源文件路径
	Line       int    `json:"line"`         // 行号
	Mode       string `json:"mode"`         // 模式: import/export/bridge
	Status     string `json:"status"`       // 状态: complete/impl_missing/decl_missing
	IsAsm      bool   `json:"is_asm"`       // 实现是否在汇编层（目标函数无 Go 函数体）
}

type ImplInfo struct {
	ImplFunc string
	ImplPkg  string
}

// LinknameInfo 表示从注释中解析的 linkname 信息
type LinknameInfo struct {
	LocalName  string
	TargetName string
}