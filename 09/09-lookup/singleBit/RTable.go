package ratbletrie

// Node tree node type
type Node struct {
	nodeKind string
	Port     int
	children [2]*Node
}

// New return a new node
func New() *Node {
	var node Node
	node.InitNode()
	return &node
}

// InitNode initializa a node
func (node *Node) InitNode() {
	node.children[0] = nil
	node.children[1] = nil
	node.Port = -1
	node.nodeKind = "internal"
}

// SetNode sets a node's attributes
func (node *Node) SetNode(port int, kind string) {
	node.Port = port
	node.nodeKind = kind
}

func getIndexFromIP(IP uint32) int {
	return int(IP >> 31)
}

// AddNewIP add new node to a trie
func (node *Node) AddNewIP(IP uint32, prefixLength int, port int) {
	index := getIndexFromIP(IP)
	if node.children[index] == nil {
		node.children[index] = New()
	}

	if prefixLength == 1 {
		node.children[index].SetNode(port, "matched")
	} else {
		node.children[index].AddNewIP(IP<<1, prefixLength-1, port)
	}
}
