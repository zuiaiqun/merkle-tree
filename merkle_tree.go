package merkletree

import "crypto/sha256"

// MerkleTree is the root node of the tree
type MerkleTree struct {
	Root *Node
}

// Node is a leaf node of the tree
type Node struct {
	Hash  []byte
	Left  *Node
	Right *Node
}

// NewMerkleTree creates a new MerkleTree from the given data
func NewMerkleTree(data [][]byte) *MerkleTree {
	if len(data) == 0 {
		return &MerkleTree{}
	}

	nodes := make([]*Node, len(data))
	for i, datum := range data {
		nodes[i] = NewNode(nil, nil, datum)
	}

	for len(nodes) > 1 {
		nextLevelLen := (len(nodes) + 1) / 2
		for i := 0; i < len(nodes)/2; i++ {
			nodes[i] = NewNode(nodes[i*2], nodes[i*2+1], nil)
		}
		if len(nodes)%2 == 1 {
			nodes[nextLevelLen-1] = NewNode(nodes[len(nodes)-1], nil, nil)
		}
		nodes = nodes[:nextLevelLen]
	}

	return &MerkleTree{Root: nodes[0]}
}

// NewNode creates a new Node from the given data
// For leaf nodes: pass nil for left and right, provide data
// For internal nodes: pass left and right children, data should be nil
func NewNode(left, right *Node, data []byte) *Node {
	node := &Node{Left: left, Right: right}

	// Leaf node: hash the data
	if left == nil && right == nil {
		hash := sha256.Sum256(data)
		node.Hash = hash[:]
		return node
	}

	// Internal node: hash the concatenation of children hashes
	if right == nil {
		right = left
		node.Right = right
	}

	combined := make([]byte, 0, len(left.Hash)+len(right.Hash))
	combined = append(combined, left.Hash...)
	combined = append(combined, right.Hash...)
	hash := sha256.Sum256(combined)
	node.Hash = hash[:]

	return node
}
