package merkletree

import "crypto/sha256"

const (
	// LeafPrefix is prepended to leaf node data before hashing
	LeafPrefix = 0x00
	// InternalPrefix is prepended to internal node hashes before hashing
	InternalPrefix = 0x01
)

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
// Uses domain separation (prefix bytes) to prevent second preimage attacks
func NewNode(left, right *Node, data []byte) *Node {
	node := &Node{Left: left, Right: right}

	// Leaf node: hash with leaf prefix (0x00 + data)
	if left == nil && right == nil {
		prefixedData := make([]byte, 1+len(data))
		prefixedData[0] = LeafPrefix
		copy(prefixedData[1:], data)
		hash := sha256.Sum256(prefixedData)
		node.Hash = hash[:]
		return node
	}

	// Internal node: hash with internal prefix (0x01 + left.Hash + right.Hash)
	if right == nil {
		right = left
		node.Right = right
	}

	combined := make([]byte, 1+len(left.Hash)+len(right.Hash))
	combined[0] = InternalPrefix
	copy(combined[1:], left.Hash)
	copy(combined[1+len(left.Hash):], right.Hash)
	hash := sha256.Sum256(combined)
	node.Hash = hash[:]

	return node
}
