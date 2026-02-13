package merkletree

import (
	"bytes"
	"crypto/sha256"
	"testing"
)

func TestNewMerkleTree(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		data [][]byte
		want []byte
	}{
		{
			name: "empty data",
			data: nil,
			want: nil,
		},
		{
			name: "single leaf",
			data: [][]byte{[]byte("a")},
			want: hashLeaf([]byte("a")),
		},
		{
			name: "even leaves",
			data: [][]byte{[]byte("a"), []byte("b")},
			want: hashPair(hashLeaf([]byte("a")), hashLeaf([]byte("b"))),
		},
		{
			name: "odd leaves duplicates last node",
			data: [][]byte{[]byte("a"), []byte("b"), []byte("c")},
			want: hashPair(
				hashPair(hashLeaf([]byte("a")), hashLeaf([]byte("b"))),
				hashPair(hashLeaf([]byte("c")), hashLeaf([]byte("c"))),
			),
		},
	}

	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			tree := NewMerkleTree(tt.data)
			if tt.want == nil {
				if tree == nil || tree.Root != nil {
					t.Fatalf("expected empty tree root, got %+v", tree)
				}
				return
			}

			if tree == nil || tree.Root == nil {
				t.Fatal("expected non-nil tree root")
			}
			if !bytes.Equal(tree.Root.Hash, tt.want) {
				t.Fatalf("unexpected root hash: got %x want %x", tree.Root.Hash, tt.want)
			}
		})
	}
}

func TestNewNodeDoesNotMutateChildHashes(t *testing.T) {
	t.Parallel()

	left := NewNode(nil, nil, []byte("left"))
	right := NewNode(nil, nil, []byte("right"))
	leftBefore := append([]byte(nil), left.Hash...)

	_ = NewNode(left, right, nil)

	if !bytes.Equal(left.Hash, leftBefore) {
		t.Fatalf("left hash mutated: got %x want %x", left.Hash, leftBefore)
	}
}

func TestNewNodeWithOneNilChildDuplicatesNonNil(t *testing.T) {
	t.Parallel()

	child := NewNode(nil, nil, []byte("x"))
	node := NewNode(child, nil, nil)
	want := hashPair(child.Hash, child.Hash)

	if node.Left == nil || node.Right == nil {
		t.Fatal("expected both children to be set")
	}
	if !bytes.Equal(node.Hash, want) {
		t.Fatalf("unexpected hash: got %x want %x", node.Hash, want)
	}
}

func hashLeaf(data []byte) []byte {
	prefixedData := make([]byte, 1+len(data))
	prefixedData[0] = LeafPrefix
	copy(prefixedData[1:], data)
	sum := sha256.Sum256(prefixedData)
	return append([]byte(nil), sum[:]...)
}

func hashPair(left, right []byte) []byte {
	combined := make([]byte, 1+len(left)+len(right))
	combined[0] = InternalPrefix
	copy(combined[1:], left)
	copy(combined[1+len(left):], right)
	sum := sha256.Sum256(combined)
	return append([]byte(nil), sum[:]...)
}
