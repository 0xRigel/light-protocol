package merkle_tree

import (
	"fmt"
	"math/big"

	"github.com/iden3/go-iden3-crypto/poseidon"
)

type PoseidonNode interface {
	depth() int
	Value() big.Int
	Bytes() []byte
	withValue(index int, val big.Int) PoseidonNode
	writeProof(index int, out []big.Int)
}

func (node *PoseidonFullNode) depth() int {
	return node.dep
}

func (node *PoseidonEmptyNode) depth() int {
	return node.dep
}

func (node *PoseidonFullNode) Value() big.Int {
	return node.val
}

//func (node *PoseidonEmptyNode) Value() big.Int {
//	return node.emptyTreeValues[node.depth()]
//}

func (node *PoseidonFullNode) Bytes() []byte {
	bytes := make([]byte, 32)
	node.val.FillBytes(bytes)
	return bytes
}

func (node *PoseidonEmptyNode) Bytes() []byte {
	bytes := make([]byte, 32)
	value := node.Value()
	value.FillBytes(bytes)
	return bytes
}

func (node *PoseidonEmptyNode) Value() big.Int {
	return node.emptyTreeValues[node.depth()]
}

func (node *PoseidonFullNode) writeProof(index int, out []big.Int) {
	if node.depth() == 0 {
		return
	}
	if indexIsLeft(index, node.depth()) {
		out[node.depth()-1] = node.Right.Value()
		node.Left.writeProof(index, out)
	} else {
		out[node.depth()-1] = node.Left.Value()
		node.Right.writeProof(index, out)
	}
}

func (node *PoseidonEmptyNode) writeProof(index int, out []big.Int) {
	for i := 0; i < node.depth(); i++ {
		out[i] = node.emptyTreeValues[i]
	}
}

type PoseidonFullNode struct {
	dep   int
	val   big.Int
	Left  PoseidonNode
	Right PoseidonNode
}

func (node *PoseidonFullNode) initHash() {
	leftVal := node.Left.Value()
	rightVal := node.Right.Value()
	newHash, _ := poseidon.Hash([]*big.Int{&leftVal, &rightVal})
	node.val = *newHash
}

type PoseidonEmptyNode struct {
	dep             int
	emptyTreeValues []big.Int
}

type PoseidonTree struct {
	Root PoseidonNode
}

func (tree *PoseidonTree) Update(index int, value big.Int) []big.Int {
	proof := make([]big.Int, tree.Root.depth())
	tree.Root.writeProof(index, proof)
	tree.Root = tree.Root.withValue(index, value)

	return proof
}

func NewTree(depth int) PoseidonTree {
	initHashes := make([]big.Int, depth+1)
	for i := 1; i <= depth; i++ {
		val, _ := poseidon.Hash([]*big.Int{&initHashes[i-1], &initHashes[i-1]})
		initHashes[i] = *val
		fmt.Printf("Empty hash at depth %d: %s\n", i, val.Text(16))
	}

	return PoseidonTree{
		Root: &PoseidonEmptyNode{
			dep:             depth,
			emptyTreeValues: initHashes,
		},
	}
}

func (tree *PoseidonTree) DeepCopy() *PoseidonTree {
	if tree == nil {
		return nil
	}
	return &PoseidonTree{
		Root: deepCopyNode(tree.Root),
	}
}

func deepCopyNode(node PoseidonNode) PoseidonNode {
	if node == nil {
		return nil
	}

	switch n := node.(type) {
	case *PoseidonFullNode:
		return deepCopyFullNode(n)
	case *PoseidonEmptyNode:
		return deepCopyEmptyNode(n)
	default:
		panic("Unknown node type")
	}
}

func deepCopyFullNode(node *PoseidonFullNode) *PoseidonFullNode {
	if node == nil {
		return nil
	}
	return &PoseidonFullNode{
		dep:   node.dep,
		val:   *new(big.Int).Set(&node.val),
		Left:  deepCopyNode(node.Left),
		Right: deepCopyNode(node.Right),
	}
}

func deepCopyEmptyNode(node *PoseidonEmptyNode) *PoseidonEmptyNode {
	if node == nil {
		return nil
	}
	emptyTreeValues := make([]big.Int, len(node.emptyTreeValues))
	for i, v := range node.emptyTreeValues {
		emptyTreeValues[i] = *new(big.Int).Set(&v)
	}
	return &PoseidonEmptyNode{
		dep:             node.dep,
		emptyTreeValues: emptyTreeValues,
	}
}

func (tree *PoseidonTree) Bytes() []byte {
	return tree.Root.Bytes()
}

func (tree *PoseidonTree) GetRightmostSubtrees(depth int) []*big.Int {
	subtrees := make([]*big.Int, depth)
	for i := 0; i < depth; i++ {
		subtrees[i] = new(big.Int).SetBytes(ZERO_BYTES[i][:])
	}

	/*
		start at top x
		take left child hash as subtree
		if right node is not zero value, go down right
		if right node is zero value go down left node
	*/

	if fullNode, ok := tree.Root.(*PoseidonFullNode); ok {
		current := fullNode
		level := depth - 1
		for current != nil && level >= 0 {
			if fullLeft, ok := current.Left.(*PoseidonFullNode); ok {
				value := fullLeft.Value()
				subtrees[level] = &value
				if fullRight, ok := current.Right.(*PoseidonFullNode); ok {
					current = fullRight
				} else {
					current = fullLeft
				}
			}
			level--
		}
	}
	return subtrees
}
func indexIsLeft(index int, depth int) bool {
	return uint(index)&(1<<(depth-1)) == 0
}

func getEmptyAtIndex(emptyValues []big.Int, index int, val big.Int, depth int) (PoseidonNode, error) {
	if depth == 0 {
		return &PoseidonFullNode{dep: 0, val: val}, nil
	}

	result := &PoseidonFullNode{dep: depth}
	emptyChild := &PoseidonEmptyNode{
		dep:             depth - 1,
		emptyTreeValues: emptyValues,
	}

	isLeft := indexIsLeft(index, depth)
	if isLeft {
		left, _ := getEmptyAtIndex(emptyValues, index, val, depth-1)
		result.Left = left
		result.Right = emptyChild
	} else {
		right, _ := getEmptyAtIndex(emptyValues, index, val, depth-1)
		result.Left = emptyChild
		result.Right = right
	}

	leftVal := result.Left.Value()
	rightVal := result.Right.Value()
	hash, _ := poseidon.Hash([]*big.Int{&leftVal, &rightVal})
	result.val = *hash

	return result, nil
}

func (node *PoseidonEmptyNode) withValue(index int, val big.Int) PoseidonNode {
	n, _ := getEmptyAtIndex(node.emptyTreeValues, index, val, node.depth())
	return n
}

func (node *PoseidonFullNode) withValue(index int, val big.Int) PoseidonNode {
	result := &PoseidonFullNode{dep: node.depth()}

	if node.depth() == 0 {
		result.val = val
		return result
	}
	if indexIsLeft(index, node.depth()) {
		result.Left = node.Left.withValue(index, val)
		result.Right = node.Right
	} else {
		result.Left = node.Left
		result.Right = node.Right.withValue(index, val)
	}

	leftVal := result.Left.Value()
	rightVal := result.Right.Value()
	newHash, _ := poseidon.Hash([]*big.Int{&leftVal, &rightVal})
	result.val = *newHash

	return result
}
