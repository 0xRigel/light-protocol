package merkle_tree

import (
	"encoding/binary"
	"fmt"
	"github.com/iden3/go-iden3-crypto/poseidon"
	"math/big"
)

type IndexedArray struct {
	elements         []IndexedElement
	currentNodeIndex uint32
	highestNodeIndex uint32
}

type IndexedElement struct {
	Value     *big.Int
	NextValue *big.Int
	NextIndex uint32
	Index     uint32
}

type IndexedElementBundle struct {
	NewLowElement       IndexedElement
	NewElement          IndexedElement
	NewElementNextValue *big.Int
}

type IndexedMerkleTree struct {
	tree       *PoseidonTree
	indexArray *IndexedArray
}

func NewIndexedMerkleTree(height uint32) (*IndexedMerkleTree, error) {
	tree := NewTree(int(height))
	indexArray := &IndexedArray{
		elements: []IndexedElement{{
			Value:     big.NewInt(0),
			NextValue: big.NewInt(0),
			NextIndex: 0,
			Index:     0,
		}},
		currentNodeIndex: 0,
		highestNodeIndex: 0,
	}

	return &IndexedMerkleTree{
		tree:       &tree,
		indexArray: indexArray,
	}, nil
}

func (ia *IndexedArray) Init() error {
	maxAddr, ok := new(big.Int).SetString("452312848583266388373324160190187140051835877600158453279131187530910662655", 10)
	if !ok {
		return fmt.Errorf("failed to parse HIGHEST_ADDRESS_PLUS_ONE")
	}

	bundle := IndexedElementBundle{
		NewLowElement: IndexedElement{
			Value:     big.NewInt(0),
			NextValue: maxAddr,
			NextIndex: 1,
			Index:     0,
		},
		NewElement: IndexedElement{
			Value:     maxAddr,
			NextValue: big.NewInt(0),
			NextIndex: 0,
			Index:     1,
		},
		NewElementNextValue: big.NewInt(0),
	}

	ia.elements = []IndexedElement{bundle.NewLowElement, bundle.NewElement}
	ia.currentNodeIndex = 1
	ia.highestNodeIndex = 1

	return nil
}

func (ia *IndexedArray) Get(index uint32) *IndexedElement {
	if int(index) >= len(ia.elements) {
		return nil
	}
	return &ia.elements[index]
}

func (ia *IndexedArray) Append(value *big.Int) error {
	lowElementIndex := ia.findLowElementIndex(value)
	lowElement := ia.elements[lowElementIndex]

	if lowElement.NextIndex != 0 {
		nextElement := ia.elements[lowElement.NextIndex]
		if value.Cmp(nextElement.Value) >= 0 {
			return fmt.Errorf("new value must be less than next element value")
		}
	}

	newElementIndex := uint32(len(ia.elements))
	newElement := IndexedElement{
		Value:     value,
		NextValue: lowElement.NextValue,
		NextIndex: lowElement.NextIndex,
		Index:     newElementIndex,
	}

	ia.elements[lowElementIndex].NextIndex = newElementIndex
	ia.elements[lowElementIndex].NextValue = value

	ia.elements = append(ia.elements, newElement)
	ia.currentNodeIndex = newElementIndex
	if lowElement.NextIndex == 0 {
		ia.highestNodeIndex = newElementIndex
	}

	return nil
}

func (imt *IndexedMerkleTree) Init() error {
	if err := imt.indexArray.Init(); err != nil {
		return fmt.Errorf("failed to init array: %v", err)
	}
	element0 := imt.indexArray.Get(0)
	element1 := imt.indexArray.Get(1)

	lowLeaf, err := poseidon.Hash([]*big.Int{
		element0.Value,
		big.NewInt(int64(element0.NextIndex)),
		element1.Value,
	})
	if err != nil {
		return fmt.Errorf("failed to create low leaf: %v", err)
	}
	imt.tree.Update(0, *lowLeaf)

	maxLeaf, err := poseidon.Hash([]*big.Int{
		element1.Value,
		big.NewInt(int64(element1.NextIndex)),
		big.NewInt(0),
	})
	if err != nil {
		return fmt.Errorf("failed to hash max leaf: %v", err)
	}
	imt.tree.Update(1, *maxLeaf)

	return nil
}

func (imt *IndexedMerkleTree) Append(value *big.Int) error {
	lowElementIndex := imt.indexArray.findLowElementIndex(value)
	lowElement := imt.indexArray.Get(lowElementIndex)

	newElementIndex := uint32(len(imt.indexArray.elements))
	newElement := &IndexedElement{
		Value:     value,
		NextValue: lowElement.NextValue,
		NextIndex: lowElement.NextIndex,
		Index:     newElementIndex,
	}
	newLowElement := &IndexedElement{
		Value:     lowElement.Value,
		NextValue: value,
		NextIndex: newElementIndex,
		Index:     lowElement.Index,
	}

	lowLeafHash, err := hashIndexedElement(newLowElement)
	if err != nil {
		return fmt.Errorf("failed to hash low leaf: %v", err)
	}
	imt.tree.Update(int(lowElement.Index), *lowLeafHash)

	newLeafHash, err := hashIndexedElement(newElement)
	if err != nil {
		return fmt.Errorf("failed to hash new leaf: %v", err)
	}
	imt.tree.Update(int(newElementIndex), *newLeafHash)

	imt.indexArray.elements[lowElement.Index] = *newLowElement
	imt.indexArray.elements = append(imt.indexArray.elements, *newElement)
	imt.indexArray.currentNodeIndex = newElementIndex
	if lowElement.NextIndex == 0 {
		imt.indexArray.highestNodeIndex = newElementIndex
	}

	return nil
}

func (ia *IndexedArray) findLowElementIndex(value *big.Int) uint32 {
	var lowIndex uint32
	for i, element := range ia.elements {
		if element.NextIndex == 0 ||
			(element.Value.Cmp(value) < 0 && ia.elements[element.NextIndex].Value.Cmp(value) > 0) {
			lowIndex = uint32(i)
			break
		}
	}
	return lowIndex
}

func hashIndexedElement(element *IndexedElement) (*big.Int, error) {
	fmt.Printf("\nHashing element:\n")
	fmt.Printf("Value: %s\n", element.Value.String())
	fmt.Printf("NextIndex: %d\n", element.NextIndex)
	fmt.Printf("NextValue: %s\n", element.NextValue.String())

	indexBytes := make([]byte, 32)
	binary.BigEndian.PutUint32(indexBytes[28:], element.NextIndex)

	fmt.Printf("Index bytes: %v\n", indexBytes)

	hash, err := poseidon.Hash([]*big.Int{
		element.Value,
		new(big.Int).SetBytes(indexBytes),
		element.NextValue,
	})
	if err != nil {
		return nil, err
	}

	hashBytes := make([]byte, 32)
	hash.FillBytes(hashBytes)
	fmt.Printf("Hash: %v\n", hashBytes)

	return hash, nil
}
