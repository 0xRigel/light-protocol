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
func (ia *IndexedArray) findLowElementIndex(value *big.Int) uint32 {
	maxAddr, _ := new(big.Int).SetString("452312848583266388373324160190187140051835877600158453279131187530910662655", 10)

	for i, element := range ia.elements {
		if element.Value.Cmp(maxAddr) == 0 {
			continue
		}

		if element.NextIndex == 0 {
			return uint32(i)
		}

		nextElement := ia.Get(element.NextIndex)
		if element.Value.Cmp(value) < 0 && nextElement.Value.Cmp(value) > 0 {
			return uint32(i)
		}
	}

	return uint32(0)
}

func (imt *IndexedMerkleTree) Append(value *big.Int) error {
	lowElementIndex := imt.indexArray.findLowElementIndex(value)
	lowElement := imt.indexArray.Get(lowElementIndex)

	var nextElement *IndexedElement
	if lowElement.NextIndex != 0 {
		nextElement = imt.indexArray.Get(lowElement.NextIndex)
		if value.Cmp(nextElement.Value) >= 0 {
			return fmt.Errorf("new value must be less than next element value")
		}
	}

	newElementIndex := uint32(len(imt.indexArray.elements))

	bundle := IndexedElementBundle{
		NewLowElement: IndexedElement{
			Value:     lowElement.Value,
			NextValue: value,
			NextIndex: newElementIndex,
			Index:     lowElement.Index,
		},
		NewElement: IndexedElement{
			Value:     value,
			NextValue: nextElement.Value,
			NextIndex: lowElement.NextIndex,
			Index:     newElementIndex,
		},
	}

	lowLeafHash, err := hashIndexedElement(&bundle.NewLowElement)
	if err != nil {
		return fmt.Errorf("failed to hash low leaf: %v", err)
	}
	imt.tree.Update(int(lowElement.Index), *lowLeafHash)

	newLeafHash, err := hashIndexedElement(&bundle.NewElement)
	if err != nil {
		return fmt.Errorf("failed to hash new leaf: %v", err)
	}
	imt.tree.Update(int(newElementIndex), *newLeafHash)

	imt.indexArray.elements[lowElement.Index] = bundle.NewLowElement
	imt.indexArray.elements = append(imt.indexArray.elements, bundle.NewElement)
	imt.indexArray.currentNodeIndex = newElementIndex
	if lowElement.NextIndex == 0 {
		imt.indexArray.highestNodeIndex = newElementIndex
	}

	return nil
}

func (imt *IndexedMerkleTree) Init() error {
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
	}

	lowLeafHash, err := hashIndexedElement(&bundle.NewLowElement)
	if err != nil {
		return fmt.Errorf("failed to hash low leaf: %v", err)
	}
	imt.tree.Update(0, *lowLeafHash)

	maxLeafHash, err := hashIndexedElement(&bundle.NewElement)
	if err != nil {
		return fmt.Errorf("failed to hash max leaf: %v", err)
	}
	imt.tree.Update(1, *maxLeafHash)

	imt.indexArray.elements = []IndexedElement{bundle.NewLowElement, bundle.NewElement}
	imt.indexArray.currentNodeIndex = 1
	imt.indexArray.highestNodeIndex = 1

	return nil
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
