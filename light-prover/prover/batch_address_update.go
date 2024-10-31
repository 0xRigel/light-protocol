package prover

import (
	"fmt"
	merkletree "light/light-prover/merkle-tree"
	"light/light-prover/prover/poseidon"
	"math/big"

	"github.com/consensys/gnark/frontend"
	"github.com/reilabs/gnark-lean-extractor/v2/abstractor"
)

type BatchAddressTreeAppendCircuit struct {
	// Public inputs
	PublicInputHash     frontend.Variable `gnark:",public"`
	OldSubTreeHashChain frontend.Variable `gnark:",private"`
	NewSubTreeHashChain frontend.Variable `gnark:",private"`
	NewRoot             frontend.Variable `gnark:",private"`
	HashchainHash       frontend.Variable `gnark:",private"`
	StartIndex          frontend.Variable `gnark:",private"`

	// Private inputs for non-inclusion proof
	LowElementValues      []frontend.Variable `gnark:",private"`
	LowElementNextValues  []frontend.Variable `gnark:",private"`
	LowElementNextIndices []frontend.Variable `gnark:",private"`

	LowElementPathIndices []frontend.Variable   `gnark:",private"`
	LowElementProofs      [][]frontend.Variable `gnark:",private"`

	// New elements to insert
	NewElementValues []frontend.Variable   `gnark:",private"`
	NewElementProofs [][]frontend.Variable `gnark:",private"`
	// Tree state
	Subtrees []frontend.Variable `gnark:",private"`

	BatchSize  uint32
	TreeHeight uint32
}

func (circuit *BatchAddressTreeAppendCircuit) Define(api frontend.API) error {
	if err := circuit.validateInputs(); err != nil {
		return err
	}
	api.Println("Target NewRoot:", circuit.NewRoot)

	hashChainInputs := make([]frontend.Variable, 5)
	hashChainInputs[0] = circuit.OldSubTreeHashChain
	hashChainInputs[1] = circuit.NewSubTreeHashChain
	hashChainInputs[2] = circuit.NewRoot
	hashChainInputs[3] = circuit.HashchainHash
	hashChainInputs[4] = circuit.StartIndex

	publicInputsHashChain := createHashChainCircuit(api, 5, hashChainInputs)
	api.AssertIsEqual(circuit.PublicInputHash, publicInputsHashChain)

	currentRoot := circuit.processLowElements(api)
	api.Println("Calculated root after processLowElements:", currentRoot)
	// Add masking before comparison
	mask := new(big.Int).Sub(new(big.Int).Lsh(big.NewInt(1), 248), big.NewInt(1))
	maskedCurrentRoot := frontend.Variable(new(big.Int).And(toBigInt(currentRoot), mask))
	maskedTargetRoot := frontend.Variable(new(big.Int).And(toBigInt(circuit.NewRoot), mask))
	api.AssertIsEqual(maskedCurrentRoot, maskedTargetRoot)
	//api.AssertIsEqual(currentRoot, circuit.NewRoot)

	oldSubtreesHashChain := createHashChainCircuit(api, int(circuit.TreeHeight), circuit.Subtrees)
	api.AssertIsEqual(oldSubtreesHashChain, circuit.OldSubTreeHashChain)

	newLeaves := circuit.calculateNewLeaves(api)
	leavesHashChain := createHashChainCircuit(api, int(circuit.BatchSize), newLeaves)
	api.AssertIsEqual(leavesHashChain, circuit.HashchainHash)

	finalRoot, newSubtrees := circuit.batchAppend(api, newLeaves)

	// 5. Verify results
	// Verify root matches
	api.AssertIsEqual(finalRoot, circuit.NewRoot)

	// Verify new subtrees hash chain
	newSubtreesHashChain := createHashChainCircuit(api, int(circuit.TreeHeight), newSubtrees)
	api.AssertIsEqual(newSubtreesHashChain, circuit.NewSubTreeHashChain)

	return nil
}
func (circuit *BatchAddressTreeAppendCircuit) processLowElements(api frontend.API) frontend.Variable {
	currentRoot := frontend.Variable(0)

	for i := uint32(0); i < circuit.BatchSize; i++ {
		api.Println("Processing element", i)

		// 1. Verify old leaf exists (unchanged)
		lowElementLeaf := LeafHashGadget{
			LeafLowerRangeValue:  circuit.LowElementValues[i],
			NextIndex:            circuit.LowElementNextIndices[i],
			LeafHigherRangeValue: circuit.LowElementNextValues[i],
			Value:                circuit.NewElementValues[i],
		}
		oldLeaf := abstractor.Call(api, lowElementLeaf)

		oldMerkleRoot := abstractor.Call(api, MerkleRootGadget{
			Hash:   oldLeaf,
			Index:  circuit.LowElementPathIndices[i],
			Path:   circuit.LowElementProofs[i],
			Height: int(circuit.TreeHeight),
		})

		if i > 0 {
			api.AssertIsEqual(oldMerkleRoot, currentRoot)
		} else {
			currentRoot = oldMerkleRoot
		}

		newLowIndex := api.Add(circuit.StartIndex, i+1)
		newLowLeaf := LeafHashGadget{
			LeafLowerRangeValue:  circuit.LowElementValues[i],
			NextIndex:            newLowIndex,
			LeafHigherRangeValue: circuit.NewElementValues[i],
			Value:                circuit.NewElementValues[i],
		}
		newLowLeafHash := abstractor.Call(api, newLowLeaf)

		currentRoot = abstractor.Call(api, MerkleRootUpdateGadget{
			OldRoot:     currentRoot,
			OldLeaf:     oldLeaf,
			NewLeaf:     newLowLeafHash,
			PathIndex:   circuit.LowElementPathIndices[i],
			MerkleProof: circuit.LowElementProofs[i],
			Height:      int(circuit.TreeHeight),
		})

		newElementLeaf := LeafHashGadget{
			LeafLowerRangeValue:  circuit.NewElementValues[i],
			NextIndex:            circuit.LowElementNextIndices[i],
			LeafHigherRangeValue: circuit.LowElementNextValues[i],
			Value:                circuit.LowElementNextValues[i],
		}
		newLeafHash := abstractor.Call(api, newElementLeaf)

		emptyLeaf := circuit.getZeroValue(api, 0)
		currentRoot = abstractor.Call(api, MerkleRootUpdateGadget{
			OldRoot:     currentRoot,
			OldLeaf:     emptyLeaf,
			NewLeaf:     newLeafHash,
			PathIndex:   newLowIndex,
			MerkleProof: circuit.NewElementProofs[i],
			Height:      int(circuit.TreeHeight),
		})
	}

	return currentRoot
}

// calculateNewLeaves creates leaf hashes for the new elements
func (circuit *BatchAddressTreeAppendCircuit) calculateNewLeaves(api frontend.API) []frontend.Variable {
	newLeaves := make([]frontend.Variable, circuit.BatchSize)

	for i := uint32(0); i < circuit.BatchSize; i++ {
		newLeaves[i] = abstractor.Call(api, poseidon.Poseidon3{
			In1: circuit.NewElementValues[i],
			In2: circuit.LowElementNextIndices[i],
			In3: circuit.LowElementNextValues[i],
		})
	}

	return newLeaves
}

// Circuit helper functions
func (circuit *BatchAddressTreeAppendCircuit) validateInputs() error {
	if len(circuit.NewElementValues) != int(circuit.BatchSize) {
		return fmt.Errorf("new elements length (%d) does not match batch size (%d)",
			len(circuit.NewElementValues), circuit.BatchSize)
	}
	if len(circuit.LowElementValues) != int(circuit.BatchSize) {
		return fmt.Errorf("low elements length (%d) does not match batch size (%d)",
			len(circuit.LowElementValues), circuit.BatchSize)
	}
	if len(circuit.Subtrees) != int(circuit.TreeHeight) {
		return fmt.Errorf("subtrees length (%d) does not match tree height (%d)",
			len(circuit.Subtrees), circuit.TreeHeight)
	}
	for i := 0; i < int(circuit.BatchSize); i++ {
		if len(circuit.LowElementProofs[i]) != int(circuit.TreeHeight) {
			return fmt.Errorf("merkle proof %d length (%d) does not match tree height (%d)",
				i, len(circuit.LowElementProofs[i]), circuit.TreeHeight)
		}
	}
	return nil
}

func createHashChainCircuit(api frontend.API, length int, inputs []frontend.Variable) frontend.Variable {
	if len(inputs) == 0 {
		return frontend.Variable(0)
	}
	if len(inputs) == 1 {
		return inputs[0]
	}

	hashChain := inputs[0]

	api.Println("Hashchain[ 0 ] = ", hashChain)

	for i := 1; i < length; i++ {
		hashChain = abstractor.Call(api, poseidon.Poseidon2{
			In1: hashChain,
			In2: inputs[i],
		})
		api.Println("Hashchain[", i, "] = ", hashChain)
	}
	return hashChain
}

// batchAppend performs the batch append operation
func (circuit *BatchAddressTreeAppendCircuit) batchAppend(
	api frontend.API,
	leaves []frontend.Variable,
) (frontend.Variable, []frontend.Variable) {
	currentSubtrees := make([]frontend.Variable, len(circuit.Subtrees))
	copy(currentSubtrees, circuit.Subtrees)

	indexBits := api.ToBinary(circuit.StartIndex, int(circuit.TreeHeight))
	newRoot := frontend.Variable(0)

	for i := 0; i < int(circuit.BatchSize); i++ {
		pathIndex := api.Add(circuit.StartIndex, i+1)
		newRoot, currentSubtrees = circuit.appendSingle(api, leaves[i], currentSubtrees, pathIndex)
		indexBits = circuit.incrementBits(api, indexBits)
	}

	return newRoot, currentSubtrees
}

// appendSingle appends a single leaf to the tree
func (circuit *BatchAddressTreeAppendCircuit) appendSingle(
	api frontend.API,
	leaf frontend.Variable,
	subtrees []frontend.Variable,
	pathIndex frontend.Variable,
) (frontend.Variable, []frontend.Variable) {
	newSubtrees := make([]frontend.Variable, len(subtrees))
	copy(newSubtrees, subtrees)

	pathBits := api.ToBinary(pathIndex, int(circuit.TreeHeight))
	currentNode := leaf

	for i := 0; i < int(circuit.TreeHeight); i++ {
		isRight := pathBits[i]
		subtrees[i] = api.Select(isRight, subtrees[i], currentNode)
		sibling := api.Select(isRight, subtrees[i], circuit.getZeroValue(api, i))

		currentNode = abstractor.Call(api, MerkleRootGadget{
			Hash:   currentNode,
			Index:  isRight,
			Path:   []frontend.Variable{sibling},
			Height: 1,
		})
	}

	return currentNode, newSubtrees
}

func (circuit *BatchAddressTreeAppendCircuit) incrementBits(
	api frontend.API,
	bits []frontend.Variable,
) []frontend.Variable {
	carry := frontend.Variable(1)
	for i := 0; i < len(bits); i++ {
		newBit := api.Xor(bits[i], carry)
		carry = api.And(bits[i], carry)
		bits[i] = newBit
	}
	return bits
}

func (circuit *BatchAddressTreeAppendCircuit) getZeroValue(api frontend.API, level int) frontend.Variable {
	return frontend.Variable(new(big.Int).SetBytes(merkletree.ZERO_BYTES[level][:]))
}

type BatchAddressTreeAppendParameters struct {
	PublicInputHash     *big.Int
	OldSubTreeHashChain *big.Int
	NewSubTreeHashChain *big.Int
	NewRoot             *big.Int
	HashchainHash       *big.Int
	StartIndex          uint32

	LowElements      []merkletree.IndexedElement
	NewElements      []merkletree.IndexedElement
	LowElementProofs [][]big.Int
	NewElementProofs [][]big.Int
	Subtrees         []*big.Int

	TreeHeight uint32
	BatchSize  uint32
	Tree       *merkletree.IndexedMerkleTree
}
