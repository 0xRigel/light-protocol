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

	// Private inputs for batch append
	NewElementValues []frontend.Variable `gnark:",private"`
	Subtrees         []frontend.Variable `gnark:",private"`

	BatchSize  uint32
	TreeHeight uint32
}

func (circuit *BatchAddressTreeAppendCircuit) Define(api frontend.API) error {
	if err := circuit.validateInputs(); err != nil {
		return err
	}

	// Create hash chain of public inputs
	hashChainInputs := make([]frontend.Variable, 5)
	hashChainInputs[0] = circuit.OldSubTreeHashChain
	hashChainInputs[1] = circuit.NewSubTreeHashChain
	hashChainInputs[2] = circuit.NewRoot
	hashChainInputs[3] = circuit.HashchainHash
	hashChainInputs[4] = circuit.StartIndex

	publicInputsHashChain := createHashChainCircuit(api, 5, hashChainInputs)

	api.Println("\npublicInputsHashChain Verification:")
	api.Println("Expected Hash:", publicInputsHashChain)
	api.Println("Circuit Hash:", publicInputsHashChain)

	api.AssertIsEqual(circuit.PublicInputHash, publicInputsHashChain)

	// 1. Process each low element and validate new elements
	currentRoot := frontend.Variable(0)

	for i := uint32(0); i < circuit.BatchSize; i++ {
		api.Println("Processing batch element: ", i)
		api.Println("Current root: ", currentRoot)

		// 1.1 Validate new element
		// Check that new element value is greater than low element value

		api.Println("Low element: ", circuit.LowElementValues[i])
		api.Println("New element: ", circuit.NewElementValues[i])

		abstractor.CallVoid(api, AssertIsLess{
			A: circuit.LowElementValues[i],
			B: circuit.NewElementValues[i],
			N: 248,
		})

		// If next index is not zero, check that new element is less than next value
		isNextIndexZero := api.IsZero(circuit.LowElementNextIndices[i])

		api.Println("Next index: ", circuit.LowElementNextIndices[i])
		api.Println("Next value: ", circuit.LowElementNextValues[i])

		// When next index is not zero, enforce that new element is less than next value
		api.AssertIsEqual(
			api.Mul(
				api.Sub(1, isNextIndexZero), // 1 when not zero, 0 when zero
				api.Sub(circuit.LowElementNextValues[i], circuit.NewElementValues[i]), // should be positive
			),
			api.Select(isNextIndexZero, 0, api.Sub(circuit.LowElementNextValues[i], circuit.NewElementValues[i])),
		)

		// 1.2 Update the tree
		// First verify the old leaf exists in the tree
		oldLeaf := abstractor.Call(api, poseidon.Poseidon3{
			In1: circuit.LowElementValues[i],
			In2: circuit.LowElementNextIndices[i],
			In3: circuit.LowElementNextValues[i],
		})

		api.Println("Old leaf: ", oldLeaf)

		oldMerkleRoot := abstractor.Call(api, MerkleRootGadget{
			Hash:   oldLeaf,
			Index:  circuit.LowElementPathIndices[i],
			Path:   circuit.LowElementProofs[i],
			Height: int(circuit.TreeHeight),
		})
		api.Println("Computed old root: ", oldMerkleRoot)

		// Update with modified low leaf
		newLowLeaf := abstractor.Call(api, poseidon.Poseidon3{
			In1: circuit.LowElementValues[i],
			In2: circuit.LowElementNextIndices[i],
			In3: circuit.NewElementValues[i],
		})

		api.Println("New low leaf: ", newLowLeaf)

		// Use MerkleRootUpdateGadget to verify and update the root
		currentRoot = abstractor.Call(api, MerkleRootUpdateGadget{
			OldRoot:     oldMerkleRoot,
			OldLeaf:     oldLeaf,
			NewLeaf:     newLowLeaf,
			PathIndex:   circuit.LowElementPathIndices[i],
			MerkleProof: circuit.LowElementProofs[i],
			Height:      int(circuit.TreeHeight),
		})

		api.Println("Root after low leaf update: ", currentRoot)

		// Add the new element
		newLeaf := abstractor.Call(api, poseidon.Poseidon3{
			In1: circuit.NewElementValues[i],
			In2: circuit.LowElementNextIndices[i],
			In3: circuit.LowElementNextValues[i],
		})

		api.Println("New leaf: ", newLeaf)

		currentRoot = abstractor.Call(api, MerkleRootUpdateGadget{
			OldRoot:     currentRoot,
			OldLeaf:     newLowLeaf,
			NewLeaf:     newLeaf,
			PathIndex:   circuit.LowElementPathIndices[i],
			MerkleProof: circuit.LowElementProofs[i],
			Height:      int(circuit.TreeHeight),
		})

		api.Println("Final root after new leaf update: ", currentRoot)
	}

	// 2. Batch append
	api.Println("Batch append")
	oldSubtreesHashChain := createHashChainCircuit(api, int(circuit.TreeHeight), circuit.Subtrees)
	api.Println("Old subtrees hash chain: ", oldSubtreesHashChain)
	api.Println("Expected old subtrees hash chain: ", circuit.OldSubTreeHashChain)
	api.AssertIsEqual(oldSubtreesHashChain, circuit.OldSubTreeHashChain)

	newLeaves := make([]frontend.Variable, circuit.BatchSize)
	for i := uint32(0); i < circuit.BatchSize; i++ {
		newLeaves[i] = abstractor.Call(api, poseidon.Poseidon3{
			In1: circuit.NewElementValues[i],
			In2: circuit.LowElementNextIndices[i],
			In3: circuit.LowElementNextValues[i],
		})
	}

	leavesHashChain := createHashChainCircuit(api, int(circuit.BatchSize), newLeaves)
	api.Println("Leaves hash chain: ", leavesHashChain)
	api.Println("Expected leaves hash chain: ", circuit.HashchainHash)
	api.AssertIsEqual(leavesHashChain, circuit.HashchainHash)

	finalRoot, newSubtrees := circuit.batchAppend(api, newLeaves)
	api.Println("Final root after batch append: ", finalRoot)
	api.Println("Circuit's new root: ", circuit.NewRoot)
	api.Println("Current root", currentRoot)
	//api.AssertIsEqual(finalRoot, currentRoot)

	for i := 0; i < int(circuit.TreeHeight); i++ {
		api.Println("Subtree", i, ":", newSubtrees[i])
	}

	newSubtreesHashChain := createHashChainCircuit(api, int(circuit.TreeHeight), newSubtrees)
	api.AssertIsEqual(newSubtreesHashChain, circuit.NewSubTreeHashChain)

	return nil
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

func (circuit *BatchAddressTreeAppendCircuit) batchAppend(
	api frontend.API,
	leaves []frontend.Variable,
) (frontend.Variable, []frontend.Variable) {
	currentSubtrees := make([]frontend.Variable, len(circuit.Subtrees))
	copy(currentSubtrees, circuit.Subtrees)

	indexBits := api.ToBinary(circuit.StartIndex, int(circuit.TreeHeight))
	newRoot := frontend.Variable(0)

	for i := 0; i < int(circuit.BatchSize); i++ {
		leaf := leaves[i]
		pathIndex := circuit.LowElementPathIndices[i]
		newRoot, currentSubtrees = circuit.append(api, leaf, currentSubtrees, pathIndex)
		indexBits = circuit.incrementBits(api, indexBits)
	}

	return newRoot, currentSubtrees
}

func (circuit *BatchAddressTreeAppendCircuit) append(
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
	return frontend.Variable(new(big.Int).SetBytes(ZERO_BYTES[level][:]))
}

// Parameters struct
type BatchAddressTreeAppendParameters struct {
	// Public inputs
	PublicInputHash     *big.Int
	OldSubTreeHashChain *big.Int
	NewSubTreeHashChain *big.Int
	NewRoot             *big.Int
	HashchainHash       *big.Int
	StartIndex          uint32

	// Low elements data
	LowElementValues      []*big.Int
	LowElementNextValues  []*big.Int
	LowElementNextIndices []uint32
	LowElementProofs      [][]big.Int
	LowElementPathIndices []uint32

	// New elements
	NewElementValues []*big.Int
	Subtrees         []*big.Int

	TreeHeight uint32
	BatchSize  uint32
	Tree       *merkletree.PoseidonTree
}
