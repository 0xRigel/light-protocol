package prover

import (
	"fmt"
	merkletree "light/light-prover/merkle-tree"
	"math/big"
	"testing"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/test"
)

func TestChainLinking(t *testing.T) {
	t.Run("Test chain linking", func(t *testing.T) {
		params := BuildTestBatchAddressAppend(10, 3, 0, nil, "")

		for i := uint32(0); i < params.BatchSize-1; i++ {
			if params.LowElements[i].NextValue.Cmp(params.NewElements[i].Value) != 0 {
				t.Errorf("Element %d: low element next value doesn't match new element value", i)
			}
			if params.LowElements[i].NextIndex != params.NewElements[i].Index {
				t.Errorf("Element %d: low element next index doesn't match new element index", i)
			}
		}
	})
}

func TestBasicUpdate2_2(t *testing.T) {
	assert := test.NewAssert(t)

	params := BuildTestBatchAddressAppend(2, 2, 0, nil, "")
	if err := verifyBatchAddressParameters(params); err != nil {
		t.Fatalf("Invalid test parameters: %v", err)
	}

	circuit := createAddressCircuit(params)
	witness := createAddressWitness(params)

	err := test.IsSolved(circuit, witness, ecc.BN254.ScalarField())
	assert.NoError(err)
}

func TestBasicUpdate26(t *testing.T) {
	assert := test.NewAssert(t)

	params := BuildTestBatchAddressAppend(26, 10, 0, nil, "")
	if err := verifyBatchAddressParameters(params); err != nil {
		t.Fatalf("Invalid test parameters: %v", err)
	}

	circuit := createAddressCircuit(params)
	witness := createAddressWitness(params)

	err := test.IsSolved(circuit, witness, ecc.BN254.ScalarField())
	assert.NoError(err)
}

// Tests
func TestBatchAddressTreeAppendCircuit(t *testing.T) {
	assert := test.NewAssert(t)

	t.Run("Functional tests", func(t *testing.T) {
		t.Run("Basic batch update - height 26", func(t *testing.T) {
			params := BuildTestBatchAddressAppend(26, 10, 0, nil, "")
			circuit := createAddressCircuit(params)
			witness := createAddressWitness(params)

			err := test.IsSolved(circuit, witness, ecc.BN254.ScalarField())
			assert.NoError(err)
		})

		t.Run("Fill tree completely - height 10", func(t *testing.T) {
			treeHeight := uint32(10)
			batchSize := uint32(4)
			totalLeaves := uint32(1 << treeHeight)

			var params *BatchAddressTreeAppendParameters
			for startIndex := uint32(0); startIndex < totalLeaves; startIndex += batchSize {
				remainingLeaves := totalLeaves - startIndex
				if remainingLeaves < batchSize {
					batchSize = remainingLeaves
				}

				newParams := BuildTestBatchAddressAppend(
					treeHeight,
					batchSize,
					startIndex,
					params,
					"",
				)

				circuit := createAddressCircuit(newParams)
				witness := createAddressWitness(newParams)

				err := test.IsSolved(circuit, witness, ecc.BN254.ScalarField())
				assert.NoError(err)

				params = newParams
			}
		})
	})

	t.Run("Failing cases", func(t *testing.T) {
		testCases := []struct {
			name        string
			invalidCase string
		}{
			{
				name:        "Invalid IndexedMerkleTree - wrong low element",
				invalidCase: "invalid_tree",
			},
			{
				name:        "Invalid IndexedMerkleTree - tree is full",
				invalidCase: "tree_full",
			},
			{
				name:        "Invalid new_element_value - outside range",
				invalidCase: "invalid_range",
			},
		}

		for _, tc := range testCases {
			t.Run(tc.name, func(t *testing.T) {
				params := BuildTestBatchAddressAppend(26, 10, 0, nil, tc.invalidCase)
				circuit := createAddressCircuit(params)
				witness := createAddressWitness(params)

				err := test.IsSolved(circuit, witness, ecc.BN254.ScalarField())
				assert.Error(err)
			})
		}
	})
}

func createAddressCircuit(params *BatchAddressTreeAppendParameters) *BatchAddressTreeAppendCircuit {
	if params == nil {
		panic("params cannot be nil")
	}

	fmt.Printf("Creating circuit with BatchSize: %d, TreeHeight: %d\n", params.BatchSize, params.TreeHeight)
	fmt.Printf("LowElements len: %d, NewElements len: %d\n", len(params.LowElements), len(params.NewElements))
	fmt.Printf("LowElementProofs len: %d, NewElementProofs len: %d\n", len(params.LowElementProofs), len(params.NewElementProofs))

	for i := range params.LowElementProofs {
		fmt.Printf("LowElementProof[%d] len: %d\n", i, len(params.LowElementProofs[i]))
	}

	for i := range params.NewElementProofs {
		fmt.Printf("NewElementProof[%d] len: %d\n", i, len(params.NewElementProofs[i]))
	}
	circuit := &BatchAddressTreeAppendCircuit{
		PublicInputHash:     frontend.Variable(0),
		OldSubTreeHashChain: frontend.Variable(0),
		NewSubTreeHashChain: frontend.Variable(0),
		NewRoot:             frontend.Variable(0),
		HashchainHash:       frontend.Variable(0),
		StartIndex:          frontend.Variable(0),

		LowElementValues:      make([]frontend.Variable, params.BatchSize),
		LowElementNextValues:  make([]frontend.Variable, params.BatchSize),
		LowElementNextIndices: make([]frontend.Variable, params.BatchSize),
		LowElementProofs:      make([][]frontend.Variable, params.BatchSize),
		NewElementProofs:      make([][]frontend.Variable, params.BatchSize),
		LowElementPathIndices: make([]frontend.Variable, params.BatchSize),

		NewElementValues: make([]frontend.Variable, params.BatchSize),
		Subtrees:         make([]frontend.Variable, params.TreeHeight),

		BatchSize:  params.BatchSize,
		TreeHeight: params.TreeHeight,
	}
	fmt.Printf("initialize proofs for BatchSize: %d\n", params.BatchSize)
	for i := uint32(0); i < params.BatchSize; i++ {
		fmt.Printf("Creating proofs for element %d\n", i)

		fmt.Printf("LowElementProofs[%d] len: %d\n", i, len(params.LowElementProofs[i]))
		fmt.Printf("NewElementProofs[%d] len: %d\n", i, len(params.NewElementProofs[i]))

		circuit.LowElementProofs[i] = make([]frontend.Variable, params.TreeHeight)
		circuit.NewElementProofs[i] = make([]frontend.Variable, params.TreeHeight)

		for j := uint32(0); j < params.TreeHeight; j++ {
			circuit.LowElementProofs[i][j] = frontend.Variable(0)
			circuit.NewElementProofs[i][j] = frontend.Variable(0)
		}
	}

	return circuit
}

func createAddressWitness(params *BatchAddressTreeAppendParameters) *BatchAddressTreeAppendCircuit {
	witness := createAddressCircuit(params)
	mask := new(big.Int).Sub(new(big.Int).Lsh(big.NewInt(1), 248), big.NewInt(1))
	fmt.Printf("\nMask bit length: %d\n", mask.BitLen())

	fmt.Printf("NewRoot from params bitLen: %d, value: %s\n", params.NewRoot.BitLen(), params.NewRoot.String())
	maskedRoot := new(big.Int).And(params.NewRoot, mask)

	fmt.Printf("Masked NewRoot bitLen: %d, value: %s\n", maskedRoot.BitLen(), maskedRoot.String())

	witness.NewRoot = frontend.Variable(maskedRoot)

	witness.PublicInputHash = frontend.Variable(params.PublicInputHash)
	witness.OldSubTreeHashChain = frontend.Variable(params.OldSubTreeHashChain)
	witness.NewSubTreeHashChain = frontend.Variable(params.NewSubTreeHashChain)
	witness.NewRoot = frontend.Variable(new(big.Int).And(params.NewRoot, mask))
	witness.HashchainHash = frontend.Variable(params.HashchainHash)
	witness.StartIndex = frontend.Variable(params.StartIndex)

	for i := uint32(0); i < params.BatchSize; i++ {
		lowValue := new(big.Int).And(params.LowElements[i].Value, mask)
		nextValue := new(big.Int).And(params.LowElements[i].NextValue, mask)
		newValue := new(big.Int).And(params.NewElements[i].Value, mask)

		fmt.Printf("\nWitness element %d before assignment:\n", i)
		fmt.Printf("Low value bitLen: %d\n", lowValue.BitLen())
		fmt.Printf("Next value bitLen: %d\n", nextValue.BitLen())
		fmt.Printf("New value bitLen: %d\n", newValue.BitLen())

		witness.LowElementValues[i] = frontend.Variable(lowValue)
		witness.LowElementNextValues[i] = frontend.Variable(nextValue)
		witness.LowElementNextIndices[i] = frontend.Variable(params.LowElements[i].NextIndex)
		witness.NewElementValues[i] = frontend.Variable(newValue)
		witness.LowElementPathIndices[i] = frontend.Variable(params.LowElements[i].Index)

		for j := range params.LowElementProofs[i] {
			proofValue := new(big.Int).And(&params.LowElementProofs[i][j], mask)
			witness.LowElementProofs[i][j] = frontend.Variable(proofValue)

			newProofValue := new(big.Int).And(&params.NewElementProofs[i][j], mask)
			witness.NewElementProofs[i][j] = frontend.Variable(newProofValue)
		}

		if v, ok := witness.LowElementNextValues[i].(frontend.Variable); ok {
			if bigInt, ok := v.(*big.Int); ok {
				fmt.Printf("Witness next value after assignment bitLen: %d\n", bigInt.BitLen())
			}
		}
	}

	for i, subtree := range params.Subtrees {
		witness.Subtrees[i] = frontend.Variable(new(big.Int).And(subtree, mask))
	}

	return witness
}

func BuildTestBatchAddressAppend(
	treeHeight uint32,
	batchSize uint32,
	startIndex uint32,
	previousParams *BatchAddressTreeAppendParameters,
	invalidCase string,
) *BatchAddressTreeAppendParameters {
	mask := new(big.Int).Sub(new(big.Int).Lsh(big.NewInt(1), 248), big.NewInt(1))

	var tree *merkletree.IndexedMerkleTree
	var err error

	if previousParams != nil {
		tree = previousParams.Tree.DeepCopy()
	} else {
		tree, err = merkletree.NewIndexedMerkleTree(treeHeight)
		if err != nil {
			panic(fmt.Sprintf("Failed to create indexed merkle tree: %v", err))
		}
		err = tree.Init()
		if err != nil {
			panic(fmt.Sprintf("Failed to initialize indexed merkle tree: %v", err))
		}
	}

	maxAddr := new(big.Int).Sub(new(big.Int).Lsh(big.NewInt(1), 248), big.NewInt(1))
	fmt.Printf("maxAddr bit length: %d\n", maxAddr.BitLen())

	lowElements := make([]merkletree.IndexedElement, batchSize)
	newElements := make([]merkletree.IndexedElement, batchSize)
	lowElementProofs := make([][]big.Int, batchSize)
	newElementProofs := make([][]big.Int, batchSize)

	for i := uint32(0); i < batchSize; i++ {
		lowElements[i] = merkletree.IndexedElement{
			Value:     big.NewInt(0),
			NextValue: big.NewInt(0),
			NextIndex: 0,
			Index:     0,
		}
		newElements[i] = merkletree.IndexedElement{
			Value:     big.NewInt(0),
			NextValue: big.NewInt(0),
			NextIndex: 0,
			Index:     0,
		}
		lowElementProofs[i] = make([]big.Int, treeHeight)
		newElementProofs[i] = make([]big.Int, treeHeight)
	}

	step := new(big.Int).Div(maxAddr, big.NewInt(100))
	processedCount := uint32(0)

	for i := uint32(0); i < batchSize; i++ {
		currentIndex := startIndex + i
		currentElement := tree.IndexArray.Get(currentIndex)

		if currentElement.Value.Cmp(maxAddr) == 0 {
			continue
		}

		var newValue *big.Int
		nextElement := tree.IndexArray.Get(currentElement.NextIndex)

		if currentElement.Value.Cmp(big.NewInt(0)) == 0 {
			newValue = new(big.Int).Set(step)
		} else {
			diff := new(big.Int).Sub(nextElement.Value, currentElement.Value)
			half := new(big.Int).Div(diff, big.NewInt(2))
			newValue = new(big.Int).Add(currentElement.Value, half)
		}

		proof, err := tree.GetProof(int(currentIndex))
		if err != nil {
			panic(fmt.Sprintf("Failed to generate initial proof: %v", err))
		}
		lowElementProofs[processedCount] = proof
		newElementIndex := uint32(len(tree.IndexArray.Elements))

		err = tree.IndexArray.Append(newValue)
		if err != nil {
			panic(fmt.Sprintf("Failed to append to index array: %v", err))
		}

		lowElement := tree.IndexArray.Get(currentIndex)
		newElement := tree.IndexArray.Get(newElementIndex)

		lowLeafHash, err := merkletree.HashIndexedElement(lowElement)
		if err != nil {
			panic(fmt.Sprintf("Failed to hash low element: %v", err))
		}
		tree.Tree.Update(int(currentIndex), *lowLeafHash)

		intermediateProof, err := tree.GetProof(int(newElementIndex))
		if err != nil {
			panic(fmt.Sprintf("Failed to generate intermediate proof: %v", err))
		}
		newElementProofs[processedCount] = intermediateProof

		newLeafHash, err := merkletree.HashIndexedElement(newElement)
		if err != nil {
			panic(fmt.Sprintf("Failed to hash new element: %v", err))
		}
		tree.Tree.Update(int(newElementIndex), *newLeafHash)
		lowElements[processedCount] = *lowElement
		newElements[processedCount] = *newElement

		fmt.Printf("Element %d - newValue before masking - bitLen: %d, value: %s\n",
			i, newValue.BitLen(), newValue.String())
		newValue.And(newValue, mask)
		fmt.Printf("Element %d - newValue after masking - bitLen: %d, value: %s\n",
			i, newValue.BitLen(), newValue.String())

		fmt.Printf("\nElement %d state:\n", processedCount)
		fmt.Printf("Low element: index=%d, value=%s, next_index=%d, next_value=%s\n",
			lowElements[processedCount].Index,
			lowElements[processedCount].Value.String(),
			lowElements[processedCount].NextIndex,
			lowElements[processedCount].NextValue.String())
		fmt.Printf("New element: index=%d, value=%s, next_index=%d, next_value=%s\n",
			newElements[processedCount].Index,
			newElements[processedCount].Value.String(),
			newElements[processedCount].NextIndex,
			newElements[processedCount].NextValue.String())
		fmt.Printf("Generated proofs - original length: %d, intermediate length: %d\n",
			len(lowElementProofs[processedCount]), len(newElementProofs[processedCount]))

		if lowElements[processedCount].Value.Cmp(lowElements[processedCount].NextValue) >= 0 {
			panic(fmt.Sprintf("Invalid ordering at element %d: low value >= new value", processedCount))
		}
		if newElements[processedCount].Value.Cmp(newElements[processedCount].NextValue) >= 0 {
			panic(fmt.Sprintf("Invalid ordering at element %d: new value >= next value", processedCount))
		}

		processedCount++
	}

	newRoot := tree.Tree.Root.Value()
	oldSubtrees := tree.Tree.GetRightmostSubtrees(int(treeHeight))
	oldSubTreeHashChain := calculateHashChain(oldSubtrees, int(treeHeight))
	newSubtrees := tree.Tree.GetRightmostSubtrees(int(treeHeight))
	newSubTreeHashChain := calculateHashChain(newSubtrees, int(treeHeight))

	newLeaves := make([]*big.Int, processedCount)
	for i := uint32(0); i < processedCount; i++ {
		merkleElement := merkletree.IndexedElement{
			Value:     new(big.Int).Set(newElements[i].Value),
			NextValue: new(big.Int).Set(newElements[i].NextValue),
			NextIndex: newElements[i].NextIndex,
			Index:     newElements[i].Index,
		}

		leaf, err := merkletree.HashIndexedElement(&merkleElement)
		if err != nil {
			panic(fmt.Sprintf("Failed to hash new element: %v", err))
		}
		newLeaves[i] = leaf
	}
	hashchainHash := calculateHashChain(newLeaves, int(processedCount))

	publicInputHash := calculateHashChain([]*big.Int{
		oldSubTreeHashChain,
		newSubTreeHashChain,
		&newRoot,
		hashchainHash,
		big.NewInt(int64(startIndex)),
	}, 5)

	returnParams := &BatchAddressTreeAppendParameters{
		PublicInputHash:     publicInputHash,
		OldSubTreeHashChain: oldSubTreeHashChain,
		NewSubTreeHashChain: newSubTreeHashChain,
		NewRoot:             &newRoot,
		HashchainHash:       hashchainHash,
		StartIndex:          startIndex,
		LowElements:         lowElements[:processedCount],
		NewElements:         newElements[:processedCount],
		LowElementProofs:    lowElementProofs[:processedCount],
		NewElementProofs:    newElementProofs[:processedCount],
		Subtrees:            oldSubtrees,
		TreeHeight:          treeHeight,
		BatchSize:           processedCount,
		Tree:                tree,
	}

	fmt.Printf("Returning params - BatchSize: %d, TreeHeight: %d\n", returnParams.BatchSize, returnParams.TreeHeight)
	fmt.Printf("Proofs lengths - Low: %d, New: %d\n", len(returnParams.LowElementProofs), len(returnParams.NewElementProofs))

	return returnParams
}
func verifyBatchAddressParameters(params *BatchAddressTreeAppendParameters) error {
	fmt.Printf("\nVerifying batch address parameters:\n")
	mask := new(big.Int).Sub(new(big.Int).Lsh(big.NewInt(1), 248), big.NewInt(1))
	for i := uint32(0); i < params.BatchSize; i++ {
		lowValue := new(big.Int).And(params.LowElements[i].Value, mask)
		nextValue := new(big.Int).And(params.LowElements[i].NextValue, mask)
		newValue := new(big.Int).And(params.NewElements[i].Value, mask)
		newNextValue := new(big.Int).And(params.NewElements[i].NextValue, mask)

		if lowValue.Cmp(newValue) >= 0 {
			return fmt.Errorf("invalid ordering at index %d: low value >= new value", i)
		}
		if newValue.Cmp(newNextValue) >= 0 {
			return fmt.Errorf("invalid ordering at index %d: new value >= next value", i)
		}
		if params.LowElements[i].Value.Cmp(lowValue) != 0 ||
			params.LowElements[i].NextValue.Cmp(nextValue) != 0 ||
			params.NewElements[i].Value.Cmp(newValue) != 0 ||
			params.NewElements[i].NextValue.Cmp(newNextValue) != 0 {
			return fmt.Errorf("values at index %d were not properly masked to 248 bits", i)
		}
	}
	verifyTree, err := merkletree.NewIndexedMerkleTree(params.TreeHeight)
	if err != nil {
		return fmt.Errorf("failed to create verify tree: %v", err)
	}
	err = verifyTree.Init()
	if err != nil {
		return fmt.Errorf("failed to initialize verify tree: %v", err)
	}

	for i := uint32(0); i < params.BatchSize; i++ {
		err = verifyTree.Append(params.NewElements[i].Value)
		if err != nil {
			return fmt.Errorf("failed to append value %d: %v", i, err)
		}
	}

	rootValue := verifyTree.Tree.Root.Value()
	if rootValue.Cmp(params.NewRoot) != 0 {
		return fmt.Errorf("root mismatch")
	}

	fmt.Printf("All parameters verified successfully\n")
	return nil
}
