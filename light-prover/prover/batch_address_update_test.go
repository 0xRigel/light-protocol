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

// Add test for value ordering
func TestValueOrdering(t *testing.T) {
	t.Run("Test value ordering", func(t *testing.T) {
		low, new, next := generateOrderedValues(0, 5)

		for i := range low {
			if low[i].Cmp(new[i]) >= 0 {
				t.Errorf("Element %d: low value >= new value", i)
			}
			if new[i].Cmp(next[i]) >= 0 {
				t.Errorf("Element %d: new value >= next value", i)
			}
		}
	})
}

// Add test for chain linking
func TestChainLinking(t *testing.T) {
	t.Run("Test chain linking", func(t *testing.T) {
		params := BuildTestBatchAddressTreeAppend(10, 3, 0, nil, "")

		for i := uint32(0); i < params.BatchSize-1; i++ {
			// Verify each element points to the next one correctly
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

	params := BuildTestBatchAddressTreeAppend(2, 2, 0, nil, "")
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

	params := BuildTestBatchAddressTreeAppend(26, 10, 0, nil, "")
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
			params := BuildTestBatchAddressTreeAppend(26, 10, 0, nil, "")
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

				newParams := BuildTestBatchAddressTreeAppend(
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
				params := BuildTestBatchAddressTreeAppend(26, 10, 0, nil, tc.invalidCase)
				circuit := createAddressCircuit(params)
				witness := createAddressWitness(params)

				err := test.IsSolved(circuit, witness, ecc.BN254.ScalarField())
				assert.Error(err)
			})
		}
	})
}

func BuildTestBatchAddressTreeAppend(
	treeHeight uint32,
	batchSize uint32,
	startIndex uint32,
	previousParams *BatchAddressTreeAppendParameters,
	invalidCase string,
) *BatchAddressTreeAppendParameters {
	// Initialize tree state
	var tree merkletree.PoseidonTree
	if previousParams != nil {
		tree = *previousParams.Tree.DeepCopy()
	} else {
		tree = merkletree.NewTree(int(treeHeight))
	}

	// Initialize elements
	lowElements := make([]IndexedElement, batchSize)
	newElements := make([]IndexedElement, batchSize)
	proofs := make([][]big.Int, batchSize)

	// Generate ordered values
	lowValues, newValues, nextValues := generateOrderedValues(startIndex, batchSize)

	fmt.Printf("\nGenerating test data for indexed Merkle tree batch append:\n")

	// Process each batch element
	for i := uint32(0); i < batchSize; i++ {
		// Set up low element with truncated values
		lowElements[i] = IndexedElement{
			Value:     truncateTo31Bytes(lowValues[i]),
			NextValue: truncateTo31Bytes(newValues[i]), // Points to new element
			NextIndex: startIndex + i + 1,              // Index where new element will go
			Index:     startIndex + i,                  // Current position
		}

		// Set up new element with truncated values
		newElements[i] = IndexedElement{
			Value:     truncateTo31Bytes(newValues[i]),
			NextValue: truncateTo31Bytes(nextValues[i]),
			NextIndex: lowElements[i].NextIndex + 1,
			Index:     lowElements[i].NextIndex,
		}
		fmt.Printf("\nProcessing element %d:\n", i)
		fmt.Printf("Low element: index=%d, value=%s (bits=%d), next_index=%d, next_value=%s (bits=%d)\n",
			lowElements[i].Index,
			lowElements[i].Value.String(),
			lowElements[i].Value.BitLen(),
			lowElements[i].NextIndex,
			lowElements[i].NextValue.String(),
			lowElements[i].NextValue.BitLen(),
		)

		// Create and verify leaves with truncated values
		newLeaf, err := hashIndexedElement(&newElements[i])
		if err != nil {
			panic(err)
		}
		tree.Update(int(newElements[i].Index), *newLeaf)

		lowLeaf, err := hashIndexedElement(&lowElements[i])
		if err != nil {
			panic(err)
		}
		proofs[i] = tree.Update(int(lowElements[i].Index), *lowLeaf)
	}

	// Calculate tree state values
	newRoot := tree.Root.Value()
	oldSubtrees := tree.GetRightmostSubtrees(int(treeHeight))
	oldSubTreeHashChain := calculateHashChain(oldSubtrees, int(treeHeight))
	newSubtrees := tree.GetRightmostSubtrees(int(treeHeight))
	newSubTreeHashChain := calculateHashChain(newSubtrees, int(treeHeight))

	// Calculate hash chain for new leaves
	newLeaves := make([]*big.Int, batchSize)
	for i := uint32(0); i < batchSize; i++ {
		leaf, err := hashIndexedElement(&newElements[i])
		if err != nil {
			panic(err)
		}
		newLeaves[i] = leaf
	}
	hashchainHash := calculateHashChain(newLeaves, int(batchSize))

	// Calculate public input hash
	publicInputHash := calculateHashChain([]*big.Int{
		oldSubTreeHashChain,
		newSubTreeHashChain,
		&newRoot,
		hashchainHash,
		big.NewInt(int64(startIndex)),
	}, 5)

	return &BatchAddressTreeAppendParameters{
		PublicInputHash:     publicInputHash,
		OldSubTreeHashChain: oldSubTreeHashChain,
		NewSubTreeHashChain: newSubTreeHashChain,
		NewRoot:             &newRoot,
		HashchainHash:       hashchainHash,
		StartIndex:          startIndex,
		LowElements:         lowElements,
		NewElements:         newElements,
		LowElementProofs:    proofs,
		Subtrees:            oldSubtrees,
		TreeHeight:          treeHeight,
		BatchSize:           batchSize,
		Tree:                &tree,
	}
}
func generateOrderedValues(startIndex uint32, batchSize uint32) (
	[]*big.Int, // lowValues
	[]*big.Int, // newValues
	[]*big.Int, // nextValues
) {
	lowValues := make([]*big.Int, batchSize)
	newValues := make([]*big.Int, batchSize)
	nextValues := make([]*big.Int, batchSize)

	// Debug max value
	maxValue := new(big.Int).Sub(
		new(big.Int).Lsh(big.NewInt(1), 248),
		big.NewInt(1),
	)

	fmt.Printf("\nValue generation debug:\n")
	fmt.Printf("Max value (bits): %d\n", maxValue.BitLen())
	fmt.Printf("Max value: %s\n", maxValue.String())

	increment := new(big.Int).Div(maxValue, big.NewInt(int64(batchSize*30)))
	fmt.Printf("Increment (bits): %d\n", increment.BitLen())
	fmt.Printf("Increment: %s\n", increment.String())

	for i := uint32(0); i < batchSize; i++ {
		base := new(big.Int).Mul(
			increment,
			big.NewInt(int64(i*10)),
		)
		fmt.Printf("\nElement %d:\n", i)
		fmt.Printf("Base before truncate (bits): %d\n", base.BitLen())

		lowValues[i] = truncateTo31Bytes(base)
		fmt.Printf("Low value after truncate (bits): %d\n", lowValues[i].BitLen())

		newBase := new(big.Int).Add(
			base,
			new(big.Int).Mul(increment, big.NewInt(3)),
		)
		fmt.Printf("New value before truncate (bits): %d\n", newBase.BitLen())
		newValues[i] = truncateTo31Bytes(newBase)
		fmt.Printf("New value after truncate (bits): %d\n", newValues[i].BitLen())

		nextBase := new(big.Int).Add(
			base,
			new(big.Int).Mul(increment, big.NewInt(7)),
		)
		fmt.Printf("Next value before truncate (bits): %d\n", nextBase.BitLen())
		nextValues[i] = truncateTo31Bytes(nextBase)
		fmt.Printf("Next value after truncate (bits): %d\n", nextValues[i].BitLen())

		if lowValues[i].BitLen() > 248 || newValues[i].BitLen() > 248 || nextValues[i].BitLen() > 248 {
			panic(fmt.Sprintf("Truncation failed at element %d: low=%d new=%d next=%d bits",
				i, lowValues[i].BitLen(), newValues[i].BitLen(), nextValues[i].BitLen()))
		}

		fmt.Printf("Final values for element %d:\n", i)
		fmt.Printf("Low:  %s\n", lowValues[i].String())
		fmt.Printf("New:  %s\n", newValues[i].String())
		fmt.Printf("Next: %s\n", nextValues[i].String())
	}

	return lowValues, newValues, nextValues
}

func truncateTo31Bytes(value *big.Int) *big.Int {
	mask := new(big.Int).Sub(
		new(big.Int).Lsh(big.NewInt(1), 248),
		big.NewInt(1),
	)

	beforeBits := value.BitLen()
	result := new(big.Int).And(value, mask)
	afterBits := result.BitLen()

	if beforeBits > 248 {
		fmt.Printf("Truncated value from %d to %d bits\n", beforeBits, afterBits)
	}

	return result
}

func verifyBatchAddressParameters(params *BatchAddressTreeAppendParameters) error {
	fmt.Printf("\nVerifying indexed Merkle tree parameters:\n")

	// Verify values are properly truncated
	for i := uint32(0); i < params.BatchSize; i++ {
		// Check all values are within 31 bytes
		if params.LowElements[i].Value.BitLen() > 248 {
			return fmt.Errorf("low value at index %d exceeds 31 bytes: %d bits",
				i, params.LowElements[i].Value.BitLen())
		}
		if params.NewElements[i].Value.BitLen() > 248 {
			return fmt.Errorf("new value at index %d exceeds 31 bytes: %d bits",
				i, params.NewElements[i].Value.BitLen())
		}
		if params.LowElements[i].NextValue.BitLen() > 248 {
			return fmt.Errorf("next value at index %d exceeds 31 bytes: %d bits",
				i, params.LowElements[i].NextValue.BitLen())
		}

		if params.LowElements[i].Value.Cmp(params.NewElements[i].Value) >= 0 {
			return fmt.Errorf("invalid ordering at index %d: low >= new", i)
		}

		if i > 1 && params.NewElements[i].Value.Cmp(params.LowElements[i].NextValue) >= 0 {
			return fmt.Errorf("invalid ordering at index %d: new >= next", i)
		}
	}

	// Verify tree state
	verifyTree := merkletree.NewTree(int(params.TreeHeight))

	for i := uint32(0); i < params.BatchSize; i++ {
		// Verify value ordering
		if params.LowElements[i].Value.Cmp(params.NewElements[i].Value) >= 0 {
			return fmt.Errorf("invalid value ordering at index %d", i)
		}

		// Insert new element
		newLeaf, err := hashIndexedElement(&params.NewElements[i])
		if err != nil {
			return fmt.Errorf("failed to hash new element: %v", err)
		}
		verifyTree.Update(int(params.NewElements[i].Index), *newLeaf)

		// Update and verify low element
		lowLeaf, err := hashIndexedElement(&params.LowElements[i])
		if err != nil {
			return fmt.Errorf("failed to hash low element: %v", err)
		}

		proof := verifyTree.Update(int(params.LowElements[i].Index), *lowLeaf)

		// Verify proof matches
		if len(proof) != len(params.LowElementProofs[i]) {
			return fmt.Errorf("proof length mismatch for element %d", i)
		}

		for j := range proof {
			if proof[j].Cmp(&params.LowElementProofs[i][j]) != 0 {
				return fmt.Errorf("proof mismatch for element %d at level %d", i, j)
			}
		}
	}

	fmt.Printf("All parameters verified successfully\n")
	return nil
}

func createAddressCircuit(params *BatchAddressTreeAppendParameters) *BatchAddressTreeAppendCircuit {
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
		LowElementPathIndices: make([]frontend.Variable, params.BatchSize),

		NewElementValues: make([]frontend.Variable, params.BatchSize),
		Subtrees:         make([]frontend.Variable, params.TreeHeight),

		BatchSize:  params.BatchSize,
		TreeHeight: params.TreeHeight,
	}

	// Initialize proofs array
	for i := range circuit.LowElementValues {
		circuit.LowElementProofs[i] = make([]frontend.Variable, params.TreeHeight)
		for j := range circuit.LowElementProofs[i] {
			circuit.LowElementProofs[i][j] = frontend.Variable(0)
		}
	}

	return circuit
}

func createAddressWitness(params *BatchAddressTreeAppendParameters) *BatchAddressTreeAppendCircuit {
	witness := createAddressCircuit(params)

	// Public inputs
	witness.PublicInputHash = frontend.Variable(params.PublicInputHash)
	witness.OldSubTreeHashChain = frontend.Variable(params.OldSubTreeHashChain)
	witness.NewSubTreeHashChain = frontend.Variable(params.NewSubTreeHashChain)
	witness.NewRoot = frontend.Variable(params.NewRoot)
	witness.HashchainHash = frontend.Variable(params.HashchainHash)
	witness.StartIndex = frontend.Variable(params.StartIndex)

	// Convert IndexedElements to circuit inputs
	for i := uint32(0); i < params.BatchSize; i++ {
		fmt.Printf("\nElement %d values going into circuit:\n", i)
		fmt.Printf("Low value bits: %d\n", params.LowElements[i].Value.BitLen())
		fmt.Printf("Next value bits: %d\n", params.LowElements[i].NextValue.BitLen())
		fmt.Printf("Next index: %d\n", params.LowElements[i].NextIndex)
		fmt.Printf("New value bits: %d\n", params.NewElements[i].Value.BitLen())

		// Low element data
		witness.LowElementValues[i] = frontend.Variable(params.LowElements[i].Value)
		witness.LowElementNextValues[i] = frontend.Variable(params.LowElements[i].NextValue)
		witness.LowElementNextIndices[i] = frontend.Variable(params.LowElements[i].NextIndex)
		witness.LowElementPathIndices[i] = frontend.Variable(params.LowElements[i].Index)

		// New element value
		witness.NewElementValues[i] = frontend.Variable(params.NewElements[i].Value)

		// Proofs
		for j := range params.LowElementProofs[i] {
			witness.LowElementProofs[i][j] = frontend.Variable(params.LowElementProofs[i][j])
		}

		// Debug hash inputs
		fmt.Printf("Leaf hash inputs for element %d:\n", i)
		fmt.Printf("Low: %s\n", params.LowElements[i].Value.String())
		fmt.Printf("Index: %d\n", params.LowElements[i].NextIndex)
		fmt.Printf("Next: %s\n", params.LowElements[i].NextValue.String())
	}

	// Subtrees
	for i, subtree := range params.Subtrees {
		witness.Subtrees[i] = frontend.Variable(subtree)
	}

	return witness
}
