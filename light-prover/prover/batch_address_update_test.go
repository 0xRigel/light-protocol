package prover

import (
	"fmt"
	merkletree "light/light-prover/merkle-tree"
	"math/big"
	"testing"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/test"
	iden3_poseidon "github.com/iden3/go-iden3-crypto/poseidon"
)

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
	// Initialize test data arrays
	lowElementValues := make([]*big.Int, batchSize)
	lowElementNextValues := make([]*big.Int, batchSize)
	lowElementNextIndices := make([]uint32, batchSize)
	lowElementProofs := make([][]big.Int, batchSize)
	lowElementPathIndices := make([]uint32, batchSize)
	newElementValues := make([]*big.Int, batchSize)

	// First, prepare all values
	for i := uint32(0); i < batchSize; i++ {
		pathIndex := startIndex + i
		lowElementPathIndices[i] = pathIndex

		// Create values that maintain ordering
		lowElementValues[i] = new(big.Int).Mul(big.NewInt(1000), big.NewInt(int64(pathIndex+1)))
		lowElementNextIndices[i] = pathIndex + 1
		lowElementNextValues[i] = new(big.Int).Mul(big.NewInt(1000), big.NewInt(int64(pathIndex+2)))
		newElementValues[i] = new(big.Int).Add(lowElementValues[i], big.NewInt(500))

		// Apply invalid cases if requested
		switch invalidCase {
		case "invalid_tree":
			lowElementValues[i].Add(lowElementValues[i], big.NewInt(999999))
		case "invalid_range":
			if i == 0 {
				newElementValues[i] = new(big.Int).Sub(lowElementValues[i], big.NewInt(1))
			}
		case "tree_full":
			startIndex = 1 << treeHeight
		}
	}

	// Initialize base tree
	tree := merkletree.NewTree(int(treeHeight))
	if previousParams != nil {
		tree = *previousParams.Tree.DeepCopy()
	}

	// Get proofs one by one
	fmt.Printf("\nCollecting proofs:\n")
	lowElementProofs = make([][]big.Int, batchSize)

	for i := uint32(0); i < batchSize; i++ {
		lowLeaf, _ := iden3_poseidon.Hash([]*big.Int{
			lowElementValues[i],
			big.NewInt(int64(lowElementNextIndices[i])),
			lowElementNextValues[i],
		})
		proof := tree.Update(int(lowElementPathIndices[i]), *lowLeaf)
		lowElementProofs[i] = proof
	}

	initialRoot := tree.Root.Value()
	oldSubtrees := GetRightmostSubtrees(&tree, int(treeHeight))
	oldSubTreeHashChain := calculateHashChain(oldSubtrees, int(treeHeight))

	fmt.Println("Initial Root: ", initialRoot.Text(10))

	newLeaves := make([]*big.Int, batchSize)
	for i := uint32(0); i < batchSize; i++ {
		newLeaf, _ := iden3_poseidon.Hash([]*big.Int{
			newElementValues[i],
			big.NewInt(int64(lowElementNextIndices[i])),
			lowElementNextValues[i],
		})
		newLeaves[i] = newLeaf
		pathIndex := lowElementPathIndices[i]
		modifiedLowLeaf, _ := iden3_poseidon.Hash([]*big.Int{
			lowElementValues[i],
			big.NewInt(int64(lowElementNextIndices[i])),
			newElementValues[i],
		})
		tree.Update(int(pathIndex), *modifiedLowLeaf)
		tree.Update(int(pathIndex+1), *newLeaves[i])
	}

	hashchainHash := calculateHashChain(newLeaves, int(batchSize))

	newRoot := tree.Root.Value()
	fmt.Println("Root after updates: ", newRoot.Text(10))

	// Calculate final state values
	newSubtrees := GetRightmostSubtrees(&tree, int(treeHeight))

	for i := range newSubtrees {
		fmt.Printf("Test Subtree %d: %v\n", i, newSubtrees[i])
	}

	newSubTreeHashChain := calculateHashChain(newSubtrees, int(treeHeight))
	fmt.Println("Test newSubTreeHashChain: ", newSubTreeHashChain)

	// Calculate hash chain inputs in circuit order
	publicInputHash := calculateHashChain([]*big.Int{
		oldSubTreeHashChain,
		newSubTreeHashChain,
		&newRoot,
		hashchainHash,
		big.NewInt(int64(startIndex)),
	}, 5)

	return &BatchAddressTreeAppendParameters{
		PublicInputHash:       publicInputHash,
		OldSubTreeHashChain:   oldSubTreeHashChain,
		NewSubTreeHashChain:   newSubTreeHashChain,
		NewRoot:               &newRoot,
		HashchainHash:         hashchainHash,
		StartIndex:            startIndex,
		LowElementValues:      lowElementValues,
		LowElementNextValues:  lowElementNextValues,
		LowElementNextIndices: lowElementNextIndices,
		LowElementProofs:      lowElementProofs,
		LowElementPathIndices: lowElementPathIndices,
		NewElementValues:      newElementValues,
		Subtrees:              oldSubtrees,
		TreeHeight:            treeHeight,
		BatchSize:             batchSize,
		Tree:                  &tree,
	}
}

func verifyBatchAddressParameters(params *BatchAddressTreeAppendParameters) error {
	fmt.Printf("\nVerifying test data:\n")

	// Create verification tree
	verifyTree := merkletree.NewTree(int(params.TreeHeight))

	// Insert leaves and collect proofs
	for i := uint32(0); i < params.BatchSize; i++ {
		// Create low leaf
		lowLeaf, _ := iden3_poseidon.Hash([]*big.Int{
			params.LowElementValues[i],
			big.NewInt(int64(params.LowElementNextIndices[i])),
			params.LowElementNextValues[i],
		})

		// Get proof for current leaf
		proof := verifyTree.Update(int(params.LowElementPathIndices[i]), *lowLeaf)

		// Compare proofs
		if len(proof) != len(params.LowElementProofs[i]) {
			return fmt.Errorf("proof length mismatch for element %d", i)
		}

		for j := range proof {
			if proof[j].Cmp(&params.LowElementProofs[i][j]) != 0 {
				return fmt.Errorf("proof mismatch for element %d at level %d", i, j)
			}
		}
	}

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

	// Assign witness values
	witness.PublicInputHash = frontend.Variable(params.PublicInputHash)
	witness.OldSubTreeHashChain = frontend.Variable(params.OldSubTreeHashChain)
	witness.NewSubTreeHashChain = frontend.Variable(params.NewSubTreeHashChain)
	witness.NewRoot = frontend.Variable(params.NewRoot)
	witness.HashchainHash = frontend.Variable(params.HashchainHash)
	witness.StartIndex = frontend.Variable(params.StartIndex)

	for i := range witness.LowElementValues {
		witness.LowElementValues[i] = frontend.Variable(params.LowElementValues[i])
		witness.LowElementNextValues[i] = frontend.Variable(params.LowElementNextValues[i])
		witness.LowElementNextIndices[i] = frontend.Variable(params.LowElementNextIndices[i])
		witness.LowElementPathIndices[i] = frontend.Variable(params.LowElementPathIndices[i])
		witness.NewElementValues[i] = frontend.Variable(params.NewElementValues[i])

		for j := range params.LowElementProofs[i] {
			witness.LowElementProofs[i][j] = frontend.Variable(params.LowElementProofs[i][j])
		}
	}

	for i, subtree := range params.Subtrees {
		witness.Subtrees[i] = frontend.Variable(subtree)
	}

	return witness
}
