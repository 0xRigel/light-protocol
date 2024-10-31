package prover

import (
	"fmt"
	"light/light-prover/logging"
	"light/light-prover/prover/poseidon"
	"math/big"
	"os"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/backend/groth16"
	"github.com/consensys/gnark/constraint"
	"github.com/consensys/gnark/frontend"

	"github.com/reilabs/gnark-lean-extractor/v2/abstractor"
)

type Proof struct {
	Proof groth16.Proof
}

type ProvingSystemV1 struct {
	InclusionTreeHeight                    uint32
	InclusionNumberOfCompressedAccounts    uint32
	NonInclusionTreeHeight                 uint32
	NonInclusionNumberOfCompressedAccounts uint32
	ProvingKey                             groth16.ProvingKey
	VerifyingKey                           groth16.VerifyingKey
	ConstraintSystem                       constraint.ConstraintSystem
}

type ProvingSystemV2 struct {
	CircuitType      CircuitType
	TreeHeight       uint32
	BatchSize        uint32
	ProvingKey       groth16.ProvingKey
	VerifyingKey     groth16.VerifyingKey
	ConstraintSystem constraint.ConstraintSystem
}

type ProveParentHash struct {
	Bit     frontend.Variable
	Hash    frontend.Variable
	Sibling frontend.Variable
}

func (gadget ProveParentHash) DefineGadget(api frontend.API) interface{} {
	api.AssertIsBoolean(gadget.Bit)
	d1 := api.Select(gadget.Bit, gadget.Sibling, gadget.Hash)
	d2 := api.Select(gadget.Bit, gadget.Hash, gadget.Sibling)
	hash := abstractor.Call(api, poseidon.Poseidon2{In1: d1, In2: d2})
	return hash
}

type InclusionProof struct {
	Roots          []frontend.Variable
	Leaves         []frontend.Variable
	InPathIndices  []frontend.Variable
	InPathElements [][]frontend.Variable

	NumberOfCompressedAccounts uint32
	Height                     uint32
}

func (gadget InclusionProof) DefineGadget(api frontend.API) interface{} {
	currentHash := make([]frontend.Variable, gadget.NumberOfCompressedAccounts)
	for proofIndex := 0; proofIndex < int(gadget.NumberOfCompressedAccounts); proofIndex++ {
		hash := MerkleRootGadget{
			Hash:   gadget.Leaves[proofIndex],
			Index:  gadget.InPathIndices[proofIndex],
			Path:   gadget.InPathElements[proofIndex],
			Height: int(gadget.Height)}
		currentHash[proofIndex] = abstractor.Call(api, hash)
		api.AssertIsEqual(currentHash[proofIndex], gadget.Roots[proofIndex])
	}
	return currentHash
}

type NonInclusionProof struct {
	Roots  []frontend.Variable
	Values []frontend.Variable

	LeafLowerRangeValues  []frontend.Variable
	LeafHigherRangeValues []frontend.Variable
	NextIndices           []frontend.Variable

	InPathIndices  []frontend.Variable
	InPathElements [][]frontend.Variable

	NumberOfCompressedAccounts uint32
	Height                     uint32
}

func (gadget NonInclusionProof) DefineGadget(api frontend.API) interface{} {
	currentHash := make([]frontend.Variable, gadget.NumberOfCompressedAccounts)
	for proofIndex := 0; proofIndex < int(gadget.NumberOfCompressedAccounts); proofIndex++ {
		leaf := LeafHashGadget{
			LeafLowerRangeValue:  gadget.LeafLowerRangeValues[proofIndex],
			NextIndex:            gadget.NextIndices[proofIndex],
			LeafHigherRangeValue: gadget.LeafHigherRangeValues[proofIndex],
			Value:                gadget.Values[proofIndex]}
		currentHash[proofIndex] = abstractor.Call(api, leaf)

		hash := MerkleRootGadget{
			Hash:   currentHash[proofIndex],
			Index:  gadget.InPathIndices[proofIndex],
			Path:   gadget.InPathElements[proofIndex],
			Height: int(gadget.Height)}
		currentHash[proofIndex] = abstractor.Call(api, hash)
		api.AssertIsEqual(currentHash[proofIndex], gadget.Roots[proofIndex])
	}
	return currentHash
}

type CombinedProof struct {
	InclusionProof    InclusionProof
	NonInclusionProof NonInclusionProof
}

func (gadget CombinedProof) DefineGadget(api frontend.API) interface{} {
	abstractor.Call(api, gadget.InclusionProof)
	abstractor.Call(api, gadget.NonInclusionProof)
	return nil
}

type VerifyProof struct {
	Leaf  frontend.Variable
	Path  []frontend.Variable
	Proof []frontend.Variable
}

func (gadget VerifyProof) DefineGadget(api frontend.API) interface{} {
	currentHash := gadget.Leaf
	for i := 0; i < len(gadget.Path); i++ {
		currentHash = abstractor.Call(api, ProveParentHash{
			Bit:     gadget.Path[i],
			Hash:    currentHash,
			Sibling: gadget.Proof[i],
		})
	}
	return currentHash
}

type LeafHashGadget struct {
	LeafLowerRangeValue  frontend.Variable
	NextIndex            frontend.Variable
	LeafHigherRangeValue frontend.Variable
	Value                frontend.Variable
}

// Limit the number of bits to 248 + 1,
// since we truncate address values to 31 bytes.
func (gadget LeafHashGadget) DefineGadget(api frontend.API) interface{} {
	api.Println("LeafHashGadget", gadget.LeafLowerRangeValue, gadget.NextIndex, gadget.LeafHigherRangeValue)
	api.Println("\nLeafHashGadget inputs:\n")
	api.Println("LeafLowerRangeValue bitLen: %d\n", toBigInt(gadget.LeafLowerRangeValue).BitLen())
	api.Println("NextIndex bitLen: %d\n", toBigInt(gadget.NextIndex).BitLen())
	api.Println("LeafHigherRangeValue bitLen: %d\n", toBigInt(gadget.LeafHigherRangeValue).BitLen())
	api.Println("Value bitLen: %d\n", toBigInt(gadget.Value).BitLen())

	// Lower bound is less than value
	abstractor.CallVoid(api, AssertIsLess{A: gadget.LeafLowerRangeValue, B: gadget.Value, N: 248})
	// Value is less than upper bound
	abstractor.CallVoid(api, AssertIsLess{A: gadget.Value, B: gadget.LeafHigherRangeValue, N: 248})

	return abstractor.Call(api, poseidon.Poseidon3{In1: gadget.LeafLowerRangeValue, In2: gadget.NextIndex, In3: gadget.LeafHigherRangeValue})
}

func toBigInt(v frontend.Variable) *big.Int {
	if b, ok := v.(*big.Int); ok {
		return b
	}
	return big.NewInt(0)
}

// Assert A is less than B.
type AssertIsLess struct {
	A frontend.Variable
	B frontend.Variable
	N int
}

// To prevent overflows N (the number of bits) must not be greater than 252 + 1,
// see https://github.com/zkopru-network/zkopru/issues/116
func (gadget AssertIsLess) DefineGadget(api frontend.API) interface{} {
	// Create mask for N bits
	mask := new(big.Int).Sub(new(big.Int).Lsh(big.NewInt(1), uint(gadget.N)), big.NewInt(1))

	// Mask inputs to ensure they're within N bits
	a := frontend.Variable(new(big.Int).And(toBigInt(gadget.A), mask))
	b := frontend.Variable(new(big.Int).And(toBigInt(gadget.B), mask))

	// Add debug logging
	api.Println("AssertIsLess masked A:", a)
	api.Println("AssertIsLess masked B:", b)

	// Calculate B-A, which should be positive
	diff := api.Sub(b, a)

	// Convert difference to binary to ensure it's positive and fits in N bits
	binaryDiff := api.ToBinary(diff, gadget.N)

	// The most significant bit should be 0 (meaning positive number)
	api.AssertIsEqual(binaryDiff[gadget.N-1], 0)

	return []frontend.Variable{}
}

type MerkleRootGadget struct {
	Hash   frontend.Variable
	Index  frontend.Variable
	Path   []frontend.Variable
	Height int
}

func (gadget MerkleRootGadget) DefineGadget(api frontend.API) interface{} {
	mask := new(big.Int).Sub(new(big.Int).Lsh(big.NewInt(1), 248), big.NewInt(1))
	currentHash := frontend.Variable(new(big.Int).And(toBigInt(gadget.Hash), mask))

	api.Println("MerkleRootGadget initial hash:", currentHash)

	currentPath := api.ToBinary(gadget.Index, gadget.Height)
	for i := 0; i < gadget.Height; i++ {
		maskedSibling := frontend.Variable(new(big.Int).And(toBigInt(gadget.Path[i]), mask))
		currentHash = abstractor.Call(api, ProveParentHash{
			Bit:     currentPath[i],
			Hash:    currentHash,
			Sibling: maskedSibling,
		})
		api.Println("MerkleRootGadget hash at level", i, ":", currentHash)
	}
	return gadget.Hash
}

type MerkleRootUpdateGadget struct {
	OldRoot     frontend.Variable
	OldLeaf     frontend.Variable
	NewLeaf     frontend.Variable
	PathIndex   frontend.Variable
	MerkleProof []frontend.Variable
	Height      int
}

func (gadget MerkleRootUpdateGadget) DefineGadget(api frontend.API) interface{} {
	api.Println("MerkleRootUpdateGadget inputs:")
	api.Println("OldRoot:", gadget.OldRoot)
	api.Println("OldLeaf:", gadget.OldLeaf)
	api.Println("NewLeaf:", gadget.NewLeaf)
	api.Println("PathIndex:", gadget.PathIndex)
	oldRoot := abstractor.Call(api, MerkleRootGadget{
		Hash:   gadget.OldLeaf,
		Index:  gadget.PathIndex,
		Path:   gadget.MerkleProof,
		Height: gadget.Height,
	})
	api.AssertIsEqual(oldRoot, gadget.OldRoot)

	newRoot := abstractor.Call(api, MerkleRootGadget{
		Hash:   gadget.NewLeaf,
		Index:  gadget.PathIndex,
		Path:   gadget.MerkleProof,
		Height: gadget.Height,
	})

	api.Println("MerkleRootUpdateGadget final values:")
	api.Println("Old root:", oldRoot)
	api.Println("New root:", newRoot)

	return newRoot
}

// Trusted setup utility functions
// Taken from: https://github.com/bnb-chain/zkbnb/blob/master/common/prove/proof_keys.go#L19
func LoadProvingKey(filepath string) (pk groth16.ProvingKey, err error) {
	logging.Logger().Info().Msg("start reading proving key")
	pk = groth16.NewProvingKey(ecc.BN254)
	f, _ := os.Open(filepath)
	_, err = pk.ReadFrom(f)
	if err != nil {
		return pk, fmt.Errorf("read file error")
	}
	err = f.Close()
	if err != nil {
		return nil, err
	}
	return pk, nil
}

// Taken from: https://github.com/bnb-chain/zkbnb/blob/master/common/prove/proof_keys.go#L32
func LoadVerifyingKey(filepath string) (verifyingKey groth16.VerifyingKey, err error) {
	logging.Logger().Info().Msg("start reading verifying key")
	verifyingKey = groth16.NewVerifyingKey(ecc.BN254)
	f, _ := os.Open(filepath)
	_, err = verifyingKey.ReadFrom(f)
	if err != nil {
		return verifyingKey, fmt.Errorf("read file error")
	}
	err = f.Close()
	if err != nil {
		return nil, err
	}

	return verifyingKey, nil
}
func GetKeys(keysDir string, circuitTypes []CircuitType, isTestMode bool) []string {
	var keys []string

	if IsCircuitEnabled(circuitTypes, Inclusion) {
		keys = append(keys, keysDir+"inclusion_26_1.key")
		keys = append(keys, keysDir+"inclusion_26_2.key")
		keys = append(keys, keysDir+"inclusion_26_3.key")
		keys = append(keys, keysDir+"inclusion_26_4.key")
		keys = append(keys, keysDir+"inclusion_26_8.key")
	}
	if IsCircuitEnabled(circuitTypes, NonInclusion) {
		keys = append(keys, keysDir+"non-inclusion_26_1.key")
		keys = append(keys, keysDir+"non-inclusion_26_2.key")
	}
	if IsCircuitEnabled(circuitTypes, Combined) {
		keys = append(keys, keysDir+"combined_26_1_1.key")
		keys = append(keys, keysDir+"combined_26_1_2.key")
		keys = append(keys, keysDir+"combined_26_2_1.key")
		keys = append(keys, keysDir+"combined_26_2_2.key")
		keys = append(keys, keysDir+"combined_26_3_1.key")
		keys = append(keys, keysDir+"combined_26_3_2.key")
		keys = append(keys, keysDir+"combined_26_4_1.key")
		keys = append(keys, keysDir+"combined_26_4_2.key")
	}

	if IsCircuitEnabled(circuitTypes, BatchAppend) {
		if isTestMode {
			keys = append(keys, keysDir+"append_10_10.key")
		} else {
			keys = append(keys, keysDir+"append_26_1.key")
			keys = append(keys, keysDir+"append_26_10.key")
			keys = append(keys, keysDir+"append_26_100.key")
			keys = append(keys, keysDir+"append_26_500.key")
			keys = append(keys, keysDir+"append_26_1000.key")
		}
	}

	if IsCircuitEnabled(circuitTypes, BatchUpdate) {
		if isTestMode {
			keys = append(keys, keysDir+"update_10_10.key")
		} else {
			keys = append(keys, keysDir+"update_26_1.key")
			keys = append(keys, keysDir+"update_26_10.key")
			keys = append(keys, keysDir+"update_26_100.key")
			keys = append(keys, keysDir+"update_26_500.key")
			keys = append(keys, keysDir+"update_26_1000.key")
		}
	}

	return keys
}
