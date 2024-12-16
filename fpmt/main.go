// Copyright 2024 Alberto Pedrouzo Ulloa
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package main

// Import necessary packages for cryptographic operations and utilities.
import (
	"log"
	"math"
	"os"
	"strconv"
	"sync"
	"time"

	"github.com/tuneinsight/lattigo/v3/bfv"
	"github.com/tuneinsight/lattigo/v3/dbfv"
	"github.com/tuneinsight/lattigo/v3/drlwe"
	"github.com/tuneinsight/lattigo/v3/rlwe"
	"github.com/tuneinsight/lattigo/v3/utils"
)

// check function to handle errors by panicking if error occurs.
func check(err error) {
	if err != nil {
		panic(err)
	}
}

// runTimed measures the execution time of a function.
func runTimed(f func()) time.Duration {
	start := time.Now()
	f()
	return time.Since(start)
}

// runTimedParty measures execution time per party and divides by the number of parties (N).
func runTimedParty(f func(), N int) time.Duration {
	start := time.Now()
	f()
	return time.Duration(time.Since(start).Nanoseconds() / int64(N))
}

// party struct stores data and cryptographic keys for a party in the protocol.
type party struct {
	sk         *rlwe.SecretKey // Secret key for decryption operations
	rlkEphemSk *rlwe.SecretKey // Ephemeral secret key for key rotation

	ckgShare    *drlwe.CKGShare    // Share for key generation protocol
	rkgShareOne *drlwe.RKGShare    // Share for relinearization key generation
	rkgShareTwo *drlwe.RKGShare    // Share for relinearization key generation
	rtgShare    *drlwe.RTGShare    // Share for key rotation protocol
	pcksShare   []*drlwe.PCKSShare // Share for public key switching protocol

	input  [][]uint64 // Fingerprint data
	NumRow int        // NumCol real: Number of rows in the fingerprint data
	NumCol int        // NumRow real: Number of columns in the fingerprint data
}

// multTask struct holds data related to a multiplication task (homomorphic encryption).
type multTask struct {
	wg              *sync.WaitGroup
	op1             [][]*bfv.Ciphertext // First operand for multiplication (encrypted)
	op2             [][]*bfv.Ciphertext // Second operand for multiplication (encrypted)
	res             *bfv.Ciphertext     // Result of encrypted dot product in all coefficients
	elapsedmultTask time.Duration       // Elapsed time for multiplication task
}

// Below are global variables that track the time spent on each phase of the protocol.
// These variables store the elapsed times for different parts of the cryptographic protocol, which helps in performance analysis and optimization.
var elapsedEncryptParty time.Duration
var elapsedEncryptCloud time.Duration
var elapsedCKGCloud time.Duration
var elapsedCKGParty time.Duration
var elapsedRKGCloud time.Duration
var elapsedRKGParty time.Duration
var elapsedRTGCloud time.Duration
var elapsedRTGParty time.Duration
var elapsedPCKSCloud time.Duration
var elapsedPCKSParty time.Duration
var elapsedEvalCloudCPU time.Duration
var elapsedEvalCloud time.Duration
var elapsedEvalParty time.Duration
var elapsedDecCloud time.Duration
var elapsedDecParty time.Duration

//--------------------------------------------------------------------------------------------------------------------------------------------------
// Example execution: N parties results in N - 1 dot products between the fingerprint of the first party (P[0].input) and the fingerprints of the other parties.
// Example for a fingerprint of size 1024 x 1024, 64 parties, and 1 Goroutine (default PN13QP218):
// go run ./fpmt 64 1 256 4096
//--------------------------------------------------------------------------------------------------------------------------------------------------

func main() {

	//-------------------------------------------------------------------------------------------------------------------------
	// For more details about the camera attribution framework, refer to the following paper:
	// - "Secure Collaborative Camera Attribution" (https://dl.acm.org/doi/abs/10.1145/3528580.3532993)
	// - Conference page: https://www.fvv.um.si/eicc2022/
	//-------------------------------------------------------------------------------------------------------------------------

	l := log.New(os.Stderr, "", 0)

	//-------------------------------------------------------------------------------------------------------------------------
	// Command-line arguments:
	// arg1: Number of parties (N parties = 1 query fingerprint + N - 1 fingerprints to match).
	// arg2: Number of Go routines.
	// arg3: Number of rows in each fingerprint.
	// arg4: Number of columns in each fingerprint.
	//-------------------------------------------------------------------------------------------------------------------------

	// Set default number of parties (N). It can be any number.
	N := 64 //Example poster

	// Parse the number of parties from command-line arguments if provided.
	var err error
	if len(os.Args[1:]) >= 1 {
		N, err = strconv.Atoi(os.Args[1])
		check(err)
	}

	// Default number of Go routines.
	NGoRoutine := 1
	if len(os.Args[1:]) >= 2 {
		NGoRoutine, err = strconv.Atoi(os.Args[2])
		check(err)
	}

	// Default number of rows in each fingerprint.
	OrNumRow := 128 //Example poster => 1024*1024 = 128*8192.
	if len(os.Args[1:]) >= 3 {
		OrNumRow, err = strconv.Atoi(os.Args[3])
		check(err)
	}

	// Default number of columns in each fingerprint.
	OrNumCol := 8192 //Example poster => 1024*1024 = 128*8192.
	if len(os.Args[1:]) >= 4 {
		OrNumCol, err = strconv.Atoi(os.Args[4])
		check(err)
	}

	//-------------------------------------------------------------------------------------------------------------------------
	// Set the encryption parameters (default: PN13QP218).
	// Adjust T (plaintext modulus) to a Proth prime (3 * 2^30 + 1) for the encryption scheme.
	//-------------------------------------------------------------------------------------------------------------------------

	paramsDef := bfv.PN13QP218                             // Default parameters for encryption.
	paramsDef.T = 3221225473                               // Proth prime value (3 * 2^30 + 1), a 32-bit prime.
	params, err := bfv.NewParametersFromLiteral(paramsDef) // Create encryption parameters from the literal definition.
	if err != nil {
		panic(err)
	}

	// Initialize a pseudo-random number generator (PRNG) with a key.
	crs, err := utils.NewKeyedPRNG([]byte{'f', 'e', 'l', 'd', 's', 'p', 'a', 'r'})
	if err != nil {
		panic(err)
	}

	// Initialize the encoder for the encryption scheme with the provided parameters.
	encoder := bfv.NewEncoder(params)

	// Generate target private and public keys used to decrypt the final result.
	tsk, tpk := bfv.NewKeyGenerator(params).GenKeyPair()

	//-------------------------------------------------------------------------------------------------------------------------
	// Create each party and allocate memory for the cryptographic shares required by the protocol.
	// Initialize the list of parties (P) based on the number of parties (N).
	// Print initialization information for the parties.
	//-------------------------------------------------------------------------------------------------------------------------
	P := genparties(params, N)
	l.Println("> Initialization of Parties")
	l.Printf("Num parties: %d, First party will receive %d encrypted scores\n", len(P), len(P)-1)

	// Inputs & expected result
	expRes := genInputs(params, P, OrNumRow, OrNumCol, 0xffffffffffffffff)
	l.Printf("> Input generation\n \tNum parties: %d \n\tExpected Results: NumRow %d, NumCol %d\n", len(P), len(expRes), len(expRes[0]))
	l.Printf("\tSize Inputs per Party: (%d, %d) uint64\n", len(P[0].input), len(P[0].input[0]))

	//-------------------------------------------------------------------------------------------------------------------------
	// Phase 1: Collective Public Key Generation
	// Generate the collective public key (PK) shared by all parties.
	pk := ckgphase(params, crs, P)

	// Phase 2: Collective Relinearization Key Generation
	// Generate the collective relinearization key (RLK) to be applied after multiplication (used only for matching).
	rlk := rkgphase(params, crs, P)

	// Phase 3: Collective Rotation Key Generation
	// Generate the collective rotation keys (RTK) for key rotation operations.
	rtk := rtkphase(params, crs, P)

	l.Printf("\tSetup done (cloud: %s, party: %s)\n",
		elapsedRKGCloud+elapsedCKGCloud+elapsedRTGCloud, elapsedRKGParty+elapsedCKGParty+elapsedRTGParty)

	//-------------------------------------------------------------------------------------------------------------------------
	// Encryption Phase:
	// Encrypt the inputs for each party using the collective public key and the encoder.
	encInputs := encPhase(params, P, pk, encoder)
	l.Printf("\tSize encInputs: (%d, %d, %d) ciphertexts\n", len(encInputs), len(encInputs[0]), len(encInputs[0][0]))

	//-------------------------------------------------------------------------------------------------------------------------
	// Evaluation Phase:
	// Perform the encrypted computations (evaluations) using the encrypted inputs, relinearization key, and rotation keys.
	encRes := evalPhase(params, NGoRoutine, encInputs, rlk, rtk)

	//-------------------------------------------------------------------------------------------------------------------------
	// Public Key Switching Phase:
	// Switch the public key for the encrypted results.
	encOut := pcksPhase(params, tpk, encRes, P)

	//-------------------------------------------------------------------------------------------------------------------------
	// Decrypt Phase:
	// Decrypt the result using the target secret key (tsk) and store the decrypted results in 'ptres'.
	// Measure the time taken for decryption by the party.
	//-------------------------------------------------------------------------------------------------------------------------
	l.Println("> Decrypt Phase")
	decryptor := bfv.NewDecryptor(params, tsk) // Initialize the decryptor with the target secret key.

	ptres := make([]*bfv.Plaintext, len(encOut)) // Create a slice to hold decrypted plaintext results.
	for i := range encOut {
		ptres[i] = bfv.NewPlaintext(params) // Allocate memory for each plaintext result.
	}

	// Run the decryption and measure the time it takes for the party to decrypt.
	elapsedDecParty = runTimed(func() {
		for i := range encOut {
			decryptor.Decrypt(encOut[i], ptres[i]) // Decrypt each ciphertext into the corresponding plaintext.
		}
	})

	elapsedDecCloud = time.Duration(0) // No decryption time measured for the cloud (handled only by the parties).
	l.Printf("\tdone (cloud: %s, party: %s)\n", elapsedDecCloud, elapsedDecParty)

	//-------------------------------------------------------------------------------------------------------------------------
	// Result Processing:
	// Print out the number of matchings computed (i.e., the number of ciphertexts decrypted).
	// Check the correctness of the decrypted results against the expected results.
	//-------------------------------------------------------------------------------------------------------------------------
	l.Println("> Result:")
	l.Printf("\t Number of matchings computed: %d ciphertexts\n", len(encOut))

	// Initialize the result matrix (res) with the same dimensions as the expected result (expRes).
	res := make([][]uint64, len(expRes))
	for i := range expRes {
		res[i] = make([]uint64, len(expRes[i])) // Allocate space for each result.
	}

	// Decode the decrypted ciphertexts into the result matrix (res).
	for i := range ptres {
		partialRes := encoder.DecodeUintNew(ptres[i]) // Decode the plaintext into uint64 values.
		for j := range partialRes {
			res[i][j] = partialRes[j] // Store the decoded result.
		}
	}

	// Prepare the final result and expected result arrays (without the first party's data).
	result := make([]uint64, N-1)
	expectedresult := make([]uint64, N-1)
	for i := 0; i < N-1; i++ {
		result[i] = res[i][0]            // Collect the first column (matching scores) from the results.
		expectedresult[i] = expRes[i][0] // Collect the expected scores from the first column.
	}

	// Print the result dimensions and scores.
	l.Printf("\t Size Res.: Row %d x Col %d\n", len(res), len(res[0]))
	l.Printf("\t Scores: \n\t%v\n", result)
	l.Printf("\t Size Exp. Res.: Row %d x Col %d\n", len(expRes), len(expRes[0]))
	l.Printf("\t Exp. Scores: \n\t%v\n", expectedresult)

	//-------------------------------------------------------------------------------------------------------------------------
	// Result Validation:
	// Compare the decrypted result with the expected result and log any discrepancies.
	//-------------------------------------------------------------------------------------------------------------------------
	for i := range expRes {
		for j := range expRes[i] {
			if expRes[i][j] != res[i][j] { // If the results don't match, log the first discrepancy.
				l.Printf("\tincorrect\n first error in position [%d][%d]\n", i, j)
				l.Printf("> Finished (total cloud: %s, total party: %s)\n", elapsedCKGCloud+elapsedRKGCloud+elapsedEncryptCloud+elapsedEvalCloud+elapsedPCKSCloud, elapsedCKGParty+elapsedRKGParty+elapsedEncryptParty+elapsedEvalParty+elapsedPCKSParty+elapsedDecParty)
				return
			}
		}
	}
	l.Println("\tcorrect") // If all results match, log that the results are correct.
	l.Printf("> Finished (total cloud: %s, total party: %s)\n", elapsedCKGCloud+elapsedRKGCloud+elapsedRTGCloud+elapsedEncryptCloud+elapsedEvalCloud+elapsedPCKSCloud, elapsedCKGParty+elapsedRKGParty+elapsedRTGParty+elapsedEncryptParty+elapsedEvalParty+elapsedPCKSParty+elapsedDecParty)

}

// Generates the individual secret key for each forensic party P[i]
// This function creates and initializes each party with its own secret key and allocates memory for the shares required by the protocols.
func genparties(params bfv.Parameters, N int) []*party { //genSKparties

	// Create a slice of parties with the size N (number of parties)
	P := make([]*party, N)

	// Loop over each party and initialize it
	for i := range P {
		pi := &party{} // Create a new instance of a party

		// Generate a secret key for each party using the parameters
		pi.sk = bfv.NewKeyGenerator(params).GenSecretKey()

		// Assign the initialized party to the slice P
		P[i] = pi
	}

	// Return the slice of parties
	return P
}

// Generates the input values (fingerprints) for each party and computes the expected results for fingerprint matching, where each party's input is randomly generated based on the parameters.
func genInputs(params bfv.Parameters, P []*party, OrNumRow int, OrNumCol int, BoundInputs uint64) (expRes [][]uint64) {

	// Loop through each party in the list P to generate input data
	for _, pi := range P {

		// Initialize the input matrix for each party with the number of rows specified by OrNumRow
		pi.input = make([][]uint64, OrNumRow)

		// Set the number of rows for the party
		for i := range pi.input {
			pi.NumRow = OrNumRow

			// Determine the number of columns for the input based on the fingerprint size and encryption parameters
			if params.N() >= OrNumCol { // If the degree of the polynomial is greater than or equal to the width of the fingerprint
				pi.NumCol = params.N()
			} else { // If the degree is smaller, make NumCol a multiple of the degree large enough
				// The number of columns is chosen as the smallest power of two greater than OrNumCol
				pi.NumCol = int(math.Pow(2, math.Ceil(math.Log2(float64(OrNumCol)))))
			}

			// Initialize each row of the input matrix
			pi.input[i] = make([]uint64, pi.NumCol)

			// Fill in the input values for the party, using random numbers within the specified bound
			for j := range pi.input[i] {
				if j < OrNumCol {

					// Generate random values for the fingerprint, modded by the BoundInputs and encryption modulus (params.T())
					pi.input[i][j] = (utils.RandUint64() % BoundInputs) % params.T()
				} else {

					// Set values beyond the original fingerprint width to 0
					pi.input[i][j] = 0
				}
			}
		}
	}

	// Allocate memory for the expected results for all parties except the first one
	expRes = make([][]uint64, len(P)-1)
	for i := range expRes {
		// Each expected result row has the same value for all columns (initialized to the polynomial degree)
		expRes[i] = make([]uint64, params.N())
	}

	// Generate the expected results based on the fingerprint of the first party (P[0])
	for i, pi := range P[1:] { // Start from P[1] to P[len(P) - 1], comparing with P[0]
		// Dot product of the fingerprints from the first party and the current party
		for j := range pi.input {
			for k := range pi.input[j] {
				// Multiply corresponding values of the fingerprints and accumulate the result
				expRes[i][0] += (pi.input[j][k] * P[0].input[j][k]) % params.T()
				// Mod the result to stay within the encryption modulus
				expRes[i][0] %= params.T()
			}
		}
		// Repeat the same value for all columns in the expected result (each row has the same value)
		for j := 1; j < params.N(); j++ {
			expRes[i][j] = expRes[i][0]
		}
	}

	// Return the expected results
	return
}

// CKG Phase (Collective Key Generation) for generating a public key and sharing the process among multiple parties.
// This function involves the key generation process where each party generates its share, and then the cloud combines the shares to create the final public key.
func ckgphase(params bfv.Parameters, crs utils.PRNG, P []*party) *rlwe.PublicKey {

	l := log.New(os.Stderr, "", 0)

	// Log the start of the CKG Phase
	l.Println("> CKG Phase")

	// Initialize the Collective Key Generation (CKG) protocol
	ckg := dbfv.NewCKGProtocol(params) // Public Collective Key Generation protocol
	// Allocate memory for the combined CKG share (used in the aggregation step)
	ckgCombined := ckg.AllocateShare()

	// For each party, allocate space for its individual CKG share
	for _, pi := range P {
		pi.ckgShare = ckg.AllocateShare()
	}

	// Sample a common reference point (CRP) for the CKG protocol
	crp := ckg.SampleCRP(crs)

	// Generate individual CKG shares for each party (this happens in parallel for all parties)
	elapsedCKGParty = runTimedParty(func() {
		for _, pi := range P {
			// Each party generates its share using its secret key and the CRP
			ckg.GenShare(pi.sk, crp, pi.ckgShare)
		}
	}, len(P))

	// Create a new public key using the aggregated shares from all parties
	pk := bfv.NewPublicKey(params)

	// Aggregate the shares from all parties and generate the final public key
	elapsedCKGCloud = runTimed(func() {
		for _, pi := range P {
			// Aggregate each party's CKG share into the combined share
			ckg.AggregateShare(pi.ckgShare, ckgCombined, ckgCombined)
		}
		// Generate the final public key from the combined CKG share and the CRP
		ckg.GenPublicKey(ckgCombined, crp, pk)
	})

	// Log the time taken for both the party and cloud operations in the CKG phase
	l.Printf("\tdone (cloud: %s, party: %s)\n", elapsedCKGCloud, elapsedCKGParty)

	// Return the generated public key
	return pk
}

// RKG Phase (Relinearization Key Generation) for generating a relinearization key and sharing the process among multiple parties.
// This function involves a multi-phase process where each party generates shares, and the cloud aggregates the shares to create the final relinearization key.
func rkgphase(params bfv.Parameters, crs utils.PRNG, P []*party) *rlwe.RelinearizationKey {

	l := log.New(os.Stderr, "", 0)

	// Log the start of the RKG Phase
	l.Println("> RKG Phase")

	// Initialize the Relinearization Key Generation (RKG) protocol
	rkg := dbfv.NewRKGProtocol(params) // Relinearization Key Generation protocol

	// Allocate memory for two combined shares that will be used in aggregation
	_, rkgCombined1, rkgCombined2 := rkg.AllocateShare()

	// For each party, allocate memory for the shares required for RKG phase
	for _, pi := range P {
		// Each party gets its own shares: an ephemeral secret key and two shares for the RKG protocol
		pi.rlkEphemSk, pi.rkgShareOne, pi.rkgShareTwo = rkg.AllocateShare()
	}

	// Sample a common reference point (CRP) for the RKG protocol
	crp := rkg.SampleCRP(crs)

	// Generate the first round of shares for each party (this happens in parallel for all parties)
	elapsedRKGParty = runTimedParty(func() {
		for _, pi := range P {
			// Each party generates its first round of shares using its secret key and the CRP
			rkg.GenShareRoundOne(pi.sk, crp, pi.rlkEphemSk, pi.rkgShareOne)
		}
	}, len(P))

	// Aggregate the first round of shares from all parties in the cloud
	elapsedRKGCloud = runTimed(func() {
		for _, pi := range P {
			// Aggregate each party's first round share into the combined share (rkgCombined1)
			rkg.AggregateShare(pi.rkgShareOne, rkgCombined1, rkgCombined1)
		}
	})

	// Generate the second round of shares for each party
	elapsedRKGParty += runTimedParty(func() {
		for _, pi := range P {
			// Each party generates its second round of shares using its ephemeral secret key, its own secret key, and the aggregated first round share
			rkg.GenShareRoundTwo(pi.rlkEphemSk, pi.sk, rkgCombined1, pi.rkgShareTwo)
		}
	}, len(P))

	// Create a new relinearization key
	rlk := bfv.NewRelinearizationKey(params, 1)

	// Aggregate the second round of shares from all parties in the cloud and generate the final relinearization key
	elapsedRKGCloud += runTimed(func() {
		for _, pi := range P {
			// Aggregate each party's second round share into the combined share (rkgCombined2)
			rkg.AggregateShare(pi.rkgShareTwo, rkgCombined2, rkgCombined2)
		}
		// Generate the final relinearization key from the combined shares
		rkg.GenRelinearizationKey(rkgCombined1, rkgCombined2, rlk)
	})

	// Log the time taken for both the party and cloud operations in the RKG phase
	l.Printf("\tdone (cloud: %s, party: %s)\n", elapsedRKGCloud, elapsedRKGParty)

	// Return the generated relinearization key
	return rlk
}

// RTG Phase (Rotation Key Generation) for generating rotation keys that allow for homomorphic rotations (e.g., shifting elements in ciphertexts).
// This function generates shares for rotation keys across multiple parties and aggregates them in the cloud to create a final set of rotation keys.
func rtkphase(params bfv.Parameters, crs utils.PRNG, P []*party) *rlwe.RotationKeySet {

	l := log.New(os.Stderr, "", 0)

	// Log the start of the RTG Phase
	l.Println("> RTG Phase")

	// Initialize the Rotation Key Generation (RTG) protocol for generating rotation keys
	rtg := dbfv.NewRotKGProtocol(params) // Rotation key generation protocol

	// Allocate memory for the rotation key shares for each party
	for _, pi := range P {
		// Each party will have its own share for the rotation key generation
		pi.rtgShare = rtg.AllocateShare()
	}

	// Get the Galois elements for row inner sum (rotation operations)
	galEls := params.GaloisElementsForRowInnerSum()

	// Initialize the Rotation Key Set that will hold the generated keys
	rotKeySet := bfv.NewRotationKeySet(params, galEls)

	// Loop over all Galois elements (which represent different rotation operations)
	for _, galEl := range galEls {

		// Allocate memory for the combined share for the current rotation key
		rtgShareCombined := rtg.AllocateShare()

		// Sample a common reference point (CRP) for the rotation key generation
		crp := rtg.SampleCRP(crs)

		// Generate shares for each party for the current Galois element (rotation operation)
		elapsedRTGParty += runTimedParty(func() {
			for _, pi := range P {
				// Each party generates its share of the rotation key for the current Galois element
				rtg.GenShare(pi.sk, galEl, crp, pi.rtgShare)
			}
		}, len(P))

		// Aggregate the shares from all parties in the cloud and generate the rotation key for the current Galois element
		elapsedRTGCloud += runTimed(func() {
			for _, pi := range P {
				// Aggregate each party's share into the combined share (rtgShareCombined)
				rtg.AggregateShare(pi.rtgShare, rtgShareCombined, rtgShareCombined)
			}
			// Generate the final rotation key for the current Galois element and store it in the rotation key set
			rtg.GenRotationKey(rtgShareCombined, crp, rotKeySet.Keys[galEl])
		})
	}

	// Log the time taken for both the party and cloud operations in the RTG phase
	l.Printf("\tdone (cloud: %s, party %s)\n", elapsedRTGCloud, elapsedRTGParty)

	// Return the generated set of rotation keys
	return rotKeySet
}

// Encrypts the inputs for each party into ciphertexts, splitting the input images into blocks and encrypting them using the provided public key (pk) and encoder. The image size is Num_Row x Num_Col, and the input is divided into smaller blocks of size 'n' for efficient encryption.
func encPhase(params bfv.Parameters, P []*party, pk *rlwe.PublicKey, encoder bfv.Encoder) (encInputs [][][]*bfv.Ciphertext) {

	l := log.New(os.Stderr, "", 0)

	// Number of rows and columns in the encrypted input
	NumRowEncIn := P[0].NumRow

	// Number of columns for the encrypted input, divided by the polynomial degree
	NumColEncIn := int(math.Ceil(float64(P[0].NumCol) / float64(params.N())))

	// Initialize the 3D slice to hold the ciphertexts for all parties, rows, and columns
	// encInputs[i][j][k] -> Party i, Row j, Column k
	encInputs = make([][][]*bfv.Ciphertext, len(P))
	for i := range encInputs {
		encInputs[i] = make([][]*bfv.Ciphertext, NumRowEncIn)
		for j := range encInputs[i] {
			encInputs[i][j] = make([]*bfv.Ciphertext, NumColEncIn)
		}
	}

	// Initialize all ciphertexts in the encInputs array
	for i := range encInputs {
		//l.Printf("\tsize encInputs = %d x %d\n", len(encInputs[0]), len(encInputs[0][0]))
		for j := range encInputs[i] {
			for k := range encInputs[i][j] {
				// Create a new ciphertext for each entry
				encInputs[i][j][k] = bfv.NewCiphertext(params, 1)
			}
		}
	}

	// Start the encryption phase for each party
	l.Println("> Encrypt Phase")

	// Create the encryptor using the public key
	encryptor := bfv.NewEncryptor(params, pk)

	// Create a plaintext object to hold the encoded data before encryption
	pt := bfv.NewPlaintext(params)

	// Encrypt the inputs of each party into ciphertexts
	elapsedEncryptParty = runTimedParty(func() {
		for i, pi := range P {
			for j := range pi.input {

				// Encrypt each block (divided into columns) of the input
				for k := 0; k < NumColEncIn; k++ {
					// The input is divided into smaller blocks. Each block is encoded and encrypted.
					// The encoder will convert the input data into a plaintext object.
					encoder.Encode(pi.input[j][(k*params.N()):((k+1)*params.N())], pt)

					// Encrypt the plaintext using the public key and store it in encInputs
					encryptor.Encrypt(pt, encInputs[i][j][k])
				}
			}

		}
	}, len(P))

	// No cloud-side encryption (for this step)
	elapsedEncryptCloud = time.Duration(0)

	// Log the time taken for the party-side encryption process
	l.Printf("\tdone (cloud: %s, party: %s)\n", elapsedEncryptCloud, elapsedEncryptParty)

	// Return the encrypted inputs for all parties
	return
}

// This function evaluates the encrypted matching of fingerprints by performing encrypted dot products of matrices, additions, relinearizations, and inner sums, utilizing a multi-threaded approach for efficient computation.
func evalPhase(params bfv.Parameters, NGoRoutine int, encInputs [][][]*bfv.Ciphertext, rlk *rlwe.RelinearizationKey, rtk *rlwe.RotationKeySet) (encRes []*bfv.Ciphertext) {

	l := log.New(os.Stderr, "", 0)

	// Output layers for storing intermediate and final results
	// encRes is the array to hold the results for each encrypted input (excluding the first one)
	encRes = make([]*bfv.Ciphertext, len(encInputs)-1)
	for i := range encRes {
		encRes[i] = bfv.NewCiphertext(params, 1) // Initialize each result with degree 1
	}

	// Initialize the evaluator with the relinearization key and rotation key set for encrypted operations
	evaluator := bfv.NewEvaluator(params, rlwe.EvaluationKey{Rlk: rlk, Rtks: rtk})

	// Create the channel to distribute tasks among multiple goroutines
	tasks := make(chan *multTask)
	workers := &sync.WaitGroup{}
	workers.Add(NGoRoutine)

	// Spawn NGoRoutine number of goroutines to handle the evaluation tasks concurrently
	for i := 1; i <= NGoRoutine; i++ {
		go func(i int) {
			evaluator := evaluator.ShallowCopy() // Each goroutine gets its own evaluator copy

			// Create temporary storage for intermediate ciphertexts (degree 2)
			tmp := make([][]*bfv.Ciphertext, len(encInputs[0]))
			for i := range encInputs[0] {
				tmp[i] = make([]*bfv.Ciphertext, len(encInputs[0][0]))
				for j := range encInputs[0][0] {
					tmp[i][j] = bfv.NewCiphertext(params, 2) // Allocate ciphertexts of degree 2
				}
			}
			tmpAdd := bfv.NewCiphertext(params, 2) // Temporary ciphertext for additions

			for task := range tasks {
				task.elapsedmultTask = runTimed(func() {

					// Loop through the rows and columns to perform multiplication and addition
					for indRow := range task.op1 {
						for indCol := range task.op1[0] {

							// 1) Multiply corresponding ciphertexts from two input matrices (fingerprint component-wise multiplication)
							evaluator.Mul(task.op1[indRow][indCol], task.op2[indRow][indCol], tmp[indRow][indCol])

							// 2) Add the result to the cumulative sum (tmpAdd) for the current row and column
							if (indRow == 0) && (indCol == 0) {
								tmpAdd = tmp[0][0] // Initialize the first addition with the result of the first multiplication
							} else {
								evaluator.Add(tmp[indRow][indCol], tmpAdd, tmpAdd) // Add subsequent results
							}
						}
					}

					// 3) Perform relinearization (converting degree-2 ciphertexts back to degree-1 ciphertexts)
					evaluator.Relinearize(tmpAdd, task.res)

					// 4) Perform inner sum operation on the result (a form of summation operation in homomorphic encryption)
					evaluator.InnerSum(task.res, task.res)
				})
				task.wg.Done() // Mark the task as done
			}

			workers.Done() // Mark the goroutine as done
		}(i)
	}

	// Start the encrypted fingerprint matching tasks in the cloud
	taskList := make([]*multTask, 0)
	l.Println("> Eval Phase")
	elapsedEvalCloud = runTimed(func() {
		l.Printf("\tStarting encrypted matching of %d fingerprints with the first fingerprint", len(encInputs)-1)
		wg := &sync.WaitGroup{}
		wg.Add(len(encInputs) - 1)

		// Assign tasks to evaluate fingerprint matching between each input and the first fingerprint
		for i := 1; i < len(encInputs); i++ {
			task := multTask{wg, encInputs[i], encInputs[0], encRes[i-1], 0}
			taskList = append(taskList, &task)
			tasks <- &task // Send task to channel
		}

		// Wait for all tasks to complete
		wg.Wait()
	})

	// Track the total time for the cloud-side evaluation and task completion
	elapsedEvalCloudCPU = time.Duration(0)
	for _, t := range taskList {
		elapsedEvalCloudCPU += t.elapsedmultTask
	}

	// Track the time for party-side evaluation (in this case, no party-side computation is done)
	elapsedEvalParty = time.Duration(0)

	// Log the total time taken for the evaluation phase
	l.Printf("\tdone (cloud: %s (wall: %s), party: %s)\n",
		elapsedEvalCloudCPU, elapsedEvalCloud, elapsedEvalParty)

	// Close the tasks channel and wait for all worker goroutines to finish
	close(tasks)
	workers.Wait()

	// Return the results of the evaluation
	return
}

// This function performs the collective key switching (PCKS) from the collective secret key to a target public key.
// It uses homomorphic encryption to securely switch keys on encrypted data without revealing the plaintext.
func pcksPhase(params bfv.Parameters, tpk *rlwe.PublicKey, encRes []*bfv.Ciphertext, P []*party) (encOut []*bfv.Ciphertext) {

	l := log.New(os.Stderr, "", 0)

	// Initialize the PCKS protocol with the given parameters.
	// PCKS allows key switching from one public key to another
	// The parameter `3.19` represents the standard deviation of the smudging noise added during the key switching process.
	// This noise is critical for ensuring privacy by masking intermediate results during the protocol.
	// We retain the value `3.19` for consistency with the poster runtime benchmarks.
	// However, recent research (see https://eprint.iacr.org/2024/116) suggests that a significantly larger value may be required for privacy reasons.
	pcks := dbfv.NewPCKSProtocol(params, 3.19)

	// Allocate shares for each party for the key-switching process
	// Each party will generate its own share of the key-switching operation
	for _, pi := range P {
		pi.pcksShare = make([]*drlwe.PCKSShare, len(encRes))
		for i := range encRes {
			pi.pcksShare[i] = pcks.AllocateShare() // Each share corresponds to a ciphertext in encRes
		}
	}

	l.Println("> PCKS Phase")

	// Perform the party-side computation for key switching (generating shares)
	elapsedPCKSParty = runTimedParty(func() {
		for _, pi := range P {
			for i := range encRes {
				// Generate the share for key switching based on the party's secret key, target public key, and ciphertext
				pcks.GenShare(pi.sk, tpk, encRes[i].Value[1], pi.pcksShare[i])
			}
		}
	}, len(P))

	// Prepare the combined shares to be used for key switching on the cloud side
	pcksCombined := make([]*drlwe.PCKSShare, len(encRes)) // Combined shares after aggregation
	encOut = make([]*bfv.Ciphertext, len(encRes))         // Output ciphertexts after key switching

	// Initialize combined shares and output ciphertexts
	for i := range encRes {
		pcksCombined[i] = pcks.AllocateShare()   // Allocate space for the combined share
		encOut[i] = bfv.NewCiphertext(params, 1) // Initialize the output ciphertexts
	}

	// Perform the cloud-side computation for key switching (aggregate shares and perform the key switch)
	elapsedPCKSCloud = runTimed(func() {

		// Aggregate the shares from all parties
		for _, pi := range P {
			for i := range encRes {
				// Aggregate the share for each ciphertext
				pcks.AggregateShare(pi.pcksShare[i], pcksCombined[i], pcksCombined[i])
			}
		}

		// Perform the key switching on the ciphertexts using the combined shares
		for i := range encRes {
			pcks.KeySwitch(encRes[i], pcksCombined[i], encOut[i]) // Perform key switching for each ciphertext
		}
	})

	// Log the elapsed time for the cloud and party operations
	l.Printf("\tdone (cloud: %s, party: %s)\n", elapsedPCKSCloud, elapsedPCKSParty)

	// Return the resulting ciphertexts after key switching
	return

}
