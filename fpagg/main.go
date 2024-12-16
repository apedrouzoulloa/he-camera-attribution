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

// check is a utility function to handle errors.
// If an error occurs, it will panic and stop execution.
func check(err error) {
	if err != nil {
		panic(err)
	}
}

// runTimed executes a function and returns the duration it took to run.
// It is used for timing various phases of the computation.
func runTimed(f func()) time.Duration {
	start := time.Now()
	f()
	return time.Since(start)
}

// runTimedParty executes a function and returns the average duration per party.
// It divides the total time by the number of parties (N) for average timing.
func runTimedParty(f func(), N int) time.Duration {
	start := time.Now()
	f()
	return time.Duration(time.Since(start).Nanoseconds() / int64(N)) // Return average time per party
}

// party struct represents a party involved in the protocol.
// It holds secret keys, shares for key generation and public key switching, and the fingerprint input data for each party.
type party struct {
	sk *rlwe.SecretKey // Secret key of the party (used for decryption)

	// Key shares for cryptographic protocols (e.g., CKG, PCKS)
	ckgShare *drlwe.CKGShare // CKG share used in the Collective Key Generation protocol

	// Public key switching protocol share (for switching to a target public key)
	pcksShare [][]*drlwe.PCKSShare // Share data for the public key switching protocol

	// Input fingerprint data for the party (e.g., image data converted into fingerprint)
	input  [][]uint64 // Fingerprint data stored as a 2D array (rows and columns)
	NumRow int        // NumCol real. Actual number of rows in the input
	NumCol int        // NumRow real. Actual number of columns in the input
}

// multTask represents a multiplication task that will be executed in parallel by different goroutines.
// It includes the necessary inputs, outputs, and synchronization details.
type multTask struct {
	wg              *sync.WaitGroup
	op1             [][]*bfv.Ciphertext // First operand matrix of ciphertexts (input data)
	op2             [][]*bfv.Ciphertext // Second operand matrix of ciphertexts (input data)
	res             [][]*bfv.Ciphertext // Result matrix of ciphertexts after multiplication
	elapsedmultTask time.Duration       // Elapsed time for this specific multiplication task
}

// Below are global variables that track the time spent on each phase of the protocol.
// These variables store the elapsed times for different parts of the cryptographic protocol, which helps in performance analysis and optimization.
var elapsedEncryptParty time.Duration
var elapsedEncryptCloud time.Duration
var elapsedCKGCloud time.Duration
var elapsedCKGParty time.Duration
var elapsedRKGCloud time.Duration
var elapsedRKGParty time.Duration
var elapsedPCKSCloud time.Duration
var elapsedPCKSParty time.Duration
var elapsedEvalCloudCPU time.Duration
var elapsedEvalCloud time.Duration
var elapsedEvalParty time.Duration
var elapsedDecCloud time.Duration
var elapsedDecParty time.Duration

// --------------------------------------------------------------------------------------------------------------------------------------------------
// Example execution: N parties results in the addition of the N fingerprints returning the resulting aggregated fingerprint.
// Example for fingerprints of size 1024 x 1024, 64 parties, and 1 Goroutine (default PN12QP109):
// go run ./fpagg 64 1 256 4096
// --------------------------------------------------------------------------------------------------------------------------------------------------

func main() {

	//-------------------------------------------------------------------------------------------------------------------------
	// For more details about the camera attribution framework, refer to the following paper:
	// - "Secure Collaborative Camera Attribution" (https://dl.acm.org/doi/abs/10.1145/3528580.3532993)
	// - Conference page: https://www.fvv.um.si/eicc2022/
	//-------------------------------------------------------------------------------------------------------------------------

	l := log.New(os.Stderr, "", 0)

	//-------------------------------------------------------------------------------------------------------------------------
	// Command-line arguments:
	// arg1: Number of parties (N parties).
	// arg2: Number of Go routines.
	// arg3: Number of rows in each fingerprint.
	// arg4: Number of columns in each fingerprint.
	//-------------------------------------------------------------------------------------------------------------------------

	// Set default values:
	// N: Number of parties involved (must be an even number for the algorithm to work)
	N := 64 // Default number of parties -> it must be an EVEN NUMBER -> pending to fix the "last layer" from a length of 3 into 1

	// Read N from command-line argument if provided
	var err error
	if len(os.Args[1:]) >= 1 {
		N, err = strconv.Atoi(os.Args[1])
		check(err)
	}

	// NGoRoutine: Number of Go routines (default is 1)
	NGoRoutine := 1 // Default number of Go routines
	if len(os.Args[1:]) >= 2 {
		NGoRoutine, err = strconv.Atoi(os.Args[2])
		check(err)
	}

	// OrNumRow: Number of rows in each fingerprint (default is 256)
	OrNumRow := 256 // Default number of Rows for fingerprint size
	if len(os.Args[1:]) >= 3 {
		OrNumRow, err = strconv.Atoi(os.Args[3])
		check(err)
	}

	// OrNumCol: Number of columns in each fingerprint (default is 4096)
	OrNumCol := 4096 // Default number of Columns for fingerprint size
	if len(os.Args[1:]) >= 4 {
		OrNumCol, err = strconv.Atoi(os.Args[4])
		check(err)
	}

	// Create encryption parameters from a default set:
	// paramsDef is a predefined structure for encryption parameters (PN12QP109)
	paramsDef := bfv.PN12QP109 // Default parameters (specific parameters can be chosen from the Lattigo library v3)
	paramsDef.T = 65537        // Set the plaintext modulus T to 65537 = 1*2^16 + 1 Proth prime (17 bits) = 4-th Fermat prime

	// Generate the encryption parameters using the predefined set and the modulus T
	params, err := bfv.NewParametersFromLiteral(paramsDef)
	if err != nil {
		panic(err)
	}

	// Initialize a cryptographic random source (PRNG) using a fixed key
	crs, err := utils.NewKeyedPRNG([]byte{'f', 'e', 'l', 'd', 's', 'p', 'a', 'r'})
	if err != nil {
		panic(err)
	}

	// Initialize the encoder for encoding and decoding the plaintext
	encoder := bfv.NewEncoder(params)

	// Generate the target secret key (tsk) and public key (tpk)
	tsk, tpk := bfv.NewKeyGenerator(params).GenKeyPair()

	// Create each party and allocate memory for all the shares that the cryptographic protocols will need
	P := genparties(params, N)               // Generate the parties based on the number of parties (N)
	l.Println("> Initialization of Parties") // Logging the party initialization

	// Generate inputs and expected results
	expRes := genInputs(params, P, OrNumRow, OrNumCol, 0xffffffffffffffff) // Generate input fingerprints for each party
	l.Printf("> Input generation\n \tNum parties: %d, NumRow: %d, NumCol: %d\n", len(P), len(expRes), len(expRes[0]))

	// Phase 1) Collective public key generation
	pk := ckgphase(params, crs, P) // Run the Collective Key Generation phase to get the public key (pk)

	// Log setup completion times for different phases (RKG and CKG)
	l.Printf("\tSetup done (cloud: %s, party: %s)\n",
		elapsedRKGCloud+elapsedCKGCloud, elapsedRKGParty+elapsedCKGParty)

	// Phase 2) Encrypt the inputs for each party
	encInputs := encPhase(params, P, pk, encoder) // Encrypt the inputs using the public key

	// Phase 3) Evaluate the encrypted inputs (fingerprint aggregation)
	encRes := evalPhase(params, NGoRoutine, encInputs) // Perform the evaluation phase (e.g., aggregation)

	// Phase 4) Public key switching (PCKS)
	encOut := pcksPhase(params, tpk, encRes, P) // Apply public key switching to get final encrypted result
	l.Printf("Size of result\t: NumRow: %d ciphertexts, NumCol: %d ciphertexts\n", len(encOut), len(encOut[0]))

	// Decrypt the result using the target secret key (tsk)
	l.Println("> Decrypt Phase")
	decryptor := bfv.NewDecryptor(params, tsk) // Initialize the decryptor with the target secret key

	// Allocate space for the decrypted plaintext results
	ptres := make([][]*bfv.Plaintext, len(encOut))
	for i := range encOut {
		ptres[i] = make([]*bfv.Plaintext, len(encOut[i]))
		for j := range encOut[i] {
			ptres[i][j] = bfv.NewPlaintext(params) // Initialize plaintext objects
		}
	}

	// Time the decryption phase for the parties
	elapsedDecParty = runTimed(func() {
		// Loop over all the encrypted results and decrypt them into plaintext
		for i := range encOut {
			for j := range encOut[i] {
				decryptor.Decrypt(encOut[i][j], ptres[i][j]) // Decrypt each ciphertext
			}
		}
	})

	// No need to measure cloud time for decryption here, since it's all done in the party phase
	elapsedDecCloud = time.Duration(0)
	l.Printf("\tdone (cloud: %s, party: %s)\n", elapsedDecCloud, elapsedDecParty)

	// Log the decrypted result and compare it to the expected result
	l.Println("> Result:")
	// Check the result
	res := make([][]uint64, len(expRes))
	for i := range expRes {
		res[i] = make([]uint64, len(expRes[i])) // Allocate memory for result
	}

	// Decode the plaintext results and populate the final result
	for i := range ptres {
		for j := range ptres[i] {
			// Decode the plaintext values into the result array
			partialRes := encoder.DecodeUintNew(ptres[i][j]) // Decode to uint64 array
			for k := range partialRes {
				res[i][(j*len(partialRes) + k)] = partialRes[k] // Store the decoded value
			}
		}
	}

	// Log the first few values of the result and expected result for comparison
	l.Printf("\t%v\n", res[0][:4])    // Print first 4 values of the result
	l.Printf("\t%v\n", expRes[0][:4]) // Print first 4 values of the expected result

	// Check if the result matches the expected result
	for i := range expRes {
		for j := range expRes[i] {
			if expRes[i][j] != res[i][j] { // If there's a mismatch
				// Log the position of the first mismatch
				l.Printf("\tincorrect\n first error in position [%d][%d]\n", i, j)
				l.Printf("> Finished (total cloud: %s, total party: %s)\n", elapsedCKGCloud+elapsedEncryptCloud+elapsedEvalCloud+elapsedPCKSCloud, elapsedCKGParty+elapsedEncryptParty+elapsedEvalParty+elapsedPCKSParty+elapsedDecParty)
				return // Terminate the program if there's an error
			}
		}
	}

	// If no mismatches, log that the result is correct
	l.Println("\tcorrect")
	l.Printf("> Finished (total cloud: %s, total party: %s)\n", elapsedCKGCloud+elapsedEncryptCloud+elapsedEvalCloud+elapsedPCKSCloud+elapsedDecCloud, elapsedCKGParty+elapsedEncryptParty+elapsedEvalParty+elapsedPCKSParty+elapsedDecParty)

}

// Generates the individual secret key for each Forensic Party P[i]
func genparties(params bfv.Parameters, N int) []*party { //genSKparties

	// Create a slice P of size N to store the parties
	// Each party will have its own secret key and necessary shares for the cryptographic protocols
	P := make([]*party, N)

	// Loop through each party in the slice
	for i := range P {
		pi := &party{} // Create a new instance of the party struct

		// Generate a secret key for the party using the provided parameters
		pi.sk = bfv.NewKeyGenerator(params).GenSecretKey()

		// Store the party in the slice P
		P[i] = pi
	}

	// Return the slice containing all the parties
	return P
}

// Generates the inputs for each party and computes the expected result by aggregating the inputs from all parties.
func genInputs(params bfv.Parameters, P []*party, OrNumRow int, OrNumCol int, BoundInputs uint64) (expRes [][]uint64) {

	// Generate inputs for each party
	for _, pi := range P {

		// Initialize the input matrix for each party with the given number of rows
		pi.input = make([][]uint64, OrNumRow)
		for i := range pi.input {
			pi.NumRow = OrNumRow

			// Adjust the number of columns based on the encryption parameters
			if params.N() >= OrNumCol { // Degree of polynomial >= width of fingerprint
				pi.NumCol = params.N() // Use the degree of the polynomial as the number of columns
			} else { // Degree of polynomial < width of fingerprint
				// (OrNumCol / params.N() + 1) -> pi.NumCol = params.N() * (OrNumCol / params.N() + 1)
				// Currently we set pi.NumCol as the next power of 2 greater than OrNumCol
				pi.NumCol = int(math.Pow(2, math.Ceil(math.Log2(float64(OrNumCol))))) // NumCol must be the smallest power-of-two bigger than the original NumCol
			}

			// Initialize each row in the input matrix with pi.NumCol elements
			pi.input[i] = make([]uint64, pi.NumCol)

			// Assign values to the input array
			for j := range pi.input[i] {
				if j < OrNumCol { // If the index is within the original column count

					// Generate a random value and mod it by BoundInputs and the parameter T
					pi.input[i][j] = (utils.RandUint64() % BoundInputs) % params.T()

				} else { // Fill the remaining columns with 0s
					pi.input[i][j] = 0
				}
			}
		}
	}

	// Allocate memory for the expected result matrix (expRes) which will hold the aggregated inputs
	expRes = make([][]uint64, OrNumRow)
	for i := range expRes {

		// Initialize each row of the expected result matrix to match the number of columns of the first party's input
		expRes[i] = make([]uint64, P[0].NumCol)
	}

	// Generate the aggregated expected results by summing up all party inputs
	for _, pi := range P {
		for i := range pi.input {
			for j := range pi.input[i] {

				// Add the current party's input to the expected result and take the modulus T
				expRes[i][j] += pi.input[i][j]
				expRes[i][j] %= params.T() // Apply modulus to ensure values stay within the plaintext modulus T
			}
		}
	}

	// Return the aggregated expected results
	return
}

// Performs the Collective Key Generation (CKG) phase.
// This phase securely generates a collective public key shared among all parties.
func ckgphase(params bfv.Parameters, crs utils.PRNG, P []*party) *rlwe.PublicKey {

	l := log.New(os.Stderr, "", 0)

	// Indicate the start of the CKG phase
	l.Println("> CKG Phase")

	// Initialize the CKG protocol for collective public key generation
	ckg := dbfv.NewCKGProtocol(params)

	// Allocate memory for the combined CKG share (used for aggregation)
	ckgCombined := ckg.AllocateShare()

	// Allocate memory for each party's individual CKG share
	for _, pi := range P {
		pi.ckgShare = ckg.AllocateShare()
	}

	// Generate a Common Random Polynomial (CRP) using the given pseudo-random number generator (PRNG)
	crp := ckg.SampleCRP(crs)

	// Generate each party's share of the CKG process
	elapsedCKGParty = runTimedParty(func() {
		for _, pi := range P {
			// Each party generates their share using their secret key and the CRP
			ckg.GenShare(pi.sk, crp, pi.ckgShare)
		}
	}, len(P)) // Divide total elapsed time by the number of parties

	// Create an empty public key that will store the result of the CKG process
	pk := bfv.NewPublicKey(params)

	// Aggregate the CKG shares from all parties and generate the collective public key
	elapsedCKGCloud = runTimed(func() {

		// Aggregate the individual shares into the combined CKG share
		for _, pi := range P {
			ckg.AggregateShare(pi.ckgShare, ckgCombined, ckgCombined)
		}

		// Generate the final public key from the aggregated CKG share and the CRP
		ckg.GenPublicKey(ckgCombined, crp, pk)
	})

	// Log the completion of the CKG phase with timings for the cloud and parties
	l.Printf("\tdone (cloud: %s, party: %s)\n", elapsedCKGCloud, elapsedCKGParty)

	// Return the generated collective public key
	return pk
}

// Encrypts the inputs for each party into ciphertexts for further homomorphic computation.
// The input is divided into blocks, and each block is encrypted independently.
func encPhase(params bfv.Parameters, P []*party, pk *rlwe.PublicKey, encoder bfv.Encoder) (encInputs [][][]*bfv.Ciphertext) {

	l := log.New(os.Stderr, "", 0)

	// Number of rows in the input (same for all parties)
	NumRowEncIn := P[0].NumRow

	// Calculate the number of blocks per row.
	// Each block size is `params.N()`. If the number of columns (NumCol) is not a multiple of `params.N()`,
	// it takes the ceiling of the division to include all remaining elements.
	NumColEncIn := int(math.Ceil(float64(P[0].NumCol) / float64(params.N())))

	// Initialize the 3D slice to hold the encrypted inputs.
	// Dimensions:
	// - `len(P)`: Number of parties
	// - `NumRowEncIn`: Number of rows per party
	// - `NumColEncIn`: Number of blocks (columns divided into chunks of size `params.N()`)
	encInputs = make([][][]*bfv.Ciphertext, len(P))
	for i := range encInputs {
		encInputs[i] = make([][]*bfv.Ciphertext, NumRowEncIn)
		for j := range encInputs[i] {
			encInputs[i][j] = make([]*bfv.Ciphertext, NumColEncIn)
		}
	}

	// Initialize all ciphertexts in `encInputs` with empty ciphertext objects.
	for i := range encInputs {
		for j := range encInputs[i] {
			for k := range encInputs[i][j] {
				encInputs[i][j][k] = bfv.NewCiphertext(params, 1) // Ciphertext degree = 1
			}
		}
	}

	// Start the encryption phase.
	l.Println("> Encrypt Phase")

	// Initialize the encryptor with the collective public key (`pk`).
	encryptor := bfv.NewEncryptor(params, pk)

	// Create an empty plaintext object for encoding and encryption.
	pt := bfv.NewPlaintext(params)

	// Measure the time taken for the encryption phase (party-side operations).
	elapsedEncryptParty = runTimedParty(func() {
		// Loop through each party
		for i, pi := range P {
			// Loop through each row of the party's input
			for j := range pi.input {
				// Loop through each block in the row
				for k := 0; k < NumColEncIn; k++ {
					// Encode a block of input into a plaintext.
					// Input data is sliced into blocks of size `params.N()`.
					encoder.Encode(pi.input[j][(k*params.N()):((k+1)*params.N())], pt)

					// Encrypt the encoded plaintext into the corresponding ciphertext.
					encryptor.Encrypt(pt, encInputs[i][j][k])
				}
			}

		}
	}, len(P)) // Normalize the elapsed time by the number of parties

	// Encryption is done entirely on the party side, so cloud-side elapsed time is zero.
	elapsedEncryptCloud = time.Duration(0)

	// Log completion of encryption phase with timing information.
	l.Printf("\tdone (cloud: %s, party: %s)\n", elapsedEncryptCloud, elapsedEncryptParty)

	// Return the encrypted inputs for further processing.
	return
}

// Performs the evaluation phase where encrypted inputs are aggregated layer by layer.
// This phase uses homomorphic addition to sum ciphertexts in a hierarchical (layered) manner.
func evalPhase(params bfv.Parameters, NGoRoutine int, encInputs [][][]*bfv.Ciphertext) (encRes [][]*bfv.Ciphertext) {

	l := log.New(os.Stderr, "", 0)

	// Dimensions of the matrices of ciphertexts (rows and columns)
	NumRowEncIn := len(encInputs[0])    // Number of rows in the input matrices
	NumColEncIn := len(encInputs[0][0]) // Number of columns in the input matrices

	// `encLayers` stores intermediate and final results across layers.
	// The first layer (`encLayers[0]`) contains the input ciphertexts (`encInputs`).
	encLayers := make([][][][]*bfv.Ciphertext, 0) // array of an array with matrices of ciphertexts
	encLayers = append(encLayers, encInputs)

	// Build the layers of the evaluation tree. Each layer aggregates ciphertexts from the previous layer.
	// The number of ciphertext matrices at each layer is halved until only one matrix remains.
	for nLayer := len(encInputs) / 2; nLayer > 0; nLayer = nLayer >> 1 { // Halve the number of matrices at each layer

		encLayer := make([][][]*bfv.Ciphertext, nLayer) // New layer

		for i := range encLayer {
			encLayer[i] = make([][]*bfv.Ciphertext, NumRowEncIn) // Initialize rows for this layer

			for j := range encLayer[i] {
				encLayer[i][j] = make([]*bfv.Ciphertext, NumColEncIn) // Initialize columns

				for k := range encLayer[i][j] {
					// Allocate a ciphertext object for the result of adding ciphertexts in this layer
					encLayer[i][j][k] = bfv.NewCiphertext(params, 1) // Degree = 1 (holds addition results)
				}
			}
		}
		encLayers = append(encLayers, encLayer) // Add this layer to the list of layers
	}

	// The final result is in the last layer (after all reductions)
	encRes = encLayers[len(encLayers)-1][0]

	// Create a homomorphic evaluator to perform ciphertext operations
	evaluator := bfv.NewEvaluator(params, rlwe.EvaluationKey{Rlk: nil, Rtks: nil})

	// Task queue to distribute work among goroutines
	tasks := make(chan *multTask)
	workers := &sync.WaitGroup{}
	workers.Add(NGoRoutine)

	// Spawn worker goroutines to handle the evaluation tasks
	for i := 1; i <= NGoRoutine; i++ {
		go func(i int) {
			evaluator := evaluator.ShallowCopy() // Each goroutine gets its own evaluator instance
			for task := range tasks {

				// Measure the time taken for each task
				task.elapsedmultTask = runTimed(func() {

					// Add ciphertexts from two matrices (element-wise) to produce the result matrix
					for indRow := range task.op1 {
						for indCol := range task.op1[0] {
							evaluator.Add(task.op1[indRow][indCol], task.op2[indRow][indCol], task.res[indRow][indCol])
						}
					}
				})
				task.wg.Done() // Mark task as done
			}
			workers.Done() // Mark worker as finished
		}(i)
	}

	// Begin the evaluation phase
	taskList := make([]*multTask, 0) // Track tasks for timing analysis

	l.Println("> Eval Phase")

	elapsedEvalCloud = runTimed(func() {
		// Iterate through each layer except the last
		for i, layer := range encLayers[:len(encLayers)-1] {
			nextLayer := encLayers[i+1] // Next layer to fill with results

			l.Println("\tEncrypted fingerprints added in layer", i, ":", len(layer), "->", len(nextLayer))

			// WaitGroup to synchronize tasks for this layer
			wg := &sync.WaitGroup{}
			wg.Add(len(nextLayer))

			// Create tasks to sum pairs of matrices from the current layer into the next layer
			for j, nextLayerCt := range nextLayer {

				// Each task aggregates two matrices from the current layer into one matrix in the next layer
				task := multTask{wg, layer[2*j], layer[2*j+1], nextLayerCt, 0}
				taskList = append(taskList, &task)
				tasks <- &task // Send task to the task queue
			}
			wg.Wait() // Wait for all tasks in this layer to finish
		}
	})

	// Aggregate elapsed time for all tasks
	elapsedEvalCloudCPU = time.Duration(0)
	for _, t := range taskList {
		elapsedEvalCloudCPU += t.elapsedmultTask
	}

	// Party-side elapsed time is zero since the evaluation happens entirely on the cloud
	elapsedEvalParty = time.Duration(0)

	// Log the completion of the evaluation phase
	l.Printf("\tdone (cloud: %s (wall: %s), party: %s)\n",
		elapsedEvalCloudCPU, elapsedEvalCloud, elapsedEvalParty)

	// Close the task queue and wait for all worker goroutines to finish
	close(tasks)
	workers.Wait()

	// Return the final result
	return
}

// Perform the Phase of Partial Collective Key Switching (PCKS).
// This phase transitions ciphertexts from being encrypted under a collective secret key to being encrypted under a target public key.
func pcksPhase(params bfv.Parameters, tpk *rlwe.PublicKey, encRes [][]*bfv.Ciphertext, P []*party) (encOut [][]*bfv.Ciphertext) {

	l := log.New(os.Stderr, "", 0)

	// Initialize the PCKS protocol with the given parameters.
	// The parameter `3.19` represents the standard deviation of the smudging noise added during the key switching process.
	// This noise is critical for ensuring privacy by masking intermediate results during the protocol.
	// We retain the value `3.19` for consistency with the poster runtime benchmarks.
	// However, recent research (see https://eprint.iacr.org/2024/116) suggests that a significantly larger value may be required for privacy reasons.
	pcks := dbfv.NewPCKSProtocol(params, 3.19)

	// Allocate memory for each party's PCKS shares
	for _, pi := range P {
		pi.pcksShare = make([][]*drlwe.PCKSShare, len(encRes)) // Each row of encRes will have corresponding shares
		for i := range encRes {
			pi.pcksShare[i] = make([]*drlwe.PCKSShare, len(encRes[i])) // Each column in the row
			for j := range encRes[0] {
				// Allocate memory for the PCKS share of this specific ciphertext
				pi.pcksShare[i][j] = pcks.AllocateShare()
			}
		}
	}

	// Log that the PCKS phase is starting
	l.Println("> PCKS Phase")

	// Generate the PCKS shares in parallel for each party
	elapsedPCKSParty = runTimedParty(func() {
		for _, pi := range P { // Loop through all parties
			for i := range encRes { // Loop through rows of encRes (ciphertext matrix)
				for j := range encRes[0] { // Loop through columns of encRes
					// Generate the share for transitioning this ciphertext.
					// The share depends on the party's secret key (`pi.sk`), the target public key (`tpk`), and the second component of the ciphertext (`encRes[i][j].Value[1]`).
					pcks.GenShare(pi.sk, tpk, encRes[i][j].Value[1], pi.pcksShare[i][j])
				}
			}
		}
	}, len(P)) // The number of parties determines the amount of parallelism.

	// Allocate memory for the combined PCKS shares and the final output ciphertexts
	pcksCombined := make([][]*drlwe.PCKSShare, len(encRes)) // Combined shares for all rows
	encOut = make([][]*bfv.Ciphertext, len(encRes))         // Final output ciphertexts

	for i := range encRes {
		pcksCombined[i] = make([]*drlwe.PCKSShare, len(encRes[i])) // Combined shares for each column in the row
		encOut[i] = make([]*bfv.Ciphertext, len(encRes[i]))        // Output ciphertexts for each column in the row

		for j := range encRes[0] {
			// Allocate memory for combined PCKS shares and ciphertexts
			pcksCombined[i][j] = pcks.AllocateShare()
			encOut[i][j] = bfv.NewCiphertext(params, 1) // Output ciphertexts are of degree 1
		}
	}

	// Aggregate the PCKS shares from all parties and perform the final key switching
	elapsedPCKSCloud = runTimed(func() {

		// Aggregate PCKS shares from all parties
		for _, pi := range P {
			for i := range encRes { // For each row
				for j := range encRes[0] { // For each column

					// Combine the current party's PCKS share into the total aggregated share
					pcks.AggregateShare(pi.pcksShare[i][j], pcksCombined[i][j], pcksCombined[i][j])
				}
			}
		}

		// Perform the key switching operation for each ciphertext
		for i := range encRes { // For each row
			for j := range encRes[0] { // For each column

				// Use the aggregated share to transition the ciphertext from the collective secret key to the target public key
				pcks.KeySwitch(encRes[i][j], pcksCombined[i][j], encOut[i][j])
			}
		}
	})

	// Log the timing results for the cloud and party operations
	l.Printf("\tdone (cloud: %s, party: %s)\n", elapsedPCKSCloud, elapsedPCKSParty)

	// Return the final ciphertexts encrypted under the target public key
	return
}
