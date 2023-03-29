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

func check(err error) {
	if err != nil {
		panic(err)
	}
}

func runTimed(f func()) time.Duration {
	start := time.Now()
	f()
	return time.Since(start)
}

func runTimedParty(f func(), N int) time.Duration {
	start := time.Now()
	f()
	return time.Duration(time.Since(start).Nanoseconds() / int64(N))
}

type party struct {
	sk         *rlwe.SecretKey
	rlkEphemSk *rlwe.SecretKey

	ckgShare    *drlwe.CKGShare
	rkgShareOne *drlwe.RKGShare
	rkgShareTwo *drlwe.RKGShare
	rtgShare    *drlwe.RTGShare    // Rotation keys
	pcksShare   []*drlwe.PCKSShare // PKCS protocol -> public key switching protocol

	input  [][]uint64 // fingerprint
	NumRow int        // NumCol real
	NumCol int        // NumRow real
}

type multTask struct {
	wg              *sync.WaitGroup
	op1             [][]*bfv.Ciphertext
	op2             [][]*bfv.Ciphertext
	res             *bfv.Ciphertext // Ciphertext with scalar product result in all coefficients
	elapsedmultTask time.Duration
}

var elapsedEncryptParty time.Duration
var elapsedEncryptCloud time.Duration
var elapsedCKGCloud time.Duration
var elapsedCKGParty time.Duration
var elapsedRKGCloud time.Duration
var elapsedRKGParty time.Duration
var elapsedRTGCloud time.Duration // tiempos rotación
var elapsedRTGParty time.Duration // tiempos rotación
var elapsedPCKSCloud time.Duration
var elapsedPCKSParty time.Duration
var elapsedEvalCloudCPU time.Duration
var elapsedEvalCloud time.Duration
var elapsedEvalParty time.Duration
var elapsedDecCloud time.Duration
var elapsedDecParty time.Duration

// missing var elapsedDecryptParty time.Duration

// prueba N parties para N - 1 scalar product con fingeprint de la first party-> go run ./psi N 1 256 4096 con PN12QP109
// se hacen N - 1 productos escalares con la fingerprint de P[0].input

func main() {
	// For more details about the camera attribution framework see
	//     Secure Collaborative Camera Attribution (<https://www.fvv.um.si/eicc2022/>)

	l := log.New(os.Stderr, "", 0)

	// $go run main.go arg1 arg2
	// arg1: number of parties -> N parties = {1 query fingerprint, N - 1 fingeprints to match}
	// arg2: number of Go routines
	// arg3: number of rows in each fingerprint
	// arg4: number of columns in each fingerprint

	// Largest for n=8192: 512 parties
	N := 5 // Default number of parties -> it can be any number
	var err error
	if len(os.Args[1:]) >= 1 {
		N, err = strconv.Atoi(os.Args[1])
		check(err)
	}

	NGoRoutine := 1 // Default number of Go routines -> we don't use this parameter!!!
	if len(os.Args[1:]) >= 2 {
		NGoRoutine, err = strconv.Atoi(os.Args[2])
		check(err)
	}

	OrNumRow := 1 //1 //2048 // Default number of Rows for fingerprint size
	if len(os.Args[1:]) >= 3 {
		OrNumRow, err = strconv.Atoi(os.Args[3])
		check(err)
	}

	OrNumCol := 1 //8096 //4096 //1 //16384 //2048 // Default number of Rows for fingerprint size
	if len(os.Args[1:]) >= 4 {
		OrNumCol, err = strconv.Atoi(os.Args[4])
		check(err)
	}

	// Creating encryption parameters from a default params with logN=14, logQP=438 with a plaintext modulus T=65537
	paramsDef := bfv.PN13QP218 //PN12QP109 //PN12QP109 //PN14QP438 // me interesa una combinación con PN12 Y L = 2 como en el paper de lattigo, PN12QP109
	paramsDef.T = 3221225473   // 3*2^30 + 1 Proth prime (32 bits) //65537        // hacer una potencia que me interese (2^16 + 1)^4 approx 64 bits
	params, err := bfv.NewParametersFromLiteral(paramsDef)
	if err != nil {
		panic(err)
	}

	crs, err := utils.NewKeyedPRNG([]byte{'f', 'e', 'l', 'd', 's', 'p', 'a', 'r'}) //'t', 'r', 'u', 'm', 'p', 'e', 't'
	if err != nil {
		panic(err)
	}

	///// PARA en un futuro emular fingerprints con una gausiana!
	///prng, err := utils.NewPRNG()
	///if err != nil {
	///	panic(err)
	///}
	///gaussianSampler := ring.NewGaussianSampler(prng, ringQ, 3.2, 19)
	/////

	encoder := bfv.NewEncoder(params)

	// Target private and public keys
	tsk, tpk := bfv.NewKeyGenerator(params).GenKeyPair()
	//_ = tsk

	// Create each party and allocate the memory for all the shares that the protocols will need
	P := genparties(params, N)
	l.Println("> Initialization of Parties") //%s", len(P[0].input)*len(P[0].input[0]))
	l.Printf("Num parties: %d, First party will receive %d encrypted scores\n", len(P), len(P)-1)

	// Inputs & expected result
	expRes := genInputs(params, P, OrNumRow, OrNumCol, 0xffffffffffffffff)
	l.Printf("> Input generation\n \tNum parties: %d \n\tExpected Results: NumRow %d, NumCol %d\n", len(P), len(expRes), len(expRes[0]))
	l.Printf("\tSize Inputs per Pary: (%d, %d) uint64\n", len(P[0].input), len(P[0].input[0]))

	// 1) Collective public key generation
	pk := ckgphase(params, crs, P)

	// 2) Collective relinearization key generation
	rlk := rkgphase(params, crs, P) // sólo se necesita en el matching

	// 3) Collective rotation keys generation
	rtk := rtkphase(params, crs, P)

	l.Printf("\tSetup done (cloud: %s, party: %s)\n",
		elapsedRKGCloud+elapsedCKGCloud+elapsedRTGCloud, elapsedRKGParty+elapsedCKGParty+elapsedRTGParty)

	encInputs := encPhase(params, P, pk, encoder)
	l.Printf("\tSize encInputs: (%d, %d, %d) ciphertexts\n", len(encInputs), len(encInputs[0]), len(encInputs[0][0]))

	encRes := evalPhase(params, NGoRoutine, encInputs, rlk, rtk)

	encOut := pcksPhase(params, tpk, encRes, P)

	//define decOut := decPhase(params, encInputs, tsk)

	// Decrypt the result with the target secret key
	l.Println("> Decrypt Phase")
	decryptor := bfv.NewDecryptor(params, tsk)

	ptres := make([]*bfv.Plaintext, len(encOut))
	for i := range encOut {
		ptres[i] = bfv.NewPlaintext(params)
	}

	elapsedDecParty = runTimed(func() {
		for i := range encOut {
			decryptor.Decrypt(encOut[i], ptres[i])
		}
	})

	elapsedDecCloud = time.Duration(0)
	l.Printf("\tdone (cloud: %s, party: %s)\n", elapsedDecCloud, elapsedDecParty)

	l.Println("> Result:")
	l.Printf("\t Number of matchings computed: %d ciphertexts\n", len(encOut))
	// Check the result
	res := make([][]uint64, len(expRes))
	for i := range expRes {
		res[i] = make([]uint64, len(expRes[i]))
	}

	for i := range ptres {
		partialRes := encoder.DecodeUintNew(ptres[i])
		for j := range partialRes {
			res[i][j] = partialRes[j]
		}
	}
	result := make([]uint64, N-1)
	expectedresult := make([]uint64, N-1)
	for i := 0; i < N-1; i++ {
		result[i] = res[i][0]
		expectedresult[i] = expRes[i][0]
	}
	l.Printf("\t Size Res.: Row %d x Col %d\n", len(res), len(res[0]))
	l.Printf("\t Scores: \n\t%v\n", result)
	l.Printf("\t Size Exp. Res.: Row %d x Col %d\n", len(expRes), len(expRes[0]))
	l.Printf("\t Exp. Scores: \n\t%v\n", expectedresult)

	//l.Println("last column")
	//l.Printf("\t%v\n", res[:4][4095])
	//l.Printf("\t%v\n", expRes[:4][4095])
	for i := range expRes {
		for j := range expRes[i] {
			if expRes[i][j] != res[i][j] {
				//l.Printf("\t%v\n", expRes)
				l.Printf("\tincorrect\n first error in position [%d][%d]\n", i, j)
				l.Printf("> Finished (total cloud: %s, total party: %s)\n", elapsedCKGCloud+elapsedRKGCloud+elapsedEncryptCloud+elapsedEvalCloud+elapsedPCKSCloud, elapsedCKGParty+elapsedRKGParty+elapsedEncryptParty+elapsedEvalParty+elapsedPCKSParty+elapsedDecParty)
				return
			}
		}
	}
	l.Println("\tcorrect")
	l.Printf("> Finished (total cloud: %s, total party: %s)\n", elapsedCKGCloud+elapsedRKGCloud+elapsedRTGCloud+elapsedEncryptCloud+elapsedEvalCloud+elapsedPCKSCloud, elapsedCKGParty+elapsedRKGParty+elapsedRTGParty+elapsedEncryptParty+elapsedEvalParty+elapsedPCKSParty+elapsedDecParty)

}

// Generates the invidividual secret key and "input images of size Num_Row x Num_Col" for each Forensic Party P[i]
func genparties(params bfv.Parameters, N int) []*party { //genSKparties

	// Create each party, and allocate the memory for all the shares that the protocols will need
	P := make([]*party, N)
	for i := range P {
		pi := &party{}
		pi.sk = bfv.NewKeyGenerator(params).GenSecretKey()
		P[i] = pi
	}

	return P
}

func genInputs(params bfv.Parameters, P []*party, OrNumRow int, OrNumCol int, BoundInputs uint64) (expRes [][]uint64) {

	//l := log.New(os.Stderr, "", 0)

	//Generate Inputs
	for _, pi := range P {
		pi.input = make([][]uint64, OrNumRow)
		for i := range pi.input {
			pi.NumRow = OrNumRow
			if params.N() >= OrNumCol { // degree polynomial >= width of fingerprint
				pi.NumCol = params.N()
			} else { // degree polynomial < width of fingerprint -> make NumCol equal to a multiple of degree big enough
				// en realidad habría que calcular el menor múltiplo de params.N() que está por encima de OrNumCol
				// (OrNumCol/params.N() + 1) -> siendo pi.NumCol = params.N()*(OrNumCol/params.N() + 1)
				pi.NumCol = int(math.Pow(2, math.Ceil(math.Log2(float64(OrNumCol))))) // NumCol must be the smallest power-of-two bigger than the "original number of columns"
			}
			pi.input[i] = make([]uint64, pi.NumCol)
			for j := range pi.input[i] {
				if j < OrNumCol {
					pi.input[i][j] = (utils.RandUint64() % BoundInputs) % params.T()
				} else {
					pi.input[i][j] = 0
				}
			}
		}
	}

	//Allocate memory for Expected Results -> Num Parties - 1 x params.N() -> cada fila el mismo valor repetido
	expRes = make([][]uint64, len(P)-1)
	for i := range expRes {
		expRes[i] = make([]uint64, params.N())
	}

	//Generate Aggregation Expected Results
	for i, pi := range P[1:] { // desde P[1] hasta P[len(P) - 1], hay que comparar con P[0]
		//l.Printf("vuelta: %d \n", i)
		for j := range pi.input {
			for k := range pi.input[j] {
				expRes[i][0] += (pi.input[j][k] * P[0].input[j][k]) % params.T()
				expRes[i][0] %= params.T()
			}
		}
		for j := 1; j < params.N(); j++ {
			expRes[i][j] = expRes[i][0]
		}
	}

	return
}

func ckgphase(params bfv.Parameters, crs utils.PRNG, P []*party) *rlwe.PublicKey {

	l := log.New(os.Stderr, "", 0)

	l.Println("> CKG Phase")

	ckg := dbfv.NewCKGProtocol(params) // Public key generation
	ckgCombined := ckg.AllocateShare()
	for _, pi := range P {
		pi.ckgShare = ckg.AllocateShare()
	}

	crp := ckg.SampleCRP(crs)

	elapsedCKGParty = runTimedParty(func() {
		for _, pi := range P {
			ckg.GenShare(pi.sk, crp, pi.ckgShare)
		}
	}, len(P))

	pk := bfv.NewPublicKey(params)

	elapsedCKGCloud = runTimed(func() {
		for _, pi := range P {
			ckg.AggregateShare(pi.ckgShare, ckgCombined, ckgCombined)
		}
		ckg.GenPublicKey(ckgCombined, crp, pk)
	})

	l.Printf("\tdone (cloud: %s, party: %s)\n", elapsedCKGCloud, elapsedCKGParty)

	return pk
}

func rkgphase(params bfv.Parameters, crs utils.PRNG, P []*party) *rlwe.RelinearizationKey {
	l := log.New(os.Stderr, "", 0)

	l.Println("> RKG Phase")

	rkg := dbfv.NewRKGProtocol(params) // Relinearization key generation
	_, rkgCombined1, rkgCombined2 := rkg.AllocateShare()

	for _, pi := range P {
		pi.rlkEphemSk, pi.rkgShareOne, pi.rkgShareTwo = rkg.AllocateShare()
	}

	crp := rkg.SampleCRP(crs)

	elapsedRKGParty = runTimedParty(func() {
		for _, pi := range P {
			rkg.GenShareRoundOne(pi.sk, crp, pi.rlkEphemSk, pi.rkgShareOne)
		}
	}, len(P))

	elapsedRKGCloud = runTimed(func() {
		for _, pi := range P {
			rkg.AggregateShare(pi.rkgShareOne, rkgCombined1, rkgCombined1)
		}
	})

	elapsedRKGParty += runTimedParty(func() {
		for _, pi := range P {
			rkg.GenShareRoundTwo(pi.rlkEphemSk, pi.sk, rkgCombined1, pi.rkgShareTwo)
		}
	}, len(P))

	rlk := bfv.NewRelinearizationKey(params, 1)
	elapsedRKGCloud += runTimed(func() {
		for _, pi := range P {
			rkg.AggregateShare(pi.rkgShareTwo, rkgCombined2, rkgCombined2)
		}
		rkg.GenRelinearizationKey(rkgCombined1, rkgCombined2, rlk)
	})

	l.Printf("\tdone (cloud: %s, party: %s)\n", elapsedRKGCloud, elapsedRKGParty)

	return rlk
}

func rtkphase(params bfv.Parameters, crs utils.PRNG, P []*party) *rlwe.RotationKeySet {

	l := log.New(os.Stderr, "", 0)

	l.Println("> RTG Phase")

	rtg := dbfv.NewRotKGProtocol(params) // Rotation keys generation

	for _, pi := range P {
		pi.rtgShare = rtg.AllocateShare()
	}

	galEls := params.GaloisElementsForRowInnerSum()
	rotKeySet := bfv.NewRotationKeySet(params, galEls)

	for _, galEl := range galEls {

		rtgShareCombined := rtg.AllocateShare()

		crp := rtg.SampleCRP(crs)

		elapsedRTGParty += runTimedParty(func() {
			for _, pi := range P {
				rtg.GenShare(pi.sk, galEl, crp, pi.rtgShare)
			}
		}, len(P))

		elapsedRTGCloud += runTimed(func() {
			for _, pi := range P {
				rtg.AggregateShare(pi.rtgShare, rtgShareCombined, rtgShareCombined)
			}
			rtg.GenRotationKey(rtgShareCombined, crp, rotKeySet.Keys[galEl])
		})
	}
	l.Printf("\tdone (cloud: %s, party %s)\n", elapsedRTGCloud, elapsedRTGParty)

	return rotKeySet
}

// adaptar inputs -> bloques dentro de las filas de imágenes, Image size -> Num_Row x Num_Col -> block size = n, num_blocks_per_row = ceil(Num_Col/n), num_blocks = num_blocks_per_row*Num_Row
func encPhase(params bfv.Parameters, P []*party, pk *rlwe.PublicKey, encoder bfv.Encoder) (encInputs [][][]*bfv.Ciphertext) {

	l := log.New(os.Stderr, "", 0)

	NumRowEncIn := P[0].NumRow
	NumColEncIn := int(math.Ceil(float64(P[0].NumCol) / float64(params.N())))
	//l.Printf("prueba %d\n", NumColEncIn)

	// encInputs[i][j][k], i through Parties, j through Rows, k through Columns
	encInputs = make([][][]*bfv.Ciphertext, len(P))
	for i := range encInputs {
		encInputs[i] = make([][]*bfv.Ciphertext, NumRowEncIn)
		for j := range encInputs[i] {
			encInputs[i][j] = make([]*bfv.Ciphertext, NumColEncIn)
		}
	}

	// Initializes "input" ciphertexts
	for i := range encInputs {
		//l.Printf("\tsize encInputs = %d x %d\n", len(encInputs[0]), len(encInputs[0][0]))
		for j := range encInputs[i] {
			for k := range encInputs[i][j] {
				encInputs[i][j][k] = bfv.NewCiphertext(params, 1) // quizás hay que poner 2
			}
		}
	}

	// Each party encrypts its bidimensional array of input vectors into a bidimensional array of input ciphertexts
	l.Println("> Encrypt Phase")
	encryptor := bfv.NewEncryptor(params, pk)

	pt := bfv.NewPlaintext(params)
	elapsedEncryptParty = runTimedParty(func() {
		for i, pi := range P {
			for j := range pi.input {
				for k := 0; k < NumColEncIn; k++ {
					//l.Printf("SIZE EACH ROW: %d\n", len(pi.input[j][(k*params.N()):((k+1)*params.N()-1)]))
					//l.Printf("valores son %d y %d", k*params.N(), (k+1)*params.N())
					//l.Printf("size total row %d", len(pi.input[j]))
					encoder.Encode(pi.input[j][(k*params.N()):((k+1)*params.N())], pt) // es uno menos en la segunda parte porque go indexa [0:n] como los valores 0, 2, ..., n - 1
					encryptor.Encrypt(pt, encInputs[i][j][k])
				}
			}

		}
	}, len(P))

	elapsedEncryptCloud = time.Duration(0)
	l.Printf("\tdone (cloud: %s, party: %s)\n", elapsedEncryptCloud, elapsedEncryptParty)

	return
}

// !! modify to include the operation I am interested
// matching case requires. (1) rlk, (2) extra dimension in encRes
func evalPhase(params bfv.Parameters, NGoRoutine int, encInputs [][][]*bfv.Ciphertext, rlk *rlwe.RelinearizationKey, rtk *rlwe.RotationKeySet) (encRes []*bfv.Ciphertext) {

	l := log.New(os.Stderr, "", 0)

	// Rows, Cols for the matrices of ciphertexts"
	//NumRowEncIn := len(encInputs[0])
	//NumColEncIn := len(encInputs[0][0])

	// Output Layers definition to store intermediate and final results
	encRes = make([]*bfv.Ciphertext, len(encInputs)-1)
	for i := range encRes {
		encRes[i] = bfv.NewCiphertext(params, 1)
	}

	evaluator := bfv.NewEvaluator(params, rlwe.EvaluationKey{Rlk: rlk, Rtks: rtk}) // if using evaluator.innersum, we have to generate the power-of-two rotations
	// generar las rotation matrices con los automorfismos de GaloisElementsForRowInnerSum()

	// Split the addition tasks among the Go routines
	tasks := make(chan *multTask)
	workers := &sync.WaitGroup{}
	workers.Add(NGoRoutine)
	//l.Println("> Spawning", NGoRoutine, "evaluator goroutine")
	for i := 1; i <= NGoRoutine; i++ {
		go func(i int) {
			evaluator := evaluator.ShallowCopy() // creates a shallow evaluator copy for this goroutine

			// definir tmp como [][]*bfv.Ciphertext y reservar memoria como matrix de ciphertexts de degree 2
			tmp := make([][]*bfv.Ciphertext, len(encInputs[0]))
			for i := range encInputs[0] {
				tmp[i] = make([]*bfv.Ciphertext, len(encInputs[0][0]))
				for j := range encInputs[0][0] {
					tmp[i][j] = bfv.NewCiphertext(params, 2)
				}
			}
			tmpAdd := bfv.NewCiphertext(params, 2) // "zero values in theory"

			for task := range tasks {
				task.elapsedmultTask = runTimed(func() {
					// Addition of two input matrices of ciphertexts
					for indRow := range task.op1 {
						for indCol := range task.op1[0] {
							// 1) Multiplication of the fingerprint "query" with the rest of fingerprints
							evaluator.Mul(task.op1[indRow][indCol], task.op2[indRow][indCol], tmp[indRow][indCol])
							if (indRow == 0) && (indCol == 0) {
								tmpAdd = tmp[0][0]
							} else {
								// 2) Addition of all the ciphertext through "indRow" and "indCol"
								evaluator.Add(tmp[indRow][indCol], tmpAdd, tmpAdd)
							}
						}
					}
					// 3) Relinearization
					evaluator.Relinearize(tmpAdd, task.res)

					// 4) InnerSum
					evaluator.InnerSum(task.res, task.res) //opción de mejora con extractLWEsample
				})
				task.wg.Done()
			}
			//l.Println("\t evaluator", i, "down")
			workers.Done()
		}(i)
		//l.Println("\t evaluator", i, "started")
	}

	// Start the fingerprint matching tasks
	taskList := make([]*multTask, 0)
	l.Println("> Eval Phase")
	elapsedEvalCloud = runTimed(func() {
		l.Printf("\tStarting encrypted matching of %d fingerprints with the first fingerprint", len(encInputs)-1)
		wg := &sync.WaitGroup{}
		wg.Add(len(encInputs) - 1)
		for i := 1; i < len(encInputs); i++ {
			task := multTask{wg, encInputs[i], encInputs[0], encRes[i-1], 0}
			taskList = append(taskList, &task)
			tasks <- &task
		}
		wg.Wait()
	})
	elapsedEvalCloudCPU = time.Duration(0)
	for _, t := range taskList {
		elapsedEvalCloudCPU += t.elapsedmultTask
	}
	elapsedEvalParty = time.Duration(0)
	l.Printf("\tdone (cloud: %s (wall: %s), party: %s)\n",
		elapsedEvalCloudCPU, elapsedEvalCloud, elapsedEvalParty)

	//l.Println("> Shutting down workers")
	close(tasks)
	workers.Wait()

	return
}

// cambio de la global secret key a la "target secret key"
func pcksPhase(params bfv.Parameters, tpk *rlwe.PublicKey, encRes []*bfv.Ciphertext, P []*party) (encOut []*bfv.Ciphertext) {

	l := log.New(os.Stderr, "", 0)

	// Collective key switching from the collective secret key to
	// the target public key

	//CHECK -> encOut and encRes are matrices of ciphertexts now
	pcks := dbfv.NewPCKSProtocol(params, 3.19)

	for _, pi := range P {
		pi.pcksShare = make([]*drlwe.PCKSShare, len(encRes))
		for i := range encRes {
			pi.pcksShare[i] = pcks.AllocateShare()
		}
	}

	l.Println("> PCKS Phase")
	elapsedPCKSParty = runTimedParty(func() {
		for _, pi := range P {
			for i := range encRes {
				pcks.GenShare(pi.sk, tpk, encRes[i].Value[1], pi.pcksShare[i])
			}
		}
	}, len(P))

	//var pcksCombined []*drlwe.PCKSShare
	pcksCombined := make([]*drlwe.PCKSShare, len(encRes))
	encOut = make([]*bfv.Ciphertext, len(encRes))
	for i := range encRes {
		pcksCombined[i] = pcks.AllocateShare()
		encOut[i] = bfv.NewCiphertext(params, 1)
	}

	elapsedPCKSCloud = runTimed(func() {
		for _, pi := range P {
			for i := range encRes {
				pcks.AggregateShare(pi.pcksShare[i], pcksCombined[i], pcksCombined[i])
			}
		}
		for i := range encRes {
			pcks.KeySwitch(encRes[i], pcksCombined[i], encOut[i])
		}
	})
	l.Printf("\tdone (cloud: %s, party: %s)\n", elapsedPCKSCloud, elapsedPCKSParty)

	return

}
