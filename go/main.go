package main

// import (
// 	"fmt"
// 	"math/big"
// 	"sync"

// 	"github.com/consensys/gnark-crypto/ecc/bn254"
// )

// // Exp sets z=xᵏ (mod q¹²) and returns it
// // uses 2-bits windowed method
// type E12 = bn254.E12

// // n
// var bigIntPool = sync.Pool{
// 	New: func() interface{} {
// 		return new(big.Int)
// 	},
// }

// func Exp(x E12, k *big.Int) *E12 {
// 	// if k.IsUint64() && k.Uint64() == 0 {
// 	// 	return z.SetOne()
// 	// }

// 	e := k
// 	// if k.Sign() == -1 {
// 	// 	// negative k, we invert
// 	// 	// if k < 0: xᵏ (mod q¹²) == (x⁻¹)ᵏ (mod q¹²)
// 	// 	x.Inverse(&x)

// 	// 	// we negate k in a temp big.Int since
// 	// 	// Int.Bit(_) of k and -k is different
// 	// 	e = bigIntPool.Get().(*big.Int)
// 	// 	defer bigIntPool.Put(e)
// 	// 	e.Neg(k)
// 	// }

// 	var res E12
// 	var ops [3]E12

// 	res.SetOne()
// 	ops[0].Set(&x)
// 	ops[1].Square(&ops[0])
// 	ops[2].Set(&ops[0]).Mul(&ops[2], &ops[1])

// 	b := e.Bytes()
// 	for i := range b {
// 		w := b[i]
// 		mask := byte(0xc0)
// 		for j := 0; j < 4; j++ {
// 			res.Square(&res).Square(&res)
// 			c := (w & mask) >> (6 - 2*j)
// 			if c != 0 {
// 				res.Mul(&res, &ops[c-1])
// 			}
// 			mask = mask >> 2
// 		}
// 	}
// 	return &res
// }

// // nolint: all
// func initFirst() *bn254.E12 {
// 	// First, create the E2 elements for the first E6 component (c0)
// 	c0_c0 := new(bn254.E2)
// 	c0_c0.A0.SetString("14841886482450590275284665479453326838835013692642419664128295955689030577864")
// 	c0_c0.A1.SetString("5207830851455123864167599687752164000431472086451572690764463195030262211885")

// 	c0_c1 := new(bn254.E2)
// 	c0_c1.A0.SetString("18121468335698912424401022180126713436428511783755107542715262246244433093212")
// 	c0_c1.A1.SetString("10210145360600084003467295060319264656595895515580755169516884295344172886067")

// 	c0_c2 := new(bn254.E2)
// 	c0_c2.A0.SetString("19943274368669850471319309422640479297814565872873473344943088944799637783524")
// 	c0_c2.A1.SetString("6014276434336631155232823804460508304187817835744161282664332728279168217024")

// 	// Create the E2 elements for the second E6 component (c1)
// 	c1_c0 := new(bn254.E2)
// 	c1_c0.A0.SetString("7772003760531576493130067815496305579503248287498288834906826441950446346442")
// 	c1_c0.A1.SetString("4585762554803027801131410465560770589466313142137617474533135284016029622585")

// 	c1_c1 := new(bn254.E2)
// 	c1_c1.A0.SetString("10031828115930482257216361621869951055987985204290892531799142614172297341525")
// 	c1_c1.A1.SetString("235419680353342740115453395106865256585124560550209673751216854247634758193")

// 	c1_c2 := new(bn254.E2)
// 	c1_c2.A0.SetString("18212498274428502988862887458246199080627074703961077644031320316808390028470")
// 	c1_c2.A1.SetString("19828822834598814655654047757822547345964721526592318706929123911148025047275")

// 	// Construct the E6 elements
// 	c0 := new(bn254.E6)
// 	c0.B0 = *c0_c0
// 	c0.B1 = *c0_c1
// 	c0.B2 = *c0_c2

// 	c1 := new(bn254.E6)
// 	c1.B0 = *c1_c0
// 	c1.B1 = *c1_c1
// 	c1.B2 = *c1_c2

// 	// Finally, create the E12 element
// 	e12 := new(bn254.E12)
// 	e12.C0 = *c0
// 	e12.C1 = *c1

// 	return e12
// }

// func main() {
// 	e := initFirst()
// 	// fmt.Println(e.Bytes())
// 	n := new(big.Int)
// 	n, _ = n.SetString("21344149548639821030140052972327954680082213940495023215006734486249949124691", 10)
// 	fmt.Println(Exp(*e, n).Bytes())
// }
