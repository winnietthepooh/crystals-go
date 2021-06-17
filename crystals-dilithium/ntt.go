package dilithium

var zetas = [n]int32{
	0, 25847, -2608894, -518909, 237124, -777960, -876248, 466468,
	1826347, 2353451, -359251, -2091905, 3119733, -2884855, 3111497, 2680103,
	2725464, 1024112, -1079900, 3585928, -549488, -1119584, 2619752, -2108549,
	-2118186, -3859737, -1399561, -3277672, 1757237, -19422, 4010497, 280005,
	2706023, 95776, 3077325, 3530437, -1661693, -3592148, -2537516, 3915439,
	-3861115, -3043716, 3574422, -2867647, 3539968, -300467, 2348700, -539299,
	-1699267, -1643818, 3505694, -3821735, 3507263, -2140649, -1600420, 3699596,
	811944, 531354, 954230, 3881043, 3900724, -2556880, 2071892, -2797779,
	-3930395, -1528703, -3677745, -3041255, -1452451, 3475950, 2176455, -1585221,
	-1257611, 1939314, -4083598, -1000202, -3190144, -3157330, -3632928, 126922,
	3412210, -983419, 2147896, 2715295, -2967645, -3693493, -411027, -2477047,
	-671102, -1228525, -22981, -1308169, -381987, 1349076, 1852771, -1430430,
	-3343383, 264944, 508951, 3097992, 44288, -1100098, 904516, 3958618,
	-3724342, -8578, 1653064, -3249728, 2389356, -210977, 759969, -1316856,
	189548, -3553272, 3159746, -1851402, -2409325, -177440, 1315589, 1341330,
	1285669, -1584928, -812732, -1439742, -3019102, -3881060, -3628969, 3839961,
	2091667, 3407706, 2316500, 3817976, -3342478, 2244091, -2446433, -3562462,
	266997, 2434439, -1235728, 3513181, -3520352, -3759364, -1197226, -3193378,
	900702, 1859098, 909542, 819034, 495491, -1613174, -43260, -522500,
	-655327, -3122442, 2031748, 3207046, -3556995, -525098, -768622, -3595838,
	342297, 286988, -2437823, 4108315, 3437287, -3342277, 1735879, 203044,
	2842341, 2691481, -2590150, 1265009, 4055324, 1247620, 2486353, 1595974,
	-3767016, 1250494, 2635921, -3548272, -2994039, 1869119, 1903435, -1050970,
	-1333058, 1237275, -3318210, -1430225, -451100, 1312455, 3306115, -1962642,
	-1279661, 1917081, -2546312, -1374803, 1500165, 777191, 2235880, 3406031,
	-542412, -2831860, -1671176, -1846953, -2584293, -3724270, 594136, -3776993,
	-2013608, 2432395, 2454455, -164721, 1957272, 3369112, 185531, -1207385,
	-3183426, 162844, 1616392, 3014001, 810149, 1652634, -3694233, -1799107,
	-3038916, 3523897, 3866901, 269760, 2213111, -975884, 1717735, 472078,
	-426683, 1723600, -1803090, 1910376, -1667432, -1104333, -260646, -3833893,
	-2939036, -2235985, -420899, -2286327, 183443, -976891, 1612842, -3545687,
	-554416, 3919660, -48306, -1362209, 3937738, 1400424, -846154, 1976782,
}

var f = int32(41978) //int32(((uint64(MONT) * MONT % Q) * (Q - 1) % Q) * ((Q - 1) >> 8) % Q)

//ntt performs in place forward NTT
func (p *Poly) ntt() {
	var len, start, j, k uint
	var zeta, t int32

	k = 1
	for len = 128; len > 0; len >>= 1 {
		for start = 0; start < n; start = j + len {
			zeta = zetas[k]
			k++
			for j = start; j < start+len; j++ {
				t = fqmul(zeta, p[j+len])
				p[j+len] = p[j] - t
				p[j] = p[j] + t
			}
		}
	}
}

//invntt perfors in place backward NTT and multiplication by Montgomery factor 2^32.
func (p *Poly) invntt() {
	var len, start, j, k uint
	var zeta, t int32

	k = n - 1
	for len = 1; len < n; len <<= 1 {
		for start = 0; start < n; start = j + len {
			zeta = zetas[k]
			k--
			for j = start; j < start+len; j++ {
				t = p[j]
				p[j] = barretReduce(t + p[j+len])
				p[j+len] = p[j+len] - t
				p[j+len] = fqmul(zeta, p[j+len])
			}
		}
	}

	for j = 0; j < n; j++ {
		p[j] = fqmul(f, p[j])
	}
}

//ntt performs in place NTT
func (v Vec) ntt(L int) {
	for i := 0; i < L; i++ {
		v[i].ntt()
	}
}

//invntt perfroms in place backward NTT
func (v Vec) invntt(L int) {
	for i := 0; i < L; i++ {
		v[i].invntt()
	}
}

//fqmul performs a multiplication in the Montgomery domain
func fqmul(a, b int32) int32 {
	return montgomeryReduce(int64(a) * int64(b))
}

func bsmul(a0, a1, b0, b1, zeta int32) (int32, int32) {
	r0 := fqmul(a1, b1)
	r0 = fqmul(r0, zeta)
	r0 += fqmul(a0, b0)
	r1 := fqmul(a0, b1)
	r1 += fqmul(a1, b0)
	return r0, r1
}

//montgomeryReduce is used to reduce a montgomery coefficient  [0, RQ]
func montgomeryReduce(a int64) int32 {
	t := int32(a * qInv)
	t = int32((a - int64(t)*q) >> 32)
	return t
}

//tomont converts a poly to its montgomery representation
func (p *Poly) tomont() {
	for i := 0; i < n; i++ {
		p[i] = montgomeryReduce(int64(p[i]))
	}
}

//barretReduce converts a poly to its barret representation
func (p *Poly) barretReduce() {
	for i := 0; i < n; i++ {
		p[i] = barretReduce(p[i])
	}
}

//Computes the integer in {-(q-1)/2,...,(q-1)/2} congruent to a modulo q
func barretReduce(a int32) int32 {
	v := int32(((uint32(1) << 26) + uint32(q/2)) / uint32(q))
	t := int32(v) * int32(a) >> 26
	t *= int32(q)
	return a - t
}

//fromMont converts back to [0, Q]
func (p *Poly) fromMont() {
	inv := uint64(8265825)
	for i := uint(0); i < n; i++ {
		p[i] = int32((uint64(p[i]) * inv) % q)
	}
}
