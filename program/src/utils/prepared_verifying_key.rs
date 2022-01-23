use ark_ff::biginteger::BigInteger256;
use ark_ff::QuadExtField;


pub fn get_alpha_g1_0() -> ark_ec::models::bn::g1::G1Affine::<ark_bn254::Parameters> { 
 	ark_ec::models::bn::g1::G1Affine::<ark_bn254::Parameters>::new(
		ark_ff::Fp256::<ark_bn254::FqParameters>::new(BigInteger256::new([6395671874356304218,7442367705146823054, 15233428457291645462, 875023476512628524])), 
		ark_ff::Fp256::<ark_bn254::FqParameters>::new(BigInteger256::new([14555270887283425686,1422345715839805534, 12284638019070615609, 406803177789034317])), false 
	)
}

pub fn get_beta_g2_0() -> ark_ec::models::bn::g2::G2Affine::<ark_bn254::Parameters> { 
 	ark_ec::models::bn::g2::G2Affine::<ark_bn254::Parameters>::new(
		QuadExtField::<ark_ff::Fp2ParamsWrapper::<ark_bn254::Fq2Parameters>>::new(
			ark_ff::Fp256::<ark_bn254::FqParameters>::new(BigInteger256::new([1908919010654538595,14236075201559531865, 3691261556633759387, 3181789518742718036])), 
			ark_ff::Fp256::<ark_bn254::FqParameters>::new(BigInteger256::new([10353321052689391367,2214908233606902394, 18270478741466760724, 309265333770134993])) 
		),
		QuadExtField::<ark_ff::Fp2ParamsWrapper::<ark_bn254::Fq2Parameters>>::new(
			ark_ff::Fp256::<ark_bn254::FqParameters>::new(BigInteger256::new([11817568029857600503,1345620474978798134, 17042686217557036156, 104499137409438257])), 
			ark_ff::Fp256::<ark_bn254::FqParameters>::new(BigInteger256::new([10979309571565419044,268767246026620089, 2670276847661099355, 1486146747370705440])) 
		),
		false
	)
}

pub fn get_gamma_g2_0() -> ark_ec::models::bn::g2::G2Affine::<ark_bn254::Parameters> { 
 	ark_ec::models::bn::g2::G2Affine::<ark_bn254::Parameters>::new(
		QuadExtField::<ark_ff::Fp2ParamsWrapper::<ark_bn254::Fq2Parameters>>::new(
			ark_ff::Fp256::<ark_bn254::FqParameters>::new(BigInteger256::new([10269251484633538598,15918845024527909234, 18138289588161026783, 1825990028691918907])), 
			ark_ff::Fp256::<ark_bn254::FqParameters>::new(BigInteger256::new([12660871435976991040,6936631231174072516, 714191060563144582, 1512910971262892907])) 
		),
		QuadExtField::<ark_ff::Fp2ParamsWrapper::<ark_bn254::Fq2Parameters>>::new(
			ark_ff::Fp256::<ark_bn254::FqParameters>::new(BigInteger256::new([7034053747528165878,18338607757778656120, 18419188534790028798, 2953656481336934918])), 
			ark_ff::Fp256::<ark_bn254::FqParameters>::new(BigInteger256::new([7208393106848765678,15877432936589245627, 6195041853444001910, 983087530859390082])) 
		),
		false
	)
}

pub fn get_delta_g2_0() -> ark_ec::models::bn::g2::G2Affine::<ark_bn254::Parameters> { 
 	ark_ec::models::bn::g2::G2Affine::<ark_bn254::Parameters>::new(
		QuadExtField::<ark_ff::Fp2ParamsWrapper::<ark_bn254::Fq2Parameters>>::new(
			ark_ff::Fp256::<ark_bn254::FqParameters>::new(BigInteger256::new([2795842264290440823,1895503996442934635, 7756996947166884284, 184786504383518664])), 
			ark_ff::Fp256::<ark_bn254::FqParameters>::new(BigInteger256::new([15457929352821742981,582457700367396190, 5094765477833743962, 3126971115040175784])) 
		),
		QuadExtField::<ark_ff::Fp2ParamsWrapper::<ark_bn254::Fq2Parameters>>::new(
			ark_ff::Fp256::<ark_bn254::FqParameters>::new(BigInteger256::new([16393952835042798559,2947381289577402084, 2622727280121326567, 111086390409439035])), 
			ark_ff::Fp256::<ark_bn254::FqParameters>::new(BigInteger256::new([2283194526230936196,8177175980162966613, 12599027446356325198, 2999842362348319157])) 
		),
		false
	)
}

pub fn get_gamma_abc_g1_0() -> ark_ec::models::bn::g1::G1Affine::<ark_bn254::Parameters> { 
 	ark_ec::models::bn::g1::G1Affine::<ark_bn254::Parameters>::new(
		ark_ff::Fp256::<ark_bn254::FqParameters>::new(BigInteger256::new([13081017878897802539,5979854018328592979, 5825414802195772079, 715786218627197019])), 
		ark_ff::Fp256::<ark_bn254::FqParameters>::new(BigInteger256::new([952075138646667651,305150188488596381, 6124826606402692569, 846040814660875257])), false 
	)
}

pub fn get_gamma_abc_g1_1() -> ark_ec::models::bn::g1::G1Affine::<ark_bn254::Parameters> { 
 	ark_ec::models::bn::g1::G1Affine::<ark_bn254::Parameters>::new(
		ark_ff::Fp256::<ark_bn254::FqParameters>::new(BigInteger256::new([15464542939769637116,13410505352636679396, 13712745987517311844, 2405898043312666510])), 
		ark_ff::Fp256::<ark_bn254::FqParameters>::new(BigInteger256::new([7870426887869995625,18247892369022602128, 4891053940453780125, 1906329627705230336])), false 
	)
}

pub fn get_gamma_abc_g1_2() -> ark_ec::models::bn::g1::G1Affine::<ark_bn254::Parameters> { 
 	ark_ec::models::bn::g1::G1Affine::<ark_bn254::Parameters>::new(
		ark_ff::Fp256::<ark_bn254::FqParameters>::new(BigInteger256::new([327863002279785962,10387491314280138458, 760645206984727278, 2311151250430612333])), 
		ark_ff::Fp256::<ark_bn254::FqParameters>::new(BigInteger256::new([13641118278430439450,6594642968493701090, 13110393668375955248, 1820752043945847384])), false 
	)
}

pub fn get_gamma_abc_g1_3() -> ark_ec::models::bn::g1::G1Affine::<ark_bn254::Parameters> { 
 	ark_ec::models::bn::g1::G1Affine::<ark_bn254::Parameters>::new(
		ark_ff::Fp256::<ark_bn254::FqParameters>::new(BigInteger256::new([14335020879993211582,4220414470887910468, 4784213620159309701, 992670808827559562])), 
		ark_ff::Fp256::<ark_bn254::FqParameters>::new(BigInteger256::new([1616900019110652933,1576740889278658015, 11619453633770566784, 1450337227856716876])), false 
	)
}

pub fn get_gamma_abc_g1_4() -> ark_ec::models::bn::g1::G1Affine::<ark_bn254::Parameters> { 
 	ark_ec::models::bn::g1::G1Affine::<ark_bn254::Parameters>::new(
		ark_ff::Fp256::<ark_bn254::FqParameters>::new(BigInteger256::new([6697526441154327948,14985724309526751469, 12255586883344175791, 123098659422302930])), 
		ark_ff::Fp256::<ark_bn254::FqParameters>::new(BigInteger256::new([8775027759219604963,10278563296417761292, 16525420935135170967, 235144879573722249])), false 
	)
}

pub fn get_gamma_abc_g1_5() -> ark_ec::models::bn::g1::G1Affine::<ark_bn254::Parameters> { 
 	ark_ec::models::bn::g1::G1Affine::<ark_bn254::Parameters>::new(
		ark_ff::Fp256::<ark_bn254::FqParameters>::new(BigInteger256::new([948158590055907696,2222750227037742358, 15116493774376575611, 1008365303707512812])), 
		ark_ff::Fp256::<ark_bn254::FqParameters>::new(BigInteger256::new([4256923413174412143,17042515474025024631, 15407609955846961185, 1219598505989113381])), false 
	)
}

pub fn get_gamma_abc_g1_6() -> ark_ec::models::bn::g1::G1Affine::<ark_bn254::Parameters> { 
 	ark_ec::models::bn::g1::G1Affine::<ark_bn254::Parameters>::new(
		ark_ff::Fp256::<ark_bn254::FqParameters>::new(BigInteger256::new([18113924876508678963,10971803437916389522, 10791661095263525936, 2936877018143358955])), 
		ark_ff::Fp256::<ark_bn254::FqParameters>::new(BigInteger256::new([10584264141143211669,13205796276135912855, 17459128109714812748, 1442375479935552475])), false 
	)
}

pub fn get_gamma_abc_g1_7() -> ark_ec::models::bn::g1::G1Affine::<ark_bn254::Parameters> { 
 	ark_ec::models::bn::g1::G1Affine::<ark_bn254::Parameters>::new(
		ark_ff::Fp256::<ark_bn254::FqParameters>::new(BigInteger256::new([4709507039546048362,18108342636272905494, 10161859358459192509, 599883615826793512])), 
		ark_ff::Fp256::<ark_bn254::FqParameters>::new(BigInteger256::new([16119224575173165950,3633520027129908410, 1042769587501782011, 3382579211241079631])), false 
	)
}

pub fn get_gamma_g2_neg_pc_0() -> (QuadExtField::<ark_ff::Fp2ParamsWrapper::<ark_bn254::Fq2Parameters>>, QuadExtField::<ark_ff::Fp2ParamsWrapper::<ark_bn254::Fq2Parameters>>, QuadExtField::<ark_ff::Fp2ParamsWrapper::<ark_bn254::Fq2Parameters>>) { 
 	(QuadExtField::<ark_ff::Fp2ParamsWrapper::<ark_bn254::Fq2Parameters>>::new(
			ark_ff::Fp256::<ark_bn254::FqParameters>::new(BigInteger256::new([9735490623776675493,7313347297369877603, 5110441044595811232, 2420314695870899172])), 
			ark_ff::Fp256::<ark_bn254::FqParameters>::new(BigInteger256::new([14416786213697531356,13308121799468939638, 12390083706888003821, 1966175061718780164])) 
		),
		QuadExtField::<ark_ff::Fp2ParamsWrapper::<ark_bn254::Fq2Parameters>>::new(
			ark_ff::Fp256::<ark_bn254::FqParameters>::new(BigInteger256::new([4129257347520110928,13798226624051452651, 4825670390762580777, 1989277302133421735])), 
			ark_ff::Fp256::<ark_bn254::FqParameters>::new(BigInteger256::new([11104699749248547751,10435997551076758402, 17853110753348405340, 3361471515497012039])) 
		),
		QuadExtField::<ark_ff::Fp2ParamsWrapper::<ark_bn254::Fq2Parameters>>::new(
			ark_ff::Fp256::<ark_bn254::FqParameters>::new(BigInteger256::new([10169789301848189331,16016180067228186549, 17334750741304028879, 2228788662616803775])), 
			ark_ff::Fp256::<ark_bn254::FqParameters>::new(BigInteger256::new([15172957284714629703,13417154794643176123, 3196086454825695542, 2093866205601446741])) 
 		)
 	)
}

pub fn get_gamma_g2_neg_pc_1() -> (QuadExtField::<ark_ff::Fp2ParamsWrapper::<ark_bn254::Fq2Parameters>>, QuadExtField::<ark_ff::Fp2ParamsWrapper::<ark_bn254::Fq2Parameters>>, QuadExtField::<ark_ff::Fp2ParamsWrapper::<ark_bn254::Fq2Parameters>>) { 
 	(QuadExtField::<ark_ff::Fp2ParamsWrapper::<ark_bn254::Fq2Parameters>>::new(
			ark_ff::Fp256::<ark_bn254::FqParameters>::new(BigInteger256::new([6373452946747570674,10270768430483208834, 11341147745087012459, 3157052191146643204])), 
			ark_ff::Fp256::<ark_bn254::FqParameters>::new(BigInteger256::new([602066187160159699,1578931260951444474, 1587541677266892445, 1992373586887236310])) 
		),
		QuadExtField::<ark_ff::Fp2ParamsWrapper::<ark_bn254::Fq2Parameters>>::new(
			ark_ff::Fp256::<ark_bn254::FqParameters>::new(BigInteger256::new([2035058501502628319,14930432017151590998, 15355551583521351086, 469587794589787657])), 
			ark_ff::Fp256::<ark_bn254::FqParameters>::new(BigInteger256::new([13631719073532767446,2065158137318837312, 5775538604822855962, 2383111915651801787])) 
		),
		QuadExtField::<ark_ff::Fp2ParamsWrapper::<ark_bn254::Fq2Parameters>>::new(
			ark_ff::Fp256::<ark_bn254::FqParameters>::new(BigInteger256::new([17544310453790923341,14459545592572037104, 12200103993180316021, 2090533022732391846])), 
			ark_ff::Fp256::<ark_bn254::FqParameters>::new(BigInteger256::new([8054743094808658598,15345477660971473493, 15443796689430031587, 1806066076678295575])) 
 		)
 	)
}

pub fn get_gamma_g2_neg_pc_2() -> (QuadExtField::<ark_ff::Fp2ParamsWrapper::<ark_bn254::Fq2Parameters>>, QuadExtField::<ark_ff::Fp2ParamsWrapper::<ark_bn254::Fq2Parameters>>, QuadExtField::<ark_ff::Fp2ParamsWrapper::<ark_bn254::Fq2Parameters>>) { 
 	(QuadExtField::<ark_ff::Fp2ParamsWrapper::<ark_bn254::Fq2Parameters>>::new(
			ark_ff::Fp256::<ark_bn254::FqParameters>::new(BigInteger256::new([1307490507467590467,15702387221270537235, 5269129970681753992, 28002378715318771])), 
			ark_ff::Fp256::<ark_bn254::FqParameters>::new(BigInteger256::new([4660357668607340467,16578489089999929478, 16748828149682735846, 739979399064110919])) 
		),
		QuadExtField::<ark_ff::Fp2ParamsWrapper::<ark_bn254::Fq2Parameters>>::new(
			ark_ff::Fp256::<ark_bn254::FqParameters>::new(BigInteger256::new([4578782715327068294,8628960991187287885, 16091835164139194461, 852554802780718793])), 
			ark_ff::Fp256::<ark_bn254::FqParameters>::new(BigInteger256::new([12096117391014189539,18239444815601499298, 7233070439485440435, 3194275071475042713])) 
		),
		QuadExtField::<ark_ff::Fp2ParamsWrapper::<ark_bn254::Fq2Parameters>>::new(
			ark_ff::Fp256::<ark_bn254::FqParameters>::new(BigInteger256::new([5827190618476342597,12470106628583867316, 17200718410803934706, 550783932675933241])), 
			ark_ff::Fp256::<ark_bn254::FqParameters>::new(BigInteger256::new([15647736919678071305,12053702395563955525, 4650097433064156528, 2812014987399368919])) 
 		)
 	)
}

pub fn get_gamma_g2_neg_pc_3() -> (QuadExtField::<ark_ff::Fp2ParamsWrapper::<ark_bn254::Fq2Parameters>>, QuadExtField::<ark_ff::Fp2ParamsWrapper::<ark_bn254::Fq2Parameters>>, QuadExtField::<ark_ff::Fp2ParamsWrapper::<ark_bn254::Fq2Parameters>>) { 
 	(QuadExtField::<ark_ff::Fp2ParamsWrapper::<ark_bn254::Fq2Parameters>>::new(
			ark_ff::Fp256::<ark_bn254::FqParameters>::new(BigInteger256::new([1836789663054811950,11512141512792473873, 1478746144118729173, 2923691560477017483])), 
			ark_ff::Fp256::<ark_bn254::FqParameters>::new(BigInteger256::new([12829111010025739515,7250912810722826978, 8129015919716064956, 1557336640775108833])) 
		),
		QuadExtField::<ark_ff::Fp2ParamsWrapper::<ark_bn254::Fq2Parameters>>::new(
			ark_ff::Fp256::<ark_bn254::FqParameters>::new(BigInteger256::new([16722324985467231953,3455514969581926786, 5435134192097375645, 445144570921449663])), 
			ark_ff::Fp256::<ark_bn254::FqParameters>::new(BigInteger256::new([17552173304110772017,6392449665810583181, 15317764502253575963, 1986700432257093656])) 
		),
		QuadExtField::<ark_ff::Fp2ParamsWrapper::<ark_bn254::Fq2Parameters>>::new(
			ark_ff::Fp256::<ark_bn254::FqParameters>::new(BigInteger256::new([5236977799088141757,16542968308152612384, 11217115100283931318, 2197361333128902643])), 
			ark_ff::Fp256::<ark_bn254::FqParameters>::new(BigInteger256::new([10433619994713991449,5468729870700106286, 13731897016295146488, 3282210527109190724])) 
 		)
 	)
}

pub fn get_gamma_g2_neg_pc_4() -> (QuadExtField::<ark_ff::Fp2ParamsWrapper::<ark_bn254::Fq2Parameters>>, QuadExtField::<ark_ff::Fp2ParamsWrapper::<ark_bn254::Fq2Parameters>>, QuadExtField::<ark_ff::Fp2ParamsWrapper::<ark_bn254::Fq2Parameters>>) { 
 	(QuadExtField::<ark_ff::Fp2ParamsWrapper::<ark_bn254::Fq2Parameters>>::new(
			ark_ff::Fp256::<ark_bn254::FqParameters>::new(BigInteger256::new([4097647836534978155,16211718821644978109, 12543988062359842685, 531950869723565272])), 
			ark_ff::Fp256::<ark_bn254::FqParameters>::new(BigInteger256::new([3732584527186327026,11009433307933628691, 9906125292583317817, 922464594331819969])) 
		),
		QuadExtField::<ark_ff::Fp2ParamsWrapper::<ark_bn254::Fq2Parameters>>::new(
			ark_ff::Fp256::<ark_bn254::FqParameters>::new(BigInteger256::new([15175933070488744052,8557412162374306745, 1363276520257215091, 1206507072649020906])), 
			ark_ff::Fp256::<ark_bn254::FqParameters>::new(BigInteger256::new([1439564256118195292,11404518156846947668, 5178720706420544533, 1208701127683364254])) 
		),
		QuadExtField::<ark_ff::Fp2ParamsWrapper::<ark_bn254::Fq2Parameters>>::new(
			ark_ff::Fp256::<ark_bn254::FqParameters>::new(BigInteger256::new([16144253490566453732,4504249177135800213, 367723188584878275, 2190328921017053644])), 
			ark_ff::Fp256::<ark_bn254::FqParameters>::new(BigInteger256::new([10025827719085050808,15989316882772203996, 15449519052851461310, 1313861631468371700])) 
 		)
 	)
}

pub fn get_gamma_g2_neg_pc_5() -> (QuadExtField::<ark_ff::Fp2ParamsWrapper::<ark_bn254::Fq2Parameters>>, QuadExtField::<ark_ff::Fp2ParamsWrapper::<ark_bn254::Fq2Parameters>>, QuadExtField::<ark_ff::Fp2ParamsWrapper::<ark_bn254::Fq2Parameters>>) { 
 	(QuadExtField::<ark_ff::Fp2ParamsWrapper::<ark_bn254::Fq2Parameters>>::new(
			ark_ff::Fp256::<ark_bn254::FqParameters>::new(BigInteger256::new([5823280062939564169,15680090768088578823, 15930926657659411240, 447669662857831647])), 
			ark_ff::Fp256::<ark_bn254::FqParameters>::new(BigInteger256::new([7123031478800885477,11854536813934295290, 4576838324085926162, 393867877332217377])) 
		),
		QuadExtField::<ark_ff::Fp2ParamsWrapper::<ark_bn254::Fq2Parameters>>::new(
			ark_ff::Fp256::<ark_bn254::FqParameters>::new(BigInteger256::new([369312874939631957,5577468896030353349, 16411512831196144769, 2225425689593265692])), 
			ark_ff::Fp256::<ark_bn254::FqParameters>::new(BigInteger256::new([6638295224199888525,18378089365476925535, 9535882037841911296, 2499032369420772404])) 
		),
		QuadExtField::<ark_ff::Fp2ParamsWrapper::<ark_bn254::Fq2Parameters>>::new(
			ark_ff::Fp256::<ark_bn254::FqParameters>::new(BigInteger256::new([13635119636550970561,6755198425354098277, 14942399890630288505, 1458437123855160184])), 
			ark_ff::Fp256::<ark_bn254::FqParameters>::new(BigInteger256::new([7719400999163966459,8978950345857190867, 3976775237719123842, 403317986652656893])) 
 		)
 	)
}

pub fn get_gamma_g2_neg_pc_6() -> (QuadExtField::<ark_ff::Fp2ParamsWrapper::<ark_bn254::Fq2Parameters>>, QuadExtField::<ark_ff::Fp2ParamsWrapper::<ark_bn254::Fq2Parameters>>, QuadExtField::<ark_ff::Fp2ParamsWrapper::<ark_bn254::Fq2Parameters>>) { 
 	(QuadExtField::<ark_ff::Fp2ParamsWrapper::<ark_bn254::Fq2Parameters>>::new(
			ark_ff::Fp256::<ark_bn254::FqParameters>::new(BigInteger256::new([6323944148176042385,14827035312785847748, 7085342050920843499, 2194884312546864639])), 
			ark_ff::Fp256::<ark_bn254::FqParameters>::new(BigInteger256::new([10713727812974110426,15122847604125151928, 7969503129420113999, 3072497528924008776])) 
		),
		QuadExtField::<ark_ff::Fp2ParamsWrapper::<ark_bn254::Fq2Parameters>>::new(
			ark_ff::Fp256::<ark_bn254::FqParameters>::new(BigInteger256::new([8245328154565749483,15008057688241463482, 1904435821669162144, 1441912631713626900])), 
			ark_ff::Fp256::<ark_bn254::FqParameters>::new(BigInteger256::new([14067806317296624525,5017805370971101456, 14326143508175705321, 2028047398688701706])) 
		),
		QuadExtField::<ark_ff::Fp2ParamsWrapper::<ark_bn254::Fq2Parameters>>::new(
			ark_ff::Fp256::<ark_bn254::FqParameters>::new(BigInteger256::new([12042115942287690287,16050192987958347428, 1145228044111305845, 2627988669539177495])), 
			ark_ff::Fp256::<ark_bn254::FqParameters>::new(BigInteger256::new([13047123149285011562,15386613089455414049, 7510911058351255393, 3316332504285088137])) 
 		)
 	)
}

pub fn get_gamma_g2_neg_pc_7() -> (QuadExtField::<ark_ff::Fp2ParamsWrapper::<ark_bn254::Fq2Parameters>>, QuadExtField::<ark_ff::Fp2ParamsWrapper::<ark_bn254::Fq2Parameters>>, QuadExtField::<ark_ff::Fp2ParamsWrapper::<ark_bn254::Fq2Parameters>>) { 
 	(QuadExtField::<ark_ff::Fp2ParamsWrapper::<ark_bn254::Fq2Parameters>>::new(
			ark_ff::Fp256::<ark_bn254::FqParameters>::new(BigInteger256::new([7891890699752675087,12715027985949561209, 6042813899840893100, 868694344373622319])), 
			ark_ff::Fp256::<ark_bn254::FqParameters>::new(BigInteger256::new([16399427437888050820,3846046456776588454, 10686023346950737987, 3344759956442768000])) 
		),
		QuadExtField::<ark_ff::Fp2ParamsWrapper::<ark_bn254::Fq2Parameters>>::new(
			ark_ff::Fp256::<ark_bn254::FqParameters>::new(BigInteger256::new([12294815732816214463,3961530758447984123, 15628978538598733560, 3202928354188042095])), 
			ark_ff::Fp256::<ark_bn254::FqParameters>::new(BigInteger256::new([18252201952929349815,6216908994703533045, 14438125476595334964, 1047171371043863825])) 
		),
		QuadExtField::<ark_ff::Fp2ParamsWrapper::<ark_bn254::Fq2Parameters>>::new(
			ark_ff::Fp256::<ark_bn254::FqParameters>::new(BigInteger256::new([13026834433791157246,14765348982607191910, 16505480142318392620, 1882850159514956635])), 
			ark_ff::Fp256::<ark_bn254::FqParameters>::new(BigInteger256::new([333599781101283695,17810853688536321163, 16496026278973326277, 2847222041893320289])) 
 		)
 	)
}

pub fn get_gamma_g2_neg_pc_8() -> (QuadExtField::<ark_ff::Fp2ParamsWrapper::<ark_bn254::Fq2Parameters>>, QuadExtField::<ark_ff::Fp2ParamsWrapper::<ark_bn254::Fq2Parameters>>, QuadExtField::<ark_ff::Fp2ParamsWrapper::<ark_bn254::Fq2Parameters>>) { 
 	(QuadExtField::<ark_ff::Fp2ParamsWrapper::<ark_bn254::Fq2Parameters>>::new(
			ark_ff::Fp256::<ark_bn254::FqParameters>::new(BigInteger256::new([7116649517358614829,2920647569665513542, 13209731436924262946, 453639253430949154])), 
			ark_ff::Fp256::<ark_bn254::FqParameters>::new(BigInteger256::new([3666803213437464831,7451829943988360517, 7980987991301795264, 2666344424132976136])) 
		),
		QuadExtField::<ark_ff::Fp2ParamsWrapper::<ark_bn254::Fq2Parameters>>::new(
			ark_ff::Fp256::<ark_bn254::FqParameters>::new(BigInteger256::new([5219278092499055320,3884916115576163386, 16328782425056420861, 3301475912234288630])), 
			ark_ff::Fp256::<ark_bn254::FqParameters>::new(BigInteger256::new([3431571446564174036,11493009609057756909, 8618636858343857939, 1986863209228296802])) 
		),
		QuadExtField::<ark_ff::Fp2ParamsWrapper::<ark_bn254::Fq2Parameters>>::new(
			ark_ff::Fp256::<ark_bn254::FqParameters>::new(BigInteger256::new([9074211749247733676,2418817438739424044, 679117380560856971, 169995907362283696])), 
			ark_ff::Fp256::<ark_bn254::FqParameters>::new(BigInteger256::new([10385737847901021227,14315582513327762173, 9738557493926035032, 950471749667491902])) 
 		)
 	)
}

pub fn get_gamma_g2_neg_pc_9() -> (QuadExtField::<ark_ff::Fp2ParamsWrapper::<ark_bn254::Fq2Parameters>>, QuadExtField::<ark_ff::Fp2ParamsWrapper::<ark_bn254::Fq2Parameters>>, QuadExtField::<ark_ff::Fp2ParamsWrapper::<ark_bn254::Fq2Parameters>>) { 
 	(QuadExtField::<ark_ff::Fp2ParamsWrapper::<ark_bn254::Fq2Parameters>>::new(
			ark_ff::Fp256::<ark_bn254::FqParameters>::new(BigInteger256::new([5252025707559437409,13953637720164835353, 3419520033516939334, 120015468621981738])), 
			ark_ff::Fp256::<ark_bn254::FqParameters>::new(BigInteger256::new([11981700070783507295,1570822996567796465, 7857295077868291515, 2144628409971280383])) 
		),
		QuadExtField::<ark_ff::Fp2ParamsWrapper::<ark_bn254::Fq2Parameters>>::new(
			ark_ff::Fp256::<ark_bn254::FqParameters>::new(BigInteger256::new([12620013865667236324,15851160004860545728, 15601915586305788059, 2284009028467699413])), 
			ark_ff::Fp256::<ark_bn254::FqParameters>::new(BigInteger256::new([12661019300699867038,3364324049985048219, 17977672049062988437, 1576103176157591547])) 
		),
		QuadExtField::<ark_ff::Fp2ParamsWrapper::<ark_bn254::Fq2Parameters>>::new(
			ark_ff::Fp256::<ark_bn254::FqParameters>::new(BigInteger256::new([18429994302768323336,13813699275930670289, 11011949919505124260, 2042408909137613241])), 
			ark_ff::Fp256::<ark_bn254::FqParameters>::new(BigInteger256::new([16574176000712322217,10294407224739185804, 11693088177603906544, 639379204620249221])) 
 		)
 	)
}

pub fn get_gamma_g2_neg_pc_10() -> (QuadExtField::<ark_ff::Fp2ParamsWrapper::<ark_bn254::Fq2Parameters>>, QuadExtField::<ark_ff::Fp2ParamsWrapper::<ark_bn254::Fq2Parameters>>, QuadExtField::<ark_ff::Fp2ParamsWrapper::<ark_bn254::Fq2Parameters>>) { 
 	(QuadExtField::<ark_ff::Fp2ParamsWrapper::<ark_bn254::Fq2Parameters>>::new(
			ark_ff::Fp256::<ark_bn254::FqParameters>::new(BigInteger256::new([11961844684395492461,15529371282921715378, 17772386125370065890, 959811724919934129])), 
			ark_ff::Fp256::<ark_bn254::FqParameters>::new(BigInteger256::new([1378846033346520785,7389322072149155598, 1592202723981715011, 2731071939212094142])) 
		),
		QuadExtField::<ark_ff::Fp2ParamsWrapper::<ark_bn254::Fq2Parameters>>::new(
			ark_ff::Fp256::<ark_bn254::FqParameters>::new(BigInteger256::new([3639945603867169008,12646131179701256118, 5410141380190428528, 3332492611662908087])), 
			ark_ff::Fp256::<ark_bn254::FqParameters>::new(BigInteger256::new([270412619520218290,10788974735074041043, 11640321094267608914, 2983084359777738873])) 
		),
		QuadExtField::<ark_ff::Fp2ParamsWrapper::<ark_bn254::Fq2Parameters>>::new(
			ark_ff::Fp256::<ark_bn254::FqParameters>::new(BigInteger256::new([12862302995183110164,11021245783930228767, 8237907725727474589, 2863977377025820330])), 
			ark_ff::Fp256::<ark_bn254::FqParameters>::new(BigInteger256::new([3599080925301125251,14847468876278789756, 10377513966858151960, 25009495063667099])) 
 		)
 	)
}

pub fn get_gamma_g2_neg_pc_11() -> (QuadExtField::<ark_ff::Fp2ParamsWrapper::<ark_bn254::Fq2Parameters>>, QuadExtField::<ark_ff::Fp2ParamsWrapper::<ark_bn254::Fq2Parameters>>, QuadExtField::<ark_ff::Fp2ParamsWrapper::<ark_bn254::Fq2Parameters>>) { 
 	(QuadExtField::<ark_ff::Fp2ParamsWrapper::<ark_bn254::Fq2Parameters>>::new(
			ark_ff::Fp256::<ark_bn254::FqParameters>::new(BigInteger256::new([7789585186810506137,3142937920393237003, 1333992290293988007, 3405117709433363837])), 
			ark_ff::Fp256::<ark_bn254::FqParameters>::new(BigInteger256::new([13941632647345873213,6335057726077175542, 4393742599438708031, 1166373703845352173])) 
		),
		QuadExtField::<ark_ff::Fp2ParamsWrapper::<ark_bn254::Fq2Parameters>>::new(
			ark_ff::Fp256::<ark_bn254::FqParameters>::new(BigInteger256::new([6390806688290935667,12163093867902728788, 9027613641070652428, 675820989212401750])), 
			ark_ff::Fp256::<ark_bn254::FqParameters>::new(BigInteger256::new([9082582285834176161,13942698388996023976, 12899799278085120109, 172651649945782945])) 
		),
		QuadExtField::<ark_ff::Fp2ParamsWrapper::<ark_bn254::Fq2Parameters>>::new(
			ark_ff::Fp256::<ark_bn254::FqParameters>::new(BigInteger256::new([8118044473652503376,3972860392159575080, 18001970451461929197, 2745036824307698284])), 
			ark_ff::Fp256::<ark_bn254::FqParameters>::new(BigInteger256::new([4725386799586988925,14574985519548118755, 13381024364756754960, 538854701215780983])) 
 		)
 	)
}

pub fn get_gamma_g2_neg_pc_12() -> (QuadExtField::<ark_ff::Fp2ParamsWrapper::<ark_bn254::Fq2Parameters>>, QuadExtField::<ark_ff::Fp2ParamsWrapper::<ark_bn254::Fq2Parameters>>, QuadExtField::<ark_ff::Fp2ParamsWrapper::<ark_bn254::Fq2Parameters>>) { 
 	(QuadExtField::<ark_ff::Fp2ParamsWrapper::<ark_bn254::Fq2Parameters>>::new(
			ark_ff::Fp256::<ark_bn254::FqParameters>::new(BigInteger256::new([10199245236306392455,18140621211891476488, 4758321317734916393, 3144595063115386286])), 
			ark_ff::Fp256::<ark_bn254::FqParameters>::new(BigInteger256::new([14898452150870613763,9487660811820973703, 13785334839928419928, 351263958619809824])) 
		),
		QuadExtField::<ark_ff::Fp2ParamsWrapper::<ark_bn254::Fq2Parameters>>::new(
			ark_ff::Fp256::<ark_bn254::FqParameters>::new(BigInteger256::new([12097172679406209335,14002882918970300028, 2452894575293828397, 1019803998844768462])), 
			ark_ff::Fp256::<ark_bn254::FqParameters>::new(BigInteger256::new([17022629186635173232,14815794137094443759, 59147758509713347, 1324693871018383428])) 
		),
		QuadExtField::<ark_ff::Fp2ParamsWrapper::<ark_bn254::Fq2Parameters>>::new(
			ark_ff::Fp256::<ark_bn254::FqParameters>::new(BigInteger256::new([13003006006967630185,14689187664240821004, 10937745255676672023, 2663930550530023819])), 
			ark_ff::Fp256::<ark_bn254::FqParameters>::new(BigInteger256::new([5770922591673404829,8464599943760791237, 7093877099597617034, 2738298317153082672])) 
 		)
 	)
}

pub fn get_gamma_g2_neg_pc_13() -> (QuadExtField::<ark_ff::Fp2ParamsWrapper::<ark_bn254::Fq2Parameters>>, QuadExtField::<ark_ff::Fp2ParamsWrapper::<ark_bn254::Fq2Parameters>>, QuadExtField::<ark_ff::Fp2ParamsWrapper::<ark_bn254::Fq2Parameters>>) { 
 	(QuadExtField::<ark_ff::Fp2ParamsWrapper::<ark_bn254::Fq2Parameters>>::new(
			ark_ff::Fp256::<ark_bn254::FqParameters>::new(BigInteger256::new([11109750628247559454,8796276775406286878, 11575195341794891410, 2389857922287860645])), 
			ark_ff::Fp256::<ark_bn254::FqParameters>::new(BigInteger256::new([13291332001938437743,15968693862995949189, 1331609001848773732, 845105697173110174])) 
		),
		QuadExtField::<ark_ff::Fp2ParamsWrapper::<ark_bn254::Fq2Parameters>>::new(
			ark_ff::Fp256::<ark_bn254::FqParameters>::new(BigInteger256::new([5555725135990097571,8359307485281021078, 17868686353996897266, 2838730614700819494])), 
			ark_ff::Fp256::<ark_bn254::FqParameters>::new(BigInteger256::new([4036007270005950917,16917628883665513001, 1930259442491108057, 1741332669860380942])) 
		),
		QuadExtField::<ark_ff::Fp2ParamsWrapper::<ark_bn254::Fq2Parameters>>::new(
			ark_ff::Fp256::<ark_bn254::FqParameters>::new(BigInteger256::new([5586692354362542943,651837647162159424, 8691242988124936691, 1385349058473676796])), 
			ark_ff::Fp256::<ark_bn254::FqParameters>::new(BigInteger256::new([2457040721467392298,10123092148601827012, 5912322787897649567, 1752588162218680612])) 
 		)
 	)
}

pub fn get_gamma_g2_neg_pc_14() -> (QuadExtField::<ark_ff::Fp2ParamsWrapper::<ark_bn254::Fq2Parameters>>, QuadExtField::<ark_ff::Fp2ParamsWrapper::<ark_bn254::Fq2Parameters>>, QuadExtField::<ark_ff::Fp2ParamsWrapper::<ark_bn254::Fq2Parameters>>) { 
 	(QuadExtField::<ark_ff::Fp2ParamsWrapper::<ark_bn254::Fq2Parameters>>::new(
			ark_ff::Fp256::<ark_bn254::FqParameters>::new(BigInteger256::new([13776818487199148544,16428840051404012162, 14603768868797311081, 39026270245661099])), 
			ark_ff::Fp256::<ark_bn254::FqParameters>::new(BigInteger256::new([7371453859000933441,2748883790921104569, 16310673174402031236, 1649547947142404824])) 
		),
		QuadExtField::<ark_ff::Fp2ParamsWrapper::<ark_bn254::Fq2Parameters>>::new(
			ark_ff::Fp256::<ark_bn254::FqParameters>::new(BigInteger256::new([16121307008453781352,8906102328050185959, 17170323266801431782, 1788962652510781744])), 
			ark_ff::Fp256::<ark_bn254::FqParameters>::new(BigInteger256::new([16877358414327449982,18399747750372623931, 9773243898135209257, 725551178318164664])) 
		),
		QuadExtField::<ark_ff::Fp2ParamsWrapper::<ark_bn254::Fq2Parameters>>::new(
			ark_ff::Fp256::<ark_bn254::FqParameters>::new(BigInteger256::new([14713002840501485040,8246605639474105338, 229732633260237634, 2530982615656977995])), 
			ark_ff::Fp256::<ark_bn254::FqParameters>::new(BigInteger256::new([17357685569203809992,10404152319868930450, 2604386299360141600, 2334543948983597560])) 
 		)
 	)
}

pub fn get_gamma_g2_neg_pc_15() -> (QuadExtField::<ark_ff::Fp2ParamsWrapper::<ark_bn254::Fq2Parameters>>, QuadExtField::<ark_ff::Fp2ParamsWrapper::<ark_bn254::Fq2Parameters>>, QuadExtField::<ark_ff::Fp2ParamsWrapper::<ark_bn254::Fq2Parameters>>) { 
 	(QuadExtField::<ark_ff::Fp2ParamsWrapper::<ark_bn254::Fq2Parameters>>::new(
			ark_ff::Fp256::<ark_bn254::FqParameters>::new(BigInteger256::new([270623735424609756,14918163881616265516, 14901762973229713371, 2337283132865193098])), 
			ark_ff::Fp256::<ark_bn254::FqParameters>::new(BigInteger256::new([6292997584620635612,2144833437084895902, 2134378183304920992, 3349347073273767152])) 
		),
		QuadExtField::<ark_ff::Fp2ParamsWrapper::<ark_bn254::Fq2Parameters>>::new(
			ark_ff::Fp256::<ark_bn254::FqParameters>::new(BigInteger256::new([17676547966088076883,458753872429696841, 11761259982572545257, 3267428759105239811])), 
			ark_ff::Fp256::<ark_bn254::FqParameters>::new(BigInteger256::new([2601818228172458045,15632739716319475472, 7593190040129529217, 2528421024446889529])) 
		),
		QuadExtField::<ark_ff::Fp2ParamsWrapper::<ark_bn254::Fq2Parameters>>::new(
			ark_ff::Fp256::<ark_bn254::FqParameters>::new(BigInteger256::new([52081136084281038,17559799843074941902, 15222581854534887623, 3101497702803168821])), 
			ark_ff::Fp256::<ark_bn254::FqParameters>::new(BigInteger256::new([8837388507886040524,7044691055583544131, 2985446620859937354, 1889381831823009255])) 
 		)
 	)
}

pub fn get_gamma_g2_neg_pc_16() -> (QuadExtField::<ark_ff::Fp2ParamsWrapper::<ark_bn254::Fq2Parameters>>, QuadExtField::<ark_ff::Fp2ParamsWrapper::<ark_bn254::Fq2Parameters>>, QuadExtField::<ark_ff::Fp2ParamsWrapper::<ark_bn254::Fq2Parameters>>) { 
 	(QuadExtField::<ark_ff::Fp2ParamsWrapper::<ark_bn254::Fq2Parameters>>::new(
			ark_ff::Fp256::<ark_bn254::FqParameters>::new(BigInteger256::new([9331137865173431579,5914118189199684899, 5777934102313478341, 1570348050393075155])), 
			ark_ff::Fp256::<ark_bn254::FqParameters>::new(BigInteger256::new([17058892582591333113,16526401512954505844, 6833232030632977913, 1570516692309383007])) 
		),
		QuadExtField::<ark_ff::Fp2ParamsWrapper::<ark_bn254::Fq2Parameters>>::new(
			ark_ff::Fp256::<ark_bn254::FqParameters>::new(BigInteger256::new([7342966309815578438,7537828808518296880, 5113539973391917665, 810797381146315792])), 
			ark_ff::Fp256::<ark_bn254::FqParameters>::new(BigInteger256::new([3323792432157577081,2371595650129315298, 16221184478425155365, 599359364534113446])) 
		),
		QuadExtField::<ark_ff::Fp2ParamsWrapper::<ark_bn254::Fq2Parameters>>::new(
			ark_ff::Fp256::<ark_bn254::FqParameters>::new(BigInteger256::new([2335360793943989129,5186525376473818449, 675441685282991805, 1469820100822170111])), 
			ark_ff::Fp256::<ark_bn254::FqParameters>::new(BigInteger256::new([8447861390500647265,13887404727194987414, 7208527949506320237, 2218806390448196634])) 
 		)
 	)
}

pub fn get_gamma_g2_neg_pc_17() -> (QuadExtField::<ark_ff::Fp2ParamsWrapper::<ark_bn254::Fq2Parameters>>, QuadExtField::<ark_ff::Fp2ParamsWrapper::<ark_bn254::Fq2Parameters>>, QuadExtField::<ark_ff::Fp2ParamsWrapper::<ark_bn254::Fq2Parameters>>) { 
 	(QuadExtField::<ark_ff::Fp2ParamsWrapper::<ark_bn254::Fq2Parameters>>::new(
			ark_ff::Fp256::<ark_bn254::FqParameters>::new(BigInteger256::new([8504167964167229421,1987673739983219397, 15695548489679160881, 1269388259138855172])), 
			ark_ff::Fp256::<ark_bn254::FqParameters>::new(BigInteger256::new([5699164409608181082,16943870829256571249, 642982170715230164, 2338598723983685377])) 
		),
		QuadExtField::<ark_ff::Fp2ParamsWrapper::<ark_bn254::Fq2Parameters>>::new(
			ark_ff::Fp256::<ark_bn254::FqParameters>::new(BigInteger256::new([8041715062708232481,6181628535962690722, 16687549753794234249, 2408128973977932429])), 
			ark_ff::Fp256::<ark_bn254::FqParameters>::new(BigInteger256::new([2642837507779895735,9929455706859507264, 16516509058985299986, 3137964488796391471])) 
		),
		QuadExtField::<ark_ff::Fp2ParamsWrapper::<ark_bn254::Fq2Parameters>>::new(
			ark_ff::Fp256::<ark_bn254::FqParameters>::new(BigInteger256::new([12562973452466521228,3911010946243569277, 16590246008846385690, 3416585279284380113])), 
			ark_ff::Fp256::<ark_bn254::FqParameters>::new(BigInteger256::new([11979507484866195887,17305143414537139887, 8613122189781079270, 2945902600826310694])) 
 		)
 	)
}

pub fn get_gamma_g2_neg_pc_18() -> (QuadExtField::<ark_ff::Fp2ParamsWrapper::<ark_bn254::Fq2Parameters>>, QuadExtField::<ark_ff::Fp2ParamsWrapper::<ark_bn254::Fq2Parameters>>, QuadExtField::<ark_ff::Fp2ParamsWrapper::<ark_bn254::Fq2Parameters>>) { 
 	(QuadExtField::<ark_ff::Fp2ParamsWrapper::<ark_bn254::Fq2Parameters>>::new(
			ark_ff::Fp256::<ark_bn254::FqParameters>::new(BigInteger256::new([9333838327472285682,9617868530653233744, 4816427301812528335, 2048661490922076411])), 
			ark_ff::Fp256::<ark_bn254::FqParameters>::new(BigInteger256::new([17618791627439204140,10703376339490122766, 10683950770439504307, 1218489958915303876])) 
		),
		QuadExtField::<ark_ff::Fp2ParamsWrapper::<ark_bn254::Fq2Parameters>>::new(
			ark_ff::Fp256::<ark_bn254::FqParameters>::new(BigInteger256::new([9243463686563249205,65292291085296869, 7672861835806619808, 1094869345595923609])), 
			ark_ff::Fp256::<ark_bn254::FqParameters>::new(BigInteger256::new([10948739580193828120,7308298784673390599, 11981784362067666487, 3240665762926479152])) 
		),
		QuadExtField::<ark_ff::Fp2ParamsWrapper::<ark_bn254::Fq2Parameters>>::new(
			ark_ff::Fp256::<ark_bn254::FqParameters>::new(BigInteger256::new([6203610873777967397,2738951366607438922, 15888588011766250519, 2916760111404819866])), 
			ark_ff::Fp256::<ark_bn254::FqParameters>::new(BigInteger256::new([8262436935845292140,9312906657530830944, 6342771037362748205, 1659944025525149408])) 
 		)
 	)
}

pub fn get_gamma_g2_neg_pc_19() -> (QuadExtField::<ark_ff::Fp2ParamsWrapper::<ark_bn254::Fq2Parameters>>, QuadExtField::<ark_ff::Fp2ParamsWrapper::<ark_bn254::Fq2Parameters>>, QuadExtField::<ark_ff::Fp2ParamsWrapper::<ark_bn254::Fq2Parameters>>) { 
 	(QuadExtField::<ark_ff::Fp2ParamsWrapper::<ark_bn254::Fq2Parameters>>::new(
			ark_ff::Fp256::<ark_bn254::FqParameters>::new(BigInteger256::new([18215517424930349890,5840556657713931368, 9726407883960506993, 2733222446438796815])), 
			ark_ff::Fp256::<ark_bn254::FqParameters>::new(BigInteger256::new([18417881114284240262,2482139030217700749, 12651144484493938070, 1778102854459179110])) 
		),
		QuadExtField::<ark_ff::Fp2ParamsWrapper::<ark_bn254::Fq2Parameters>>::new(
			ark_ff::Fp256::<ark_bn254::FqParameters>::new(BigInteger256::new([1917567522355933632,3472920225926259847, 11627235905984107810, 1299194979255028525])), 
			ark_ff::Fp256::<ark_bn254::FqParameters>::new(BigInteger256::new([2734437922946594316,10025277329724169898, 5235261717006898493, 1327260968417511176])) 
		),
		QuadExtField::<ark_ff::Fp2ParamsWrapper::<ark_bn254::Fq2Parameters>>::new(
			ark_ff::Fp256::<ark_bn254::FqParameters>::new(BigInteger256::new([10250183287278618915,4151673337958646318, 17710617657432679854, 293291523528482704])), 
			ark_ff::Fp256::<ark_bn254::FqParameters>::new(BigInteger256::new([18320702472934346261,16514596468241182434, 16851076470380498635, 124666343977784341])) 
 		)
 	)
}

pub fn get_gamma_g2_neg_pc_20() -> (QuadExtField::<ark_ff::Fp2ParamsWrapper::<ark_bn254::Fq2Parameters>>, QuadExtField::<ark_ff::Fp2ParamsWrapper::<ark_bn254::Fq2Parameters>>, QuadExtField::<ark_ff::Fp2ParamsWrapper::<ark_bn254::Fq2Parameters>>) { 
 	(QuadExtField::<ark_ff::Fp2ParamsWrapper::<ark_bn254::Fq2Parameters>>::new(
			ark_ff::Fp256::<ark_bn254::FqParameters>::new(BigInteger256::new([12524438342549689577,5459481667655562933, 2221836122553761812, 2705195649187196137])), 
			ark_ff::Fp256::<ark_bn254::FqParameters>::new(BigInteger256::new([15909703146204720789,12131145516101663775, 8211724729294568100, 1505061990392751464])) 
		),
		QuadExtField::<ark_ff::Fp2ParamsWrapper::<ark_bn254::Fq2Parameters>>::new(
			ark_ff::Fp256::<ark_bn254::FqParameters>::new(BigInteger256::new([3226095913684730576,6186281304628777765, 14402556762457030217, 358278747336173175])), 
			ark_ff::Fp256::<ark_bn254::FqParameters>::new(BigInteger256::new([12039415121966808908,5900712388241029694, 1602599201193736784, 1815031710939884417])) 
		),
		QuadExtField::<ark_ff::Fp2ParamsWrapper::<ark_bn254::Fq2Parameters>>::new(
			ark_ff::Fp256::<ark_bn254::FqParameters>::new(BigInteger256::new([9512238475105550544,5874643446923927502, 12215691537564421078, 3056989570116418167])), 
			ark_ff::Fp256::<ark_bn254::FqParameters>::new(BigInteger256::new([10175333386773080829,11724856316761978061, 3360793854081019486, 2320196409143829544])) 
 		)
 	)
}

pub fn get_gamma_g2_neg_pc_21() -> (QuadExtField::<ark_ff::Fp2ParamsWrapper::<ark_bn254::Fq2Parameters>>, QuadExtField::<ark_ff::Fp2ParamsWrapper::<ark_bn254::Fq2Parameters>>, QuadExtField::<ark_ff::Fp2ParamsWrapper::<ark_bn254::Fq2Parameters>>) { 
 	(QuadExtField::<ark_ff::Fp2ParamsWrapper::<ark_bn254::Fq2Parameters>>::new(
			ark_ff::Fp256::<ark_bn254::FqParameters>::new(BigInteger256::new([3448963930128990034,12901635784669426942, 7828660345994972202, 2116947423036271518])), 
			ark_ff::Fp256::<ark_bn254::FqParameters>::new(BigInteger256::new([9414229755864789752,17757293741410830478, 4382661608433947301, 238452403777729495])) 
		),
		QuadExtField::<ark_ff::Fp2ParamsWrapper::<ark_bn254::Fq2Parameters>>::new(
			ark_ff::Fp256::<ark_bn254::FqParameters>::new(BigInteger256::new([6037166602713789517,16155624344065464919, 3981335822407313408, 846547834482100606])), 
			ark_ff::Fp256::<ark_bn254::FqParameters>::new(BigInteger256::new([6703252619463926074,11776578003599003015, 9239601730106065788, 2065465790354154486])) 
		),
		QuadExtField::<ark_ff::Fp2ParamsWrapper::<ark_bn254::Fq2Parameters>>::new(
			ark_ff::Fp256::<ark_bn254::FqParameters>::new(BigInteger256::new([5126522199413229057,9866650836818007137, 9913248993236841148, 1875131280615191969])), 
			ark_ff::Fp256::<ark_bn254::FqParameters>::new(BigInteger256::new([17103899062020561889,16231513481229464812, 12555789897688984844, 2304275733230114852])) 
 		)
 	)
}

pub fn get_gamma_g2_neg_pc_22() -> (QuadExtField::<ark_ff::Fp2ParamsWrapper::<ark_bn254::Fq2Parameters>>, QuadExtField::<ark_ff::Fp2ParamsWrapper::<ark_bn254::Fq2Parameters>>, QuadExtField::<ark_ff::Fp2ParamsWrapper::<ark_bn254::Fq2Parameters>>) { 
 	(QuadExtField::<ark_ff::Fp2ParamsWrapper::<ark_bn254::Fq2Parameters>>::new(
			ark_ff::Fp256::<ark_bn254::FqParameters>::new(BigInteger256::new([287109964313747249,11413262288885818636, 2780078482931684748, 390486440201454578])), 
			ark_ff::Fp256::<ark_bn254::FqParameters>::new(BigInteger256::new([18441510591766573402,7220632814781873578, 9367905646664557674, 50888335744684078])) 
		),
		QuadExtField::<ark_ff::Fp2ParamsWrapper::<ark_bn254::Fq2Parameters>>::new(
			ark_ff::Fp256::<ark_bn254::FqParameters>::new(BigInteger256::new([5123043798498298775,14258897169578363292, 8639034688359796122, 1307358757862109190])), 
			ark_ff::Fp256::<ark_bn254::FqParameters>::new(BigInteger256::new([9949337711694557619,4190678447805837035, 3030679323270283036, 246924042674169612])) 
		),
		QuadExtField::<ark_ff::Fp2ParamsWrapper::<ark_bn254::Fq2Parameters>>::new(
			ark_ff::Fp256::<ark_bn254::FqParameters>::new(BigInteger256::new([9612367799524911901,13944124324546598759, 3933530899587146181, 3447805002723971132])), 
			ark_ff::Fp256::<ark_bn254::FqParameters>::new(BigInteger256::new([8480116776824046264,12370791869108421604, 9243542121437243874, 562931378724632129])) 
 		)
 	)
}

pub fn get_gamma_g2_neg_pc_23() -> (QuadExtField::<ark_ff::Fp2ParamsWrapper::<ark_bn254::Fq2Parameters>>, QuadExtField::<ark_ff::Fp2ParamsWrapper::<ark_bn254::Fq2Parameters>>, QuadExtField::<ark_ff::Fp2ParamsWrapper::<ark_bn254::Fq2Parameters>>) { 
 	(QuadExtField::<ark_ff::Fp2ParamsWrapper::<ark_bn254::Fq2Parameters>>::new(
			ark_ff::Fp256::<ark_bn254::FqParameters>::new(BigInteger256::new([6819347212443508627,14380817956009020122, 11490613643786868874, 2675884994885701690])), 
			ark_ff::Fp256::<ark_bn254::FqParameters>::new(BigInteger256::new([8539140479632408989,8194211470684079269, 2077135028506898385, 524589038608530199])) 
		),
		QuadExtField::<ark_ff::Fp2ParamsWrapper::<ark_bn254::Fq2Parameters>>::new(
			ark_ff::Fp256::<ark_bn254::FqParameters>::new(BigInteger256::new([7238320634589634943,2810869298491860188, 18190823316940059167, 601328476248575923])), 
			ark_ff::Fp256::<ark_bn254::FqParameters>::new(BigInteger256::new([17330135560310379025,13326842942671423959, 14192570876734829607, 3187189158523402450])) 
		),
		QuadExtField::<ark_ff::Fp2ParamsWrapper::<ark_bn254::Fq2Parameters>>::new(
			ark_ff::Fp256::<ark_bn254::FqParameters>::new(BigInteger256::new([7347441058293950809,2381654992628648694, 12283127418585427050, 554127190895867299])), 
			ark_ff::Fp256::<ark_bn254::FqParameters>::new(BigInteger256::new([14525920750940424436,6251376237155514255, 9119745497840928963, 3026137110213085883])) 
 		)
 	)
}

pub fn get_gamma_g2_neg_pc_24() -> (QuadExtField::<ark_ff::Fp2ParamsWrapper::<ark_bn254::Fq2Parameters>>, QuadExtField::<ark_ff::Fp2ParamsWrapper::<ark_bn254::Fq2Parameters>>, QuadExtField::<ark_ff::Fp2ParamsWrapper::<ark_bn254::Fq2Parameters>>) { 
 	(QuadExtField::<ark_ff::Fp2ParamsWrapper::<ark_bn254::Fq2Parameters>>::new(
			ark_ff::Fp256::<ark_bn254::FqParameters>::new(BigInteger256::new([2415338884681002846,2912680339196872922, 11710442952716234915, 1744538961600730111])), 
			ark_ff::Fp256::<ark_bn254::FqParameters>::new(BigInteger256::new([713726665293542916,16116446517150523815, 7301716985417093672, 646541849301241213])) 
		),
		QuadExtField::<ark_ff::Fp2ParamsWrapper::<ark_bn254::Fq2Parameters>>::new(
			ark_ff::Fp256::<ark_bn254::FqParameters>::new(BigInteger256::new([2802651880837342007,15264407571275126130, 11482219452212366791, 2580029176521980262])), 
			ark_ff::Fp256::<ark_bn254::FqParameters>::new(BigInteger256::new([8051384972651499709,13509097628089186570, 15987139753249728088, 1724821564430626417])) 
		),
		QuadExtField::<ark_ff::Fp2ParamsWrapper::<ark_bn254::Fq2Parameters>>::new(
			ark_ff::Fp256::<ark_bn254::FqParameters>::new(BigInteger256::new([8664415540163095049,12168471377940660156, 10660581930556816542, 2985417154117979585])), 
			ark_ff::Fp256::<ark_bn254::FqParameters>::new(BigInteger256::new([7215323165745287777,17512809659064767494, 12967761364295926488, 1156086464150001555])) 
 		)
 	)
}

pub fn get_gamma_g2_neg_pc_25() -> (QuadExtField::<ark_ff::Fp2ParamsWrapper::<ark_bn254::Fq2Parameters>>, QuadExtField::<ark_ff::Fp2ParamsWrapper::<ark_bn254::Fq2Parameters>>, QuadExtField::<ark_ff::Fp2ParamsWrapper::<ark_bn254::Fq2Parameters>>) { 
 	(QuadExtField::<ark_ff::Fp2ParamsWrapper::<ark_bn254::Fq2Parameters>>::new(
			ark_ff::Fp256::<ark_bn254::FqParameters>::new(BigInteger256::new([5847020509332917002,16107840255528183857, 13424777394943063602, 1118213906854175275])), 
			ark_ff::Fp256::<ark_bn254::FqParameters>::new(BigInteger256::new([7302759526184944596,13438215651397792756, 17503339316445158656, 2803489848961804495])) 
		),
		QuadExtField::<ark_ff::Fp2ParamsWrapper::<ark_bn254::Fq2Parameters>>::new(
			ark_ff::Fp256::<ark_bn254::FqParameters>::new(BigInteger256::new([16118693761543242214,539489330238339253, 8780338381895319476, 3091216389784702423])), 
			ark_ff::Fp256::<ark_bn254::FqParameters>::new(BigInteger256::new([3819222424053953391,9484305177404131071, 4427467557402947400, 1081013420385521109])) 
		),
		QuadExtField::<ark_ff::Fp2ParamsWrapper::<ark_bn254::Fq2Parameters>>::new(
			ark_ff::Fp256::<ark_bn254::FqParameters>::new(BigInteger256::new([3197682013228612250,14100609499874712157, 13041169619542001726, 3150877883620438330])), 
			ark_ff::Fp256::<ark_bn254::FqParameters>::new(BigInteger256::new([15031901740242069817,11552635673714776172, 13108773350990590777, 1584779323744170842])) 
 		)
 	)
}

pub fn get_gamma_g2_neg_pc_26() -> (QuadExtField::<ark_ff::Fp2ParamsWrapper::<ark_bn254::Fq2Parameters>>, QuadExtField::<ark_ff::Fp2ParamsWrapper::<ark_bn254::Fq2Parameters>>, QuadExtField::<ark_ff::Fp2ParamsWrapper::<ark_bn254::Fq2Parameters>>) { 
 	(QuadExtField::<ark_ff::Fp2ParamsWrapper::<ark_bn254::Fq2Parameters>>::new(
			ark_ff::Fp256::<ark_bn254::FqParameters>::new(BigInteger256::new([7736666091845641957,18358818191766746013, 1679233114620004144, 375335990723118298])), 
			ark_ff::Fp256::<ark_bn254::FqParameters>::new(BigInteger256::new([17733721025036990864,6393003824585435020, 13936297069596663203, 1893327663359801799])) 
		),
		QuadExtField::<ark_ff::Fp2ParamsWrapper::<ark_bn254::Fq2Parameters>>::new(
			ark_ff::Fp256::<ark_bn254::FqParameters>::new(BigInteger256::new([18093693628223309491,17936637473177723327, 8003761580206033133, 2282159549033336541])), 
			ark_ff::Fp256::<ark_bn254::FqParameters>::new(BigInteger256::new([13237504704449068028,4438394540129058755, 1419876011796052562, 322554199750204231])) 
		),
		QuadExtField::<ark_ff::Fp2ParamsWrapper::<ark_bn254::Fq2Parameters>>::new(
			ark_ff::Fp256::<ark_bn254::FqParameters>::new(BigInteger256::new([2749757163456989388,3040049802220625708, 12838925560779984220, 3418584958513450119])), 
			ark_ff::Fp256::<ark_bn254::FqParameters>::new(BigInteger256::new([14131965388775222832,10546007623566370784, 4986128003727216251, 1822858366434246446])) 
 		)
 	)
}

pub fn get_gamma_g2_neg_pc_27() -> (QuadExtField::<ark_ff::Fp2ParamsWrapper::<ark_bn254::Fq2Parameters>>, QuadExtField::<ark_ff::Fp2ParamsWrapper::<ark_bn254::Fq2Parameters>>, QuadExtField::<ark_ff::Fp2ParamsWrapper::<ark_bn254::Fq2Parameters>>) { 
 	(QuadExtField::<ark_ff::Fp2ParamsWrapper::<ark_bn254::Fq2Parameters>>::new(
			ark_ff::Fp256::<ark_bn254::FqParameters>::new(BigInteger256::new([16609168794555169316,16493659075023120097, 11085579940439096654, 3058228494886721962])), 
			ark_ff::Fp256::<ark_bn254::FqParameters>::new(BigInteger256::new([6282040349389757097,14665126689889831816, 47941081847894345, 1159320964236639124])) 
		),
		QuadExtField::<ark_ff::Fp2ParamsWrapper::<ark_bn254::Fq2Parameters>>::new(
			ark_ff::Fp256::<ark_bn254::FqParameters>::new(BigInteger256::new([10106442699566474898,15481463452236569372, 2216549774949871936, 3214875185114687074])), 
			ark_ff::Fp256::<ark_bn254::FqParameters>::new(BigInteger256::new([12559738513751922886,11635511430638918878, 5707967392493025109, 2697916725532091242])) 
		),
		QuadExtField::<ark_ff::Fp2ParamsWrapper::<ark_bn254::Fq2Parameters>>::new(
			ark_ff::Fp256::<ark_bn254::FqParameters>::new(BigInteger256::new([14166363440832640524,2696326784354862706, 14232084503259944463, 1343655363295586643])), 
			ark_ff::Fp256::<ark_bn254::FqParameters>::new(BigInteger256::new([3968375579488864249,5891246078049120946, 5881896279230690117, 2297090914499491897])) 
 		)
 	)
}

pub fn get_gamma_g2_neg_pc_28() -> (QuadExtField::<ark_ff::Fp2ParamsWrapper::<ark_bn254::Fq2Parameters>>, QuadExtField::<ark_ff::Fp2ParamsWrapper::<ark_bn254::Fq2Parameters>>, QuadExtField::<ark_ff::Fp2ParamsWrapper::<ark_bn254::Fq2Parameters>>) { 
 	(QuadExtField::<ark_ff::Fp2ParamsWrapper::<ark_bn254::Fq2Parameters>>::new(
			ark_ff::Fp256::<ark_bn254::FqParameters>::new(BigInteger256::new([12796089133672114267,13701325530126098697, 8552244792200768737, 251608614261995397])), 
			ark_ff::Fp256::<ark_bn254::FqParameters>::new(BigInteger256::new([1739651274117659838,10383924183274804335, 1232401508593539744, 3192787264745467455])) 
		),
		QuadExtField::<ark_ff::Fp2ParamsWrapper::<ark_bn254::Fq2Parameters>>::new(
			ark_ff::Fp256::<ark_bn254::FqParameters>::new(BigInteger256::new([16131052045340976757,7521662895573958583, 4066729838210315437, 3246864608797333303])), 
			ark_ff::Fp256::<ark_bn254::FqParameters>::new(BigInteger256::new([3556682161449420215,4447305674296501708, 16756527478588630418, 1611660486408356589])) 
		),
		QuadExtField::<ark_ff::Fp2ParamsWrapper::<ark_bn254::Fq2Parameters>>::new(
			ark_ff::Fp256::<ark_bn254::FqParameters>::new(BigInteger256::new([17007742788691177755,8528942540112163609, 12106460327544228034, 1689339426891782604])), 
			ark_ff::Fp256::<ark_bn254::FqParameters>::new(BigInteger256::new([17788581739690298860,18079010206976808141, 11311196041425439257, 3128397073005990618])) 
 		)
 	)
}

pub fn get_gamma_g2_neg_pc_29() -> (QuadExtField::<ark_ff::Fp2ParamsWrapper::<ark_bn254::Fq2Parameters>>, QuadExtField::<ark_ff::Fp2ParamsWrapper::<ark_bn254::Fq2Parameters>>, QuadExtField::<ark_ff::Fp2ParamsWrapper::<ark_bn254::Fq2Parameters>>) { 
 	(QuadExtField::<ark_ff::Fp2ParamsWrapper::<ark_bn254::Fq2Parameters>>::new(
			ark_ff::Fp256::<ark_bn254::FqParameters>::new(BigInteger256::new([7399514695810299876,15915840024206767881, 7861964664907148309, 3128730485594524316])), 
			ark_ff::Fp256::<ark_bn254::FqParameters>::new(BigInteger256::new([446723938111159206,1287246602372247874, 4703622397805887749, 2094720261554967625])) 
		),
		QuadExtField::<ark_ff::Fp2ParamsWrapper::<ark_bn254::Fq2Parameters>>::new(
			ark_ff::Fp256::<ark_bn254::FqParameters>::new(BigInteger256::new([14360350713707645204,16896621100042785798, 12877008806139365476, 856443816251001523])), 
			ark_ff::Fp256::<ark_bn254::FqParameters>::new(BigInteger256::new([12227319666002125525,16680200133876766018, 4570629093810756863, 128061889664448605])) 
		),
		QuadExtField::<ark_ff::Fp2ParamsWrapper::<ark_bn254::Fq2Parameters>>::new(
			ark_ff::Fp256::<ark_bn254::FqParameters>::new(BigInteger256::new([7638453536790487049,13445264415522465708, 8959408682309985432, 3425125355783343221])), 
			ark_ff::Fp256::<ark_bn254::FqParameters>::new(BigInteger256::new([4941642995010997310,6415545896376924726, 6286639352509907220, 1166330931770153584])) 
 		)
 	)
}

pub fn get_gamma_g2_neg_pc_30() -> (QuadExtField::<ark_ff::Fp2ParamsWrapper::<ark_bn254::Fq2Parameters>>, QuadExtField::<ark_ff::Fp2ParamsWrapper::<ark_bn254::Fq2Parameters>>, QuadExtField::<ark_ff::Fp2ParamsWrapper::<ark_bn254::Fq2Parameters>>) { 
 	(QuadExtField::<ark_ff::Fp2ParamsWrapper::<ark_bn254::Fq2Parameters>>::new(
			ark_ff::Fp256::<ark_bn254::FqParameters>::new(BigInteger256::new([4138536755720428249,16213310326368166523, 14764021647284744860, 2364884853001270249])), 
			ark_ff::Fp256::<ark_bn254::FqParameters>::new(BigInteger256::new([18155959633571591871,16139433975535113501, 435080588100196060, 910213465518351194])) 
		),
		QuadExtField::<ark_ff::Fp2ParamsWrapper::<ark_bn254::Fq2Parameters>>::new(
			ark_ff::Fp256::<ark_bn254::FqParameters>::new(BigInteger256::new([7662805989174451489,13192898642512506288, 9837691826938349091, 996548280215820609])), 
			ark_ff::Fp256::<ark_bn254::FqParameters>::new(BigInteger256::new([14641212265627999576,9971000290503377956, 18325498896227450631, 49306008440482674])) 
		),
		QuadExtField::<ark_ff::Fp2ParamsWrapper::<ark_bn254::Fq2Parameters>>::new(
			ark_ff::Fp256::<ark_bn254::FqParameters>::new(BigInteger256::new([14987163974283789123,15369367139258711381, 4805108040536182164, 865389779847616075])), 
			ark_ff::Fp256::<ark_bn254::FqParameters>::new(BigInteger256::new([12780902668628266944,4670264411791925444, 914787537407591974, 2802652746619412481])) 
 		)
 	)
}

pub fn get_gamma_g2_neg_pc_31() -> (QuadExtField::<ark_ff::Fp2ParamsWrapper::<ark_bn254::Fq2Parameters>>, QuadExtField::<ark_ff::Fp2ParamsWrapper::<ark_bn254::Fq2Parameters>>, QuadExtField::<ark_ff::Fp2ParamsWrapper::<ark_bn254::Fq2Parameters>>) { 
 	(QuadExtField::<ark_ff::Fp2ParamsWrapper::<ark_bn254::Fq2Parameters>>::new(
			ark_ff::Fp256::<ark_bn254::FqParameters>::new(BigInteger256::new([1543219374122905771,8090450085994893608, 8765342238743279456, 2645906120949195560])), 
			ark_ff::Fp256::<ark_bn254::FqParameters>::new(BigInteger256::new([10590034945958063776,2148406424358347708, 11445056787421280387, 210343342343922388])) 
		),
		QuadExtField::<ark_ff::Fp2ParamsWrapper::<ark_bn254::Fq2Parameters>>::new(
			ark_ff::Fp256::<ark_bn254::FqParameters>::new(BigInteger256::new([84160011354238373,13765682145630609955, 7800796773103963386, 1406300471758320952])), 
			ark_ff::Fp256::<ark_bn254::FqParameters>::new(BigInteger256::new([710490933452581864,18193564024607700386, 3400943045746472605, 9575821229388628])) 
		),
		QuadExtField::<ark_ff::Fp2ParamsWrapper::<ark_bn254::Fq2Parameters>>::new(
			ark_ff::Fp256::<ark_bn254::FqParameters>::new(BigInteger256::new([17760125995096386084,11664557531912333499, 13522375229170762481, 375777927578750945])), 
			ark_ff::Fp256::<ark_bn254::FqParameters>::new(BigInteger256::new([12565086070997357285,9691086342514185574, 11509833649633872030, 1610814813808774869])) 
 		)
 	)
}

pub fn get_gamma_g2_neg_pc_32() -> (QuadExtField::<ark_ff::Fp2ParamsWrapper::<ark_bn254::Fq2Parameters>>, QuadExtField::<ark_ff::Fp2ParamsWrapper::<ark_bn254::Fq2Parameters>>, QuadExtField::<ark_ff::Fp2ParamsWrapper::<ark_bn254::Fq2Parameters>>) { 
 	(QuadExtField::<ark_ff::Fp2ParamsWrapper::<ark_bn254::Fq2Parameters>>::new(
			ark_ff::Fp256::<ark_bn254::FqParameters>::new(BigInteger256::new([7291542090865801949,1577101696128872745, 17460728556119018831, 1481908667538396308])), 
			ark_ff::Fp256::<ark_bn254::FqParameters>::new(BigInteger256::new([11357486338903428945,9402931630429116071, 931417004746301649, 585421111836374602])) 
		),
		QuadExtField::<ark_ff::Fp2ParamsWrapper::<ark_bn254::Fq2Parameters>>::new(
			ark_ff::Fp256::<ark_bn254::FqParameters>::new(BigInteger256::new([18076471528705267126,5349588559294005231, 9256503960246701550, 1811180944784968872])), 
			ark_ff::Fp256::<ark_bn254::FqParameters>::new(BigInteger256::new([8344292930152609609,425056255882468959, 13425843550653486842, 264791131786334434])) 
		),
		QuadExtField::<ark_ff::Fp2ParamsWrapper::<ark_bn254::Fq2Parameters>>::new(
			ark_ff::Fp256::<ark_bn254::FqParameters>::new(BigInteger256::new([11086156574821929778,5292553283741095858, 12089065119319887245, 2319694087620793161])), 
			ark_ff::Fp256::<ark_bn254::FqParameters>::new(BigInteger256::new([4633273787664257371,7547310177033538971, 6601454254372768242, 2712998898483652673])) 
 		)
 	)
}

pub fn get_gamma_g2_neg_pc_33() -> (QuadExtField::<ark_ff::Fp2ParamsWrapper::<ark_bn254::Fq2Parameters>>, QuadExtField::<ark_ff::Fp2ParamsWrapper::<ark_bn254::Fq2Parameters>>, QuadExtField::<ark_ff::Fp2ParamsWrapper::<ark_bn254::Fq2Parameters>>) { 
 	(QuadExtField::<ark_ff::Fp2ParamsWrapper::<ark_bn254::Fq2Parameters>>::new(
			ark_ff::Fp256::<ark_bn254::FqParameters>::new(BigInteger256::new([15409796379905470930,7552359155329271944, 8707799418017204781, 2077799144247017100])), 
			ark_ff::Fp256::<ark_bn254::FqParameters>::new(BigInteger256::new([1542392928164153258,10603876708432473252, 10302427976007626990, 1603620034839836595])) 
		),
		QuadExtField::<ark_ff::Fp2ParamsWrapper::<ark_bn254::Fq2Parameters>>::new(
			ark_ff::Fp256::<ark_bn254::FqParameters>::new(BigInteger256::new([14244300257937697759,1487105642315742749, 9475997014904662615, 904186338103397177])), 
			ark_ff::Fp256::<ark_bn254::FqParameters>::new(BigInteger256::new([11713173046184750089,9160977860234461357, 6078171397054457180, 2002854249002367041])) 
		),
		QuadExtField::<ark_ff::Fp2ParamsWrapper::<ark_bn254::Fq2Parameters>>::new(
			ark_ff::Fp256::<ark_bn254::FqParameters>::new(BigInteger256::new([4780673991028727399,4569514823412893415, 16683474281454486792, 168860920449206376])), 
			ark_ff::Fp256::<ark_bn254::FqParameters>::new(BigInteger256::new([4445516531299081531,4336300495570212604, 15119934909769648988, 2113658241731487389])) 
 		)
 	)
}

pub fn get_gamma_g2_neg_pc_34() -> (QuadExtField::<ark_ff::Fp2ParamsWrapper::<ark_bn254::Fq2Parameters>>, QuadExtField::<ark_ff::Fp2ParamsWrapper::<ark_bn254::Fq2Parameters>>, QuadExtField::<ark_ff::Fp2ParamsWrapper::<ark_bn254::Fq2Parameters>>) { 
 	(QuadExtField::<ark_ff::Fp2ParamsWrapper::<ark_bn254::Fq2Parameters>>::new(
			ark_ff::Fp256::<ark_bn254::FqParameters>::new(BigInteger256::new([3739053348046568870,13759850316338548409, 13717292334514285466, 229901727331435613])), 
			ark_ff::Fp256::<ark_bn254::FqParameters>::new(BigInteger256::new([9837388131089352616,13837864382286695963, 16647339903286215086, 1392188083563275559])) 
		),
		QuadExtField::<ark_ff::Fp2ParamsWrapper::<ark_bn254::Fq2Parameters>>::new(
			ark_ff::Fp256::<ark_bn254::FqParameters>::new(BigInteger256::new([5614503646084565013,11539317751278873413, 15777690545326792255, 1179853794666144299])), 
			ark_ff::Fp256::<ark_bn254::FqParameters>::new(BigInteger256::new([15640529013230252674,17167675400528452069, 6341480850007228862, 2516290777480162977])) 
		),
		QuadExtField::<ark_ff::Fp2ParamsWrapper::<ark_bn254::Fq2Parameters>>::new(
			ark_ff::Fp256::<ark_bn254::FqParameters>::new(BigInteger256::new([2568985754653549489,8331258617886507398, 15289896141672320485, 3111748989238118641])), 
			ark_ff::Fp256::<ark_bn254::FqParameters>::new(BigInteger256::new([8520725304405802997,15638238802437077320, 17665258704505957543, 2731156151271490823])) 
 		)
 	)
}

pub fn get_gamma_g2_neg_pc_35() -> (QuadExtField::<ark_ff::Fp2ParamsWrapper::<ark_bn254::Fq2Parameters>>, QuadExtField::<ark_ff::Fp2ParamsWrapper::<ark_bn254::Fq2Parameters>>, QuadExtField::<ark_ff::Fp2ParamsWrapper::<ark_bn254::Fq2Parameters>>) { 
 	(QuadExtField::<ark_ff::Fp2ParamsWrapper::<ark_bn254::Fq2Parameters>>::new(
			ark_ff::Fp256::<ark_bn254::FqParameters>::new(BigInteger256::new([7120317261476557715,7552257997228182021, 16358236190799863642, 1629867967602944431])), 
			ark_ff::Fp256::<ark_bn254::FqParameters>::new(BigInteger256::new([2926655896310185389,11342398253884210994, 14243889332822464811, 5673933864441291])) 
		),
		QuadExtField::<ark_ff::Fp2ParamsWrapper::<ark_bn254::Fq2Parameters>>::new(
			ark_ff::Fp256::<ark_bn254::FqParameters>::new(BigInteger256::new([15263597988564605707,1834204502393602270, 2781236779387804203, 335388004383960306])), 
			ark_ff::Fp256::<ark_bn254::FqParameters>::new(BigInteger256::new([13837667168429014907,4675266620119564585, 17991599336536916282, 205128786167620998])) 
		),
		QuadExtField::<ark_ff::Fp2ParamsWrapper::<ark_bn254::Fq2Parameters>>::new(
			ark_ff::Fp256::<ark_bn254::FqParameters>::new(BigInteger256::new([12226457088307444571,13281439801408605565, 6871025939324737887, 1355231828771092400])), 
			ark_ff::Fp256::<ark_bn254::FqParameters>::new(BigInteger256::new([5848111637689269596,18344987805008892157, 10290344629027789717, 2394074559139099143])) 
 		)
 	)
}

pub fn get_gamma_g2_neg_pc_36() -> (QuadExtField::<ark_ff::Fp2ParamsWrapper::<ark_bn254::Fq2Parameters>>, QuadExtField::<ark_ff::Fp2ParamsWrapper::<ark_bn254::Fq2Parameters>>, QuadExtField::<ark_ff::Fp2ParamsWrapper::<ark_bn254::Fq2Parameters>>) { 
 	(QuadExtField::<ark_ff::Fp2ParamsWrapper::<ark_bn254::Fq2Parameters>>::new(
			ark_ff::Fp256::<ark_bn254::FqParameters>::new(BigInteger256::new([13555239015132717788,14924527318658672652, 9612862511435704261, 1788235917197541149])), 
			ark_ff::Fp256::<ark_bn254::FqParameters>::new(BigInteger256::new([13743185498493428374,13042375823225200846, 7761942357328267608, 862687485163677080])) 
		),
		QuadExtField::<ark_ff::Fp2ParamsWrapper::<ark_bn254::Fq2Parameters>>::new(
			ark_ff::Fp256::<ark_bn254::FqParameters>::new(BigInteger256::new([14465100373986763913,11398519268715632530, 23522222063967972, 1057670260062133535])), 
			ark_ff::Fp256::<ark_bn254::FqParameters>::new(BigInteger256::new([15976699050801485602,6319788719106771266, 5566995811024330042, 2387504266708092562])) 
		),
		QuadExtField::<ark_ff::Fp2ParamsWrapper::<ark_bn254::Fq2Parameters>>::new(
			ark_ff::Fp256::<ark_bn254::FqParameters>::new(BigInteger256::new([16569113230526403569,17725514535345950488, 11866006831990305753, 2130996117207853294])), 
			ark_ff::Fp256::<ark_bn254::FqParameters>::new(BigInteger256::new([1527532136197539549,2786640387952763279, 4094770523233825381, 1206940085346694695])) 
 		)
 	)
}

pub fn get_gamma_g2_neg_pc_37() -> (QuadExtField::<ark_ff::Fp2ParamsWrapper::<ark_bn254::Fq2Parameters>>, QuadExtField::<ark_ff::Fp2ParamsWrapper::<ark_bn254::Fq2Parameters>>, QuadExtField::<ark_ff::Fp2ParamsWrapper::<ark_bn254::Fq2Parameters>>) { 
 	(QuadExtField::<ark_ff::Fp2ParamsWrapper::<ark_bn254::Fq2Parameters>>::new(
			ark_ff::Fp256::<ark_bn254::FqParameters>::new(BigInteger256::new([5114804075405120203,4172763077557640727, 3328951903873692349, 472711820379981624])), 
			ark_ff::Fp256::<ark_bn254::FqParameters>::new(BigInteger256::new([12486348542366902455,5733542869038903260, 9171736716159526893, 347286838645629371])) 
		),
		QuadExtField::<ark_ff::Fp2ParamsWrapper::<ark_bn254::Fq2Parameters>>::new(
			ark_ff::Fp256::<ark_bn254::FqParameters>::new(BigInteger256::new([7426745889640868715,7336034198735935872, 225818981130895468, 2851352892440829973])), 
			ark_ff::Fp256::<ark_bn254::FqParameters>::new(BigInteger256::new([13558352020304174794,8731800623672578152, 8611997025371520380, 803901775735360605])) 
		),
		QuadExtField::<ark_ff::Fp2ParamsWrapper::<ark_bn254::Fq2Parameters>>::new(
			ark_ff::Fp256::<ark_bn254::FqParameters>::new(BigInteger256::new([4306725704066455433,18139295094576557768, 10045251235784233754, 2086969227141113700])), 
			ark_ff::Fp256::<ark_bn254::FqParameters>::new(BigInteger256::new([14119044221441020420,6574752427733012334, 17898012107281779637, 1994133102098711084])) 
 		)
 	)
}

pub fn get_gamma_g2_neg_pc_38() -> (QuadExtField::<ark_ff::Fp2ParamsWrapper::<ark_bn254::Fq2Parameters>>, QuadExtField::<ark_ff::Fp2ParamsWrapper::<ark_bn254::Fq2Parameters>>, QuadExtField::<ark_ff::Fp2ParamsWrapper::<ark_bn254::Fq2Parameters>>) { 
 	(QuadExtField::<ark_ff::Fp2ParamsWrapper::<ark_bn254::Fq2Parameters>>::new(
			ark_ff::Fp256::<ark_bn254::FqParameters>::new(BigInteger256::new([7155714555768312444,10481259648759533641, 3320847119085430469, 735361489356423879])), 
			ark_ff::Fp256::<ark_bn254::FqParameters>::new(BigInteger256::new([17450582325843748451,9873542994348163314, 14772659291204377472, 626502329742690870])) 
		),
		QuadExtField::<ark_ff::Fp2ParamsWrapper::<ark_bn254::Fq2Parameters>>::new(
			ark_ff::Fp256::<ark_bn254::FqParameters>::new(BigInteger256::new([3371886791869284567,15381838635685684107, 5657371297269882352, 2651932389293531103])), 
			ark_ff::Fp256::<ark_bn254::FqParameters>::new(BigInteger256::new([12269515269623735501,8918742107553422877, 4172805128451843932, 2733666274434653456])) 
		),
		QuadExtField::<ark_ff::Fp2ParamsWrapper::<ark_bn254::Fq2Parameters>>::new(
			ark_ff::Fp256::<ark_bn254::FqParameters>::new(BigInteger256::new([9573118767154288402,15470856646598692794, 8105024619525140398, 2224539222662921593])), 
			ark_ff::Fp256::<ark_bn254::FqParameters>::new(BigInteger256::new([17034452844578716199,8554107061262379270, 16591785574730849418, 1633226586394386861])) 
 		)
 	)
}

pub fn get_gamma_g2_neg_pc_39() -> (QuadExtField::<ark_ff::Fp2ParamsWrapper::<ark_bn254::Fq2Parameters>>, QuadExtField::<ark_ff::Fp2ParamsWrapper::<ark_bn254::Fq2Parameters>>, QuadExtField::<ark_ff::Fp2ParamsWrapper::<ark_bn254::Fq2Parameters>>) { 
 	(QuadExtField::<ark_ff::Fp2ParamsWrapper::<ark_bn254::Fq2Parameters>>::new(
			ark_ff::Fp256::<ark_bn254::FqParameters>::new(BigInteger256::new([4711161931912789291,18130371323456201232, 15277646067184296809, 1342727550878387191])), 
			ark_ff::Fp256::<ark_bn254::FqParameters>::new(BigInteger256::new([1467126513716047660,8021413539023584799, 17801508658762354334, 3213122867712408619])) 
		),
		QuadExtField::<ark_ff::Fp2ParamsWrapper::<ark_bn254::Fq2Parameters>>::new(
			ark_ff::Fp256::<ark_bn254::FqParameters>::new(BigInteger256::new([5853050774925202553,9705908432060068641, 7538740777643461165, 1804229708703189317])), 
			ark_ff::Fp256::<ark_bn254::FqParameters>::new(BigInteger256::new([13532391595908283977,2706364488996114206, 13664153023687637490, 2790608905367055510])) 
		),
		QuadExtField::<ark_ff::Fp2ParamsWrapper::<ark_bn254::Fq2Parameters>>::new(
			ark_ff::Fp256::<ark_bn254::FqParameters>::new(BigInteger256::new([14519164874451284801,9104102277442927166, 13279729600879296984, 2861474850255824756])), 
			ark_ff::Fp256::<ark_bn254::FqParameters>::new(BigInteger256::new([5377949737843903762,12797117373748448714, 14215446886332233979, 2017226962682556292])) 
 		)
 	)
}

pub fn get_gamma_g2_neg_pc_40() -> (QuadExtField::<ark_ff::Fp2ParamsWrapper::<ark_bn254::Fq2Parameters>>, QuadExtField::<ark_ff::Fp2ParamsWrapper::<ark_bn254::Fq2Parameters>>, QuadExtField::<ark_ff::Fp2ParamsWrapper::<ark_bn254::Fq2Parameters>>) { 
 	(QuadExtField::<ark_ff::Fp2ParamsWrapper::<ark_bn254::Fq2Parameters>>::new(
			ark_ff::Fp256::<ark_bn254::FqParameters>::new(BigInteger256::new([6267645080032865320,10750275706111093063, 2107525863779491991, 1968861127619145353])), 
			ark_ff::Fp256::<ark_bn254::FqParameters>::new(BigInteger256::new([4415519846160173950,11096921346300086957, 1170710085091004866, 72616782227125758])) 
		),
		QuadExtField::<ark_ff::Fp2ParamsWrapper::<ark_bn254::Fq2Parameters>>::new(
			ark_ff::Fp256::<ark_bn254::FqParameters>::new(BigInteger256::new([10232906705228961780,15876358800657746107, 7449296634528376275, 3191557894907054641])), 
			ark_ff::Fp256::<ark_bn254::FqParameters>::new(BigInteger256::new([6084185408544380217,12166250516002141475, 2699655953210779176, 135679131148756839])) 
		),
		QuadExtField::<ark_ff::Fp2ParamsWrapper::<ark_bn254::Fq2Parameters>>::new(
			ark_ff::Fp256::<ark_bn254::FqParameters>::new(BigInteger256::new([13839678956621451371,5837800799471155642, 13017709583009916558, 3397622215689528221])), 
			ark_ff::Fp256::<ark_bn254::FqParameters>::new(BigInteger256::new([15500223681764224151,10301813571936861125, 14855805854578839215, 1474196592120957640])) 
 		)
 	)
}

pub fn get_gamma_g2_neg_pc_41() -> (QuadExtField::<ark_ff::Fp2ParamsWrapper::<ark_bn254::Fq2Parameters>>, QuadExtField::<ark_ff::Fp2ParamsWrapper::<ark_bn254::Fq2Parameters>>, QuadExtField::<ark_ff::Fp2ParamsWrapper::<ark_bn254::Fq2Parameters>>) { 
 	(QuadExtField::<ark_ff::Fp2ParamsWrapper::<ark_bn254::Fq2Parameters>>::new(
			ark_ff::Fp256::<ark_bn254::FqParameters>::new(BigInteger256::new([6159919441405191294,4477945359632189959, 15198662699206172876, 1280396025645841436])), 
			ark_ff::Fp256::<ark_bn254::FqParameters>::new(BigInteger256::new([10477543762425302075,7064537348438568871, 11743696811261499485, 2383919542106740699])) 
		),
		QuadExtField::<ark_ff::Fp2ParamsWrapper::<ark_bn254::Fq2Parameters>>::new(
			ark_ff::Fp256::<ark_bn254::FqParameters>::new(BigInteger256::new([248751161004592530,12216330140153424401, 8543578797685815603, 2859027025838042733])), 
			ark_ff::Fp256::<ark_bn254::FqParameters>::new(BigInteger256::new([6194656446907457552,17876752927769885539, 8407565900741576915, 482489911112910917])) 
		),
		QuadExtField::<ark_ff::Fp2ParamsWrapper::<ark_bn254::Fq2Parameters>>::new(
			ark_ff::Fp256::<ark_bn254::FqParameters>::new(BigInteger256::new([2765500164015116551,3029999966476280962, 11243794975661292962, 860337896095117828])), 
			ark_ff::Fp256::<ark_bn254::FqParameters>::new(BigInteger256::new([16994853261164388493,10277461362946878297, 11170518452121706239, 1160792507953008658])) 
 		)
 	)
}

pub fn get_gamma_g2_neg_pc_42() -> (QuadExtField::<ark_ff::Fp2ParamsWrapper::<ark_bn254::Fq2Parameters>>, QuadExtField::<ark_ff::Fp2ParamsWrapper::<ark_bn254::Fq2Parameters>>, QuadExtField::<ark_ff::Fp2ParamsWrapper::<ark_bn254::Fq2Parameters>>) { 
 	(QuadExtField::<ark_ff::Fp2ParamsWrapper::<ark_bn254::Fq2Parameters>>::new(
			ark_ff::Fp256::<ark_bn254::FqParameters>::new(BigInteger256::new([15529561912129630379,2206068326658408061, 10937502935126907161, 1810329932763296750])), 
			ark_ff::Fp256::<ark_bn254::FqParameters>::new(BigInteger256::new([11773988251929245535,8168905259549524408, 15881146625677964247, 3301148154720107604])) 
		),
		QuadExtField::<ark_ff::Fp2ParamsWrapper::<ark_bn254::Fq2Parameters>>::new(
			ark_ff::Fp256::<ark_bn254::FqParameters>::new(BigInteger256::new([8727185441572338877,456204486442982053, 8562669116275066184, 1105708298348662747])), 
			ark_ff::Fp256::<ark_bn254::FqParameters>::new(BigInteger256::new([9870364555866928692,232546030253946073, 10620863432028529411, 1618420585265274997])) 
		),
		QuadExtField::<ark_ff::Fp2ParamsWrapper::<ark_bn254::Fq2Parameters>>::new(
			ark_ff::Fp256::<ark_bn254::FqParameters>::new(BigInteger256::new([10112613435221297756,5169148670295997689, 3957217890151964010, 2979695178810704664])), 
			ark_ff::Fp256::<ark_bn254::FqParameters>::new(BigInteger256::new([8131745237183518180,8781822738273576162, 754287471595691592, 1808012455343298918])) 
 		)
 	)
}

pub fn get_gamma_g2_neg_pc_43() -> (QuadExtField::<ark_ff::Fp2ParamsWrapper::<ark_bn254::Fq2Parameters>>, QuadExtField::<ark_ff::Fp2ParamsWrapper::<ark_bn254::Fq2Parameters>>, QuadExtField::<ark_ff::Fp2ParamsWrapper::<ark_bn254::Fq2Parameters>>) { 
 	(QuadExtField::<ark_ff::Fp2ParamsWrapper::<ark_bn254::Fq2Parameters>>::new(
			ark_ff::Fp256::<ark_bn254::FqParameters>::new(BigInteger256::new([7685420508597090459,2244927223990886702, 1415534581430209074, 1799099260139195975])), 
			ark_ff::Fp256::<ark_bn254::FqParameters>::new(BigInteger256::new([37517095230738605,1692194596799775857, 4156007241714134993, 1625175245680050152])) 
		),
		QuadExtField::<ark_ff::Fp2ParamsWrapper::<ark_bn254::Fq2Parameters>>::new(
			ark_ff::Fp256::<ark_bn254::FqParameters>::new(BigInteger256::new([16597362184989623665,8874879443557824057, 4575284840779117537, 818887851400572696])), 
			ark_ff::Fp256::<ark_bn254::FqParameters>::new(BigInteger256::new([12080683947072644023,6758163829153298377, 784679329732419071, 309203053972157318])) 
		),
		QuadExtField::<ark_ff::Fp2ParamsWrapper::<ark_bn254::Fq2Parameters>>::new(
			ark_ff::Fp256::<ark_bn254::FqParameters>::new(BigInteger256::new([3952837571701453180,1903135870921686260, 10457117118987937084, 3405423714905158163])), 
			ark_ff::Fp256::<ark_bn254::FqParameters>::new(BigInteger256::new([15017229640277038985,13803203662891018815, 8747510305522008880, 1448200982938534942])) 
 		)
 	)
}

pub fn get_gamma_g2_neg_pc_44() -> (QuadExtField::<ark_ff::Fp2ParamsWrapper::<ark_bn254::Fq2Parameters>>, QuadExtField::<ark_ff::Fp2ParamsWrapper::<ark_bn254::Fq2Parameters>>, QuadExtField::<ark_ff::Fp2ParamsWrapper::<ark_bn254::Fq2Parameters>>) { 
 	(QuadExtField::<ark_ff::Fp2ParamsWrapper::<ark_bn254::Fq2Parameters>>::new(
			ark_ff::Fp256::<ark_bn254::FqParameters>::new(BigInteger256::new([556304748214622935,3135283039681552363, 16865373005037478071, 2938350916681646433])), 
			ark_ff::Fp256::<ark_bn254::FqParameters>::new(BigInteger256::new([13050139955487689154,13333430870083485265, 4329060736223953731, 1047348912653006317])) 
		),
		QuadExtField::<ark_ff::Fp2ParamsWrapper::<ark_bn254::Fq2Parameters>>::new(
			ark_ff::Fp256::<ark_bn254::FqParameters>::new(BigInteger256::new([8770383764551582800,56366096034035302, 2685154886001377122, 3249409559619901998])), 
			ark_ff::Fp256::<ark_bn254::FqParameters>::new(BigInteger256::new([12884160568804891593,11581608250361043986, 14196902620164457538, 2578710095761385912])) 
		),
		QuadExtField::<ark_ff::Fp2ParamsWrapper::<ark_bn254::Fq2Parameters>>::new(
			ark_ff::Fp256::<ark_bn254::FqParameters>::new(BigInteger256::new([15546851523730721805,14092579518078533720, 8871348309890717741, 294049289375972753])), 
			ark_ff::Fp256::<ark_bn254::FqParameters>::new(BigInteger256::new([342085843141481611,10154361958468512950, 11174549408220543679, 2893600745735005009])) 
 		)
 	)
}

pub fn get_gamma_g2_neg_pc_45() -> (QuadExtField::<ark_ff::Fp2ParamsWrapper::<ark_bn254::Fq2Parameters>>, QuadExtField::<ark_ff::Fp2ParamsWrapper::<ark_bn254::Fq2Parameters>>, QuadExtField::<ark_ff::Fp2ParamsWrapper::<ark_bn254::Fq2Parameters>>) { 
 	(QuadExtField::<ark_ff::Fp2ParamsWrapper::<ark_bn254::Fq2Parameters>>::new(
			ark_ff::Fp256::<ark_bn254::FqParameters>::new(BigInteger256::new([14647082872060818788,14817078032273354816, 10064634629631738490, 1606188032088004980])), 
			ark_ff::Fp256::<ark_bn254::FqParameters>::new(BigInteger256::new([3705444889065882940,7361127136866573738, 6520054309572279251, 1051268700445219106])) 
		),
		QuadExtField::<ark_ff::Fp2ParamsWrapper::<ark_bn254::Fq2Parameters>>::new(
			ark_ff::Fp256::<ark_bn254::FqParameters>::new(BigInteger256::new([18336063286515740324,15224883798088497869, 6278436591878330149, 2163055900135459124])), 
			ark_ff::Fp256::<ark_bn254::FqParameters>::new(BigInteger256::new([6793070038140550276,18017444111817406813, 6767301765502429892, 212697772470584297])) 
		),
		QuadExtField::<ark_ff::Fp2ParamsWrapper::<ark_bn254::Fq2Parameters>>::new(
			ark_ff::Fp256::<ark_bn254::FqParameters>::new(BigInteger256::new([14535225152069889826,533382451973379504, 6614622700216502268, 537210752675714696])), 
			ark_ff::Fp256::<ark_bn254::FqParameters>::new(BigInteger256::new([214839826762703769,4686888271532457721, 13579582382283685089, 2716294784014812582])) 
 		)
 	)
}

pub fn get_gamma_g2_neg_pc_46() -> (QuadExtField::<ark_ff::Fp2ParamsWrapper::<ark_bn254::Fq2Parameters>>, QuadExtField::<ark_ff::Fp2ParamsWrapper::<ark_bn254::Fq2Parameters>>, QuadExtField::<ark_ff::Fp2ParamsWrapper::<ark_bn254::Fq2Parameters>>) { 
 	(QuadExtField::<ark_ff::Fp2ParamsWrapper::<ark_bn254::Fq2Parameters>>::new(
			ark_ff::Fp256::<ark_bn254::FqParameters>::new(BigInteger256::new([8355857482047942794,9648467663681812189, 480005125199695496, 1250818138525467346])), 
			ark_ff::Fp256::<ark_bn254::FqParameters>::new(BigInteger256::new([17343404999127466843,6425518906437539942, 870875280672844244, 3161873369949566100])) 
		),
		QuadExtField::<ark_ff::Fp2ParamsWrapper::<ark_bn254::Fq2Parameters>>::new(
			ark_ff::Fp256::<ark_bn254::FqParameters>::new(BigInteger256::new([17907793707812022497,10691554820921122451, 1280459195158690356, 2990099148364492831])), 
			ark_ff::Fp256::<ark_bn254::FqParameters>::new(BigInteger256::new([3617438327511701730,12341708758349691462, 16098706603763747897, 1436467705391832432])) 
		),
		QuadExtField::<ark_ff::Fp2ParamsWrapper::<ark_bn254::Fq2Parameters>>::new(
			ark_ff::Fp256::<ark_bn254::FqParameters>::new(BigInteger256::new([6862210410128284842,2985523853272151856, 10472690361103266932, 400516676924338298])), 
			ark_ff::Fp256::<ark_bn254::FqParameters>::new(BigInteger256::new([7221846984979338584,334208652697608704, 2438082793402141192, 1673680049462395272])) 
 		)
 	)
}

pub fn get_gamma_g2_neg_pc_47() -> (QuadExtField::<ark_ff::Fp2ParamsWrapper::<ark_bn254::Fq2Parameters>>, QuadExtField::<ark_ff::Fp2ParamsWrapper::<ark_bn254::Fq2Parameters>>, QuadExtField::<ark_ff::Fp2ParamsWrapper::<ark_bn254::Fq2Parameters>>) { 
 	(QuadExtField::<ark_ff::Fp2ParamsWrapper::<ark_bn254::Fq2Parameters>>::new(
			ark_ff::Fp256::<ark_bn254::FqParameters>::new(BigInteger256::new([8428076325473342447,9130298170338116706, 14251703806791933252, 452784505910647687])), 
			ark_ff::Fp256::<ark_bn254::FqParameters>::new(BigInteger256::new([12548639873433632870,6647155020402947175, 15808303000429910320, 922278877994736356])) 
		),
		QuadExtField::<ark_ff::Fp2ParamsWrapper::<ark_bn254::Fq2Parameters>>::new(
			ark_ff::Fp256::<ark_bn254::FqParameters>::new(BigInteger256::new([16670237437411228134,13110053254265281925, 11070339283954752612, 3344003398560746676])), 
			ark_ff::Fp256::<ark_bn254::FqParameters>::new(BigInteger256::new([15344203836219615739,16450005542301114345, 7928336079533256047, 3092930395156423900])) 
		),
		QuadExtField::<ark_ff::Fp2ParamsWrapper::<ark_bn254::Fq2Parameters>>::new(
			ark_ff::Fp256::<ark_bn254::FqParameters>::new(BigInteger256::new([4842364196863981737,16835448445746375808, 17822749353942278677, 1766986132760433167])), 
			ark_ff::Fp256::<ark_bn254::FqParameters>::new(BigInteger256::new([12903021811818100894,17392054340424039541, 2970692416086698943, 1092678685318618832])) 
 		)
 	)
}

pub fn get_gamma_g2_neg_pc_48() -> (QuadExtField::<ark_ff::Fp2ParamsWrapper::<ark_bn254::Fq2Parameters>>, QuadExtField::<ark_ff::Fp2ParamsWrapper::<ark_bn254::Fq2Parameters>>, QuadExtField::<ark_ff::Fp2ParamsWrapper::<ark_bn254::Fq2Parameters>>) { 
 	(QuadExtField::<ark_ff::Fp2ParamsWrapper::<ark_bn254::Fq2Parameters>>::new(
			ark_ff::Fp256::<ark_bn254::FqParameters>::new(BigInteger256::new([6053571397947271628,8986382231993405489, 4470814686790468009, 1670109159964864270])), 
			ark_ff::Fp256::<ark_bn254::FqParameters>::new(BigInteger256::new([11670954415637520480,8676064407044588983, 3493307303700138283, 381991932643337351])) 
		),
		QuadExtField::<ark_ff::Fp2ParamsWrapper::<ark_bn254::Fq2Parameters>>::new(
			ark_ff::Fp256::<ark_bn254::FqParameters>::new(BigInteger256::new([14919872639259527266,11204446196210274807, 3938746915973795236, 193071420051602668])), 
			ark_ff::Fp256::<ark_bn254::FqParameters>::new(BigInteger256::new([2169640326393674147,2976414262502596941, 1068741284613745466, 3241248254328953421])) 
		),
		QuadExtField::<ark_ff::Fp2ParamsWrapper::<ark_bn254::Fq2Parameters>>::new(
			ark_ff::Fp256::<ark_bn254::FqParameters>::new(BigInteger256::new([3347050930566263179,15227623261940056373, 5064449734588130975, 1644841272216980058])), 
			ark_ff::Fp256::<ark_bn254::FqParameters>::new(BigInteger256::new([1625280631411413880,1702262130639902885, 9529161201018776810, 1829165212640860034])) 
 		)
 	)
}

pub fn get_gamma_g2_neg_pc_49() -> (QuadExtField::<ark_ff::Fp2ParamsWrapper::<ark_bn254::Fq2Parameters>>, QuadExtField::<ark_ff::Fp2ParamsWrapper::<ark_bn254::Fq2Parameters>>, QuadExtField::<ark_ff::Fp2ParamsWrapper::<ark_bn254::Fq2Parameters>>) { 
 	(QuadExtField::<ark_ff::Fp2ParamsWrapper::<ark_bn254::Fq2Parameters>>::new(
			ark_ff::Fp256::<ark_bn254::FqParameters>::new(BigInteger256::new([9946192486741291674,16009888218582641868, 5258189543169640418, 2800620383260601224])), 
			ark_ff::Fp256::<ark_bn254::FqParameters>::new(BigInteger256::new([6260910462313486021,18019731693449785283, 6581400544059660888, 344253000900514168])) 
		),
		QuadExtField::<ark_ff::Fp2ParamsWrapper::<ark_bn254::Fq2Parameters>>::new(
			ark_ff::Fp256::<ark_bn254::FqParameters>::new(BigInteger256::new([10913968561495584788,17286209953281281921, 3832380249816653571, 2296504327540868255])), 
			ark_ff::Fp256::<ark_bn254::FqParameters>::new(BigInteger256::new([5980313309144068105,9676642392212827000, 12750006247630515173, 2419885455009742218])) 
		),
		QuadExtField::<ark_ff::Fp2ParamsWrapper::<ark_bn254::Fq2Parameters>>::new(
			ark_ff::Fp256::<ark_bn254::FqParameters>::new(BigInteger256::new([10736283731559531821,469413005744342390, 6693792377875160787, 709913673382984383])), 
			ark_ff::Fp256::<ark_bn254::FqParameters>::new(BigInteger256::new([14260366320606871896,16001207483173510002, 9418928439988216436, 1940515962799049672])) 
 		)
 	)
}

pub fn get_gamma_g2_neg_pc_50() -> (QuadExtField::<ark_ff::Fp2ParamsWrapper::<ark_bn254::Fq2Parameters>>, QuadExtField::<ark_ff::Fp2ParamsWrapper::<ark_bn254::Fq2Parameters>>, QuadExtField::<ark_ff::Fp2ParamsWrapper::<ark_bn254::Fq2Parameters>>) { 
 	(QuadExtField::<ark_ff::Fp2ParamsWrapper::<ark_bn254::Fq2Parameters>>::new(
			ark_ff::Fp256::<ark_bn254::FqParameters>::new(BigInteger256::new([668612708904202850,3167321822604705979, 1579530902783930144, 2346397967698798449])), 
			ark_ff::Fp256::<ark_bn254::FqParameters>::new(BigInteger256::new([14290763155749462758,2407447641980493596, 15407234844910327919, 3384970810715598847])) 
		),
		QuadExtField::<ark_ff::Fp2ParamsWrapper::<ark_bn254::Fq2Parameters>>::new(
			ark_ff::Fp256::<ark_bn254::FqParameters>::new(BigInteger256::new([1177380238022283512,8961579017544796719, 8591946660150039578, 2492736147752479232])), 
			ark_ff::Fp256::<ark_bn254::FqParameters>::new(BigInteger256::new([1066371122727170893,10595411439863435174, 13669654662988561356, 1536218391537906349])) 
		),
		QuadExtField::<ark_ff::Fp2ParamsWrapper::<ark_bn254::Fq2Parameters>>::new(
			ark_ff::Fp256::<ark_bn254::FqParameters>::new(BigInteger256::new([3990287772318266996,4126143702790782387, 12391293695136844386, 2226590308183300015])), 
			ark_ff::Fp256::<ark_bn254::FqParameters>::new(BigInteger256::new([11474196062101036939,6512232067889266870, 15299488138452155551, 1359612874814541172])) 
 		)
 	)
}

pub fn get_gamma_g2_neg_pc_51() -> (QuadExtField::<ark_ff::Fp2ParamsWrapper::<ark_bn254::Fq2Parameters>>, QuadExtField::<ark_ff::Fp2ParamsWrapper::<ark_bn254::Fq2Parameters>>, QuadExtField::<ark_ff::Fp2ParamsWrapper::<ark_bn254::Fq2Parameters>>) { 
 	(QuadExtField::<ark_ff::Fp2ParamsWrapper::<ark_bn254::Fq2Parameters>>::new(
			ark_ff::Fp256::<ark_bn254::FqParameters>::new(BigInteger256::new([7833810580934822787,2278173342061405224, 16625781782762714556, 449975474420201749])), 
			ark_ff::Fp256::<ark_bn254::FqParameters>::new(BigInteger256::new([15908676400454436457,7659075249519984796, 6092125453849823626, 2347403061601242932])) 
		),
		QuadExtField::<ark_ff::Fp2ParamsWrapper::<ark_bn254::Fq2Parameters>>::new(
			ark_ff::Fp256::<ark_bn254::FqParameters>::new(BigInteger256::new([704334472188542423,7265255395597411589, 17778200845973254481, 2916194317447545558])), 
			ark_ff::Fp256::<ark_bn254::FqParameters>::new(BigInteger256::new([12120008460566880578,7050874281741056724, 16913640816487850711, 69787359441453702])) 
		),
		QuadExtField::<ark_ff::Fp2ParamsWrapper::<ark_bn254::Fq2Parameters>>::new(
			ark_ff::Fp256::<ark_bn254::FqParameters>::new(BigInteger256::new([12421985291619175106,13616740946265748115, 15690972551032352715, 2976784100392826795])), 
			ark_ff::Fp256::<ark_bn254::FqParameters>::new(BigInteger256::new([13053194126554283537,2221797547088586530, 5087119149953290972, 2606351311925567415])) 
 		)
 	)
}

pub fn get_gamma_g2_neg_pc_52() -> (QuadExtField::<ark_ff::Fp2ParamsWrapper::<ark_bn254::Fq2Parameters>>, QuadExtField::<ark_ff::Fp2ParamsWrapper::<ark_bn254::Fq2Parameters>>, QuadExtField::<ark_ff::Fp2ParamsWrapper::<ark_bn254::Fq2Parameters>>) { 
 	(QuadExtField::<ark_ff::Fp2ParamsWrapper::<ark_bn254::Fq2Parameters>>::new(
			ark_ff::Fp256::<ark_bn254::FqParameters>::new(BigInteger256::new([14910168874986442728,8031767862594161641, 13082123848268012237, 327033253264007364])), 
			ark_ff::Fp256::<ark_bn254::FqParameters>::new(BigInteger256::new([16437551873538962056,9555318888998921550, 10441499694453588872, 1216857201682350755])) 
		),
		QuadExtField::<ark_ff::Fp2ParamsWrapper::<ark_bn254::Fq2Parameters>>::new(
			ark_ff::Fp256::<ark_bn254::FqParameters>::new(BigInteger256::new([8929484257290050721,12216641768225203374, 17797023415867847222, 457776622682966994])), 
			ark_ff::Fp256::<ark_bn254::FqParameters>::new(BigInteger256::new([1003814703751094379,8402320400688343081, 14095669723564397446, 2701594127802062962])) 
		),
		QuadExtField::<ark_ff::Fp2ParamsWrapper::<ark_bn254::Fq2Parameters>>::new(
			ark_ff::Fp256::<ark_bn254::FqParameters>::new(BigInteger256::new([1605828574345606971,2282854075343552347, 5322406924554484809, 1772824224631335692])), 
			ark_ff::Fp256::<ark_bn254::FqParameters>::new(BigInteger256::new([7578546237214991511,14700451298734272718, 11949868685548483703, 612554363523646164])) 
 		)
 	)
}

pub fn get_gamma_g2_neg_pc_53() -> (QuadExtField::<ark_ff::Fp2ParamsWrapper::<ark_bn254::Fq2Parameters>>, QuadExtField::<ark_ff::Fp2ParamsWrapper::<ark_bn254::Fq2Parameters>>, QuadExtField::<ark_ff::Fp2ParamsWrapper::<ark_bn254::Fq2Parameters>>) { 
 	(QuadExtField::<ark_ff::Fp2ParamsWrapper::<ark_bn254::Fq2Parameters>>::new(
			ark_ff::Fp256::<ark_bn254::FqParameters>::new(BigInteger256::new([16667485799333773504,3221086101404825275, 18335055350165017628, 3220724970874634648])), 
			ark_ff::Fp256::<ark_bn254::FqParameters>::new(BigInteger256::new([9965961477366606014,9514984276782648940, 6659055027309226244, 432815556239122909])) 
		),
		QuadExtField::<ark_ff::Fp2ParamsWrapper::<ark_bn254::Fq2Parameters>>::new(
			ark_ff::Fp256::<ark_bn254::FqParameters>::new(BigInteger256::new([8871475679956329666,13656411655313599985, 10278285147808794900, 2104758402770576031])), 
			ark_ff::Fp256::<ark_bn254::FqParameters>::new(BigInteger256::new([1881275745878281923,11114772088861627375, 10479992110691850233, 463976086458283984])) 
		),
		QuadExtField::<ark_ff::Fp2ParamsWrapper::<ark_bn254::Fq2Parameters>>::new(
			ark_ff::Fp256::<ark_bn254::FqParameters>::new(BigInteger256::new([7107780817631756592,10796550827481526984, 17689566673997668915, 1425588873985650284])), 
			ark_ff::Fp256::<ark_bn254::FqParameters>::new(BigInteger256::new([13455981903192993053,2524251370558876649, 8142796561702863700, 1489982824885883810])) 
 		)
 	)
}

pub fn get_gamma_g2_neg_pc_54() -> (QuadExtField::<ark_ff::Fp2ParamsWrapper::<ark_bn254::Fq2Parameters>>, QuadExtField::<ark_ff::Fp2ParamsWrapper::<ark_bn254::Fq2Parameters>>, QuadExtField::<ark_ff::Fp2ParamsWrapper::<ark_bn254::Fq2Parameters>>) { 
 	(QuadExtField::<ark_ff::Fp2ParamsWrapper::<ark_bn254::Fq2Parameters>>::new(
			ark_ff::Fp256::<ark_bn254::FqParameters>::new(BigInteger256::new([4608410307150166716,9949176550436589210, 8414886195581298390, 3351545680158952230])), 
			ark_ff::Fp256::<ark_bn254::FqParameters>::new(BigInteger256::new([12614760649397657074,10333447317345225951, 15068923264347419408, 944617349099394366])) 
		),
		QuadExtField::<ark_ff::Fp2ParamsWrapper::<ark_bn254::Fq2Parameters>>::new(
			ark_ff::Fp256::<ark_bn254::FqParameters>::new(BigInteger256::new([7315350430268972497,3548934616792043495, 9263354149466389875, 1806153137917315461])), 
			ark_ff::Fp256::<ark_bn254::FqParameters>::new(BigInteger256::new([890712979474667191,10947174018244634898, 12411878852338739934, 2406696367944098355])) 
		),
		QuadExtField::<ark_ff::Fp2ParamsWrapper::<ark_bn254::Fq2Parameters>>::new(
			ark_ff::Fp256::<ark_bn254::FqParameters>::new(BigInteger256::new([17753449963041275052,289830216119421164, 10823988019836381479, 1864433638483422165])), 
			ark_ff::Fp256::<ark_bn254::FqParameters>::new(BigInteger256::new([12659154223165019981,14291208385812288033, 4211077010581610829, 405180633523493395])) 
 		)
 	)
}

pub fn get_gamma_g2_neg_pc_55() -> (QuadExtField::<ark_ff::Fp2ParamsWrapper::<ark_bn254::Fq2Parameters>>, QuadExtField::<ark_ff::Fp2ParamsWrapper::<ark_bn254::Fq2Parameters>>, QuadExtField::<ark_ff::Fp2ParamsWrapper::<ark_bn254::Fq2Parameters>>) { 
 	(QuadExtField::<ark_ff::Fp2ParamsWrapper::<ark_bn254::Fq2Parameters>>::new(
			ark_ff::Fp256::<ark_bn254::FqParameters>::new(BigInteger256::new([512316247260094648,6786053729138575658, 10061032147386610763, 1327278236519464884])), 
			ark_ff::Fp256::<ark_bn254::FqParameters>::new(BigInteger256::new([7775870594655883823,8686737039564117681, 5138930906871917634, 2225217506801160330])) 
		),
		QuadExtField::<ark_ff::Fp2ParamsWrapper::<ark_bn254::Fq2Parameters>>::new(
			ark_ff::Fp256::<ark_bn254::FqParameters>::new(BigInteger256::new([17678949499006414264,3046943661362056954, 603782209793683918, 2949855076993879063])), 
			ark_ff::Fp256::<ark_bn254::FqParameters>::new(BigInteger256::new([15648404799849869824,8852492324982358106, 7236352333723893911, 2968792539319848949])) 
		),
		QuadExtField::<ark_ff::Fp2ParamsWrapper::<ark_bn254::Fq2Parameters>>::new(
			ark_ff::Fp256::<ark_bn254::FqParameters>::new(BigInteger256::new([1341824392415388245,14839234163860451146, 10927154602245338474, 1723556217420853083])), 
			ark_ff::Fp256::<ark_bn254::FqParameters>::new(BigInteger256::new([3698733681168442673,12520078737395306409, 6552099471998238285, 3297070465959638818])) 
 		)
 	)
}

pub fn get_gamma_g2_neg_pc_56() -> (QuadExtField::<ark_ff::Fp2ParamsWrapper::<ark_bn254::Fq2Parameters>>, QuadExtField::<ark_ff::Fp2ParamsWrapper::<ark_bn254::Fq2Parameters>>, QuadExtField::<ark_ff::Fp2ParamsWrapper::<ark_bn254::Fq2Parameters>>) { 
 	(QuadExtField::<ark_ff::Fp2ParamsWrapper::<ark_bn254::Fq2Parameters>>::new(
			ark_ff::Fp256::<ark_bn254::FqParameters>::new(BigInteger256::new([9365894875577831369,5088926746804912808, 12206089286387205189, 2720900606756380239])), 
			ark_ff::Fp256::<ark_bn254::FqParameters>::new(BigInteger256::new([7869130394231972803,87614893153743506, 7398100225563446544, 425580236367558222])) 
		),
		QuadExtField::<ark_ff::Fp2ParamsWrapper::<ark_bn254::Fq2Parameters>>::new(
			ark_ff::Fp256::<ark_bn254::FqParameters>::new(BigInteger256::new([9623386052275909434,14136039815193396738, 1039748712468975291, 2703775407007442287])), 
			ark_ff::Fp256::<ark_bn254::FqParameters>::new(BigInteger256::new([9874018372711419703,17610825206743430688, 2030382861131513741, 1089540355975414475])) 
		),
		QuadExtField::<ark_ff::Fp2ParamsWrapper::<ark_bn254::Fq2Parameters>>::new(
			ark_ff::Fp256::<ark_bn254::FqParameters>::new(BigInteger256::new([18198233620107185292,8383715319697940874, 16092961870783587833, 3059404893348632448])), 
			ark_ff::Fp256::<ark_bn254::FqParameters>::new(BigInteger256::new([8030201406162679647,14390016679756577003, 281274593549247080, 3355147701823212150])) 
 		)
 	)
}

pub fn get_gamma_g2_neg_pc_57() -> (QuadExtField::<ark_ff::Fp2ParamsWrapper::<ark_bn254::Fq2Parameters>>, QuadExtField::<ark_ff::Fp2ParamsWrapper::<ark_bn254::Fq2Parameters>>, QuadExtField::<ark_ff::Fp2ParamsWrapper::<ark_bn254::Fq2Parameters>>) { 
 	(QuadExtField::<ark_ff::Fp2ParamsWrapper::<ark_bn254::Fq2Parameters>>::new(
			ark_ff::Fp256::<ark_bn254::FqParameters>::new(BigInteger256::new([5422680240265832996,1946318342117916306, 3664916472817012405, 3241874286956908535])), 
			ark_ff::Fp256::<ark_bn254::FqParameters>::new(BigInteger256::new([18311043380692671418,8100242697301145939, 12667924700306939342, 1916567917399583004])) 
		),
		QuadExtField::<ark_ff::Fp2ParamsWrapper::<ark_bn254::Fq2Parameters>>::new(
			ark_ff::Fp256::<ark_bn254::FqParameters>::new(BigInteger256::new([17950967283822921384,16844242693178970687, 8067610294475730584, 2973722185713614929])), 
			ark_ff::Fp256::<ark_bn254::FqParameters>::new(BigInteger256::new([1586896194752532496,14530098787235041139, 14057579702446203562, 156923356255504831])) 
		),
		QuadExtField::<ark_ff::Fp2ParamsWrapper::<ark_bn254::Fq2Parameters>>::new(
			ark_ff::Fp256::<ark_bn254::FqParameters>::new(BigInteger256::new([16355350933727732631,11776541475409484475, 14261559773007539506, 2751337877015607329])), 
			ark_ff::Fp256::<ark_bn254::FqParameters>::new(BigInteger256::new([828737256128366603,13583580367718593264, 11493988924326139353, 457769640694574808])) 
 		)
 	)
}

pub fn get_gamma_g2_neg_pc_58() -> (QuadExtField::<ark_ff::Fp2ParamsWrapper::<ark_bn254::Fq2Parameters>>, QuadExtField::<ark_ff::Fp2ParamsWrapper::<ark_bn254::Fq2Parameters>>, QuadExtField::<ark_ff::Fp2ParamsWrapper::<ark_bn254::Fq2Parameters>>) { 
 	(QuadExtField::<ark_ff::Fp2ParamsWrapper::<ark_bn254::Fq2Parameters>>::new(
			ark_ff::Fp256::<ark_bn254::FqParameters>::new(BigInteger256::new([13003328686856013800,1711598861164327991, 6468057120367482348, 2730935446791051989])), 
			ark_ff::Fp256::<ark_bn254::FqParameters>::new(BigInteger256::new([7935427476618081549,9348338193126529088, 4081002799623368688, 928439523363955439])) 
		),
		QuadExtField::<ark_ff::Fp2ParamsWrapper::<ark_bn254::Fq2Parameters>>::new(
			ark_ff::Fp256::<ark_bn254::FqParameters>::new(BigInteger256::new([13002181057977534922,2628453963212504637, 18352375669292150337, 1235495029864377313])), 
			ark_ff::Fp256::<ark_bn254::FqParameters>::new(BigInteger256::new([15338249627883426984,18007053840077985809, 12604282715825014794, 2692787787259905194])) 
		),
		QuadExtField::<ark_ff::Fp2ParamsWrapper::<ark_bn254::Fq2Parameters>>::new(
			ark_ff::Fp256::<ark_bn254::FqParameters>::new(BigInteger256::new([9093686028111629152,7994041345650666007, 11608789992358999520, 3223982669655634038])), 
			ark_ff::Fp256::<ark_bn254::FqParameters>::new(BigInteger256::new([2992640776169583751,1871142284957443263, 7623327292315785978, 1387205035875433685])) 
 		)
 	)
}

pub fn get_gamma_g2_neg_pc_59() -> (QuadExtField::<ark_ff::Fp2ParamsWrapper::<ark_bn254::Fq2Parameters>>, QuadExtField::<ark_ff::Fp2ParamsWrapper::<ark_bn254::Fq2Parameters>>, QuadExtField::<ark_ff::Fp2ParamsWrapper::<ark_bn254::Fq2Parameters>>) { 
 	(QuadExtField::<ark_ff::Fp2ParamsWrapper::<ark_bn254::Fq2Parameters>>::new(
			ark_ff::Fp256::<ark_bn254::FqParameters>::new(BigInteger256::new([5463865735891083899,14630160823257816750, 1155950244367731559, 3099083154394233077])), 
			ark_ff::Fp256::<ark_bn254::FqParameters>::new(BigInteger256::new([11224215036972939113,9261469020329846904, 6881454910289088652, 671621440445142178])) 
		),
		QuadExtField::<ark_ff::Fp2ParamsWrapper::<ark_bn254::Fq2Parameters>>::new(
			ark_ff::Fp256::<ark_bn254::FqParameters>::new(BigInteger256::new([4421356026529641239,9446130041908699392, 1922014958537615400, 3274503252285438062])), 
			ark_ff::Fp256::<ark_bn254::FqParameters>::new(BigInteger256::new([8580277962475378750,2554147701309430660, 11589922152054583084, 1644363429981893214])) 
		),
		QuadExtField::<ark_ff::Fp2ParamsWrapper::<ark_bn254::Fq2Parameters>>::new(
			ark_ff::Fp256::<ark_bn254::FqParameters>::new(BigInteger256::new([2759293219903128844,13723779788575808075, 5429734218610420872, 284270640615813289])), 
			ark_ff::Fp256::<ark_bn254::FqParameters>::new(BigInteger256::new([10127298648082168099,9775834864860166971, 16034285677595279060, 1969785921159627744])) 
 		)
 	)
}

pub fn get_gamma_g2_neg_pc_60() -> (QuadExtField::<ark_ff::Fp2ParamsWrapper::<ark_bn254::Fq2Parameters>>, QuadExtField::<ark_ff::Fp2ParamsWrapper::<ark_bn254::Fq2Parameters>>, QuadExtField::<ark_ff::Fp2ParamsWrapper::<ark_bn254::Fq2Parameters>>) { 
 	(QuadExtField::<ark_ff::Fp2ParamsWrapper::<ark_bn254::Fq2Parameters>>::new(
			ark_ff::Fp256::<ark_bn254::FqParameters>::new(BigInteger256::new([600580334032652804,2321757057342758172, 12927044650911696839, 912481606074830813])), 
			ark_ff::Fp256::<ark_bn254::FqParameters>::new(BigInteger256::new([1742222540423170356,5388411484089577888, 15669036111913009800, 2290353886734264530])) 
		),
		QuadExtField::<ark_ff::Fp2ParamsWrapper::<ark_bn254::Fq2Parameters>>::new(
			ark_ff::Fp256::<ark_bn254::FqParameters>::new(BigInteger256::new([13524932709418747676,8729729059288064300, 13248815784412083209, 985601685628940268])), 
			ark_ff::Fp256::<ark_bn254::FqParameters>::new(BigInteger256::new([8095896670723043672,9479714206220833451, 9935357687700323105, 1987935092865768071])) 
		),
		QuadExtField::<ark_ff::Fp2ParamsWrapper::<ark_bn254::Fq2Parameters>>::new(
			ark_ff::Fp256::<ark_bn254::FqParameters>::new(BigInteger256::new([12351501345222280255,4564669834210920077, 13079238967595314121, 2893588379208385448])), 
			ark_ff::Fp256::<ark_bn254::FqParameters>::new(BigInteger256::new([6790684858368175968,12342307814734069340, 17437338779261382151, 3113323595042518587])) 
 		)
 	)
}

pub fn get_gamma_g2_neg_pc_61() -> (QuadExtField::<ark_ff::Fp2ParamsWrapper::<ark_bn254::Fq2Parameters>>, QuadExtField::<ark_ff::Fp2ParamsWrapper::<ark_bn254::Fq2Parameters>>, QuadExtField::<ark_ff::Fp2ParamsWrapper::<ark_bn254::Fq2Parameters>>) { 
 	(QuadExtField::<ark_ff::Fp2ParamsWrapper::<ark_bn254::Fq2Parameters>>::new(
			ark_ff::Fp256::<ark_bn254::FqParameters>::new(BigInteger256::new([4335458208259077364,3070146124880902986, 12132813483765417998, 2189079783051835915])), 
			ark_ff::Fp256::<ark_bn254::FqParameters>::new(BigInteger256::new([1273417055656037261,15242501717304447765, 7470293015109889396, 60979368330265425])) 
		),
		QuadExtField::<ark_ff::Fp2ParamsWrapper::<ark_bn254::Fq2Parameters>>::new(
			ark_ff::Fp256::<ark_bn254::FqParameters>::new(BigInteger256::new([495352304476389410,2522603611861727223, 17400605418483600773, 2405243173227662275])), 
			ark_ff::Fp256::<ark_bn254::FqParameters>::new(BigInteger256::new([4145492522477043770,3930196348863807874, 14033363453362515818, 1683218100918056121])) 
		),
		QuadExtField::<ark_ff::Fp2ParamsWrapper::<ark_bn254::Fq2Parameters>>::new(
			ark_ff::Fp256::<ark_bn254::FqParameters>::new(BigInteger256::new([17948501231187937250,16236352245361706135, 13876518441607112130, 1989605743992033509])), 
			ark_ff::Fp256::<ark_bn254::FqParameters>::new(BigInteger256::new([16575051902264652112,3638918838457874372, 12639744488953793639, 2286623855733929397])) 
 		)
 	)
}

pub fn get_gamma_g2_neg_pc_62() -> (QuadExtField::<ark_ff::Fp2ParamsWrapper::<ark_bn254::Fq2Parameters>>, QuadExtField::<ark_ff::Fp2ParamsWrapper::<ark_bn254::Fq2Parameters>>, QuadExtField::<ark_ff::Fp2ParamsWrapper::<ark_bn254::Fq2Parameters>>) { 
 	(QuadExtField::<ark_ff::Fp2ParamsWrapper::<ark_bn254::Fq2Parameters>>::new(
			ark_ff::Fp256::<ark_bn254::FqParameters>::new(BigInteger256::new([10038236537227454322,3834487206512150896, 4837315834914812659, 304845306814793610])), 
			ark_ff::Fp256::<ark_bn254::FqParameters>::new(BigInteger256::new([14889474274324897851,4412684911204420504, 12052436362387123584, 2319462749387062806])) 
		),
		QuadExtField::<ark_ff::Fp2ParamsWrapper::<ark_bn254::Fq2Parameters>>::new(
			ark_ff::Fp256::<ark_bn254::FqParameters>::new(BigInteger256::new([6844925402023018696,2984767693307730228, 8452064398111784330, 2380067291807988977])), 
			ark_ff::Fp256::<ark_bn254::FqParameters>::new(BigInteger256::new([5724892535103664571,11711437062631280273, 16270950815446121735, 2789330935070267190])) 
		),
		QuadExtField::<ark_ff::Fp2ParamsWrapper::<ark_bn254::Fq2Parameters>>::new(
			ark_ff::Fp256::<ark_bn254::FqParameters>::new(BigInteger256::new([9755397992000155692,6036355593694428132, 4635001509125872439, 2886159028675813399])), 
			ark_ff::Fp256::<ark_bn254::FqParameters>::new(BigInteger256::new([16069879372809196519,2291312007277523126, 6433180933700077439, 1486270900233595497])) 
 		)
 	)
}

pub fn get_gamma_g2_neg_pc_63() -> (QuadExtField::<ark_ff::Fp2ParamsWrapper::<ark_bn254::Fq2Parameters>>, QuadExtField::<ark_ff::Fp2ParamsWrapper::<ark_bn254::Fq2Parameters>>, QuadExtField::<ark_ff::Fp2ParamsWrapper::<ark_bn254::Fq2Parameters>>) { 
 	(QuadExtField::<ark_ff::Fp2ParamsWrapper::<ark_bn254::Fq2Parameters>>::new(
			ark_ff::Fp256::<ark_bn254::FqParameters>::new(BigInteger256::new([13921265890829940939,7636330375160570474, 4665960856949324823, 2637580595337034782])), 
			ark_ff::Fp256::<ark_bn254::FqParameters>::new(BigInteger256::new([1676311535076855475,14388116664785243967, 6999886116491182694, 1225600792830782493])) 
		),
		QuadExtField::<ark_ff::Fp2ParamsWrapper::<ark_bn254::Fq2Parameters>>::new(
			ark_ff::Fp256::<ark_bn254::FqParameters>::new(BigInteger256::new([18421970317862919207,1327288065051737192, 7012137319813403714, 2211320130364568615])), 
			ark_ff::Fp256::<ark_bn254::FqParameters>::new(BigInteger256::new([17479704104393317052,7470349539550992410, 7224478043021223785, 2243932882698239654])) 
		),
		QuadExtField::<ark_ff::Fp2ParamsWrapper::<ark_bn254::Fq2Parameters>>::new(
			ark_ff::Fp256::<ark_bn254::FqParameters>::new(BigInteger256::new([3112539271062938499,17833733510041471540, 15283182265851972375, 44533906695271561])), 
			ark_ff::Fp256::<ark_bn254::FqParameters>::new(BigInteger256::new([17205450681903040044,3522788048615418771, 16922755076551489721, 1439467848016457250])) 
 		)
 	)
}

pub fn get_gamma_g2_neg_pc_64() -> (QuadExtField::<ark_ff::Fp2ParamsWrapper::<ark_bn254::Fq2Parameters>>, QuadExtField::<ark_ff::Fp2ParamsWrapper::<ark_bn254::Fq2Parameters>>, QuadExtField::<ark_ff::Fp2ParamsWrapper::<ark_bn254::Fq2Parameters>>) { 
 	(QuadExtField::<ark_ff::Fp2ParamsWrapper::<ark_bn254::Fq2Parameters>>::new(
			ark_ff::Fp256::<ark_bn254::FqParameters>::new(BigInteger256::new([13377146695259432802,14100753620496409992, 7674379385896553691, 2573832464465008930])), 
			ark_ff::Fp256::<ark_bn254::FqParameters>::new(BigInteger256::new([557324928434175368,16981228059930419063, 6030243056256668828, 3417519645769543382])) 
		),
		QuadExtField::<ark_ff::Fp2ParamsWrapper::<ark_bn254::Fq2Parameters>>::new(
			ark_ff::Fp256::<ark_bn254::FqParameters>::new(BigInteger256::new([16569293480025381657,10061462583010325847, 1668892605250494803, 3372783123198145055])), 
			ark_ff::Fp256::<ark_bn254::FqParameters>::new(BigInteger256::new([2313789391118724807,8732181255536968160, 4654984413883914588, 2797945300820465029])) 
		),
		QuadExtField::<ark_ff::Fp2ParamsWrapper::<ark_bn254::Fq2Parameters>>::new(
			ark_ff::Fp256::<ark_bn254::FqParameters>::new(BigInteger256::new([10786873503828530253,12816469824825706583, 12612291718157215005, 765198871954081674])), 
			ark_ff::Fp256::<ark_bn254::FqParameters>::new(BigInteger256::new([16567936393605057352,14195469192344509149, 2677336580189740007, 1591821379742287238])) 
 		)
 	)
}

pub fn get_gamma_g2_neg_pc_65() -> (QuadExtField::<ark_ff::Fp2ParamsWrapper::<ark_bn254::Fq2Parameters>>, QuadExtField::<ark_ff::Fp2ParamsWrapper::<ark_bn254::Fq2Parameters>>, QuadExtField::<ark_ff::Fp2ParamsWrapper::<ark_bn254::Fq2Parameters>>) { 
 	(QuadExtField::<ark_ff::Fp2ParamsWrapper::<ark_bn254::Fq2Parameters>>::new(
			ark_ff::Fp256::<ark_bn254::FqParameters>::new(BigInteger256::new([13626726796417775597,905039304520630014, 14385262270270118529, 931464122089285366])), 
			ark_ff::Fp256::<ark_bn254::FqParameters>::new(BigInteger256::new([6459046813597811608,686563215136329104, 17840121544795996864, 2526159168346761237])) 
		),
		QuadExtField::<ark_ff::Fp2ParamsWrapper::<ark_bn254::Fq2Parameters>>::new(
			ark_ff::Fp256::<ark_bn254::FqParameters>::new(BigInteger256::new([1740725520778714189,3970588031411753937, 15138818668422454728, 3154065812649955101])), 
			ark_ff::Fp256::<ark_bn254::FqParameters>::new(BigInteger256::new([16142871230366316420,382147931728803859, 1578398685310446495, 2892321005796480272])) 
		),
		QuadExtField::<ark_ff::Fp2ParamsWrapper::<ark_bn254::Fq2Parameters>>::new(
			ark_ff::Fp256::<ark_bn254::FqParameters>::new(BigInteger256::new([4573347424348238098,13930425395157667377, 7547321432605579256, 2713293223971936786])), 
			ark_ff::Fp256::<ark_bn254::FqParameters>::new(BigInteger256::new([2939755484115294576,6869514172505015788, 7002476311999383824, 207732096327248456])) 
 		)
 	)
}

pub fn get_gamma_g2_neg_pc_66() -> (QuadExtField::<ark_ff::Fp2ParamsWrapper::<ark_bn254::Fq2Parameters>>, QuadExtField::<ark_ff::Fp2ParamsWrapper::<ark_bn254::Fq2Parameters>>, QuadExtField::<ark_ff::Fp2ParamsWrapper::<ark_bn254::Fq2Parameters>>) { 
 	(QuadExtField::<ark_ff::Fp2ParamsWrapper::<ark_bn254::Fq2Parameters>>::new(
			ark_ff::Fp256::<ark_bn254::FqParameters>::new(BigInteger256::new([13709442686358577124,15832464831351649571, 12076039113892243546, 3455485297433323062])), 
			ark_ff::Fp256::<ark_bn254::FqParameters>::new(BigInteger256::new([18023010755270710631,1345091752456542941, 7706395518894446797, 3294337764106111222])) 
		),
		QuadExtField::<ark_ff::Fp2ParamsWrapper::<ark_bn254::Fq2Parameters>>::new(
			ark_ff::Fp256::<ark_bn254::FqParameters>::new(BigInteger256::new([17912043887633553435,3081559084720998117, 18054355427023015612, 3134494175808145082])), 
			ark_ff::Fp256::<ark_bn254::FqParameters>::new(BigInteger256::new([186337887500567930,7222531963656893566, 14155938318246282343, 2771351750031622878])) 
		),
		QuadExtField::<ark_ff::Fp2ParamsWrapper::<ark_bn254::Fq2Parameters>>::new(
			ark_ff::Fp256::<ark_bn254::FqParameters>::new(BigInteger256::new([12609246564220273487,1594397207756565949, 9825723030124067254, 2724717191726459635])), 
			ark_ff::Fp256::<ark_bn254::FqParameters>::new(BigInteger256::new([12983994115142587269,976540368811885047, 18335483755257327302, 2167427977713783633])) 
 		)
 	)
}

pub fn get_gamma_g2_neg_pc_67() -> (QuadExtField::<ark_ff::Fp2ParamsWrapper::<ark_bn254::Fq2Parameters>>, QuadExtField::<ark_ff::Fp2ParamsWrapper::<ark_bn254::Fq2Parameters>>, QuadExtField::<ark_ff::Fp2ParamsWrapper::<ark_bn254::Fq2Parameters>>) { 
 	(QuadExtField::<ark_ff::Fp2ParamsWrapper::<ark_bn254::Fq2Parameters>>::new(
			ark_ff::Fp256::<ark_bn254::FqParameters>::new(BigInteger256::new([16767682901827683841,13701264828479258978, 10181214404393679883, 1395082227297335398])), 
			ark_ff::Fp256::<ark_bn254::FqParameters>::new(BigInteger256::new([9978352420098653778,15908682512986432460, 13661981653086040843, 424470769782416566])) 
		),
		QuadExtField::<ark_ff::Fp2ParamsWrapper::<ark_bn254::Fq2Parameters>>::new(
			ark_ff::Fp256::<ark_bn254::FqParameters>::new(BigInteger256::new([4767469812439913295,12418131412191642916, 4756013449213123766, 1564404981129552671])), 
			ark_ff::Fp256::<ark_bn254::FqParameters>::new(BigInteger256::new([8809079650558686821,2123224115614886271, 6313393965193212986, 3378636516059800730])) 
		),
		QuadExtField::<ark_ff::Fp2ParamsWrapper::<ark_bn254::Fq2Parameters>>::new(
			ark_ff::Fp256::<ark_bn254::FqParameters>::new(BigInteger256::new([17072499987405276473,10034793520409945765, 15759239356590162154, 413675290036181673])), 
			ark_ff::Fp256::<ark_bn254::FqParameters>::new(BigInteger256::new([10403544644649022418,4260743975056099883, 13757505939064072804, 595280312120297909])) 
 		)
 	)
}

pub fn get_gamma_g2_neg_pc_68() -> (QuadExtField::<ark_ff::Fp2ParamsWrapper::<ark_bn254::Fq2Parameters>>, QuadExtField::<ark_ff::Fp2ParamsWrapper::<ark_bn254::Fq2Parameters>>, QuadExtField::<ark_ff::Fp2ParamsWrapper::<ark_bn254::Fq2Parameters>>) { 
 	(QuadExtField::<ark_ff::Fp2ParamsWrapper::<ark_bn254::Fq2Parameters>>::new(
			ark_ff::Fp256::<ark_bn254::FqParameters>::new(BigInteger256::new([11927676530117983136,13988462498903978459, 16181886719869833670, 160879608735390606])), 
			ark_ff::Fp256::<ark_bn254::FqParameters>::new(BigInteger256::new([15764181760919483149,4749684855409639810, 3265710675173907460, 1373672660229324824])) 
		),
		QuadExtField::<ark_ff::Fp2ParamsWrapper::<ark_bn254::Fq2Parameters>>::new(
			ark_ff::Fp256::<ark_bn254::FqParameters>::new(BigInteger256::new([4702490859355290177,10088008658301722056, 15951539533040514730, 3112554746247782292])), 
			ark_ff::Fp256::<ark_bn254::FqParameters>::new(BigInteger256::new([7717613784005755383,9824452686697220968, 4108379304217917329, 2144271069510608047])) 
		),
		QuadExtField::<ark_ff::Fp2ParamsWrapper::<ark_bn254::Fq2Parameters>>::new(
			ark_ff::Fp256::<ark_bn254::FqParameters>::new(BigInteger256::new([5210921203500069385,8541209335657447558, 1626519623793301518, 2000565976104463586])), 
			ark_ff::Fp256::<ark_bn254::FqParameters>::new(BigInteger256::new([14157975516393092985,12099147446097414594, 6648131713760764113, 969754343192134911])) 
 		)
 	)
}

pub fn get_gamma_g2_neg_pc_69() -> (QuadExtField::<ark_ff::Fp2ParamsWrapper::<ark_bn254::Fq2Parameters>>, QuadExtField::<ark_ff::Fp2ParamsWrapper::<ark_bn254::Fq2Parameters>>, QuadExtField::<ark_ff::Fp2ParamsWrapper::<ark_bn254::Fq2Parameters>>) { 
 	(QuadExtField::<ark_ff::Fp2ParamsWrapper::<ark_bn254::Fq2Parameters>>::new(
			ark_ff::Fp256::<ark_bn254::FqParameters>::new(BigInteger256::new([17980189460187830778,1889219941237090783, 13909195107060244038, 1685396046443038178])), 
			ark_ff::Fp256::<ark_bn254::FqParameters>::new(BigInteger256::new([3051833930183928347,18416720040833329799, 10087408079259648135, 1576906038236231369])) 
		),
		QuadExtField::<ark_ff::Fp2ParamsWrapper::<ark_bn254::Fq2Parameters>>::new(
			ark_ff::Fp256::<ark_bn254::FqParameters>::new(BigInteger256::new([15466516961608624603,16844094941723239288, 11285642211676663926, 2975145632133377167])), 
			ark_ff::Fp256::<ark_bn254::FqParameters>::new(BigInteger256::new([13471066094520601513,17016282780077945631, 3938930665007322204, 708245874277978584])) 
		),
		QuadExtField::<ark_ff::Fp2ParamsWrapper::<ark_bn254::Fq2Parameters>>::new(
			ark_ff::Fp256::<ark_bn254::FqParameters>::new(BigInteger256::new([15031906007597449965,6239039503303329396, 13836318553878840955, 2695871689734768577])), 
			ark_ff::Fp256::<ark_bn254::FqParameters>::new(BigInteger256::new([6793852692303112306,6313229706798686289, 1376699463481876760, 2357506978952490562])) 
 		)
 	)
}

pub fn get_gamma_g2_neg_pc_70() -> (QuadExtField::<ark_ff::Fp2ParamsWrapper::<ark_bn254::Fq2Parameters>>, QuadExtField::<ark_ff::Fp2ParamsWrapper::<ark_bn254::Fq2Parameters>>, QuadExtField::<ark_ff::Fp2ParamsWrapper::<ark_bn254::Fq2Parameters>>) { 
 	(QuadExtField::<ark_ff::Fp2ParamsWrapper::<ark_bn254::Fq2Parameters>>::new(
			ark_ff::Fp256::<ark_bn254::FqParameters>::new(BigInteger256::new([11366828076657158452,9549996211954041848, 3650044825479732830, 1373814187006603594])), 
			ark_ff::Fp256::<ark_bn254::FqParameters>::new(BigInteger256::new([9692203809937244817,7673331868786818439, 541285382427134688, 2059056691169337877])) 
		),
		QuadExtField::<ark_ff::Fp2ParamsWrapper::<ark_bn254::Fq2Parameters>>::new(
			ark_ff::Fp256::<ark_bn254::FqParameters>::new(BigInteger256::new([2839986922434318894,6239121690087443138, 3236924118009391825, 2074927829763140595])), 
			ark_ff::Fp256::<ark_bn254::FqParameters>::new(BigInteger256::new([3579273526184828578,4647357847463812081, 10661538303636942038, 3413451426506981126])) 
		),
		QuadExtField::<ark_ff::Fp2ParamsWrapper::<ark_bn254::Fq2Parameters>>::new(
			ark_ff::Fp256::<ark_bn254::FqParameters>::new(BigInteger256::new([14254589568286730706,13380399875864742632, 10230702462255046996, 2216587113744176350])), 
			ark_ff::Fp256::<ark_bn254::FqParameters>::new(BigInteger256::new([12638907948086058139,10816299396480670272, 6983807940519337989, 3230703026124390459])) 
 		)
 	)
}

pub fn get_gamma_g2_neg_pc_71() -> (QuadExtField::<ark_ff::Fp2ParamsWrapper::<ark_bn254::Fq2Parameters>>, QuadExtField::<ark_ff::Fp2ParamsWrapper::<ark_bn254::Fq2Parameters>>, QuadExtField::<ark_ff::Fp2ParamsWrapper::<ark_bn254::Fq2Parameters>>) { 
 	(QuadExtField::<ark_ff::Fp2ParamsWrapper::<ark_bn254::Fq2Parameters>>::new(
			ark_ff::Fp256::<ark_bn254::FqParameters>::new(BigInteger256::new([5058092415032108019,8462765089004818857, 7967880597174752471, 1490019821615785378])), 
			ark_ff::Fp256::<ark_bn254::FqParameters>::new(BigInteger256::new([14070960174070275357,11842197375827090414, 1306527162536347535, 1957376770316997198])) 
		),
		QuadExtField::<ark_ff::Fp2ParamsWrapper::<ark_bn254::Fq2Parameters>>::new(
			ark_ff::Fp256::<ark_bn254::FqParameters>::new(BigInteger256::new([13198164446365042680,11901445055653796909, 2281480632337590920, 3142146612845804764])), 
			ark_ff::Fp256::<ark_bn254::FqParameters>::new(BigInteger256::new([4156556221081109790,9039985719708943681, 7223578382291564494, 570548833514427866])) 
		),
		QuadExtField::<ark_ff::Fp2ParamsWrapper::<ark_bn254::Fq2Parameters>>::new(
			ark_ff::Fp256::<ark_bn254::FqParameters>::new(BigInteger256::new([14506878757868128098,16544943007052494589, 2198031624981621405, 2033961111379319849])), 
			ark_ff::Fp256::<ark_bn254::FqParameters>::new(BigInteger256::new([1569457014480111647,8958345506216933074, 3065879269802886706, 1556744670853561648])) 
 		)
 	)
}

pub fn get_gamma_g2_neg_pc_72() -> (QuadExtField::<ark_ff::Fp2ParamsWrapper::<ark_bn254::Fq2Parameters>>, QuadExtField::<ark_ff::Fp2ParamsWrapper::<ark_bn254::Fq2Parameters>>, QuadExtField::<ark_ff::Fp2ParamsWrapper::<ark_bn254::Fq2Parameters>>) { 
 	(QuadExtField::<ark_ff::Fp2ParamsWrapper::<ark_bn254::Fq2Parameters>>::new(
			ark_ff::Fp256::<ark_bn254::FqParameters>::new(BigInteger256::new([8670769452050281486,2603157643224096297, 5170940931522518091, 2169635355341440494])), 
			ark_ff::Fp256::<ark_bn254::FqParameters>::new(BigInteger256::new([17858655563487727388,13974350819178327018, 14191523303038937084, 1933479454295296944])) 
		),
		QuadExtField::<ark_ff::Fp2ParamsWrapper::<ark_bn254::Fq2Parameters>>::new(
			ark_ff::Fp256::<ark_bn254::FqParameters>::new(BigInteger256::new([11561363935362204025,5244667953953900991, 17590897577082643744, 452292303762752503])), 
			ark_ff::Fp256::<ark_bn254::FqParameters>::new(BigInteger256::new([10548293481047491397,3726803642967868876, 16004578249770811828, 1197762234507486424])) 
		),
		QuadExtField::<ark_ff::Fp2ParamsWrapper::<ark_bn254::Fq2Parameters>>::new(
			ark_ff::Fp256::<ark_bn254::FqParameters>::new(BigInteger256::new([4825160836412796851,15796880338500075246, 18104269758408963704, 3351107969528331429])), 
			ark_ff::Fp256::<ark_bn254::FqParameters>::new(BigInteger256::new([3677353594604656777,13243886080375460536, 493482802944247320, 2887949280159124944])) 
 		)
 	)
}

pub fn get_gamma_g2_neg_pc_73() -> (QuadExtField::<ark_ff::Fp2ParamsWrapper::<ark_bn254::Fq2Parameters>>, QuadExtField::<ark_ff::Fp2ParamsWrapper::<ark_bn254::Fq2Parameters>>, QuadExtField::<ark_ff::Fp2ParamsWrapper::<ark_bn254::Fq2Parameters>>) { 
 	(QuadExtField::<ark_ff::Fp2ParamsWrapper::<ark_bn254::Fq2Parameters>>::new(
			ark_ff::Fp256::<ark_bn254::FqParameters>::new(BigInteger256::new([8479760529281690674,7994751242138411134, 15345767225237783154, 3430220711344759297])), 
			ark_ff::Fp256::<ark_bn254::FqParameters>::new(BigInteger256::new([524416989865606757,904006822949417225, 2796530985342658600, 479884119105635171])) 
		),
		QuadExtField::<ark_ff::Fp2ParamsWrapper::<ark_bn254::Fq2Parameters>>::new(
			ark_ff::Fp256::<ark_bn254::FqParameters>::new(BigInteger256::new([830443950718677975,1025634055668035284, 18172819390113448366, 131764769808948612])), 
			ark_ff::Fp256::<ark_bn254::FqParameters>::new(BigInteger256::new([4222005762950425160,17555140366314449330, 14403806003810144495, 2669422862431671005])) 
		),
		QuadExtField::<ark_ff::Fp2ParamsWrapper::<ark_bn254::Fq2Parameters>>::new(
			ark_ff::Fp256::<ark_bn254::FqParameters>::new(BigInteger256::new([14565552002431377048,16565630375138188061, 14575995455443639551, 1274682148956826002])), 
			ark_ff::Fp256::<ark_bn254::FqParameters>::new(BigInteger256::new([4889098274062523040,3593520692859002798, 5392306450307316027, 3182134861099261142])) 
 		)
 	)
}

pub fn get_gamma_g2_neg_pc_74() -> (QuadExtField::<ark_ff::Fp2ParamsWrapper::<ark_bn254::Fq2Parameters>>, QuadExtField::<ark_ff::Fp2ParamsWrapper::<ark_bn254::Fq2Parameters>>, QuadExtField::<ark_ff::Fp2ParamsWrapper::<ark_bn254::Fq2Parameters>>) { 
 	(QuadExtField::<ark_ff::Fp2ParamsWrapper::<ark_bn254::Fq2Parameters>>::new(
			ark_ff::Fp256::<ark_bn254::FqParameters>::new(BigInteger256::new([1309357342976202953,4214876501554558651, 612196342916926809, 2975961936085837136])), 
			ark_ff::Fp256::<ark_bn254::FqParameters>::new(BigInteger256::new([10269679222705203257,11780564713707960686, 1794612721178241253, 1534343832212062965])) 
		),
		QuadExtField::<ark_ff::Fp2ParamsWrapper::<ark_bn254::Fq2Parameters>>::new(
			ark_ff::Fp256::<ark_bn254::FqParameters>::new(BigInteger256::new([15678624791121454939,10355914611054688241, 7599887174411926085, 2863204088224670613])), 
			ark_ff::Fp256::<ark_bn254::FqParameters>::new(BigInteger256::new([6002955251576793929,6234348676434665827, 14978427608665948614, 2268876856796670138])) 
		),
		QuadExtField::<ark_ff::Fp2ParamsWrapper::<ark_bn254::Fq2Parameters>>::new(
			ark_ff::Fp256::<ark_bn254::FqParameters>::new(BigInteger256::new([9257438800131341756,3130394428690402783, 18230611937698292340, 2740678391300670167])), 
			ark_ff::Fp256::<ark_bn254::FqParameters>::new(BigInteger256::new([14390331293882510601,16419122494332313410, 9922013992643156140, 2844396889136699083])) 
 		)
 	)
}

pub fn get_gamma_g2_neg_pc_75() -> (QuadExtField::<ark_ff::Fp2ParamsWrapper::<ark_bn254::Fq2Parameters>>, QuadExtField::<ark_ff::Fp2ParamsWrapper::<ark_bn254::Fq2Parameters>>, QuadExtField::<ark_ff::Fp2ParamsWrapper::<ark_bn254::Fq2Parameters>>) { 
 	(QuadExtField::<ark_ff::Fp2ParamsWrapper::<ark_bn254::Fq2Parameters>>::new(
			ark_ff::Fp256::<ark_bn254::FqParameters>::new(BigInteger256::new([10098955407197731028,12656715286844168905, 15535148986134773930, 2947605084333243272])), 
			ark_ff::Fp256::<ark_bn254::FqParameters>::new(BigInteger256::new([10657330263306238797,2217315742359539172, 18265949491644139088, 846602167354454739])) 
		),
		QuadExtField::<ark_ff::Fp2ParamsWrapper::<ark_bn254::Fq2Parameters>>::new(
			ark_ff::Fp256::<ark_bn254::FqParameters>::new(BigInteger256::new([9038037631799291094,5225532145101885408, 8281059509122928437, 28324414295733782])), 
			ark_ff::Fp256::<ark_bn254::FqParameters>::new(BigInteger256::new([17467972194800785766,5536291185643948069, 12736906291079283085, 1852657603193167013])) 
		),
		QuadExtField::<ark_ff::Fp2ParamsWrapper::<ark_bn254::Fq2Parameters>>::new(
			ark_ff::Fp256::<ark_bn254::FqParameters>::new(BigInteger256::new([1516587024314539810,11982255204610613517, 1155001714131273471, 896401992504972885])), 
			ark_ff::Fp256::<ark_bn254::FqParameters>::new(BigInteger256::new([17030494227113718239,13630795687692713630, 7460998560730100552, 132793221639939795])) 
 		)
 	)
}

pub fn get_gamma_g2_neg_pc_76() -> (QuadExtField::<ark_ff::Fp2ParamsWrapper::<ark_bn254::Fq2Parameters>>, QuadExtField::<ark_ff::Fp2ParamsWrapper::<ark_bn254::Fq2Parameters>>, QuadExtField::<ark_ff::Fp2ParamsWrapper::<ark_bn254::Fq2Parameters>>) { 
 	(QuadExtField::<ark_ff::Fp2ParamsWrapper::<ark_bn254::Fq2Parameters>>::new(
			ark_ff::Fp256::<ark_bn254::FqParameters>::new(BigInteger256::new([10176615368683446660,601583534723294556, 13110665065271052236, 2861720736213065106])), 
			ark_ff::Fp256::<ark_bn254::FqParameters>::new(BigInteger256::new([17880345649508354921,3871979978980853183, 6655522217469181008, 200518909375314463])) 
		),
		QuadExtField::<ark_ff::Fp2ParamsWrapper::<ark_bn254::Fq2Parameters>>::new(
			ark_ff::Fp256::<ark_bn254::FqParameters>::new(BigInteger256::new([1798745044690121375,10759244287798089531, 8948551391234015540, 928153838998254791])), 
			ark_ff::Fp256::<ark_bn254::FqParameters>::new(BigInteger256::new([4854644120111971641,11604223912110353503, 18403836121615736198, 2037443035641934904])) 
		),
		QuadExtField::<ark_ff::Fp2ParamsWrapper::<ark_bn254::Fq2Parameters>>::new(
			ark_ff::Fp256::<ark_bn254::FqParameters>::new(BigInteger256::new([16565873182373372440,7400749194843479231, 3008657753327233814, 839805860278934523])), 
			ark_ff::Fp256::<ark_bn254::FqParameters>::new(BigInteger256::new([9378001881854219365,8314728862485991704, 7763929823464409236, 1843342585299060254])) 
 		)
 	)
}

pub fn get_gamma_g2_neg_pc_77() -> (QuadExtField::<ark_ff::Fp2ParamsWrapper::<ark_bn254::Fq2Parameters>>, QuadExtField::<ark_ff::Fp2ParamsWrapper::<ark_bn254::Fq2Parameters>>, QuadExtField::<ark_ff::Fp2ParamsWrapper::<ark_bn254::Fq2Parameters>>) { 
 	(QuadExtField::<ark_ff::Fp2ParamsWrapper::<ark_bn254::Fq2Parameters>>::new(
			ark_ff::Fp256::<ark_bn254::FqParameters>::new(BigInteger256::new([4856522731738463993,12034688578446946381, 193602104566264668, 2354117359251320137])), 
			ark_ff::Fp256::<ark_bn254::FqParameters>::new(BigInteger256::new([13090388147234528083,6770974428891810482, 1846596488981736037, 1971220940796455096])) 
		),
		QuadExtField::<ark_ff::Fp2ParamsWrapper::<ark_bn254::Fq2Parameters>>::new(
			ark_ff::Fp256::<ark_bn254::FqParameters>::new(BigInteger256::new([14016549827697015028,9608312358581675044, 4938637631394377688, 2612555136020187704])), 
			ark_ff::Fp256::<ark_bn254::FqParameters>::new(BigInteger256::new([3767156235301953140,3708001549184614692, 15817524667752243240, 2711889907619030045])) 
		),
		QuadExtField::<ark_ff::Fp2ParamsWrapper::<ark_bn254::Fq2Parameters>>::new(
			ark_ff::Fp256::<ark_bn254::FqParameters>::new(BigInteger256::new([1325748209183447016,14610883328180414904, 1759057113030637034, 525339018639169178])), 
			ark_ff::Fp256::<ark_bn254::FqParameters>::new(BigInteger256::new([16428758989474667697,13196397865265683154, 9151441209947915125, 3283208787367466898])) 
 		)
 	)
}

pub fn get_gamma_g2_neg_pc_78() -> (QuadExtField::<ark_ff::Fp2ParamsWrapper::<ark_bn254::Fq2Parameters>>, QuadExtField::<ark_ff::Fp2ParamsWrapper::<ark_bn254::Fq2Parameters>>, QuadExtField::<ark_ff::Fp2ParamsWrapper::<ark_bn254::Fq2Parameters>>) { 
 	(QuadExtField::<ark_ff::Fp2ParamsWrapper::<ark_bn254::Fq2Parameters>>::new(
			ark_ff::Fp256::<ark_bn254::FqParameters>::new(BigInteger256::new([6553874684694368455,9301571099664561278, 14237282328599277535, 2471261460831592801])), 
			ark_ff::Fp256::<ark_bn254::FqParameters>::new(BigInteger256::new([1636100556647778311,3827957952009907610, 15551048411498001302, 1898011813581247742])) 
		),
		QuadExtField::<ark_ff::Fp2ParamsWrapper::<ark_bn254::Fq2Parameters>>::new(
			ark_ff::Fp256::<ark_bn254::FqParameters>::new(BigInteger256::new([16950077254605975014,14754718289583278266, 11624264081282056163, 1305554521772707728])), 
			ark_ff::Fp256::<ark_bn254::FqParameters>::new(BigInteger256::new([12772965760979088209,394669632841202750, 16394036464624281841, 3426583584086903179])) 
		),
		QuadExtField::<ark_ff::Fp2ParamsWrapper::<ark_bn254::Fq2Parameters>>::new(
			ark_ff::Fp256::<ark_bn254::FqParameters>::new(BigInteger256::new([3965499529118527969,1864766547587760102, 4921104890318981551, 1038463313152890140])), 
			ark_ff::Fp256::<ark_bn254::FqParameters>::new(BigInteger256::new([17072525794739801527,6022531744446010312, 14453564009875723049, 3325175676479929237])) 
 		)
 	)
}

pub fn get_gamma_g2_neg_pc_79() -> (QuadExtField::<ark_ff::Fp2ParamsWrapper::<ark_bn254::Fq2Parameters>>, QuadExtField::<ark_ff::Fp2ParamsWrapper::<ark_bn254::Fq2Parameters>>, QuadExtField::<ark_ff::Fp2ParamsWrapper::<ark_bn254::Fq2Parameters>>) { 
 	(QuadExtField::<ark_ff::Fp2ParamsWrapper::<ark_bn254::Fq2Parameters>>::new(
			ark_ff::Fp256::<ark_bn254::FqParameters>::new(BigInteger256::new([1090926775047554870,7374864286345996973, 5785741914586266972, 2276686030916015238])), 
			ark_ff::Fp256::<ark_bn254::FqParameters>::new(BigInteger256::new([9792707039150846344,4516930697246621247, 4448084479452425457, 1996587931051355115])) 
		),
		QuadExtField::<ark_ff::Fp2ParamsWrapper::<ark_bn254::Fq2Parameters>>::new(
			ark_ff::Fp256::<ark_bn254::FqParameters>::new(BigInteger256::new([17379415007087396391,9575908516321139397, 9530433683536101519, 3122784550798977959])), 
			ark_ff::Fp256::<ark_bn254::FqParameters>::new(BigInteger256::new([16525951791268729871,16200773062959914622, 17199317757738025354, 2450494661415658234])) 
		),
		QuadExtField::<ark_ff::Fp2ParamsWrapper::<ark_bn254::Fq2Parameters>>::new(
			ark_ff::Fp256::<ark_bn254::FqParameters>::new(BigInteger256::new([17506600053239517039,6744584825066007595, 6840225580237310845, 1171279626464492107])), 
			ark_ff::Fp256::<ark_bn254::FqParameters>::new(BigInteger256::new([4265082730179779326,16653451769088725385, 12829350476060252712, 1346333834376613912])) 
 		)
 	)
}

pub fn get_gamma_g2_neg_pc_80() -> (QuadExtField::<ark_ff::Fp2ParamsWrapper::<ark_bn254::Fq2Parameters>>, QuadExtField::<ark_ff::Fp2ParamsWrapper::<ark_bn254::Fq2Parameters>>, QuadExtField::<ark_ff::Fp2ParamsWrapper::<ark_bn254::Fq2Parameters>>) { 
 	(QuadExtField::<ark_ff::Fp2ParamsWrapper::<ark_bn254::Fq2Parameters>>::new(
			ark_ff::Fp256::<ark_bn254::FqParameters>::new(BigInteger256::new([7432876191203405911,12664807927281999210, 1595364054487489041, 2701447910710025167])), 
			ark_ff::Fp256::<ark_bn254::FqParameters>::new(BigInteger256::new([11940602867216769464,7627319978759996784, 10788959484739266130, 1949685945741268869])) 
		),
		QuadExtField::<ark_ff::Fp2ParamsWrapper::<ark_bn254::Fq2Parameters>>::new(
			ark_ff::Fp256::<ark_bn254::FqParameters>::new(BigInteger256::new([3967213674833130328,9488545194614397643, 10379184825751751890, 2121056850668979323])), 
			ark_ff::Fp256::<ark_bn254::FqParameters>::new(BigInteger256::new([15678207676027215262,7992288253016774215, 8771697536939175083, 3445525118491567819])) 
		),
		QuadExtField::<ark_ff::Fp2ParamsWrapper::<ark_bn254::Fq2Parameters>>::new(
			ark_ff::Fp256::<ark_bn254::FqParameters>::new(BigInteger256::new([135614741216695967,16195561188624744339, 7911415893389956452, 2790743246561021932])), 
			ark_ff::Fp256::<ark_bn254::FqParameters>::new(BigInteger256::new([6623361901228602847,5489245354088947357, 4262256575266375647, 162980415131956532])) 
 		)
 	)
}

pub fn get_gamma_g2_neg_pc_81() -> (QuadExtField::<ark_ff::Fp2ParamsWrapper::<ark_bn254::Fq2Parameters>>, QuadExtField::<ark_ff::Fp2ParamsWrapper::<ark_bn254::Fq2Parameters>>, QuadExtField::<ark_ff::Fp2ParamsWrapper::<ark_bn254::Fq2Parameters>>) { 
 	(QuadExtField::<ark_ff::Fp2ParamsWrapper::<ark_bn254::Fq2Parameters>>::new(
			ark_ff::Fp256::<ark_bn254::FqParameters>::new(BigInteger256::new([3519293655442125928,11780008180724893403, 12228611059897045935, 1697727080360643973])), 
			ark_ff::Fp256::<ark_bn254::FqParameters>::new(BigInteger256::new([16170302785219017980,5730153183903731472, 4020348276203094029, 366170179338240947])) 
		),
		QuadExtField::<ark_ff::Fp2ParamsWrapper::<ark_bn254::Fq2Parameters>>::new(
			ark_ff::Fp256::<ark_bn254::FqParameters>::new(BigInteger256::new([15621740143426463190,7449733180026159217, 869406022328016112, 3219751642499375377])), 
			ark_ff::Fp256::<ark_bn254::FqParameters>::new(BigInteger256::new([17387351768998469767,6892753790464412759, 11476027800764791449, 3178641352535219284])) 
		),
		QuadExtField::<ark_ff::Fp2ParamsWrapper::<ark_bn254::Fq2Parameters>>::new(
			ark_ff::Fp256::<ark_bn254::FqParameters>::new(BigInteger256::new([14840849188449838914,15625289482808013370, 13932615326385662473, 3016388555336841699])), 
			ark_ff::Fp256::<ark_bn254::FqParameters>::new(BigInteger256::new([13737340252094200359,828424022266252818, 10426451617748214473, 574784688313300629])) 
 		)
 	)
}

pub fn get_gamma_g2_neg_pc_82() -> (QuadExtField::<ark_ff::Fp2ParamsWrapper::<ark_bn254::Fq2Parameters>>, QuadExtField::<ark_ff::Fp2ParamsWrapper::<ark_bn254::Fq2Parameters>>, QuadExtField::<ark_ff::Fp2ParamsWrapper::<ark_bn254::Fq2Parameters>>) { 
 	(QuadExtField::<ark_ff::Fp2ParamsWrapper::<ark_bn254::Fq2Parameters>>::new(
			ark_ff::Fp256::<ark_bn254::FqParameters>::new(BigInteger256::new([16227214634012445639,10180816771680461395, 5748796231136300764, 109165530280654655])), 
			ark_ff::Fp256::<ark_bn254::FqParameters>::new(BigInteger256::new([1722301671187689106,2808728941222518632, 11092363639505192063, 2725335253653097289])) 
		),
		QuadExtField::<ark_ff::Fp2ParamsWrapper::<ark_bn254::Fq2Parameters>>::new(
			ark_ff::Fp256::<ark_bn254::FqParameters>::new(BigInteger256::new([11681521770028146767,11672153066658936838, 17998965641137332885, 3151190869304898104])), 
			ark_ff::Fp256::<ark_bn254::FqParameters>::new(BigInteger256::new([9099300166845450022,8531745995743027770, 9899135786717951957, 208878410924132320])) 
		),
		QuadExtField::<ark_ff::Fp2ParamsWrapper::<ark_bn254::Fq2Parameters>>::new(
			ark_ff::Fp256::<ark_bn254::FqParameters>::new(BigInteger256::new([4766498456916239682,12673053865872984467, 12345543418898768255, 474193184295504085])), 
			ark_ff::Fp256::<ark_bn254::FqParameters>::new(BigInteger256::new([10284844796759031945,5244886598751168886, 15962087395817320263, 2880419048435354140])) 
 		)
 	)
}

pub fn get_gamma_g2_neg_pc_83() -> (QuadExtField::<ark_ff::Fp2ParamsWrapper::<ark_bn254::Fq2Parameters>>, QuadExtField::<ark_ff::Fp2ParamsWrapper::<ark_bn254::Fq2Parameters>>, QuadExtField::<ark_ff::Fp2ParamsWrapper::<ark_bn254::Fq2Parameters>>) { 
 	(QuadExtField::<ark_ff::Fp2ParamsWrapper::<ark_bn254::Fq2Parameters>>::new(
			ark_ff::Fp256::<ark_bn254::FqParameters>::new(BigInteger256::new([3583795318172233317,11268429957831117231, 8134382223248204832, 770582330385718857])), 
			ark_ff::Fp256::<ark_bn254::FqParameters>::new(BigInteger256::new([5445011628784955794,8132405898873957770, 13207376010329008512, 3022248363674238333])) 
		),
		QuadExtField::<ark_ff::Fp2ParamsWrapper::<ark_bn254::Fq2Parameters>>::new(
			ark_ff::Fp256::<ark_bn254::FqParameters>::new(BigInteger256::new([14806908376731975256,5676584781280515677, 2181484093012997946, 47417766018892056])), 
			ark_ff::Fp256::<ark_bn254::FqParameters>::new(BigInteger256::new([4534754134813343491,41333861970492782, 8049221930611838086, 1061618236260490291])) 
		),
		QuadExtField::<ark_ff::Fp2ParamsWrapper::<ark_bn254::Fq2Parameters>>::new(
			ark_ff::Fp256::<ark_bn254::FqParameters>::new(BigInteger256::new([7633387908047997279,10470260179857079669, 12862306077389804594, 1146878657420453056])), 
			ark_ff::Fp256::<ark_bn254::FqParameters>::new(BigInteger256::new([8307119838564452965,13272869246662139979, 4002361588242659082, 407514155588243603])) 
 		)
 	)
}

pub fn get_gamma_g2_neg_pc_84() -> (QuadExtField::<ark_ff::Fp2ParamsWrapper::<ark_bn254::Fq2Parameters>>, QuadExtField::<ark_ff::Fp2ParamsWrapper::<ark_bn254::Fq2Parameters>>, QuadExtField::<ark_ff::Fp2ParamsWrapper::<ark_bn254::Fq2Parameters>>) { 
 	(QuadExtField::<ark_ff::Fp2ParamsWrapper::<ark_bn254::Fq2Parameters>>::new(
			ark_ff::Fp256::<ark_bn254::FqParameters>::new(BigInteger256::new([13263646417427634136,17355738782685760364, 9357544541436672632, 2221196746893269601])), 
			ark_ff::Fp256::<ark_bn254::FqParameters>::new(BigInteger256::new([16541889920093155845,3879754979833245024, 11772995882777749148, 1494809808540438513])) 
		),
		QuadExtField::<ark_ff::Fp2ParamsWrapper::<ark_bn254::Fq2Parameters>>::new(
			ark_ff::Fp256::<ark_bn254::FqParameters>::new(BigInteger256::new([17276331879514065224,7052008681533180528, 13373166147395170538, 1416611334284347550])), 
			ark_ff::Fp256::<ark_bn254::FqParameters>::new(BigInteger256::new([1583651981840925397,16640752858233130827, 10454241491761773452, 3392937361912669238])) 
		),
		QuadExtField::<ark_ff::Fp2ParamsWrapper::<ark_bn254::Fq2Parameters>>::new(
			ark_ff::Fp256::<ark_bn254::FqParameters>::new(BigInteger256::new([1353976248177513358,8562732089841534050, 11765294704957119933, 1810876761327035348])), 
			ark_ff::Fp256::<ark_bn254::FqParameters>::new(BigInteger256::new([656799983739244941,8068547632821329446, 401210878746038035, 617449648840504201])) 
 		)
 	)
}

pub fn get_gamma_g2_neg_pc_85() -> (QuadExtField::<ark_ff::Fp2ParamsWrapper::<ark_bn254::Fq2Parameters>>, QuadExtField::<ark_ff::Fp2ParamsWrapper::<ark_bn254::Fq2Parameters>>, QuadExtField::<ark_ff::Fp2ParamsWrapper::<ark_bn254::Fq2Parameters>>) { 
 	(QuadExtField::<ark_ff::Fp2ParamsWrapper::<ark_bn254::Fq2Parameters>>::new(
			ark_ff::Fp256::<ark_bn254::FqParameters>::new(BigInteger256::new([15439336233301813122,6708743064136549125, 6956120218660849920, 1426788904589992037])), 
			ark_ff::Fp256::<ark_bn254::FqParameters>::new(BigInteger256::new([10482862259574859089,2720795240313759542, 13849853619347396249, 451045416005369770])) 
		),
		QuadExtField::<ark_ff::Fp2ParamsWrapper::<ark_bn254::Fq2Parameters>>::new(
			ark_ff::Fp256::<ark_bn254::FqParameters>::new(BigInteger256::new([16629460883034211643,15841847014574277074, 7307152824076067709, 3220001320002591522])), 
			ark_ff::Fp256::<ark_bn254::FqParameters>::new(BigInteger256::new([7364705659418664452,87748415856981029, 884386995931112496, 2978143857741552980])) 
		),
		QuadExtField::<ark_ff::Fp2ParamsWrapper::<ark_bn254::Fq2Parameters>>::new(
			ark_ff::Fp256::<ark_bn254::FqParameters>::new(BigInteger256::new([11607446160836332799,5935320633989379015, 1950226349158249541, 1477507517931399127])), 
			ark_ff::Fp256::<ark_bn254::FqParameters>::new(BigInteger256::new([13643865300084526800,4288803503352663118, 2234848628509192220, 2162603572046936857])) 
 		)
 	)
}

pub fn get_gamma_g2_neg_pc_86() -> (QuadExtField::<ark_ff::Fp2ParamsWrapper::<ark_bn254::Fq2Parameters>>, QuadExtField::<ark_ff::Fp2ParamsWrapper::<ark_bn254::Fq2Parameters>>, QuadExtField::<ark_ff::Fp2ParamsWrapper::<ark_bn254::Fq2Parameters>>) { 
 	(QuadExtField::<ark_ff::Fp2ParamsWrapper::<ark_bn254::Fq2Parameters>>::new(
			ark_ff::Fp256::<ark_bn254::FqParameters>::new(BigInteger256::new([4618868288865848009,18154973364001707526, 3008530448383180123, 320132757662851989])), 
			ark_ff::Fp256::<ark_bn254::FqParameters>::new(BigInteger256::new([2679164917805814420,1582666986058664909, 18104076937350696389, 2547159725166493304])) 
		),
		QuadExtField::<ark_ff::Fp2ParamsWrapper::<ark_bn254::Fq2Parameters>>::new(
			ark_ff::Fp256::<ark_bn254::FqParameters>::new(BigInteger256::new([665923590493782918,15080850902817201290, 15247621324780990287, 1373009601597800244])), 
			ark_ff::Fp256::<ark_bn254::FqParameters>::new(BigInteger256::new([10136008735044576801,5925439540950230479, 4926715132399968983, 2379420566225313231])) 
		),
		QuadExtField::<ark_ff::Fp2ParamsWrapper::<ark_bn254::Fq2Parameters>>::new(
			ark_ff::Fp256::<ark_bn254::FqParameters>::new(BigInteger256::new([4561965519654710606,10785850761679807080, 43372938273663600, 3414280957004115003])), 
			ark_ff::Fp256::<ark_bn254::FqParameters>::new(BigInteger256::new([9244942981313276843,3041430537908235615, 17139575369328235653, 2256865004348951090])) 
 		)
 	)
}

pub fn get_gamma_g2_neg_pc_87() -> (QuadExtField::<ark_ff::Fp2ParamsWrapper::<ark_bn254::Fq2Parameters>>, QuadExtField::<ark_ff::Fp2ParamsWrapper::<ark_bn254::Fq2Parameters>>, QuadExtField::<ark_ff::Fp2ParamsWrapper::<ark_bn254::Fq2Parameters>>) { 
 	(QuadExtField::<ark_ff::Fp2ParamsWrapper::<ark_bn254::Fq2Parameters>>::new(
			ark_ff::Fp256::<ark_bn254::FqParameters>::new(BigInteger256::new([12022285821251125120,8394710227083158936, 9190625303714994848, 1316584088401679566])), 
			ark_ff::Fp256::<ark_bn254::FqParameters>::new(BigInteger256::new([2648153319109453592,7281114132632607450, 4723070212040088738, 1264676797495982032])) 
		),
		QuadExtField::<ark_ff::Fp2ParamsWrapper::<ark_bn254::Fq2Parameters>>::new(
			ark_ff::Fp256::<ark_bn254::FqParameters>::new(BigInteger256::new([16868530150508351437,12130043265208003121, 13122728819502030419, 2305990981832655472])), 
			ark_ff::Fp256::<ark_bn254::FqParameters>::new(BigInteger256::new([16000751638757593015,18294701796841483430, 10785978653820750417, 2876298256075627220])) 
		),
		QuadExtField::<ark_ff::Fp2ParamsWrapper::<ark_bn254::Fq2Parameters>>::new(
			ark_ff::Fp256::<ark_bn254::FqParameters>::new(BigInteger256::new([8640937735723485698,812414643428927659, 313595488712102211, 1576472057062325075])), 
			ark_ff::Fp256::<ark_bn254::FqParameters>::new(BigInteger256::new([14748628538018346012,16530758572193484058, 15555401233343268105, 2341080813301348146])) 
 		)
 	)
}

pub fn get_gamma_g2_neg_pc_88() -> (QuadExtField::<ark_ff::Fp2ParamsWrapper::<ark_bn254::Fq2Parameters>>, QuadExtField::<ark_ff::Fp2ParamsWrapper::<ark_bn254::Fq2Parameters>>, QuadExtField::<ark_ff::Fp2ParamsWrapper::<ark_bn254::Fq2Parameters>>) { 
 	(QuadExtField::<ark_ff::Fp2ParamsWrapper::<ark_bn254::Fq2Parameters>>::new(
			ark_ff::Fp256::<ark_bn254::FqParameters>::new(BigInteger256::new([16880261864759797230,11149320296478205677, 13670673657387330497, 2008564746625684525])), 
			ark_ff::Fp256::<ark_bn254::FqParameters>::new(BigInteger256::new([1950835287171218464,16239277735248765879, 16663203488411686767, 2143460148601497489])) 
		),
		QuadExtField::<ark_ff::Fp2ParamsWrapper::<ark_bn254::Fq2Parameters>>::new(
			ark_ff::Fp256::<ark_bn254::FqParameters>::new(BigInteger256::new([17668110190351798747,16869553882511565562, 14545293657630083960, 211851059569339709])), 
			ark_ff::Fp256::<ark_bn254::FqParameters>::new(BigInteger256::new([5286719363536782032,10967886215506487151, 10989156048966279274, 788469298650854834])) 
		),
		QuadExtField::<ark_ff::Fp2ParamsWrapper::<ark_bn254::Fq2Parameters>>::new(
			ark_ff::Fp256::<ark_bn254::FqParameters>::new(BigInteger256::new([15938110350409015742,3964858519090176321, 12162238490720959149, 1789796613784663246])), 
			ark_ff::Fp256::<ark_bn254::FqParameters>::new(BigInteger256::new([14738972261860833048,2448765326472352742, 18020981669628922767, 2543466490105874023])) 
 		)
 	)
}

pub fn get_gamma_g2_neg_pc_89() -> (QuadExtField::<ark_ff::Fp2ParamsWrapper::<ark_bn254::Fq2Parameters>>, QuadExtField::<ark_ff::Fp2ParamsWrapper::<ark_bn254::Fq2Parameters>>, QuadExtField::<ark_ff::Fp2ParamsWrapper::<ark_bn254::Fq2Parameters>>) { 
 	(QuadExtField::<ark_ff::Fp2ParamsWrapper::<ark_bn254::Fq2Parameters>>::new(
			ark_ff::Fp256::<ark_bn254::FqParameters>::new(BigInteger256::new([17710901417794188576,18236591538600929218, 12412898114312061470, 398462371967701669])), 
			ark_ff::Fp256::<ark_bn254::FqParameters>::new(BigInteger256::new([8909664890651079601,5380521210117490734, 1250490496235015662, 2362333341771676681])) 
		),
		QuadExtField::<ark_ff::Fp2ParamsWrapper::<ark_bn254::Fq2Parameters>>::new(
			ark_ff::Fp256::<ark_bn254::FqParameters>::new(BigInteger256::new([7524201333331065030,5738359738418169909, 6363940170721752921, 2937552274851588943])), 
			ark_ff::Fp256::<ark_bn254::FqParameters>::new(BigInteger256::new([8641970889876524681,15112341560553929654, 15325233780144964676, 1970929248826172742])) 
		),
		QuadExtField::<ark_ff::Fp2ParamsWrapper::<ark_bn254::Fq2Parameters>>::new(
			ark_ff::Fp256::<ark_bn254::FqParameters>::new(BigInteger256::new([985343584010635771,13139852461916839594, 997942083546923325, 1200546018464584570])), 
			ark_ff::Fp256::<ark_bn254::FqParameters>::new(BigInteger256::new([12833498188098157810,8667921397909111577, 4027833419537256378, 530474779784853633])) 
 		)
 	)
}

pub fn get_gamma_g2_neg_pc_90() -> (QuadExtField::<ark_ff::Fp2ParamsWrapper::<ark_bn254::Fq2Parameters>>, QuadExtField::<ark_ff::Fp2ParamsWrapper::<ark_bn254::Fq2Parameters>>, QuadExtField::<ark_ff::Fp2ParamsWrapper::<ark_bn254::Fq2Parameters>>) { 
 	(QuadExtField::<ark_ff::Fp2ParamsWrapper::<ark_bn254::Fq2Parameters>>::new(
			ark_ff::Fp256::<ark_bn254::FqParameters>::new(BigInteger256::new([13996630899790034017,1290716614717735497, 8575162876585456788, 987692379801789046])), 
			ark_ff::Fp256::<ark_bn254::FqParameters>::new(BigInteger256::new([12847700138400039910,11302335817046679317, 15327917039527460971, 1379901220959135260])) 
		),
		QuadExtField::<ark_ff::Fp2ParamsWrapper::<ark_bn254::Fq2Parameters>>::new(
			ark_ff::Fp256::<ark_bn254::FqParameters>::new(BigInteger256::new([8107823658327067608,849344582515770278, 830549737769622907, 1862251517777338692])), 
			ark_ff::Fp256::<ark_bn254::FqParameters>::new(BigInteger256::new([8325223645169189936,5839473372025888201, 2719260694822918577, 2075505971877390177])) 
		),
		QuadExtField::<ark_ff::Fp2ParamsWrapper::<ark_bn254::Fq2Parameters>>::new(
			ark_ff::Fp256::<ark_bn254::FqParameters>::new(BigInteger256::new([5131551208787955579,5038163076084876730, 15415259148435454002, 743545834700814883])), 
			ark_ff::Fp256::<ark_bn254::FqParameters>::new(BigInteger256::new([6452707443835080404,16592201127676679593, 1209024538326743467, 3342681632315438568])) 
 		)
 	)
}

pub fn get_delta_g2_neg_pc_0() -> (QuadExtField::<ark_ff::Fp2ParamsWrapper::<ark_bn254::Fq2Parameters>>, QuadExtField::<ark_ff::Fp2ParamsWrapper::<ark_bn254::Fq2Parameters>>, QuadExtField::<ark_ff::Fp2ParamsWrapper::<ark_bn254::Fq2Parameters>>) { 
 	(QuadExtField::<ark_ff::Fp2ParamsWrapper::<ark_bn254::Fq2Parameters>>::new(
			ark_ff::Fp256::<ark_bn254::FqParameters>::new(BigInteger256::new([14341161596376045502,5894762579154804169, 5245454560242653134, 222172780818878070])), 
			ark_ff::Fp256::<ark_bn254::FqParameters>::new(BigInteger256::new([233772181182216129,5437227815848050205, 11916862941437955647, 2512686457893667649])) 
		),
		QuadExtField::<ark_ff::Fp2ParamsWrapper::<ark_bn254::Fq2Parameters>>::new(
			ark_ff::Fp256::<ark_bn254::FqParameters>::new(BigInteger256::new([17974038999183991139,7991773612563452846, 7369446040937470725, 643013610355983856])), 
			ark_ff::Fp256::<ark_bn254::FqParameters>::new(BigInteger256::new([8931668419685785025,10351281944586144139, 14344872892963365858, 3285578256282243617])) 
		),
		QuadExtField::<ark_ff::Fp2ParamsWrapper::<ark_bn254::Fq2Parameters>>::new(
			ark_ff::Fp256::<ark_bn254::FqParameters>::new(BigInteger256::new([2715958056140845027,3349814174903584560, 17112807554182606584, 1134651105210534999])), 
			ark_ff::Fp256::<ark_bn254::FqParameters>::new(BigInteger256::new([16064141433400403551,12779413678465965845, 9978420196026496735, 1534008967179517623])) 
 		)
 	)
}

pub fn get_delta_g2_neg_pc_1() -> (QuadExtField::<ark_ff::Fp2ParamsWrapper::<ark_bn254::Fq2Parameters>>, QuadExtField::<ark_ff::Fp2ParamsWrapper::<ark_bn254::Fq2Parameters>>, QuadExtField::<ark_ff::Fp2ParamsWrapper::<ark_bn254::Fq2Parameters>>) { 
 	(QuadExtField::<ark_ff::Fp2ParamsWrapper::<ark_bn254::Fq2Parameters>>::new(
			ark_ff::Fp256::<ark_bn254::FqParameters>::new(BigInteger256::new([5509548300098920427,3181484130768045297, 15247265894179665734, 3481238464286369065])), 
			ark_ff::Fp256::<ark_bn254::FqParameters>::new(BigInteger256::new([7258159113255561207,15324995707223314476, 12989213629992338963, 2332661270265327462])) 
		),
		QuadExtField::<ark_ff::Fp2ParamsWrapper::<ark_bn254::Fq2Parameters>>::new(
			ark_ff::Fp256::<ark_bn254::FqParameters>::new(BigInteger256::new([5279844438076765283,17990501568046375383, 4205295508148911761, 527930967407795978])), 
			ark_ff::Fp256::<ark_bn254::FqParameters>::new(BigInteger256::new([892697809067168237,4561515514831125425, 15258527065474765059, 3246149503228025455])) 
		),
		QuadExtField::<ark_ff::Fp2ParamsWrapper::<ark_bn254::Fq2Parameters>>::new(
			ark_ff::Fp256::<ark_bn254::FqParameters>::new(BigInteger256::new([3108994539352334673,8423044397757324384, 15559013282636980807, 3231503944532685641])), 
			ark_ff::Fp256::<ark_bn254::FqParameters>::new(BigInteger256::new([6261403571636823319,2065663387747680495, 3369444419405255489, 2114015281715886774])) 
 		)
 	)
}

pub fn get_delta_g2_neg_pc_2() -> (QuadExtField::<ark_ff::Fp2ParamsWrapper::<ark_bn254::Fq2Parameters>>, QuadExtField::<ark_ff::Fp2ParamsWrapper::<ark_bn254::Fq2Parameters>>, QuadExtField::<ark_ff::Fp2ParamsWrapper::<ark_bn254::Fq2Parameters>>) { 
 	(QuadExtField::<ark_ff::Fp2ParamsWrapper::<ark_bn254::Fq2Parameters>>::new(
			ark_ff::Fp256::<ark_bn254::FqParameters>::new(BigInteger256::new([14611080511923805014,9386490071283524228, 6015785756833800922, 578852452791182283])), 
			ark_ff::Fp256::<ark_bn254::FqParameters>::new(BigInteger256::new([6136274641316012773,15251373585822748848, 14790917131219219578, 2192476332382658905])) 
		),
		QuadExtField::<ark_ff::Fp2ParamsWrapper::<ark_bn254::Fq2Parameters>>::new(
			ark_ff::Fp256::<ark_bn254::FqParameters>::new(BigInteger256::new([418107868074445241,17174709087548798299, 15354725006180282440, 951000093997622543])), 
			ark_ff::Fp256::<ark_bn254::FqParameters>::new(BigInteger256::new([11172137234020445342,2110180171629591285, 4972760624676692296, 2313350567760616715])) 
		),
		QuadExtField::<ark_ff::Fp2ParamsWrapper::<ark_bn254::Fq2Parameters>>::new(
			ark_ff::Fp256::<ark_bn254::FqParameters>::new(BigInteger256::new([6289413734298796283,2921918807754202203, 4268949692579616335, 193100688756063437])), 
			ark_ff::Fp256::<ark_bn254::FqParameters>::new(BigInteger256::new([18307989528423290969,10273158667091834808, 10696865547687865596, 1864078682175817564])) 
 		)
 	)
}

pub fn get_delta_g2_neg_pc_3() -> (QuadExtField::<ark_ff::Fp2ParamsWrapper::<ark_bn254::Fq2Parameters>>, QuadExtField::<ark_ff::Fp2ParamsWrapper::<ark_bn254::Fq2Parameters>>, QuadExtField::<ark_ff::Fp2ParamsWrapper::<ark_bn254::Fq2Parameters>>) { 
 	(QuadExtField::<ark_ff::Fp2ParamsWrapper::<ark_bn254::Fq2Parameters>>::new(
			ark_ff::Fp256::<ark_bn254::FqParameters>::new(BigInteger256::new([13138664815582736950,3841987477232419076, 5552641688143128391, 1768491934734024982])), 
			ark_ff::Fp256::<ark_bn254::FqParameters>::new(BigInteger256::new([2957053244846465947,14972227832494403357, 9655858399164434334, 1090134677249263147])) 
		),
		QuadExtField::<ark_ff::Fp2ParamsWrapper::<ark_bn254::Fq2Parameters>>::new(
			ark_ff::Fp256::<ark_bn254::FqParameters>::new(BigInteger256::new([1271581310163613827,4952422424049335139, 5298751594453798235, 2359361121629909713])), 
			ark_ff::Fp256::<ark_bn254::FqParameters>::new(BigInteger256::new([9574333742664323431,272187488839703577, 2739146699154573742, 248469239998656915])) 
		),
		QuadExtField::<ark_ff::Fp2ParamsWrapper::<ark_bn254::Fq2Parameters>>::new(
			ark_ff::Fp256::<ark_bn254::FqParameters>::new(BigInteger256::new([12356535516086766408,4314120633484544102, 7874971360208052988, 3353266295255120856])), 
			ark_ff::Fp256::<ark_bn254::FqParameters>::new(BigInteger256::new([10936415650528600771,4907523557810564026, 14681468740683701873, 3196797814965889411])) 
 		)
 	)
}

pub fn get_delta_g2_neg_pc_4() -> (QuadExtField::<ark_ff::Fp2ParamsWrapper::<ark_bn254::Fq2Parameters>>, QuadExtField::<ark_ff::Fp2ParamsWrapper::<ark_bn254::Fq2Parameters>>, QuadExtField::<ark_ff::Fp2ParamsWrapper::<ark_bn254::Fq2Parameters>>) { 
 	(QuadExtField::<ark_ff::Fp2ParamsWrapper::<ark_bn254::Fq2Parameters>>::new(
			ark_ff::Fp256::<ark_bn254::FqParameters>::new(BigInteger256::new([4370591737491306806,11566661587376567164, 5570438092096126744, 477680951391231704])), 
			ark_ff::Fp256::<ark_bn254::FqParameters>::new(BigInteger256::new([5529634441478798767,3881917619587952062, 5655208379596206655, 1213002022791535855])) 
		),
		QuadExtField::<ark_ff::Fp2ParamsWrapper::<ark_bn254::Fq2Parameters>>::new(
			ark_ff::Fp256::<ark_bn254::FqParameters>::new(BigInteger256::new([17643852971169021744,12468707990069303161, 13759506149668194288, 2759458550384449314])), 
			ark_ff::Fp256::<ark_bn254::FqParameters>::new(BigInteger256::new([16901444420440294780,15782051451037145412, 16351208565918744304, 1924441754767049714])) 
		),
		QuadExtField::<ark_ff::Fp2ParamsWrapper::<ark_bn254::Fq2Parameters>>::new(
			ark_ff::Fp256::<ark_bn254::FqParameters>::new(BigInteger256::new([14622068395001000190,10759712108642773186, 5252022418256846870, 2810222453696054066])), 
			ark_ff::Fp256::<ark_bn254::FqParameters>::new(BigInteger256::new([6247076893004890567,17736496039249420357, 3344917988997711808, 708126050757204464])) 
 		)
 	)
}

pub fn get_delta_g2_neg_pc_5() -> (QuadExtField::<ark_ff::Fp2ParamsWrapper::<ark_bn254::Fq2Parameters>>, QuadExtField::<ark_ff::Fp2ParamsWrapper::<ark_bn254::Fq2Parameters>>, QuadExtField::<ark_ff::Fp2ParamsWrapper::<ark_bn254::Fq2Parameters>>) { 
 	(QuadExtField::<ark_ff::Fp2ParamsWrapper::<ark_bn254::Fq2Parameters>>::new(
			ark_ff::Fp256::<ark_bn254::FqParameters>::new(BigInteger256::new([15282228408171048171,5124870807690504094, 15332470183926601235, 16571252284997728])), 
			ark_ff::Fp256::<ark_bn254::FqParameters>::new(BigInteger256::new([13544869188058977821,9731100525541001609, 9606874141811916156, 3283374047339810876])) 
		),
		QuadExtField::<ark_ff::Fp2ParamsWrapper::<ark_bn254::Fq2Parameters>>::new(
			ark_ff::Fp256::<ark_bn254::FqParameters>::new(BigInteger256::new([14949535381132280413,8511394953373336765, 3542896091456427650, 3479735043558756658])), 
			ark_ff::Fp256::<ark_bn254::FqParameters>::new(BigInteger256::new([5636916422351222709,4835702045678637953, 14881616283246525742, 842881987171372361])) 
		),
		QuadExtField::<ark_ff::Fp2ParamsWrapper::<ark_bn254::Fq2Parameters>>::new(
			ark_ff::Fp256::<ark_bn254::FqParameters>::new(BigInteger256::new([16274768463761414642,5651012680516197487, 17346996622292980720, 1974588966608182870])), 
			ark_ff::Fp256::<ark_bn254::FqParameters>::new(BigInteger256::new([9829222542070833694,1008353130320273625, 5644527340147990719, 942902196720587280])) 
 		)
 	)
}

pub fn get_delta_g2_neg_pc_6() -> (QuadExtField::<ark_ff::Fp2ParamsWrapper::<ark_bn254::Fq2Parameters>>, QuadExtField::<ark_ff::Fp2ParamsWrapper::<ark_bn254::Fq2Parameters>>, QuadExtField::<ark_ff::Fp2ParamsWrapper::<ark_bn254::Fq2Parameters>>) { 
 	(QuadExtField::<ark_ff::Fp2ParamsWrapper::<ark_bn254::Fq2Parameters>>::new(
			ark_ff::Fp256::<ark_bn254::FqParameters>::new(BigInteger256::new([8957496028244544485,14598600969184152012, 12837331663653700419, 2937948498156673081])), 
			ark_ff::Fp256::<ark_bn254::FqParameters>::new(BigInteger256::new([15426738619962268878,15718843933021454633, 17791976033443360198, 1429120281346748924])) 
		),
		QuadExtField::<ark_ff::Fp2ParamsWrapper::<ark_bn254::Fq2Parameters>>::new(
			ark_ff::Fp256::<ark_bn254::FqParameters>::new(BigInteger256::new([16903883984188090302,8140132367743351580, 6511360785329877492, 2642007234678978968])), 
			ark_ff::Fp256::<ark_bn254::FqParameters>::new(BigInteger256::new([8975177569794016824,18312113221873134777, 4677999366339136126, 885577065367647504])) 
		),
		QuadExtField::<ark_ff::Fp2ParamsWrapper::<ark_bn254::Fq2Parameters>>::new(
			ark_ff::Fp256::<ark_bn254::FqParameters>::new(BigInteger256::new([18285960281626674681,8839255615266213550, 1908851446952203565, 1674856575820080108])), 
			ark_ff::Fp256::<ark_bn254::FqParameters>::new(BigInteger256::new([980869788562486545,8071803483324123878, 3774767389536165053, 1972789690298939526])) 
 		)
 	)
}

pub fn get_delta_g2_neg_pc_7() -> (QuadExtField::<ark_ff::Fp2ParamsWrapper::<ark_bn254::Fq2Parameters>>, QuadExtField::<ark_ff::Fp2ParamsWrapper::<ark_bn254::Fq2Parameters>>, QuadExtField::<ark_ff::Fp2ParamsWrapper::<ark_bn254::Fq2Parameters>>) { 
 	(QuadExtField::<ark_ff::Fp2ParamsWrapper::<ark_bn254::Fq2Parameters>>::new(
			ark_ff::Fp256::<ark_bn254::FqParameters>::new(BigInteger256::new([17457546594683002786,8993614324054141400, 14596004528420400983, 3280822230291827006])), 
			ark_ff::Fp256::<ark_bn254::FqParameters>::new(BigInteger256::new([13388385942111257095,9722354581281792738, 12292506053748700611, 1901531539359479668])) 
		),
		QuadExtField::<ark_ff::Fp2ParamsWrapper::<ark_bn254::Fq2Parameters>>::new(
			ark_ff::Fp256::<ark_bn254::FqParameters>::new(BigInteger256::new([13045872017651582755,6600880264028621874, 7400222789379445284, 1560959709308286463])), 
			ark_ff::Fp256::<ark_bn254::FqParameters>::new(BigInteger256::new([1508449274019025594,5151015651123116567, 8141325123325350224, 1943305015129512534])) 
		),
		QuadExtField::<ark_ff::Fp2ParamsWrapper::<ark_bn254::Fq2Parameters>>::new(
			ark_ff::Fp256::<ark_bn254::FqParameters>::new(BigInteger256::new([3881152167240075328,10468806991275960855, 4833201164672308870, 2261845501704044888])), 
			ark_ff::Fp256::<ark_bn254::FqParameters>::new(BigInteger256::new([16755443257180241809,9976866254703754501, 107281735593384826, 1104884557799841248])) 
 		)
 	)
}

pub fn get_delta_g2_neg_pc_8() -> (QuadExtField::<ark_ff::Fp2ParamsWrapper::<ark_bn254::Fq2Parameters>>, QuadExtField::<ark_ff::Fp2ParamsWrapper::<ark_bn254::Fq2Parameters>>, QuadExtField::<ark_ff::Fp2ParamsWrapper::<ark_bn254::Fq2Parameters>>) { 
 	(QuadExtField::<ark_ff::Fp2ParamsWrapper::<ark_bn254::Fq2Parameters>>::new(
			ark_ff::Fp256::<ark_bn254::FqParameters>::new(BigInteger256::new([2213956025063762048,8193944738355756380, 4319555912801111634, 757745423119402514])), 
			ark_ff::Fp256::<ark_bn254::FqParameters>::new(BigInteger256::new([14508405564612545240,16583054211995845149, 12188122231701191125, 1646022046501940230])) 
		),
		QuadExtField::<ark_ff::Fp2ParamsWrapper::<ark_bn254::Fq2Parameters>>::new(
			ark_ff::Fp256::<ark_bn254::FqParameters>::new(BigInteger256::new([6796067627190905519,17874313419952111493, 17567868059911899375, 2974306462529005391])), 
			ark_ff::Fp256::<ark_bn254::FqParameters>::new(BigInteger256::new([11413972502593519894,2221489207671341675, 11676846353786148795, 3009403929056291932])) 
		),
		QuadExtField::<ark_ff::Fp2ParamsWrapper::<ark_bn254::Fq2Parameters>>::new(
			ark_ff::Fp256::<ark_bn254::FqParameters>::new(BigInteger256::new([9948547352335457688,9145043022083081017, 17169782426807985486, 2805218170735201582])), 
			ark_ff::Fp256::<ark_bn254::FqParameters>::new(BigInteger256::new([10291113644477415723,14282037894840330879, 4399105929703146758, 2421216894708904116])) 
 		)
 	)
}

pub fn get_delta_g2_neg_pc_9() -> (QuadExtField::<ark_ff::Fp2ParamsWrapper::<ark_bn254::Fq2Parameters>>, QuadExtField::<ark_ff::Fp2ParamsWrapper::<ark_bn254::Fq2Parameters>>, QuadExtField::<ark_ff::Fp2ParamsWrapper::<ark_bn254::Fq2Parameters>>) { 
 	(QuadExtField::<ark_ff::Fp2ParamsWrapper::<ark_bn254::Fq2Parameters>>::new(
			ark_ff::Fp256::<ark_bn254::FqParameters>::new(BigInteger256::new([10560316511197858556,6767678991888937531, 8019359775753737340, 2855464178837772402])), 
			ark_ff::Fp256::<ark_bn254::FqParameters>::new(BigInteger256::new([946342647932251067,2186020930495366610, 7003209502383447046, 2413023980251940026])) 
		),
		QuadExtField::<ark_ff::Fp2ParamsWrapper::<ark_bn254::Fq2Parameters>>::new(
			ark_ff::Fp256::<ark_bn254::FqParameters>::new(BigInteger256::new([10943774554478674690,13915752419547891803, 11726545889899822585, 443578483942348584])), 
			ark_ff::Fp256::<ark_bn254::FqParameters>::new(BigInteger256::new([13940885341246864576,11719448233543287833, 7998090508070118767, 1498431443812195110])) 
		),
		QuadExtField::<ark_ff::Fp2ParamsWrapper::<ark_bn254::Fq2Parameters>>::new(
			ark_ff::Fp256::<ark_bn254::FqParameters>::new(BigInteger256::new([6522215050980131829,11440318900294421064, 8708926270148404648, 3285634608818474671])), 
			ark_ff::Fp256::<ark_bn254::FqParameters>::new(BigInteger256::new([17524058794029341134,10966371829136491702, 3722721041862440484, 1503670113585978685])) 
 		)
 	)
}

pub fn get_delta_g2_neg_pc_10() -> (QuadExtField::<ark_ff::Fp2ParamsWrapper::<ark_bn254::Fq2Parameters>>, QuadExtField::<ark_ff::Fp2ParamsWrapper::<ark_bn254::Fq2Parameters>>, QuadExtField::<ark_ff::Fp2ParamsWrapper::<ark_bn254::Fq2Parameters>>) { 
 	(QuadExtField::<ark_ff::Fp2ParamsWrapper::<ark_bn254::Fq2Parameters>>::new(
			ark_ff::Fp256::<ark_bn254::FqParameters>::new(BigInteger256::new([4560762466741347202,10648870179630098415, 10721825452962523396, 2553768955734876590])), 
			ark_ff::Fp256::<ark_bn254::FqParameters>::new(BigInteger256::new([10913648674479894688,16642425928871367069, 15724287144861590359, 1321738606776765921])) 
		),
		QuadExtField::<ark_ff::Fp2ParamsWrapper::<ark_bn254::Fq2Parameters>>::new(
			ark_ff::Fp256::<ark_bn254::FqParameters>::new(BigInteger256::new([8260127569346877318,3950208471604164267, 2054108817721185023, 1723615684246607772])), 
			ark_ff::Fp256::<ark_bn254::FqParameters>::new(BigInteger256::new([6964544778784692967,16797847852261378877, 15344045951474305828, 1560065501742929202])) 
		),
		QuadExtField::<ark_ff::Fp2ParamsWrapper::<ark_bn254::Fq2Parameters>>::new(
			ark_ff::Fp256::<ark_bn254::FqParameters>::new(BigInteger256::new([16685593616080517526,13778252412041911606, 16693815034391130357, 2937133165578598713])), 
			ark_ff::Fp256::<ark_bn254::FqParameters>::new(BigInteger256::new([7411004975325128961,3740463073871591975, 4383084148257776241, 1090414761792553806])) 
 		)
 	)
}

pub fn get_delta_g2_neg_pc_11() -> (QuadExtField::<ark_ff::Fp2ParamsWrapper::<ark_bn254::Fq2Parameters>>, QuadExtField::<ark_ff::Fp2ParamsWrapper::<ark_bn254::Fq2Parameters>>, QuadExtField::<ark_ff::Fp2ParamsWrapper::<ark_bn254::Fq2Parameters>>) { 
 	(QuadExtField::<ark_ff::Fp2ParamsWrapper::<ark_bn254::Fq2Parameters>>::new(
			ark_ff::Fp256::<ark_bn254::FqParameters>::new(BigInteger256::new([5418183557475789791,12828820132392234820, 3248020743094388897, 3297955897067613258])), 
			ark_ff::Fp256::<ark_bn254::FqParameters>::new(BigInteger256::new([16089739259483907303,15982467588937252595, 14701937795891051564, 1021950688967868872])) 
		),
		QuadExtField::<ark_ff::Fp2ParamsWrapper::<ark_bn254::Fq2Parameters>>::new(
			ark_ff::Fp256::<ark_bn254::FqParameters>::new(BigInteger256::new([9853319878795926530,3088566035799832489, 2608034142983315, 1258013615708607031])), 
			ark_ff::Fp256::<ark_bn254::FqParameters>::new(BigInteger256::new([18097684182296841906,11705001741332022582, 16918636586313137268, 2872933412418933996])) 
		),
		QuadExtField::<ark_ff::Fp2ParamsWrapper::<ark_bn254::Fq2Parameters>>::new(
			ark_ff::Fp256::<ark_bn254::FqParameters>::new(BigInteger256::new([652414829728872444,16425812928807632862, 9618100182398216650, 135387072041413188])), 
			ark_ff::Fp256::<ark_bn254::FqParameters>::new(BigInteger256::new([5019513322847860150,17116344103871624691, 8384709290830728610, 659025422889498282])) 
 		)
 	)
}

pub fn get_delta_g2_neg_pc_12() -> (QuadExtField::<ark_ff::Fp2ParamsWrapper::<ark_bn254::Fq2Parameters>>, QuadExtField::<ark_ff::Fp2ParamsWrapper::<ark_bn254::Fq2Parameters>>, QuadExtField::<ark_ff::Fp2ParamsWrapper::<ark_bn254::Fq2Parameters>>) { 
 	(QuadExtField::<ark_ff::Fp2ParamsWrapper::<ark_bn254::Fq2Parameters>>::new(
			ark_ff::Fp256::<ark_bn254::FqParameters>::new(BigInteger256::new([6794794630910549199,17167804850809841013, 11219466035565014731, 1009968339966197002])), 
			ark_ff::Fp256::<ark_bn254::FqParameters>::new(BigInteger256::new([789707884503238136,6368618744673491542, 8577707535239277638, 553599786111590473])) 
		),
		QuadExtField::<ark_ff::Fp2ParamsWrapper::<ark_bn254::Fq2Parameters>>::new(
			ark_ff::Fp256::<ark_bn254::FqParameters>::new(BigInteger256::new([2836922723740023812,14601940022517576742, 3304821103600530243, 3426598476483165074])), 
			ark_ff::Fp256::<ark_bn254::FqParameters>::new(BigInteger256::new([3641267767809003516,14550659232092107957, 3842221080594562470, 234860644950864793])) 
		),
		QuadExtField::<ark_ff::Fp2ParamsWrapper::<ark_bn254::Fq2Parameters>>::new(
			ark_ff::Fp256::<ark_bn254::FqParameters>::new(BigInteger256::new([11261205215387463329,4223766812940680495, 16091865649043217929, 1812206989563280374])), 
			ark_ff::Fp256::<ark_bn254::FqParameters>::new(BigInteger256::new([14207864133362634947,8363807528627985876, 4230739853973732609, 2015236937363559287])) 
 		)
 	)
}

pub fn get_delta_g2_neg_pc_13() -> (QuadExtField::<ark_ff::Fp2ParamsWrapper::<ark_bn254::Fq2Parameters>>, QuadExtField::<ark_ff::Fp2ParamsWrapper::<ark_bn254::Fq2Parameters>>, QuadExtField::<ark_ff::Fp2ParamsWrapper::<ark_bn254::Fq2Parameters>>) { 
 	(QuadExtField::<ark_ff::Fp2ParamsWrapper::<ark_bn254::Fq2Parameters>>::new(
			ark_ff::Fp256::<ark_bn254::FqParameters>::new(BigInteger256::new([4232399230937262321,273945279593763928, 11863595094425324106, 579669636397758786])), 
			ark_ff::Fp256::<ark_bn254::FqParameters>::new(BigInteger256::new([13309520962210798331,4396463613619013481, 18272294889390827608, 392794554583793698])) 
		),
		QuadExtField::<ark_ff::Fp2ParamsWrapper::<ark_bn254::Fq2Parameters>>::new(
			ark_ff::Fp256::<ark_bn254::FqParameters>::new(BigInteger256::new([4428143326777332453,4622437663253733297, 16251861282756880958, 1697654917530674555])), 
			ark_ff::Fp256::<ark_bn254::FqParameters>::new(BigInteger256::new([6683547807231086511,2599405914467253078, 9503227070046156417, 207783505889180159])) 
		),
		QuadExtField::<ark_ff::Fp2ParamsWrapper::<ark_bn254::Fq2Parameters>>::new(
			ark_ff::Fp256::<ark_bn254::FqParameters>::new(BigInteger256::new([3603053851606382891,4553530849874619583, 1293469066775091743, 619093314414967711])), 
			ark_ff::Fp256::<ark_bn254::FqParameters>::new(BigInteger256::new([7490471473509676831,12883463005350172595, 10718954026092726879, 1901312917431188321])) 
 		)
 	)
}

pub fn get_delta_g2_neg_pc_14() -> (QuadExtField::<ark_ff::Fp2ParamsWrapper::<ark_bn254::Fq2Parameters>>, QuadExtField::<ark_ff::Fp2ParamsWrapper::<ark_bn254::Fq2Parameters>>, QuadExtField::<ark_ff::Fp2ParamsWrapper::<ark_bn254::Fq2Parameters>>) { 
 	(QuadExtField::<ark_ff::Fp2ParamsWrapper::<ark_bn254::Fq2Parameters>>::new(
			ark_ff::Fp256::<ark_bn254::FqParameters>::new(BigInteger256::new([4119989198300580906,397605298988119435, 14939049554842410383, 1362403645916644155])), 
			ark_ff::Fp256::<ark_bn254::FqParameters>::new(BigInteger256::new([4959965351189186078,4866961381904014029, 17401235882020362223, 882320474359175833])) 
		),
		QuadExtField::<ark_ff::Fp2ParamsWrapper::<ark_bn254::Fq2Parameters>>::new(
			ark_ff::Fp256::<ark_bn254::FqParameters>::new(BigInteger256::new([4737181116858537087,4765254463139571040, 10568502797308286926, 582908476436142418])), 
			ark_ff::Fp256::<ark_bn254::FqParameters>::new(BigInteger256::new([3205671185412169333,344627029657410373, 7536275034459964461, 1977612022732618599])) 
		),
		QuadExtField::<ark_ff::Fp2ParamsWrapper::<ark_bn254::Fq2Parameters>>::new(
			ark_ff::Fp256::<ark_bn254::FqParameters>::new(BigInteger256::new([4157270109941362291,17171944149661253016, 3588628958671770069, 126878367639473379])), 
			ark_ff::Fp256::<ark_bn254::FqParameters>::new(BigInteger256::new([5597012510723363196,10332456634507628326, 7669242161442315923, 1131572068320081405])) 
 		)
 	)
}

pub fn get_delta_g2_neg_pc_15() -> (QuadExtField::<ark_ff::Fp2ParamsWrapper::<ark_bn254::Fq2Parameters>>, QuadExtField::<ark_ff::Fp2ParamsWrapper::<ark_bn254::Fq2Parameters>>, QuadExtField::<ark_ff::Fp2ParamsWrapper::<ark_bn254::Fq2Parameters>>) { 
 	(QuadExtField::<ark_ff::Fp2ParamsWrapper::<ark_bn254::Fq2Parameters>>::new(
			ark_ff::Fp256::<ark_bn254::FqParameters>::new(BigInteger256::new([17754306044801861683,13811469115029928203, 12690532357336448273, 94246986997559586])), 
			ark_ff::Fp256::<ark_bn254::FqParameters>::new(BigInteger256::new([1592984011536233356,11311621544944329289, 16757580525766238651, 2566640548912205946])) 
		),
		QuadExtField::<ark_ff::Fp2ParamsWrapper::<ark_bn254::Fq2Parameters>>::new(
			ark_ff::Fp256::<ark_bn254::FqParameters>::new(BigInteger256::new([5194570903644943649,1167942648421390256, 849706796719271200, 2975291766060192822])), 
			ark_ff::Fp256::<ark_bn254::FqParameters>::new(BigInteger256::new([14474156029031062314,1128570293748791557, 7693836299446285145, 384293857020344020])) 
		),
		QuadExtField::<ark_ff::Fp2ParamsWrapper::<ark_bn254::Fq2Parameters>>::new(
			ark_ff::Fp256::<ark_bn254::FqParameters>::new(BigInteger256::new([6425635930152096864,15367901649369055878, 4300678908562743308, 2102592819608190929])), 
			ark_ff::Fp256::<ark_bn254::FqParameters>::new(BigInteger256::new([17303581656471029975,6178858892391761295, 1974584085805767970, 1416705731702164045])) 
 		)
 	)
}

pub fn get_delta_g2_neg_pc_16() -> (QuadExtField::<ark_ff::Fp2ParamsWrapper::<ark_bn254::Fq2Parameters>>, QuadExtField::<ark_ff::Fp2ParamsWrapper::<ark_bn254::Fq2Parameters>>, QuadExtField::<ark_ff::Fp2ParamsWrapper::<ark_bn254::Fq2Parameters>>) { 
 	(QuadExtField::<ark_ff::Fp2ParamsWrapper::<ark_bn254::Fq2Parameters>>::new(
			ark_ff::Fp256::<ark_bn254::FqParameters>::new(BigInteger256::new([14936955610421618329,871217084244213746, 14946319916557369313, 250731501221926058])), 
			ark_ff::Fp256::<ark_bn254::FqParameters>::new(BigInteger256::new([394718900435716649,14099881758719085509, 6473284471962993073, 3251279793397917984])) 
		),
		QuadExtField::<ark_ff::Fp2ParamsWrapper::<ark_bn254::Fq2Parameters>>::new(
			ark_ff::Fp256::<ark_bn254::FqParameters>::new(BigInteger256::new([1326416965051399699,4047515493830466871, 9507370743572523984, 3325781478136585774])), 
			ark_ff::Fp256::<ark_bn254::FqParameters>::new(BigInteger256::new([6930034428629109845,16695620158938364133, 9120827727265492211, 498329959066373871])) 
		),
		QuadExtField::<ark_ff::Fp2ParamsWrapper::<ark_bn254::Fq2Parameters>>::new(
			ark_ff::Fp256::<ark_bn254::FqParameters>::new(BigInteger256::new([16843351938210038580,4837946362266294214, 9995787880465086294, 3368895493849710315])), 
			ark_ff::Fp256::<ark_bn254::FqParameters>::new(BigInteger256::new([2819527356581231213,6638463752658497964, 15156920792176512826, 780424129188351758])) 
 		)
 	)
}

pub fn get_delta_g2_neg_pc_17() -> (QuadExtField::<ark_ff::Fp2ParamsWrapper::<ark_bn254::Fq2Parameters>>, QuadExtField::<ark_ff::Fp2ParamsWrapper::<ark_bn254::Fq2Parameters>>, QuadExtField::<ark_ff::Fp2ParamsWrapper::<ark_bn254::Fq2Parameters>>) { 
 	(QuadExtField::<ark_ff::Fp2ParamsWrapper::<ark_bn254::Fq2Parameters>>::new(
			ark_ff::Fp256::<ark_bn254::FqParameters>::new(BigInteger256::new([3192139194585261975,5191000860383407312, 428656294932183789, 2787090266673067855])), 
			ark_ff::Fp256::<ark_bn254::FqParameters>::new(BigInteger256::new([9725075620642905180,3597338929312452414, 7476226292588950057, 328368627259892504])) 
		),
		QuadExtField::<ark_ff::Fp2ParamsWrapper::<ark_bn254::Fq2Parameters>>::new(
			ark_ff::Fp256::<ark_bn254::FqParameters>::new(BigInteger256::new([9657401161791557085,528436342767380461, 13748685449359700813, 195381619310188007])), 
			ark_ff::Fp256::<ark_bn254::FqParameters>::new(BigInteger256::new([4165017612223452745,6077648954026546719, 8405361161796565157, 316270214440742313])) 
		),
		QuadExtField::<ark_ff::Fp2ParamsWrapper::<ark_bn254::Fq2Parameters>>::new(
			ark_ff::Fp256::<ark_bn254::FqParameters>::new(BigInteger256::new([13685411274888187506,16834136690605136971, 13564330337344061427, 1392537708756400831])), 
			ark_ff::Fp256::<ark_bn254::FqParameters>::new(BigInteger256::new([16900321306159320096,6082856598333492716, 17692621624919723621, 796943987850026800])) 
 		)
 	)
}

pub fn get_delta_g2_neg_pc_18() -> (QuadExtField::<ark_ff::Fp2ParamsWrapper::<ark_bn254::Fq2Parameters>>, QuadExtField::<ark_ff::Fp2ParamsWrapper::<ark_bn254::Fq2Parameters>>, QuadExtField::<ark_ff::Fp2ParamsWrapper::<ark_bn254::Fq2Parameters>>) { 
 	(QuadExtField::<ark_ff::Fp2ParamsWrapper::<ark_bn254::Fq2Parameters>>::new(
			ark_ff::Fp256::<ark_bn254::FqParameters>::new(BigInteger256::new([1903928009323494370,1629343048797731086, 9573350389189343884, 2022842485513236122])), 
			ark_ff::Fp256::<ark_bn254::FqParameters>::new(BigInteger256::new([7213376134154417562,5013726246383951537, 10938426118452236498, 2146772929132535458])) 
		),
		QuadExtField::<ark_ff::Fp2ParamsWrapper::<ark_bn254::Fq2Parameters>>::new(
			ark_ff::Fp256::<ark_bn254::FqParameters>::new(BigInteger256::new([12718532696378682011,15829996704708569434, 6029683176111919559, 879374172227208739])), 
			ark_ff::Fp256::<ark_bn254::FqParameters>::new(BigInteger256::new([2296377269877333154,5935314651790980820, 8432918168006252239, 1031621985552802266])) 
		),
		QuadExtField::<ark_ff::Fp2ParamsWrapper::<ark_bn254::Fq2Parameters>>::new(
			ark_ff::Fp256::<ark_bn254::FqParameters>::new(BigInteger256::new([9278337165284342206,14982288540586730182, 15018389711077717965, 18507080406041574])), 
			ark_ff::Fp256::<ark_bn254::FqParameters>::new(BigInteger256::new([16607837166023800116,10983895135352408297, 14858109922396346241, 78444527141129726])) 
 		)
 	)
}

pub fn get_delta_g2_neg_pc_19() -> (QuadExtField::<ark_ff::Fp2ParamsWrapper::<ark_bn254::Fq2Parameters>>, QuadExtField::<ark_ff::Fp2ParamsWrapper::<ark_bn254::Fq2Parameters>>, QuadExtField::<ark_ff::Fp2ParamsWrapper::<ark_bn254::Fq2Parameters>>) { 
 	(QuadExtField::<ark_ff::Fp2ParamsWrapper::<ark_bn254::Fq2Parameters>>::new(
			ark_ff::Fp256::<ark_bn254::FqParameters>::new(BigInteger256::new([15512159013261281006,3429341583678045692, 4301708123809093318, 84710882061981023])), 
			ark_ff::Fp256::<ark_bn254::FqParameters>::new(BigInteger256::new([8359609388072365015,1654659912303746411, 4703014870564640847, 1267936544572131369])) 
		),
		QuadExtField::<ark_ff::Fp2ParamsWrapper::<ark_bn254::Fq2Parameters>>::new(
			ark_ff::Fp256::<ark_bn254::FqParameters>::new(BigInteger256::new([5093055410917270894,18164688735049488579, 7174249326265750722, 1040909618284618064])), 
			ark_ff::Fp256::<ark_bn254::FqParameters>::new(BigInteger256::new([15898496835973724323,5455818687686458480, 3482691758534082030, 2074505288719978331])) 
		),
		QuadExtField::<ark_ff::Fp2ParamsWrapper::<ark_bn254::Fq2Parameters>>::new(
			ark_ff::Fp256::<ark_bn254::FqParameters>::new(BigInteger256::new([5873868778849140587,15645371500260442519, 12176984191544977505, 775809815348332544])), 
			ark_ff::Fp256::<ark_bn254::FqParameters>::new(BigInteger256::new([5713380098755274447,8937851913018556677, 6898495969331370142, 3097901253739633885])) 
 		)
 	)
}

pub fn get_delta_g2_neg_pc_20() -> (QuadExtField::<ark_ff::Fp2ParamsWrapper::<ark_bn254::Fq2Parameters>>, QuadExtField::<ark_ff::Fp2ParamsWrapper::<ark_bn254::Fq2Parameters>>, QuadExtField::<ark_ff::Fp2ParamsWrapper::<ark_bn254::Fq2Parameters>>) { 
 	(QuadExtField::<ark_ff::Fp2ParamsWrapper::<ark_bn254::Fq2Parameters>>::new(
			ark_ff::Fp256::<ark_bn254::FqParameters>::new(BigInteger256::new([9758162494335621070,14116034774482892902, 15625296013276587584, 1587484740805831019])), 
			ark_ff::Fp256::<ark_bn254::FqParameters>::new(BigInteger256::new([4862315258716814323,11825024047771221162, 10809304008657308132, 2679894139076607303])) 
		),
		QuadExtField::<ark_ff::Fp2ParamsWrapper::<ark_bn254::Fq2Parameters>>::new(
			ark_ff::Fp256::<ark_bn254::FqParameters>::new(BigInteger256::new([15512519343828343330,16358670773486115544, 1729507115855613949, 1092483027112118729])), 
			ark_ff::Fp256::<ark_bn254::FqParameters>::new(BigInteger256::new([12807539951723817177,11381296324572140572, 4957406403806017485, 2443366389230981407])) 
		),
		QuadExtField::<ark_ff::Fp2ParamsWrapper::<ark_bn254::Fq2Parameters>>::new(
			ark_ff::Fp256::<ark_bn254::FqParameters>::new(BigInteger256::new([2038169722473385253,80040796925000742, 10982359214798148804, 3006774366214953652])), 
			ark_ff::Fp256::<ark_bn254::FqParameters>::new(BigInteger256::new([17469157521776550129,719626220079999495, 12147148602854886625, 762570196158802579])) 
 		)
 	)
}

pub fn get_delta_g2_neg_pc_21() -> (QuadExtField::<ark_ff::Fp2ParamsWrapper::<ark_bn254::Fq2Parameters>>, QuadExtField::<ark_ff::Fp2ParamsWrapper::<ark_bn254::Fq2Parameters>>, QuadExtField::<ark_ff::Fp2ParamsWrapper::<ark_bn254::Fq2Parameters>>) { 
 	(QuadExtField::<ark_ff::Fp2ParamsWrapper::<ark_bn254::Fq2Parameters>>::new(
			ark_ff::Fp256::<ark_bn254::FqParameters>::new(BigInteger256::new([7268868298092156944,5386995568223959514, 17143020008031988584, 891779254272610001])), 
			ark_ff::Fp256::<ark_bn254::FqParameters>::new(BigInteger256::new([5535975753047221888,533625948881569252, 13159051156098275748, 1368022712523487332])) 
		),
		QuadExtField::<ark_ff::Fp2ParamsWrapper::<ark_bn254::Fq2Parameters>>::new(
			ark_ff::Fp256::<ark_bn254::FqParameters>::new(BigInteger256::new([18359353689069815720,2972284266756642703, 17523849228038157818, 3033058186549584001])), 
			ark_ff::Fp256::<ark_bn254::FqParameters>::new(BigInteger256::new([11756960295350793555,2190718068100300133, 1307093494430400660, 1362085255072651096])) 
		),
		QuadExtField::<ark_ff::Fp2ParamsWrapper::<ark_bn254::Fq2Parameters>>::new(
			ark_ff::Fp256::<ark_bn254::FqParameters>::new(BigInteger256::new([4420628605046982500,6743128858484850999, 15948860351081070197, 164877867279488310])), 
			ark_ff::Fp256::<ark_bn254::FqParameters>::new(BigInteger256::new([15031845218263543481,3259111628318404013, 10762467131633640733, 406241885684971820])) 
 		)
 	)
}

pub fn get_delta_g2_neg_pc_22() -> (QuadExtField::<ark_ff::Fp2ParamsWrapper::<ark_bn254::Fq2Parameters>>, QuadExtField::<ark_ff::Fp2ParamsWrapper::<ark_bn254::Fq2Parameters>>, QuadExtField::<ark_ff::Fp2ParamsWrapper::<ark_bn254::Fq2Parameters>>) { 
 	(QuadExtField::<ark_ff::Fp2ParamsWrapper::<ark_bn254::Fq2Parameters>>::new(
			ark_ff::Fp256::<ark_bn254::FqParameters>::new(BigInteger256::new([1971410702725619577,5758250410187703711, 16482706601202787548, 1089339583638756390])), 
			ark_ff::Fp256::<ark_bn254::FqParameters>::new(BigInteger256::new([13437324923339592625,7712273994602306415, 31564964800788005, 1381811984577096850])) 
		),
		QuadExtField::<ark_ff::Fp2ParamsWrapper::<ark_bn254::Fq2Parameters>>::new(
			ark_ff::Fp256::<ark_bn254::FqParameters>::new(BigInteger256::new([5897275933014326926,10062930960528770116, 714935428508179753, 1605403845344056813])), 
			ark_ff::Fp256::<ark_bn254::FqParameters>::new(BigInteger256::new([346580444598005407,5013273747576345038, 11579937286616086406, 1355361693118679044])) 
		),
		QuadExtField::<ark_ff::Fp2ParamsWrapper::<ark_bn254::Fq2Parameters>>::new(
			ark_ff::Fp256::<ark_bn254::FqParameters>::new(BigInteger256::new([6828619497711813398,12649056606532708883, 11682223450785442598, 841780263516961160])), 
			ark_ff::Fp256::<ark_bn254::FqParameters>::new(BigInteger256::new([6205981752505251558,5627588218584907543, 11594186548394195650, 1739134442376282732])) 
 		)
 	)
}

pub fn get_delta_g2_neg_pc_23() -> (QuadExtField::<ark_ff::Fp2ParamsWrapper::<ark_bn254::Fq2Parameters>>, QuadExtField::<ark_ff::Fp2ParamsWrapper::<ark_bn254::Fq2Parameters>>, QuadExtField::<ark_ff::Fp2ParamsWrapper::<ark_bn254::Fq2Parameters>>) { 
 	(QuadExtField::<ark_ff::Fp2ParamsWrapper::<ark_bn254::Fq2Parameters>>::new(
			ark_ff::Fp256::<ark_bn254::FqParameters>::new(BigInteger256::new([9449728572708285270,18376749124182066936, 2035883413100098465, 3471215317105171897])), 
			ark_ff::Fp256::<ark_bn254::FqParameters>::new(BigInteger256::new([11541922955540399278,9305927317088572491, 17791830240714540251, 3046718335176719139])) 
		),
		QuadExtField::<ark_ff::Fp2ParamsWrapper::<ark_bn254::Fq2Parameters>>::new(
			ark_ff::Fp256::<ark_bn254::FqParameters>::new(BigInteger256::new([2558849775410523625,11976167108599283058, 7593838833789891558, 2798323723286796830])), 
			ark_ff::Fp256::<ark_bn254::FqParameters>::new(BigInteger256::new([4237206835781216063,2797382925127412289, 1668242953868191653, 223045299770263199])) 
		),
		QuadExtField::<ark_ff::Fp2ParamsWrapper::<ark_bn254::Fq2Parameters>>::new(
			ark_ff::Fp256::<ark_bn254::FqParameters>::new(BigInteger256::new([6807061401929861409,3836101397027168896, 2270148606511797250, 3474403703105538837])), 
			ark_ff::Fp256::<ark_bn254::FqParameters>::new(BigInteger256::new([8420591533985111771,17967639346498547993, 6195469929707720913, 1370416334721957311])) 
 		)
 	)
}

pub fn get_delta_g2_neg_pc_24() -> (QuadExtField::<ark_ff::Fp2ParamsWrapper::<ark_bn254::Fq2Parameters>>, QuadExtField::<ark_ff::Fp2ParamsWrapper::<ark_bn254::Fq2Parameters>>, QuadExtField::<ark_ff::Fp2ParamsWrapper::<ark_bn254::Fq2Parameters>>) { 
 	(QuadExtField::<ark_ff::Fp2ParamsWrapper::<ark_bn254::Fq2Parameters>>::new(
			ark_ff::Fp256::<ark_bn254::FqParameters>::new(BigInteger256::new([14427202859878561154,2130400129972668273, 16663679561785543174, 2156531975656502583])), 
			ark_ff::Fp256::<ark_bn254::FqParameters>::new(BigInteger256::new([17564045277934933817,3064348578004823664, 13685425451024364968, 2798024434335551599])) 
		),
		QuadExtField::<ark_ff::Fp2ParamsWrapper::<ark_bn254::Fq2Parameters>>::new(
			ark_ff::Fp256::<ark_bn254::FqParameters>::new(BigInteger256::new([762981144066544691,12413212879071235936, 4490213910989608400, 2839032939267995038])), 
			ark_ff::Fp256::<ark_bn254::FqParameters>::new(BigInteger256::new([13300759831771270974,3190398031262338414, 3709523462824197053, 3047130944860355025])) 
		),
		QuadExtField::<ark_ff::Fp2ParamsWrapper::<ark_bn254::Fq2Parameters>>::new(
			ark_ff::Fp256::<ark_bn254::FqParameters>::new(BigInteger256::new([17406619193778530401,17126143565160478928, 4168740336166748308, 2726053784748192922])), 
			ark_ff::Fp256::<ark_bn254::FqParameters>::new(BigInteger256::new([3284490204576602127,9031828085799644314, 9465283660165328342, 2980296673106326474])) 
 		)
 	)
}

pub fn get_delta_g2_neg_pc_25() -> (QuadExtField::<ark_ff::Fp2ParamsWrapper::<ark_bn254::Fq2Parameters>>, QuadExtField::<ark_ff::Fp2ParamsWrapper::<ark_bn254::Fq2Parameters>>, QuadExtField::<ark_ff::Fp2ParamsWrapper::<ark_bn254::Fq2Parameters>>) { 
 	(QuadExtField::<ark_ff::Fp2ParamsWrapper::<ark_bn254::Fq2Parameters>>::new(
			ark_ff::Fp256::<ark_bn254::FqParameters>::new(BigInteger256::new([13576720334010478085,6895237787875705652, 13217230446653937648, 2953110801606495412])), 
			ark_ff::Fp256::<ark_bn254::FqParameters>::new(BigInteger256::new([11610034210110773962,7136905888192615043, 14229931542283255538, 1652316045855932431])) 
		),
		QuadExtField::<ark_ff::Fp2ParamsWrapper::<ark_bn254::Fq2Parameters>>::new(
			ark_ff::Fp256::<ark_bn254::FqParameters>::new(BigInteger256::new([5145292147363286779,180334245611657397, 6249959050527327223, 332791145202162213])), 
			ark_ff::Fp256::<ark_bn254::FqParameters>::new(BigInteger256::new([7423051415980805225,13808091056195133551, 17262695961842646820, 2331528638053206246])) 
		),
		QuadExtField::<ark_ff::Fp2ParamsWrapper::<ark_bn254::Fq2Parameters>>::new(
			ark_ff::Fp256::<ark_bn254::FqParameters>::new(BigInteger256::new([16672768386519373238,10049946103152320114, 9676948843226648533, 452903856640312846])), 
			ark_ff::Fp256::<ark_bn254::FqParameters>::new(BigInteger256::new([3551081806113733226,1067598013504997445, 8113786179491512035, 1014778287317384664])) 
 		)
 	)
}

pub fn get_delta_g2_neg_pc_26() -> (QuadExtField::<ark_ff::Fp2ParamsWrapper::<ark_bn254::Fq2Parameters>>, QuadExtField::<ark_ff::Fp2ParamsWrapper::<ark_bn254::Fq2Parameters>>, QuadExtField::<ark_ff::Fp2ParamsWrapper::<ark_bn254::Fq2Parameters>>) { 
 	(QuadExtField::<ark_ff::Fp2ParamsWrapper::<ark_bn254::Fq2Parameters>>::new(
			ark_ff::Fp256::<ark_bn254::FqParameters>::new(BigInteger256::new([16323985048019808350,6025443033618040178, 16786315148791210840, 1925410219398249039])), 
			ark_ff::Fp256::<ark_bn254::FqParameters>::new(BigInteger256::new([1945410753794462930,13317293441510259676, 18150229148220641283, 388785318326110065])) 
		),
		QuadExtField::<ark_ff::Fp2ParamsWrapper::<ark_bn254::Fq2Parameters>>::new(
			ark_ff::Fp256::<ark_bn254::FqParameters>::new(BigInteger256::new([6791363067133690056,1867832332573009086, 4832925584591612199, 2318229615897818449])), 
			ark_ff::Fp256::<ark_bn254::FqParameters>::new(BigInteger256::new([10412308479878224798,13804769201883497548, 6504241806657967584, 230704710443844233])) 
		),
		QuadExtField::<ark_ff::Fp2ParamsWrapper::<ark_bn254::Fq2Parameters>>::new(
			ark_ff::Fp256::<ark_bn254::FqParameters>::new(BigInteger256::new([10311444426145359302,3683618707068893191, 16795202403114732080, 645612600585757256])), 
			ark_ff::Fp256::<ark_bn254::FqParameters>::new(BigInteger256::new([14613902194060534190,438451375291936255, 693621921005938412, 616669782473076965])) 
 		)
 	)
}

pub fn get_delta_g2_neg_pc_27() -> (QuadExtField::<ark_ff::Fp2ParamsWrapper::<ark_bn254::Fq2Parameters>>, QuadExtField::<ark_ff::Fp2ParamsWrapper::<ark_bn254::Fq2Parameters>>, QuadExtField::<ark_ff::Fp2ParamsWrapper::<ark_bn254::Fq2Parameters>>) { 
 	(QuadExtField::<ark_ff::Fp2ParamsWrapper::<ark_bn254::Fq2Parameters>>::new(
			ark_ff::Fp256::<ark_bn254::FqParameters>::new(BigInteger256::new([4583988437082085315,1765446433911214053, 14562955934400926183, 3424114876096163925])), 
			ark_ff::Fp256::<ark_bn254::FqParameters>::new(BigInteger256::new([17594609546838389033,12361949208336740632, 9788336497573107345, 826066505059990248])) 
		),
		QuadExtField::<ark_ff::Fp2ParamsWrapper::<ark_bn254::Fq2Parameters>>::new(
			ark_ff::Fp256::<ark_bn254::FqParameters>::new(BigInteger256::new([14465618868807709381,5244960365812747730, 16128198698354227788, 1508775289839765057])), 
			ark_ff::Fp256::<ark_bn254::FqParameters>::new(BigInteger256::new([2624891856309594293,5890520231231348202, 17110343480409785063, 1412935424221733481])) 
		),
		QuadExtField::<ark_ff::Fp2ParamsWrapper::<ark_bn254::Fq2Parameters>>::new(
			ark_ff::Fp256::<ark_bn254::FqParameters>::new(BigInteger256::new([15158938921305002591,6838244301388607731, 8709222656696599374, 265129173140399124])), 
			ark_ff::Fp256::<ark_bn254::FqParameters>::new(BigInteger256::new([7559105085338976103,11243803433793176152, 6224004354883189909, 3265264898157598752])) 
 		)
 	)
}

pub fn get_delta_g2_neg_pc_28() -> (QuadExtField::<ark_ff::Fp2ParamsWrapper::<ark_bn254::Fq2Parameters>>, QuadExtField::<ark_ff::Fp2ParamsWrapper::<ark_bn254::Fq2Parameters>>, QuadExtField::<ark_ff::Fp2ParamsWrapper::<ark_bn254::Fq2Parameters>>) { 
 	(QuadExtField::<ark_ff::Fp2ParamsWrapper::<ark_bn254::Fq2Parameters>>::new(
			ark_ff::Fp256::<ark_bn254::FqParameters>::new(BigInteger256::new([7948867415665914744,17166433830741961548, 7100668184286691752, 317261521781824521])), 
			ark_ff::Fp256::<ark_bn254::FqParameters>::new(BigInteger256::new([10979169594456077141,10267475655261668160, 8291752986056046191, 2207038577076351517])) 
		),
		QuadExtField::<ark_ff::Fp2ParamsWrapper::<ark_bn254::Fq2Parameters>>::new(
			ark_ff::Fp256::<ark_bn254::FqParameters>::new(BigInteger256::new([5267412641282190406,9329901219783354598, 13409383471386707634, 1211242088382784640])), 
			ark_ff::Fp256::<ark_bn254::FqParameters>::new(BigInteger256::new([8100166776758950894,126161170468808543, 5906903715625792650, 782806811024878426])) 
		),
		QuadExtField::<ark_ff::Fp2ParamsWrapper::<ark_bn254::Fq2Parameters>>::new(
			ark_ff::Fp256::<ark_bn254::FqParameters>::new(BigInteger256::new([15462459961064155926,14988754319299119742, 8764796389335429005, 2708985341280893442])), 
			ark_ff::Fp256::<ark_bn254::FqParameters>::new(BigInteger256::new([5771937279791845615,17476303904795628278, 15153357264580475565, 910344298792181247])) 
 		)
 	)
}

pub fn get_delta_g2_neg_pc_29() -> (QuadExtField::<ark_ff::Fp2ParamsWrapper::<ark_bn254::Fq2Parameters>>, QuadExtField::<ark_ff::Fp2ParamsWrapper::<ark_bn254::Fq2Parameters>>, QuadExtField::<ark_ff::Fp2ParamsWrapper::<ark_bn254::Fq2Parameters>>) { 
 	(QuadExtField::<ark_ff::Fp2ParamsWrapper::<ark_bn254::Fq2Parameters>>::new(
			ark_ff::Fp256::<ark_bn254::FqParameters>::new(BigInteger256::new([10450553065320070433,4568678427798071300, 14680279767608064502, 463962013393164281])), 
			ark_ff::Fp256::<ark_bn254::FqParameters>::new(BigInteger256::new([17600214192449005783,17851025105501759740, 8134907636038834159, 561336732936326011])) 
		),
		QuadExtField::<ark_ff::Fp2ParamsWrapper::<ark_bn254::Fq2Parameters>>::new(
			ark_ff::Fp256::<ark_bn254::FqParameters>::new(BigInteger256::new([2755451914254598938,1060442221871958008, 7099730168805413281, 3435208630661663250])), 
			ark_ff::Fp256::<ark_bn254::FqParameters>::new(BigInteger256::new([18173183923319074115,11374745922151117215, 10827662318929438458, 92865515646712958])) 
		),
		QuadExtField::<ark_ff::Fp2ParamsWrapper::<ark_bn254::Fq2Parameters>>::new(
			ark_ff::Fp256::<ark_bn254::FqParameters>::new(BigInteger256::new([17952643659935569038,5881471819381150649, 1115536179340792702, 1118672374975623743])), 
			ark_ff::Fp256::<ark_bn254::FqParameters>::new(BigInteger256::new([9414201372082238277,13243183352090779182, 1161987279433072349, 1820820770647474600])) 
 		)
 	)
}

pub fn get_delta_g2_neg_pc_30() -> (QuadExtField::<ark_ff::Fp2ParamsWrapper::<ark_bn254::Fq2Parameters>>, QuadExtField::<ark_ff::Fp2ParamsWrapper::<ark_bn254::Fq2Parameters>>, QuadExtField::<ark_ff::Fp2ParamsWrapper::<ark_bn254::Fq2Parameters>>) { 
 	(QuadExtField::<ark_ff::Fp2ParamsWrapper::<ark_bn254::Fq2Parameters>>::new(
			ark_ff::Fp256::<ark_bn254::FqParameters>::new(BigInteger256::new([17313850356343021935,3434211712207809840, 17631677726994884148, 666488528655546777])), 
			ark_ff::Fp256::<ark_bn254::FqParameters>::new(BigInteger256::new([9819822124312572176,15254228437240305657, 8179876400677154176, 3369298233874634446])) 
		),
		QuadExtField::<ark_ff::Fp2ParamsWrapper::<ark_bn254::Fq2Parameters>>::new(
			ark_ff::Fp256::<ark_bn254::FqParameters>::new(BigInteger256::new([14645090567343350599,5145293646346313457, 15667222227439022, 1147561517776234604])), 
			ark_ff::Fp256::<ark_bn254::FqParameters>::new(BigInteger256::new([9500619475864268326,5375014985631624581, 208176899228245953, 198173176966823026])) 
		),
		QuadExtField::<ark_ff::Fp2ParamsWrapper::<ark_bn254::Fq2Parameters>>::new(
			ark_ff::Fp256::<ark_bn254::FqParameters>::new(BigInteger256::new([9221216074000252967,7547193793186048712, 1635207585873365705, 2369018125192838794])), 
			ark_ff::Fp256::<ark_bn254::FqParameters>::new(BigInteger256::new([9098860609438156000,2289829168907044416, 9835930309259502086, 2654589633572786147])) 
 		)
 	)
}

pub fn get_delta_g2_neg_pc_31() -> (QuadExtField::<ark_ff::Fp2ParamsWrapper::<ark_bn254::Fq2Parameters>>, QuadExtField::<ark_ff::Fp2ParamsWrapper::<ark_bn254::Fq2Parameters>>, QuadExtField::<ark_ff::Fp2ParamsWrapper::<ark_bn254::Fq2Parameters>>) { 
 	(QuadExtField::<ark_ff::Fp2ParamsWrapper::<ark_bn254::Fq2Parameters>>::new(
			ark_ff::Fp256::<ark_bn254::FqParameters>::new(BigInteger256::new([11885424035933766828,9933012369466901950, 10770288704816965974, 907375053671688890])), 
			ark_ff::Fp256::<ark_bn254::FqParameters>::new(BigInteger256::new([14043073073434498835,8586842183081297302, 12334603759666925827, 3110030381553002301])) 
		),
		QuadExtField::<ark_ff::Fp2ParamsWrapper::<ark_bn254::Fq2Parameters>>::new(
			ark_ff::Fp256::<ark_bn254::FqParameters>::new(BigInteger256::new([15778759795899361313,3478295290470972600, 15667020029525773492, 1727420806828689597])), 
			ark_ff::Fp256::<ark_bn254::FqParameters>::new(BigInteger256::new([7398781139198999103,10579542326429679984, 4538729240789796105, 1383741349509760403])) 
		),
		QuadExtField::<ark_ff::Fp2ParamsWrapper::<ark_bn254::Fq2Parameters>>::new(
			ark_ff::Fp256::<ark_bn254::FqParameters>::new(BigInteger256::new([1483807587608031609,11526948793976618517, 1228290509265236720, 1392382130895355064])), 
			ark_ff::Fp256::<ark_bn254::FqParameters>::new(BigInteger256::new([3756456449496263664,3042755305651419450, 4664904017535309272, 1229587940978085699])) 
 		)
 	)
}

pub fn get_delta_g2_neg_pc_32() -> (QuadExtField::<ark_ff::Fp2ParamsWrapper::<ark_bn254::Fq2Parameters>>, QuadExtField::<ark_ff::Fp2ParamsWrapper::<ark_bn254::Fq2Parameters>>, QuadExtField::<ark_ff::Fp2ParamsWrapper::<ark_bn254::Fq2Parameters>>) { 
 	(QuadExtField::<ark_ff::Fp2ParamsWrapper::<ark_bn254::Fq2Parameters>>::new(
			ark_ff::Fp256::<ark_bn254::FqParameters>::new(BigInteger256::new([4382520299098615159,18088365090142785741, 16059750707491600202, 1687875352218330284])), 
			ark_ff::Fp256::<ark_bn254::FqParameters>::new(BigInteger256::new([16112612422732200961,3100384277092154243, 6899307179306861744, 270263107367669585])) 
		),
		QuadExtField::<ark_ff::Fp2ParamsWrapper::<ark_bn254::Fq2Parameters>>::new(
			ark_ff::Fp256::<ark_bn254::FqParameters>::new(BigInteger256::new([1900658267504144599,17886010266696465840, 11438841693894370400, 1791790800710512916])), 
			ark_ff::Fp256::<ark_bn254::FqParameters>::new(BigInteger256::new([10724157563050880852,7952463719642223313, 11977511658780567988, 361967180975374159])) 
		),
		QuadExtField::<ark_ff::Fp2ParamsWrapper::<ark_bn254::Fq2Parameters>>::new(
			ark_ff::Fp256::<ark_bn254::FqParameters>::new(BigInteger256::new([386974571059456214,18372466107860745945, 11185732686621282484, 25608075588895188])), 
			ark_ff::Fp256::<ark_bn254::FqParameters>::new(BigInteger256::new([4875790767609643866,14513643723323989442, 14047697075902756072, 1437543301910001491])) 
 		)
 	)
}

pub fn get_delta_g2_neg_pc_33() -> (QuadExtField::<ark_ff::Fp2ParamsWrapper::<ark_bn254::Fq2Parameters>>, QuadExtField::<ark_ff::Fp2ParamsWrapper::<ark_bn254::Fq2Parameters>>, QuadExtField::<ark_ff::Fp2ParamsWrapper::<ark_bn254::Fq2Parameters>>) { 
 	(QuadExtField::<ark_ff::Fp2ParamsWrapper::<ark_bn254::Fq2Parameters>>::new(
			ark_ff::Fp256::<ark_bn254::FqParameters>::new(BigInteger256::new([13530915400478310983,4253572125508050838, 2971994068272489797, 2367822101739384520])), 
			ark_ff::Fp256::<ark_bn254::FqParameters>::new(BigInteger256::new([16021054026609012497,14004498504330030849, 13372919675522885981, 3294374707886058886])) 
		),
		QuadExtField::<ark_ff::Fp2ParamsWrapper::<ark_bn254::Fq2Parameters>>::new(
			ark_ff::Fp256::<ark_bn254::FqParameters>::new(BigInteger256::new([668148838415564339,15913247190499098877, 10687434721680491758, 1031677702704595988])), 
			ark_ff::Fp256::<ark_bn254::FqParameters>::new(BigInteger256::new([1862205293111328390,15605937252887735449, 13308883041717434527, 1702524198916243824])) 
		),
		QuadExtField::<ark_ff::Fp2ParamsWrapper::<ark_bn254::Fq2Parameters>>::new(
			ark_ff::Fp256::<ark_bn254::FqParameters>::new(BigInteger256::new([886307529921096152,12596718365151255104, 5242191872331271349, 3456502714543599935])), 
			ark_ff::Fp256::<ark_bn254::FqParameters>::new(BigInteger256::new([10709234766124141259,3284402214301907104, 1550061793923494970, 2095444801756743855])) 
 		)
 	)
}

pub fn get_delta_g2_neg_pc_34() -> (QuadExtField::<ark_ff::Fp2ParamsWrapper::<ark_bn254::Fq2Parameters>>, QuadExtField::<ark_ff::Fp2ParamsWrapper::<ark_bn254::Fq2Parameters>>, QuadExtField::<ark_ff::Fp2ParamsWrapper::<ark_bn254::Fq2Parameters>>) { 
 	(QuadExtField::<ark_ff::Fp2ParamsWrapper::<ark_bn254::Fq2Parameters>>::new(
			ark_ff::Fp256::<ark_bn254::FqParameters>::new(BigInteger256::new([17845949523508914373,6227691680700206235, 15000053116819229246, 2846399627165061101])), 
			ark_ff::Fp256::<ark_bn254::FqParameters>::new(BigInteger256::new([1042692586680651005,361538664394135937, 26099644418857687, 3298583897324979500])) 
		),
		QuadExtField::<ark_ff::Fp2ParamsWrapper::<ark_bn254::Fq2Parameters>>::new(
			ark_ff::Fp256::<ark_bn254::FqParameters>::new(BigInteger256::new([10059645036634933643,1834168137484191742, 18434435045931066924, 2350144429325095708])), 
			ark_ff::Fp256::<ark_bn254::FqParameters>::new(BigInteger256::new([4217276909482207124,2422881294276106630, 11262636878658526560, 363676745770567951])) 
		),
		QuadExtField::<ark_ff::Fp2ParamsWrapper::<ark_bn254::Fq2Parameters>>::new(
			ark_ff::Fp256::<ark_bn254::FqParameters>::new(BigInteger256::new([15946142205436926358,4926842331595679044, 1213801617162988510, 1264875414510423940])), 
			ark_ff::Fp256::<ark_bn254::FqParameters>::new(BigInteger256::new([6694323573702574183,5124342637403053008, 17361415969457940776, 1498484371308562739])) 
 		)
 	)
}

pub fn get_delta_g2_neg_pc_35() -> (QuadExtField::<ark_ff::Fp2ParamsWrapper::<ark_bn254::Fq2Parameters>>, QuadExtField::<ark_ff::Fp2ParamsWrapper::<ark_bn254::Fq2Parameters>>, QuadExtField::<ark_ff::Fp2ParamsWrapper::<ark_bn254::Fq2Parameters>>) { 
 	(QuadExtField::<ark_ff::Fp2ParamsWrapper::<ark_bn254::Fq2Parameters>>::new(
			ark_ff::Fp256::<ark_bn254::FqParameters>::new(BigInteger256::new([1101048439178737123,11927325252621354794, 8995087854937795899, 1657310918276092017])), 
			ark_ff::Fp256::<ark_bn254::FqParameters>::new(BigInteger256::new([11180313823062715649,13482324267530987738, 7134390685793744314, 1812456992774306994])) 
		),
		QuadExtField::<ark_ff::Fp2ParamsWrapper::<ark_bn254::Fq2Parameters>>::new(
			ark_ff::Fp256::<ark_bn254::FqParameters>::new(BigInteger256::new([13820211720143186343,4493760932594037641, 9426713824455177588, 515809058274034586])), 
			ark_ff::Fp256::<ark_bn254::FqParameters>::new(BigInteger256::new([9920899605206767407,16761889482509776964, 6199094360650940936, 3296007994093222966])) 
		),
		QuadExtField::<ark_ff::Fp2ParamsWrapper::<ark_bn254::Fq2Parameters>>::new(
			ark_ff::Fp256::<ark_bn254::FqParameters>::new(BigInteger256::new([10527926464521375390,6448214260792779418, 7774692947959909350, 101860269617379376])), 
			ark_ff::Fp256::<ark_bn254::FqParameters>::new(BigInteger256::new([8337687974767258381,11689997108174641030, 3561987523534274156, 1035003168263298812])) 
 		)
 	)
}

pub fn get_delta_g2_neg_pc_36() -> (QuadExtField::<ark_ff::Fp2ParamsWrapper::<ark_bn254::Fq2Parameters>>, QuadExtField::<ark_ff::Fp2ParamsWrapper::<ark_bn254::Fq2Parameters>>, QuadExtField::<ark_ff::Fp2ParamsWrapper::<ark_bn254::Fq2Parameters>>) { 
 	(QuadExtField::<ark_ff::Fp2ParamsWrapper::<ark_bn254::Fq2Parameters>>::new(
			ark_ff::Fp256::<ark_bn254::FqParameters>::new(BigInteger256::new([4825260206338416576,6801378444057421734, 11877862133766487377, 1687937010429562779])), 
			ark_ff::Fp256::<ark_bn254::FqParameters>::new(BigInteger256::new([14893256430897919757,16127192203979576052, 15496543261841776643, 1902445273292069037])) 
		),
		QuadExtField::<ark_ff::Fp2ParamsWrapper::<ark_bn254::Fq2Parameters>>::new(
			ark_ff::Fp256::<ark_bn254::FqParameters>::new(BigInteger256::new([8677859715898936669,1966272331690499398, 6450671106593626597, 314762754053221661])), 
			ark_ff::Fp256::<ark_bn254::FqParameters>::new(BigInteger256::new([10518850844804287459,8554965497765490430, 13138338079892559314, 598086383259827922])) 
		),
		QuadExtField::<ark_ff::Fp2ParamsWrapper::<ark_bn254::Fq2Parameters>>::new(
			ark_ff::Fp256::<ark_bn254::FqParameters>::new(BigInteger256::new([8708848925061425752,4392728668671599523, 9318973497611118420, 2958053615451490501])), 
			ark_ff::Fp256::<ark_bn254::FqParameters>::new(BigInteger256::new([672227996854098060,6762255526985462561, 8012242903352027992, 1971482339735651487])) 
 		)
 	)
}

pub fn get_delta_g2_neg_pc_37() -> (QuadExtField::<ark_ff::Fp2ParamsWrapper::<ark_bn254::Fq2Parameters>>, QuadExtField::<ark_ff::Fp2ParamsWrapper::<ark_bn254::Fq2Parameters>>, QuadExtField::<ark_ff::Fp2ParamsWrapper::<ark_bn254::Fq2Parameters>>) { 
 	(QuadExtField::<ark_ff::Fp2ParamsWrapper::<ark_bn254::Fq2Parameters>>::new(
			ark_ff::Fp256::<ark_bn254::FqParameters>::new(BigInteger256::new([16742732270493672421,6462369513493438016, 17612045754045736514, 3243408292147913091])), 
			ark_ff::Fp256::<ark_bn254::FqParameters>::new(BigInteger256::new([4510357691155795171,12475313537658290390, 1262669005188215238, 1509919040973497624])) 
		),
		QuadExtField::<ark_ff::Fp2ParamsWrapper::<ark_bn254::Fq2Parameters>>::new(
			ark_ff::Fp256::<ark_bn254::FqParameters>::new(BigInteger256::new([12333683461261238269,9426420374056292940, 5563333062652148927, 1169543760241639891])), 
			ark_ff::Fp256::<ark_bn254::FqParameters>::new(BigInteger256::new([4809812835441091039,11221292607427688733, 3339485584556078106, 3365248144643559042])) 
		),
		QuadExtField::<ark_ff::Fp2ParamsWrapper::<ark_bn254::Fq2Parameters>>::new(
			ark_ff::Fp256::<ark_bn254::FqParameters>::new(BigInteger256::new([2608506645318135397,1674430509478896786, 7864969965622387258, 69708050986860037])), 
			ark_ff::Fp256::<ark_bn254::FqParameters>::new(BigInteger256::new([2464975745863648604,8970678759463919242, 984048935420687480, 1263137576865615292])) 
 		)
 	)
}

pub fn get_delta_g2_neg_pc_38() -> (QuadExtField::<ark_ff::Fp2ParamsWrapper::<ark_bn254::Fq2Parameters>>, QuadExtField::<ark_ff::Fp2ParamsWrapper::<ark_bn254::Fq2Parameters>>, QuadExtField::<ark_ff::Fp2ParamsWrapper::<ark_bn254::Fq2Parameters>>) { 
 	(QuadExtField::<ark_ff::Fp2ParamsWrapper::<ark_bn254::Fq2Parameters>>::new(
			ark_ff::Fp256::<ark_bn254::FqParameters>::new(BigInteger256::new([5673946019138271374,4153112625116469363, 4242166058821772788, 1010565222841329216])), 
			ark_ff::Fp256::<ark_bn254::FqParameters>::new(BigInteger256::new([1542054439928329875,2850513863668610074, 14807349783859742530, 2222822896623526765])) 
		),
		QuadExtField::<ark_ff::Fp2ParamsWrapper::<ark_bn254::Fq2Parameters>>::new(
			ark_ff::Fp256::<ark_bn254::FqParameters>::new(BigInteger256::new([1055261615317687018,13156401892575717394, 10147018908608172009, 1566007535656763509])), 
			ark_ff::Fp256::<ark_bn254::FqParameters>::new(BigInteger256::new([344615151946816106,17635337287837930567, 11729207091761940531, 3478652722088483962])) 
		),
		QuadExtField::<ark_ff::Fp2ParamsWrapper::<ark_bn254::Fq2Parameters>>::new(
			ark_ff::Fp256::<ark_bn254::FqParameters>::new(BigInteger256::new([3216532752515001268,5272174628811344948, 16534768269872805099, 753219241663628699])), 
			ark_ff::Fp256::<ark_bn254::FqParameters>::new(BigInteger256::new([13830760950708452271,11989418086304992135, 16786470169883152768, 1932590879584069847])) 
 		)
 	)
}

pub fn get_delta_g2_neg_pc_39() -> (QuadExtField::<ark_ff::Fp2ParamsWrapper::<ark_bn254::Fq2Parameters>>, QuadExtField::<ark_ff::Fp2ParamsWrapper::<ark_bn254::Fq2Parameters>>, QuadExtField::<ark_ff::Fp2ParamsWrapper::<ark_bn254::Fq2Parameters>>) { 
 	(QuadExtField::<ark_ff::Fp2ParamsWrapper::<ark_bn254::Fq2Parameters>>::new(
			ark_ff::Fp256::<ark_bn254::FqParameters>::new(BigInteger256::new([12003303986944440217,12604167989195097450, 16432474340411252868, 2677674274448099843])), 
			ark_ff::Fp256::<ark_bn254::FqParameters>::new(BigInteger256::new([9335312774782394544,1874455159791381256, 6890794314130897232, 1223447056448310631])) 
		),
		QuadExtField::<ark_ff::Fp2ParamsWrapper::<ark_bn254::Fq2Parameters>>::new(
			ark_ff::Fp256::<ark_bn254::FqParameters>::new(BigInteger256::new([16850539831717110973,11722582007168978342, 6126384566712159352, 368203979001824068])), 
			ark_ff::Fp256::<ark_bn254::FqParameters>::new(BigInteger256::new([2720324936418026949,5888316243110174961, 14265110291295467107, 96040705153772093])) 
		),
		QuadExtField::<ark_ff::Fp2ParamsWrapper::<ark_bn254::Fq2Parameters>>::new(
			ark_ff::Fp256::<ark_bn254::FqParameters>::new(BigInteger256::new([17023906609352868279,2303583264987545940, 4224793758212586677, 1935176698314879582])), 
			ark_ff::Fp256::<ark_bn254::FqParameters>::new(BigInteger256::new([5941948345168913066,17936811366873135704, 10054608806658177569, 295547581904407056])) 
 		)
 	)
}

pub fn get_delta_g2_neg_pc_40() -> (QuadExtField::<ark_ff::Fp2ParamsWrapper::<ark_bn254::Fq2Parameters>>, QuadExtField::<ark_ff::Fp2ParamsWrapper::<ark_bn254::Fq2Parameters>>, QuadExtField::<ark_ff::Fp2ParamsWrapper::<ark_bn254::Fq2Parameters>>) { 
 	(QuadExtField::<ark_ff::Fp2ParamsWrapper::<ark_bn254::Fq2Parameters>>::new(
			ark_ff::Fp256::<ark_bn254::FqParameters>::new(BigInteger256::new([11664494201438200262,5587742952924076336, 4879157057137570349, 7289216692730497])), 
			ark_ff::Fp256::<ark_bn254::FqParameters>::new(BigInteger256::new([5047865332597816354,9368608531370243776, 2538924223602732750, 1569662175948108112])) 
		),
		QuadExtField::<ark_ff::Fp2ParamsWrapper::<ark_bn254::Fq2Parameters>>::new(
			ark_ff::Fp256::<ark_bn254::FqParameters>::new(BigInteger256::new([238858652776058322,16150938557506299849, 6422910904606806616, 1958037353311251177])), 
			ark_ff::Fp256::<ark_bn254::FqParameters>::new(BigInteger256::new([3257169208422332950,3101662074671092940, 2587763982965448986, 44631004943401966])) 
		),
		QuadExtField::<ark_ff::Fp2ParamsWrapper::<ark_bn254::Fq2Parameters>>::new(
			ark_ff::Fp256::<ark_bn254::FqParameters>::new(BigInteger256::new([4441802370443198838,8310434281254039021, 16636132420173780060, 3411503998178140325])), 
			ark_ff::Fp256::<ark_bn254::FqParameters>::new(BigInteger256::new([15675005390760936618,10373691354607994199, 10012811008317086560, 1832783172933706868])) 
 		)
 	)
}

pub fn get_delta_g2_neg_pc_41() -> (QuadExtField::<ark_ff::Fp2ParamsWrapper::<ark_bn254::Fq2Parameters>>, QuadExtField::<ark_ff::Fp2ParamsWrapper::<ark_bn254::Fq2Parameters>>, QuadExtField::<ark_ff::Fp2ParamsWrapper::<ark_bn254::Fq2Parameters>>) { 
 	(QuadExtField::<ark_ff::Fp2ParamsWrapper::<ark_bn254::Fq2Parameters>>::new(
			ark_ff::Fp256::<ark_bn254::FqParameters>::new(BigInteger256::new([60662610634881212,15658764839184397109, 15987807772079033220, 2053045723709636338])), 
			ark_ff::Fp256::<ark_bn254::FqParameters>::new(BigInteger256::new([3048768240911070939,14955036261135913423, 7563442753013368116, 1917910253813807199])) 
		),
		QuadExtField::<ark_ff::Fp2ParamsWrapper::<ark_bn254::Fq2Parameters>>::new(
			ark_ff::Fp256::<ark_bn254::FqParameters>::new(BigInteger256::new([541382106736012965,431088692220278503, 14567858044716650288, 2983264816362395660])), 
			ark_ff::Fp256::<ark_bn254::FqParameters>::new(BigInteger256::new([15966803663155542593,365479404585703893, 7840831244731374681, 2210829256630179276])) 
		),
		QuadExtField::<ark_ff::Fp2ParamsWrapper::<ark_bn254::Fq2Parameters>>::new(
			ark_ff::Fp256::<ark_bn254::FqParameters>::new(BigInteger256::new([1356804389731070330,8553203088665248094, 8407290419110707911, 1279303969489535769])), 
			ark_ff::Fp256::<ark_bn254::FqParameters>::new(BigInteger256::new([3924106807472228805,16029121592068925414, 11918828681295886287, 3175366320024772917])) 
 		)
 	)
}

pub fn get_delta_g2_neg_pc_42() -> (QuadExtField::<ark_ff::Fp2ParamsWrapper::<ark_bn254::Fq2Parameters>>, QuadExtField::<ark_ff::Fp2ParamsWrapper::<ark_bn254::Fq2Parameters>>, QuadExtField::<ark_ff::Fp2ParamsWrapper::<ark_bn254::Fq2Parameters>>) { 
 	(QuadExtField::<ark_ff::Fp2ParamsWrapper::<ark_bn254::Fq2Parameters>>::new(
			ark_ff::Fp256::<ark_bn254::FqParameters>::new(BigInteger256::new([8376943299938002749,4896562140342391120, 1885148321160201085, 2148849343919002785])), 
			ark_ff::Fp256::<ark_bn254::FqParameters>::new(BigInteger256::new([18110914987665237685,13564411993686488289, 1953489703271863341, 2499677445338553026])) 
		),
		QuadExtField::<ark_ff::Fp2ParamsWrapper::<ark_bn254::Fq2Parameters>>::new(
			ark_ff::Fp256::<ark_bn254::FqParameters>::new(BigInteger256::new([15720661824273163652,3916452567522523698, 370029651423353495, 1651337081793284759])), 
			ark_ff::Fp256::<ark_bn254::FqParameters>::new(BigInteger256::new([4093845323449319648,10157876707267899889, 16523350809051820387, 3335086172474644760])) 
		),
		QuadExtField::<ark_ff::Fp2ParamsWrapper::<ark_bn254::Fq2Parameters>>::new(
			ark_ff::Fp256::<ark_bn254::FqParameters>::new(BigInteger256::new([9531485963024243683,15239298771097287119, 5862848321033951157, 883396086505249434])), 
			ark_ff::Fp256::<ark_bn254::FqParameters>::new(BigInteger256::new([9710872196619158854,10799150112109424577, 235795545420472630, 572422124010677511])) 
 		)
 	)
}

pub fn get_delta_g2_neg_pc_43() -> (QuadExtField::<ark_ff::Fp2ParamsWrapper::<ark_bn254::Fq2Parameters>>, QuadExtField::<ark_ff::Fp2ParamsWrapper::<ark_bn254::Fq2Parameters>>, QuadExtField::<ark_ff::Fp2ParamsWrapper::<ark_bn254::Fq2Parameters>>) { 
 	(QuadExtField::<ark_ff::Fp2ParamsWrapper::<ark_bn254::Fq2Parameters>>::new(
			ark_ff::Fp256::<ark_bn254::FqParameters>::new(BigInteger256::new([7569372868992018039,55946188671217347, 1889893931355253016, 874124733832615287])), 
			ark_ff::Fp256::<ark_bn254::FqParameters>::new(BigInteger256::new([1714037268218975954,11438486221542495192, 2716042857971420644, 2733306203350589364])) 
		),
		QuadExtField::<ark_ff::Fp2ParamsWrapper::<ark_bn254::Fq2Parameters>>::new(
			ark_ff::Fp256::<ark_bn254::FqParameters>::new(BigInteger256::new([1732065097484866077,4052856592025440777, 6043487287027245716, 6270296297808346])), 
			ark_ff::Fp256::<ark_bn254::FqParameters>::new(BigInteger256::new([10531558173591146457,1125406242106883808, 11501648761872752957, 321196793998398810])) 
		),
		QuadExtField::<ark_ff::Fp2ParamsWrapper::<ark_bn254::Fq2Parameters>>::new(
			ark_ff::Fp256::<ark_bn254::FqParameters>::new(BigInteger256::new([15812612282768987541,79922533366313483, 75813860867869728, 813981693473105620])), 
			ark_ff::Fp256::<ark_bn254::FqParameters>::new(BigInteger256::new([12554152242437851615,10928598725550514617, 4876291308207135894, 2504359076899091241])) 
 		)
 	)
}

pub fn get_delta_g2_neg_pc_44() -> (QuadExtField::<ark_ff::Fp2ParamsWrapper::<ark_bn254::Fq2Parameters>>, QuadExtField::<ark_ff::Fp2ParamsWrapper::<ark_bn254::Fq2Parameters>>, QuadExtField::<ark_ff::Fp2ParamsWrapper::<ark_bn254::Fq2Parameters>>) { 
 	(QuadExtField::<ark_ff::Fp2ParamsWrapper::<ark_bn254::Fq2Parameters>>::new(
			ark_ff::Fp256::<ark_bn254::FqParameters>::new(BigInteger256::new([3194151859560377321,18141454896485898589, 13280681068456738754, 58246880686732903])), 
			ark_ff::Fp256::<ark_bn254::FqParameters>::new(BigInteger256::new([7739628253681412067,13775739333274369636, 11016248544698889326, 2912631531500597459])) 
		),
		QuadExtField::<ark_ff::Fp2ParamsWrapper::<ark_bn254::Fq2Parameters>>::new(
			ark_ff::Fp256::<ark_bn254::FqParameters>::new(BigInteger256::new([9066484844732704184,12403084477849825866, 14302793796963175498, 2715306486529124022])), 
			ark_ff::Fp256::<ark_bn254::FqParameters>::new(BigInteger256::new([16186737054280919147,4746469111104406645, 15278292070057620477, 1316507216108061252])) 
		),
		QuadExtField::<ark_ff::Fp2ParamsWrapper::<ark_bn254::Fq2Parameters>>::new(
			ark_ff::Fp256::<ark_bn254::FqParameters>::new(BigInteger256::new([14493817658120034019,10409977545513887454, 554110661232929043, 189070721799099355])), 
			ark_ff::Fp256::<ark_bn254::FqParameters>::new(BigInteger256::new([23843002728921747,13762218144533701840, 17179888742255292509, 1941235329619238049])) 
 		)
 	)
}

pub fn get_delta_g2_neg_pc_45() -> (QuadExtField::<ark_ff::Fp2ParamsWrapper::<ark_bn254::Fq2Parameters>>, QuadExtField::<ark_ff::Fp2ParamsWrapper::<ark_bn254::Fq2Parameters>>, QuadExtField::<ark_ff::Fp2ParamsWrapper::<ark_bn254::Fq2Parameters>>) { 
 	(QuadExtField::<ark_ff::Fp2ParamsWrapper::<ark_bn254::Fq2Parameters>>::new(
			ark_ff::Fp256::<ark_bn254::FqParameters>::new(BigInteger256::new([9507476525806360660,7025888600542814158, 1809949783326154848, 516263921555749904])), 
			ark_ff::Fp256::<ark_bn254::FqParameters>::new(BigInteger256::new([13316083955930812637,496852009974324216, 10411100182279964523, 806888742689311818])) 
		),
		QuadExtField::<ark_ff::Fp2ParamsWrapper::<ark_bn254::Fq2Parameters>>::new(
			ark_ff::Fp256::<ark_bn254::FqParameters>::new(BigInteger256::new([9531341171179202497,4690629875409773365, 2448272779795076128, 445542382308482729])), 
			ark_ff::Fp256::<ark_bn254::FqParameters>::new(BigInteger256::new([14958379458199061410,8417846073981791523, 11224275712899124518, 89086869768607483])) 
		),
		QuadExtField::<ark_ff::Fp2ParamsWrapper::<ark_bn254::Fq2Parameters>>::new(
			ark_ff::Fp256::<ark_bn254::FqParameters>::new(BigInteger256::new([2444033747424828562,6678200673511126723, 9817504889093549315, 1245776194098939773])), 
			ark_ff::Fp256::<ark_bn254::FqParameters>::new(BigInteger256::new([4670763907088366919,17758762434872946123, 10003507224031793780, 1385821933853827262])) 
 		)
 	)
}

pub fn get_delta_g2_neg_pc_46() -> (QuadExtField::<ark_ff::Fp2ParamsWrapper::<ark_bn254::Fq2Parameters>>, QuadExtField::<ark_ff::Fp2ParamsWrapper::<ark_bn254::Fq2Parameters>>, QuadExtField::<ark_ff::Fp2ParamsWrapper::<ark_bn254::Fq2Parameters>>) { 
 	(QuadExtField::<ark_ff::Fp2ParamsWrapper::<ark_bn254::Fq2Parameters>>::new(
			ark_ff::Fp256::<ark_bn254::FqParameters>::new(BigInteger256::new([15968582013993682984,2173415041414816108, 5204416559003621808, 3168568347561719872])), 
			ark_ff::Fp256::<ark_bn254::FqParameters>::new(BigInteger256::new([6257091442278848079,12078240710791128113, 17738926759398032567, 2897540662155471371])) 
		),
		QuadExtField::<ark_ff::Fp2ParamsWrapper::<ark_bn254::Fq2Parameters>>::new(
			ark_ff::Fp256::<ark_bn254::FqParameters>::new(BigInteger256::new([15289162597602202644,12692043343008422056, 1063423372200811605, 3041218502561291563])), 
			ark_ff::Fp256::<ark_bn254::FqParameters>::new(BigInteger256::new([8514486196874904811,6354430394592347325, 12811770127488380559, 2914731046641363906])) 
		),
		QuadExtField::<ark_ff::Fp2ParamsWrapper::<ark_bn254::Fq2Parameters>>::new(
			ark_ff::Fp256::<ark_bn254::FqParameters>::new(BigInteger256::new([5754749212330800155,7223284294080898223, 16475147126132732476, 3248232915944126729])), 
			ark_ff::Fp256::<ark_bn254::FqParameters>::new(BigInteger256::new([18095947890617511317,14806631832997858843, 2023241633356925420, 2210482383731759481])) 
 		)
 	)
}

pub fn get_delta_g2_neg_pc_47() -> (QuadExtField::<ark_ff::Fp2ParamsWrapper::<ark_bn254::Fq2Parameters>>, QuadExtField::<ark_ff::Fp2ParamsWrapper::<ark_bn254::Fq2Parameters>>, QuadExtField::<ark_ff::Fp2ParamsWrapper::<ark_bn254::Fq2Parameters>>) { 
 	(QuadExtField::<ark_ff::Fp2ParamsWrapper::<ark_bn254::Fq2Parameters>>::new(
			ark_ff::Fp256::<ark_bn254::FqParameters>::new(BigInteger256::new([2127746327786271021,9612575552546451466, 16911478106514418847, 1598190196561889874])), 
			ark_ff::Fp256::<ark_bn254::FqParameters>::new(BigInteger256::new([2553960968079378493,10894739034628453295, 8445530504760853242, 367627883892576986])) 
		),
		QuadExtField::<ark_ff::Fp2ParamsWrapper::<ark_bn254::Fq2Parameters>>::new(
			ark_ff::Fp256::<ark_bn254::FqParameters>::new(BigInteger256::new([4956014945711289841,2794853999453266966, 4883975097327605557, 2868151605123228168])), 
			ark_ff::Fp256::<ark_bn254::FqParameters>::new(BigInteger256::new([6427979619418010932,16959737279446431478, 1105806374540020948, 2360007617866052252])) 
		),
		QuadExtField::<ark_ff::Fp2ParamsWrapper::<ark_bn254::Fq2Parameters>>::new(
			ark_ff::Fp256::<ark_bn254::FqParameters>::new(BigInteger256::new([6949104892712743255,16716667028271897059, 7335849938726648327, 621372826126673025])), 
			ark_ff::Fp256::<ark_bn254::FqParameters>::new(BigInteger256::new([2675656168294152260,13949160421103688927, 11551353183404757590, 231907094521594374])) 
 		)
 	)
}

pub fn get_delta_g2_neg_pc_48() -> (QuadExtField::<ark_ff::Fp2ParamsWrapper::<ark_bn254::Fq2Parameters>>, QuadExtField::<ark_ff::Fp2ParamsWrapper::<ark_bn254::Fq2Parameters>>, QuadExtField::<ark_ff::Fp2ParamsWrapper::<ark_bn254::Fq2Parameters>>) { 
 	(QuadExtField::<ark_ff::Fp2ParamsWrapper::<ark_bn254::Fq2Parameters>>::new(
			ark_ff::Fp256::<ark_bn254::FqParameters>::new(BigInteger256::new([16253128144295430346,13950996204523863917, 3076851412516988994, 1673802698724981452])), 
			ark_ff::Fp256::<ark_bn254::FqParameters>::new(BigInteger256::new([9098028010077014580,2788725501947838088, 13455143024053607742, 3332291798031242325])) 
		),
		QuadExtField::<ark_ff::Fp2ParamsWrapper::<ark_bn254::Fq2Parameters>>::new(
			ark_ff::Fp256::<ark_bn254::FqParameters>::new(BigInteger256::new([701588978832034635,1179088259954906290, 6237707586696625959, 1819142268786125295])), 
			ark_ff::Fp256::<ark_bn254::FqParameters>::new(BigInteger256::new([12903625469516721282,12789314611018181816, 13467133297396388907, 1423341051816136249])) 
		),
		QuadExtField::<ark_ff::Fp2ParamsWrapper::<ark_bn254::Fq2Parameters>>::new(
			ark_ff::Fp256::<ark_bn254::FqParameters>::new(BigInteger256::new([12741041238599850115,2343607584687470484, 11907494651336077601, 350185171173093668])), 
			ark_ff::Fp256::<ark_bn254::FqParameters>::new(BigInteger256::new([3577621216466744854,1211050013910150047, 3023676614812469118, 3155844093930869161])) 
 		)
 	)
}

pub fn get_delta_g2_neg_pc_49() -> (QuadExtField::<ark_ff::Fp2ParamsWrapper::<ark_bn254::Fq2Parameters>>, QuadExtField::<ark_ff::Fp2ParamsWrapper::<ark_bn254::Fq2Parameters>>, QuadExtField::<ark_ff::Fp2ParamsWrapper::<ark_bn254::Fq2Parameters>>) { 
 	(QuadExtField::<ark_ff::Fp2ParamsWrapper::<ark_bn254::Fq2Parameters>>::new(
			ark_ff::Fp256::<ark_bn254::FqParameters>::new(BigInteger256::new([13729272988915997024,11959823695203163884, 3410112114652176263, 2454622736191541873])), 
			ark_ff::Fp256::<ark_bn254::FqParameters>::new(BigInteger256::new([3045301730460856363,129137107427236908, 8414938548717025042, 2864037315448600761])) 
		),
		QuadExtField::<ark_ff::Fp2ParamsWrapper::<ark_bn254::Fq2Parameters>>::new(
			ark_ff::Fp256::<ark_bn254::FqParameters>::new(BigInteger256::new([16376170180371889021,7996410424563884633, 12561080597220091199, 873149807881015367])), 
			ark_ff::Fp256::<ark_bn254::FqParameters>::new(BigInteger256::new([16041490511119967164,11439799309823834931, 8290666758946785457, 2759031246730879865])) 
		),
		QuadExtField::<ark_ff::Fp2ParamsWrapper::<ark_bn254::Fq2Parameters>>::new(
			ark_ff::Fp256::<ark_bn254::FqParameters>::new(BigInteger256::new([1008461629803149598,13607635935812995246, 13135417098948330898, 327415381730762384])), 
			ark_ff::Fp256::<ark_bn254::FqParameters>::new(BigInteger256::new([7897961056897469901,14795025592467183781, 14931498309914704253, 827739667752686245])) 
 		)
 	)
}

pub fn get_delta_g2_neg_pc_50() -> (QuadExtField::<ark_ff::Fp2ParamsWrapper::<ark_bn254::Fq2Parameters>>, QuadExtField::<ark_ff::Fp2ParamsWrapper::<ark_bn254::Fq2Parameters>>, QuadExtField::<ark_ff::Fp2ParamsWrapper::<ark_bn254::Fq2Parameters>>) { 
 	(QuadExtField::<ark_ff::Fp2ParamsWrapper::<ark_bn254::Fq2Parameters>>::new(
			ark_ff::Fp256::<ark_bn254::FqParameters>::new(BigInteger256::new([8098947097078656376,7489977525759314985, 11382598141140238504, 2489650402160796499])), 
			ark_ff::Fp256::<ark_bn254::FqParameters>::new(BigInteger256::new([12129603627906947045,17184270324564106616, 10857680635867721834, 742279255185999307])) 
		),
		QuadExtField::<ark_ff::Fp2ParamsWrapper::<ark_bn254::Fq2Parameters>>::new(
			ark_ff::Fp256::<ark_bn254::FqParameters>::new(BigInteger256::new([334257319032090523,12399289234800721671, 5097901519728226052, 896619920849069383])), 
			ark_ff::Fp256::<ark_bn254::FqParameters>::new(BigInteger256::new([2182420903648296519,7980332995910084550, 15838322794097867174, 616129639599997474])) 
		),
		QuadExtField::<ark_ff::Fp2ParamsWrapper::<ark_bn254::Fq2Parameters>>::new(
			ark_ff::Fp256::<ark_bn254::FqParameters>::new(BigInteger256::new([16312355878213281177,12413024007006519495, 4261474747465574567, 3342208166468433102])), 
			ark_ff::Fp256::<ark_bn254::FqParameters>::new(BigInteger256::new([13333433826488418240,468483911144888034, 13663428224637905474, 1409664571632010242])) 
 		)
 	)
}

pub fn get_delta_g2_neg_pc_51() -> (QuadExtField::<ark_ff::Fp2ParamsWrapper::<ark_bn254::Fq2Parameters>>, QuadExtField::<ark_ff::Fp2ParamsWrapper::<ark_bn254::Fq2Parameters>>, QuadExtField::<ark_ff::Fp2ParamsWrapper::<ark_bn254::Fq2Parameters>>) { 
 	(QuadExtField::<ark_ff::Fp2ParamsWrapper::<ark_bn254::Fq2Parameters>>::new(
			ark_ff::Fp256::<ark_bn254::FqParameters>::new(BigInteger256::new([15510598698394183762,4071131618056430489, 4058694245810731935, 2479721974567774635])), 
			ark_ff::Fp256::<ark_bn254::FqParameters>::new(BigInteger256::new([13614727245047219873,4485175498404154698, 13722123283822940504, 3078473359836419359])) 
		),
		QuadExtField::<ark_ff::Fp2ParamsWrapper::<ark_bn254::Fq2Parameters>>::new(
			ark_ff::Fp256::<ark_bn254::FqParameters>::new(BigInteger256::new([9841101078117526302,14058118331469012053, 4521185128587146868, 1673553861831881830])), 
			ark_ff::Fp256::<ark_bn254::FqParameters>::new(BigInteger256::new([9887296666913788064,1116000388284607256, 6149678779789819446, 1980646224178991499])) 
		),
		QuadExtField::<ark_ff::Fp2ParamsWrapper::<ark_bn254::Fq2Parameters>>::new(
			ark_ff::Fp256::<ark_bn254::FqParameters>::new(BigInteger256::new([7317798425795393961,3817428889289250076, 7184676141155817740, 2374653738269871063])), 
			ark_ff::Fp256::<ark_bn254::FqParameters>::new(BigInteger256::new([336376723955198094,9270266739688178314, 1609210574029240646, 3239201286090007254])) 
 		)
 	)
}

pub fn get_delta_g2_neg_pc_52() -> (QuadExtField::<ark_ff::Fp2ParamsWrapper::<ark_bn254::Fq2Parameters>>, QuadExtField::<ark_ff::Fp2ParamsWrapper::<ark_bn254::Fq2Parameters>>, QuadExtField::<ark_ff::Fp2ParamsWrapper::<ark_bn254::Fq2Parameters>>) { 
 	(QuadExtField::<ark_ff::Fp2ParamsWrapper::<ark_bn254::Fq2Parameters>>::new(
			ark_ff::Fp256::<ark_bn254::FqParameters>::new(BigInteger256::new([5212632926043159360,2379444503570431056, 18018787702269554008, 3160193691176978100])), 
			ark_ff::Fp256::<ark_bn254::FqParameters>::new(BigInteger256::new([1334927224417195213,8727242594498046123, 13791403500191710152, 405042984010265134])) 
		),
		QuadExtField::<ark_ff::Fp2ParamsWrapper::<ark_bn254::Fq2Parameters>>::new(
			ark_ff::Fp256::<ark_bn254::FqParameters>::new(BigInteger256::new([16784434261690297583,5399869758793892338, 18353992966480854764, 2930877002055363901])), 
			ark_ff::Fp256::<ark_bn254::FqParameters>::new(BigInteger256::new([6168075890142514737,16183425216927715899, 7202099757585550001, 2198653798865584331])) 
		),
		QuadExtField::<ark_ff::Fp2ParamsWrapper::<ark_bn254::Fq2Parameters>>::new(
			ark_ff::Fp256::<ark_bn254::FqParameters>::new(BigInteger256::new([16579720986066225407,9329656290441058592, 7125186608091555106, 1130002320021820200])), 
			ark_ff::Fp256::<ark_bn254::FqParameters>::new(BigInteger256::new([15251604310291536185,2882562767785322292, 9841458872152545927, 865817232541321969])) 
 		)
 	)
}

pub fn get_delta_g2_neg_pc_53() -> (QuadExtField::<ark_ff::Fp2ParamsWrapper::<ark_bn254::Fq2Parameters>>, QuadExtField::<ark_ff::Fp2ParamsWrapper::<ark_bn254::Fq2Parameters>>, QuadExtField::<ark_ff::Fp2ParamsWrapper::<ark_bn254::Fq2Parameters>>) { 
 	(QuadExtField::<ark_ff::Fp2ParamsWrapper::<ark_bn254::Fq2Parameters>>::new(
			ark_ff::Fp256::<ark_bn254::FqParameters>::new(BigInteger256::new([2808710867030303172,8869854121234430258, 10128928586378147534, 2398267640516842403])), 
			ark_ff::Fp256::<ark_bn254::FqParameters>::new(BigInteger256::new([13841831145831259687,10865908028565022926, 2169776344227768443, 858518883181802694])) 
		),
		QuadExtField::<ark_ff::Fp2ParamsWrapper::<ark_bn254::Fq2Parameters>>::new(
			ark_ff::Fp256::<ark_bn254::FqParameters>::new(BigInteger256::new([11804661144811815715,5223070023628316977, 3682675212116870408, 2781398324620177359])), 
			ark_ff::Fp256::<ark_bn254::FqParameters>::new(BigInteger256::new([7979482080676151593,7533666953277505279, 3510062813657027043, 2665977957694187850])) 
		),
		QuadExtField::<ark_ff::Fp2ParamsWrapper::<ark_bn254::Fq2Parameters>>::new(
			ark_ff::Fp256::<ark_bn254::FqParameters>::new(BigInteger256::new([8119716347321225556,123222392487727688, 15135279669105026274, 1055551913739381920])), 
			ark_ff::Fp256::<ark_bn254::FqParameters>::new(BigInteger256::new([18089754436006910774,13056697375614243127, 11961762177680681540, 3078656987899121520])) 
 		)
 	)
}

pub fn get_delta_g2_neg_pc_54() -> (QuadExtField::<ark_ff::Fp2ParamsWrapper::<ark_bn254::Fq2Parameters>>, QuadExtField::<ark_ff::Fp2ParamsWrapper::<ark_bn254::Fq2Parameters>>, QuadExtField::<ark_ff::Fp2ParamsWrapper::<ark_bn254::Fq2Parameters>>) { 
 	(QuadExtField::<ark_ff::Fp2ParamsWrapper::<ark_bn254::Fq2Parameters>>::new(
			ark_ff::Fp256::<ark_bn254::FqParameters>::new(BigInteger256::new([294462372352726223,5263720507999421651, 1980277246440072159, 1269480161122348283])), 
			ark_ff::Fp256::<ark_bn254::FqParameters>::new(BigInteger256::new([5030611906758042572,9102980774606033669, 12658808889488961609, 3076247767905662544])) 
		),
		QuadExtField::<ark_ff::Fp2ParamsWrapper::<ark_bn254::Fq2Parameters>>::new(
			ark_ff::Fp256::<ark_bn254::FqParameters>::new(BigInteger256::new([10090853928960880344,11885615234853755960, 5178851380433300030, 1298264992602980737])), 
			ark_ff::Fp256::<ark_bn254::FqParameters>::new(BigInteger256::new([1560503141873143219,11743127930349725067, 11782657577241830133, 2994524725744834730])) 
		),
		QuadExtField::<ark_ff::Fp2ParamsWrapper::<ark_bn254::Fq2Parameters>>::new(
			ark_ff::Fp256::<ark_bn254::FqParameters>::new(BigInteger256::new([1644428165091079211,4886358070978753086, 10300720391170996816, 1671192436459919033])), 
			ark_ff::Fp256::<ark_bn254::FqParameters>::new(BigInteger256::new([10034696238905307937,12813475714406313786, 2796807579632596606, 2900716817252786457])) 
 		)
 	)
}

pub fn get_delta_g2_neg_pc_55() -> (QuadExtField::<ark_ff::Fp2ParamsWrapper::<ark_bn254::Fq2Parameters>>, QuadExtField::<ark_ff::Fp2ParamsWrapper::<ark_bn254::Fq2Parameters>>, QuadExtField::<ark_ff::Fp2ParamsWrapper::<ark_bn254::Fq2Parameters>>) { 
 	(QuadExtField::<ark_ff::Fp2ParamsWrapper::<ark_bn254::Fq2Parameters>>::new(
			ark_ff::Fp256::<ark_bn254::FqParameters>::new(BigInteger256::new([13240593249822471203,7297412312543750028, 12283169257361715677, 423192182389462558])), 
			ark_ff::Fp256::<ark_bn254::FqParameters>::new(BigInteger256::new([7485372119966677436,1995572044405634112, 10489423583037291314, 1504708168999981450])) 
		),
		QuadExtField::<ark_ff::Fp2ParamsWrapper::<ark_bn254::Fq2Parameters>>::new(
			ark_ff::Fp256::<ark_bn254::FqParameters>::new(BigInteger256::new([13702596025329534021,4693632495496912113, 3988386419474832634, 2623726136424614989])), 
			ark_ff::Fp256::<ark_bn254::FqParameters>::new(BigInteger256::new([7553898412766040280,9323896252188069777, 10742294910817828088, 466974496650343562])) 
		),
		QuadExtField::<ark_ff::Fp2ParamsWrapper::<ark_bn254::Fq2Parameters>>::new(
			ark_ff::Fp256::<ark_bn254::FqParameters>::new(BigInteger256::new([10315320813829878298,5831421074596625597, 9231201889191749141, 490494866783279951])), 
			ark_ff::Fp256::<ark_bn254::FqParameters>::new(BigInteger256::new([12575154167380001455,1192259058203258891, 11712763157236833848, 1447601513155716471])) 
 		)
 	)
}

pub fn get_delta_g2_neg_pc_56() -> (QuadExtField::<ark_ff::Fp2ParamsWrapper::<ark_bn254::Fq2Parameters>>, QuadExtField::<ark_ff::Fp2ParamsWrapper::<ark_bn254::Fq2Parameters>>, QuadExtField::<ark_ff::Fp2ParamsWrapper::<ark_bn254::Fq2Parameters>>) { 
 	(QuadExtField::<ark_ff::Fp2ParamsWrapper::<ark_bn254::Fq2Parameters>>::new(
			ark_ff::Fp256::<ark_bn254::FqParameters>::new(BigInteger256::new([5799572451915008674,492325225212319707, 5336804324912468662, 2426179958075977133])), 
			ark_ff::Fp256::<ark_bn254::FqParameters>::new(BigInteger256::new([17081678578675039027,6406093390116289862, 8945113978387516013, 2374803883907035278])) 
		),
		QuadExtField::<ark_ff::Fp2ParamsWrapper::<ark_bn254::Fq2Parameters>>::new(
			ark_ff::Fp256::<ark_bn254::FqParameters>::new(BigInteger256::new([3808559321476630138,10176537850731434728, 3097867074597851764, 2962331216863277615])), 
			ark_ff::Fp256::<ark_bn254::FqParameters>::new(BigInteger256::new([15556994690565393319,15332001390657684457, 5603448362349552200, 1753540288172732373])) 
		),
		QuadExtField::<ark_ff::Fp2ParamsWrapper::<ark_bn254::Fq2Parameters>>::new(
			ark_ff::Fp256::<ark_bn254::FqParameters>::new(BigInteger256::new([13493897997638818836,16964349422750512130, 4272171288799794225, 3233214769205812225])), 
			ark_ff::Fp256::<ark_bn254::FqParameters>::new(BigInteger256::new([7971668999570687336,12900909968279116095, 2443563852887953120, 3087641737810669951])) 
 		)
 	)
}

pub fn get_delta_g2_neg_pc_57() -> (QuadExtField::<ark_ff::Fp2ParamsWrapper::<ark_bn254::Fq2Parameters>>, QuadExtField::<ark_ff::Fp2ParamsWrapper::<ark_bn254::Fq2Parameters>>, QuadExtField::<ark_ff::Fp2ParamsWrapper::<ark_bn254::Fq2Parameters>>) { 
 	(QuadExtField::<ark_ff::Fp2ParamsWrapper::<ark_bn254::Fq2Parameters>>::new(
			ark_ff::Fp256::<ark_bn254::FqParameters>::new(BigInteger256::new([5662316433972774979,14200390388618283200, 12919233386616551177, 1648041521172765076])), 
			ark_ff::Fp256::<ark_bn254::FqParameters>::new(BigInteger256::new([16295048921931450896,667081309994116578, 15789686041684891854, 2974594051709038059])) 
		),
		QuadExtField::<ark_ff::Fp2ParamsWrapper::<ark_bn254::Fq2Parameters>>::new(
			ark_ff::Fp256::<ark_bn254::FqParameters>::new(BigInteger256::new([6105664004567533408,15745682472337468936, 9568798873977680757, 324665108175858960])), 
			ark_ff::Fp256::<ark_bn254::FqParameters>::new(BigInteger256::new([12785439414240430958,16301926865352402320, 15477203312250995102, 2968010733592263147])) 
		),
		QuadExtField::<ark_ff::Fp2ParamsWrapper::<ark_bn254::Fq2Parameters>>::new(
			ark_ff::Fp256::<ark_bn254::FqParameters>::new(BigInteger256::new([237766318333773902,3064328134149721578, 15507502284556490759, 183162016903916022])), 
			ark_ff::Fp256::<ark_bn254::FqParameters>::new(BigInteger256::new([13117739543388171267,1103866766072884603, 2979117450137383624, 1804802690002653808])) 
 		)
 	)
}

pub fn get_delta_g2_neg_pc_58() -> (QuadExtField::<ark_ff::Fp2ParamsWrapper::<ark_bn254::Fq2Parameters>>, QuadExtField::<ark_ff::Fp2ParamsWrapper::<ark_bn254::Fq2Parameters>>, QuadExtField::<ark_ff::Fp2ParamsWrapper::<ark_bn254::Fq2Parameters>>) { 
 	(QuadExtField::<ark_ff::Fp2ParamsWrapper::<ark_bn254::Fq2Parameters>>::new(
			ark_ff::Fp256::<ark_bn254::FqParameters>::new(BigInteger256::new([18142790834626377852,7478020981403918527, 10235062276959252708, 2576084494271104348])), 
			ark_ff::Fp256::<ark_bn254::FqParameters>::new(BigInteger256::new([3364805388894461861,15950635099378873406, 16973636040210924625, 2304743346997837611])) 
		),
		QuadExtField::<ark_ff::Fp2ParamsWrapper::<ark_bn254::Fq2Parameters>>::new(
			ark_ff::Fp256::<ark_bn254::FqParameters>::new(BigInteger256::new([18147051049912831117,12495344195700730026, 9479569577223538999, 173504644105336020])), 
			ark_ff::Fp256::<ark_bn254::FqParameters>::new(BigInteger256::new([15751622160010044633,11780402155000896832, 13606630451298975938, 249618818080592965])) 
		),
		QuadExtField::<ark_ff::Fp2ParamsWrapper::<ark_bn254::Fq2Parameters>>::new(
			ark_ff::Fp256::<ark_bn254::FqParameters>::new(BigInteger256::new([13553777722176886630,1546636418151760485, 2361802616872632521, 2275167843604663985])), 
			ark_ff::Fp256::<ark_bn254::FqParameters>::new(BigInteger256::new([1093234916825030199,5100723531216385603, 2469034732231309654, 507118706071009800])) 
 		)
 	)
}

pub fn get_delta_g2_neg_pc_59() -> (QuadExtField::<ark_ff::Fp2ParamsWrapper::<ark_bn254::Fq2Parameters>>, QuadExtField::<ark_ff::Fp2ParamsWrapper::<ark_bn254::Fq2Parameters>>, QuadExtField::<ark_ff::Fp2ParamsWrapper::<ark_bn254::Fq2Parameters>>) { 
 	(QuadExtField::<ark_ff::Fp2ParamsWrapper::<ark_bn254::Fq2Parameters>>::new(
			ark_ff::Fp256::<ark_bn254::FqParameters>::new(BigInteger256::new([1307191055388154833,1737485019882968357, 6280821055867064922, 2113401769335440235])), 
			ark_ff::Fp256::<ark_bn254::FqParameters>::new(BigInteger256::new([9356910268008538427,960975339016316192, 14164123169346607564, 3120787671629426976])) 
		),
		QuadExtField::<ark_ff::Fp2ParamsWrapper::<ark_bn254::Fq2Parameters>>::new(
			ark_ff::Fp256::<ark_bn254::FqParameters>::new(BigInteger256::new([7827800844247852909,506426198100943007, 6605257003856559587, 2098716344461808512])), 
			ark_ff::Fp256::<ark_bn254::FqParameters>::new(BigInteger256::new([11906613049604200582,3896498639038946319, 11645302274280937472, 1141121274537961945])) 
		),
		QuadExtField::<ark_ff::Fp2ParamsWrapper::<ark_bn254::Fq2Parameters>>::new(
			ark_ff::Fp256::<ark_bn254::FqParameters>::new(BigInteger256::new([6838638455760086965,6022563620022975902, 7494634698535677419, 1707660189230777784])), 
			ark_ff::Fp256::<ark_bn254::FqParameters>::new(BigInteger256::new([8164137447549270334,1089847080650878998, 14785025048218541551, 3219988802644331186])) 
 		)
 	)
}

pub fn get_delta_g2_neg_pc_60() -> (QuadExtField::<ark_ff::Fp2ParamsWrapper::<ark_bn254::Fq2Parameters>>, QuadExtField::<ark_ff::Fp2ParamsWrapper::<ark_bn254::Fq2Parameters>>, QuadExtField::<ark_ff::Fp2ParamsWrapper::<ark_bn254::Fq2Parameters>>) { 
 	(QuadExtField::<ark_ff::Fp2ParamsWrapper::<ark_bn254::Fq2Parameters>>::new(
			ark_ff::Fp256::<ark_bn254::FqParameters>::new(BigInteger256::new([4705614788350440089,13604840688516037931, 12852116026850027948, 3149152432150023434])), 
			ark_ff::Fp256::<ark_bn254::FqParameters>::new(BigInteger256::new([5231853232095595026,5996759043087175332, 11704519332044937224, 844038753072525968])) 
		),
		QuadExtField::<ark_ff::Fp2ParamsWrapper::<ark_bn254::Fq2Parameters>>::new(
			ark_ff::Fp256::<ark_bn254::FqParameters>::new(BigInteger256::new([3733675712571785557,17432960022717704359, 4557688684884078587, 38616197274025328])), 
			ark_ff::Fp256::<ark_bn254::FqParameters>::new(BigInteger256::new([10742100622244629146,16613763994249513993, 16992281782212612711, 536251980546672681])) 
		),
		QuadExtField::<ark_ff::Fp2ParamsWrapper::<ark_bn254::Fq2Parameters>>::new(
			ark_ff::Fp256::<ark_bn254::FqParameters>::new(BigInteger256::new([15714524927185426441,1018464222973969610, 11972480179019860562, 2862301246406212330])), 
			ark_ff::Fp256::<ark_bn254::FqParameters>::new(BigInteger256::new([10313648758070967725,5232800827751657623, 1025767298901809511, 2550347321276132429])) 
 		)
 	)
}

pub fn get_delta_g2_neg_pc_61() -> (QuadExtField::<ark_ff::Fp2ParamsWrapper::<ark_bn254::Fq2Parameters>>, QuadExtField::<ark_ff::Fp2ParamsWrapper::<ark_bn254::Fq2Parameters>>, QuadExtField::<ark_ff::Fp2ParamsWrapper::<ark_bn254::Fq2Parameters>>) { 
 	(QuadExtField::<ark_ff::Fp2ParamsWrapper::<ark_bn254::Fq2Parameters>>::new(
			ark_ff::Fp256::<ark_bn254::FqParameters>::new(BigInteger256::new([9875050898494213487,14147365625290632146, 18189963924978061786, 368630939457559025])), 
			ark_ff::Fp256::<ark_bn254::FqParameters>::new(BigInteger256::new([5437896895920863775,15105351347234147211, 14011201532948948241, 3176594381029698120])) 
		),
		QuadExtField::<ark_ff::Fp2ParamsWrapper::<ark_bn254::Fq2Parameters>>::new(
			ark_ff::Fp256::<ark_bn254::FqParameters>::new(BigInteger256::new([158104825642067928,9704397703317506383, 13040313725969544803, 3131729054592160094])), 
			ark_ff::Fp256::<ark_bn254::FqParameters>::new(BigInteger256::new([13564312918393256783,11223260005076378950, 15319105673489478377, 1510379420569988696])) 
		),
		QuadExtField::<ark_ff::Fp2ParamsWrapper::<ark_bn254::Fq2Parameters>>::new(
			ark_ff::Fp256::<ark_bn254::FqParameters>::new(BigInteger256::new([4441078278289923762,13289589292477629695, 15089923586974730514, 1699049506303853300])), 
			ark_ff::Fp256::<ark_bn254::FqParameters>::new(BigInteger256::new([8658477142421329917,8256635396411944774, 9682090028953333111, 1302040760137096664])) 
 		)
 	)
}

pub fn get_delta_g2_neg_pc_62() -> (QuadExtField::<ark_ff::Fp2ParamsWrapper::<ark_bn254::Fq2Parameters>>, QuadExtField::<ark_ff::Fp2ParamsWrapper::<ark_bn254::Fq2Parameters>>, QuadExtField::<ark_ff::Fp2ParamsWrapper::<ark_bn254::Fq2Parameters>>) { 
 	(QuadExtField::<ark_ff::Fp2ParamsWrapper::<ark_bn254::Fq2Parameters>>::new(
			ark_ff::Fp256::<ark_bn254::FqParameters>::new(BigInteger256::new([5091780685747523363,16236088601465701729, 17789835999069709940, 2918823137868826900])), 
			ark_ff::Fp256::<ark_bn254::FqParameters>::new(BigInteger256::new([4414516980357368637,1653099688997909847, 16901463820446030226, 2633204909737785356])) 
		),
		QuadExtField::<ark_ff::Fp2ParamsWrapper::<ark_bn254::Fq2Parameters>>::new(
			ark_ff::Fp256::<ark_bn254::FqParameters>::new(BigInteger256::new([14909339491870147562,9399417399859339250, 3983201963678627586, 1352642148081724670])), 
			ark_ff::Fp256::<ark_bn254::FqParameters>::new(BigInteger256::new([7282763297962322097,11539996785825206037, 1809211207825033708, 2854837107658314046])) 
		),
		QuadExtField::<ark_ff::Fp2ParamsWrapper::<ark_bn254::Fq2Parameters>>::new(
			ark_ff::Fp256::<ark_bn254::FqParameters>::new(BigInteger256::new([13156067686357970376,1010231375069174299, 5410980318355786857, 1133669765347864510])), 
			ark_ff::Fp256::<ark_bn254::FqParameters>::new(BigInteger256::new([2254700652655234811,3468538183322217549, 955267630840438857, 3338950718421202314])) 
 		)
 	)
}

pub fn get_delta_g2_neg_pc_63() -> (QuadExtField::<ark_ff::Fp2ParamsWrapper::<ark_bn254::Fq2Parameters>>, QuadExtField::<ark_ff::Fp2ParamsWrapper::<ark_bn254::Fq2Parameters>>, QuadExtField::<ark_ff::Fp2ParamsWrapper::<ark_bn254::Fq2Parameters>>) { 
 	(QuadExtField::<ark_ff::Fp2ParamsWrapper::<ark_bn254::Fq2Parameters>>::new(
			ark_ff::Fp256::<ark_bn254::FqParameters>::new(BigInteger256::new([10841905780805447180,13082325188947640009, 724647252735038982, 1651594973689879532])), 
			ark_ff::Fp256::<ark_bn254::FqParameters>::new(BigInteger256::new([16729223895020847583,8667331144776307525, 10054554317672496003, 427747139381508981])) 
		),
		QuadExtField::<ark_ff::Fp2ParamsWrapper::<ark_bn254::Fq2Parameters>>::new(
			ark_ff::Fp256::<ark_bn254::FqParameters>::new(BigInteger256::new([9318128406576992776,9618623429665276232, 6299246179715141384, 104582079782177256])), 
			ark_ff::Fp256::<ark_bn254::FqParameters>::new(BigInteger256::new([15523519603595153413,9567536077591226979, 13392278928037146454, 2260690530700125257])) 
		),
		QuadExtField::<ark_ff::Fp2ParamsWrapper::<ark_bn254::Fq2Parameters>>::new(
			ark_ff::Fp256::<ark_bn254::FqParameters>::new(BigInteger256::new([7703844119287350159,12764568684624407406, 6384867947849286799, 106169929388452644])), 
			ark_ff::Fp256::<ark_bn254::FqParameters>::new(BigInteger256::new([11875537754882019328,12488305448834875881, 7768771617584129442, 2785898682866734720])) 
 		)
 	)
}

pub fn get_delta_g2_neg_pc_64() -> (QuadExtField::<ark_ff::Fp2ParamsWrapper::<ark_bn254::Fq2Parameters>>, QuadExtField::<ark_ff::Fp2ParamsWrapper::<ark_bn254::Fq2Parameters>>, QuadExtField::<ark_ff::Fp2ParamsWrapper::<ark_bn254::Fq2Parameters>>) { 
 	(QuadExtField::<ark_ff::Fp2ParamsWrapper::<ark_bn254::Fq2Parameters>>::new(
			ark_ff::Fp256::<ark_bn254::FqParameters>::new(BigInteger256::new([5470570590763435398,14190156918673524942, 2351892837553676313, 37904708641752248])), 
			ark_ff::Fp256::<ark_bn254::FqParameters>::new(BigInteger256::new([185615856902764790,17809218021263051992, 9308007246533262778, 2541354337476217288])) 
		),
		QuadExtField::<ark_ff::Fp2ParamsWrapper::<ark_bn254::Fq2Parameters>>::new(
			ark_ff::Fp256::<ark_bn254::FqParameters>::new(BigInteger256::new([5740877909535423636,15602514601936647515, 16097228495700563808, 2082441281620749760])), 
			ark_ff::Fp256::<ark_bn254::FqParameters>::new(BigInteger256::new([38382456864659265,15835628017305829042, 16015716503024829347, 1138944336540929100])) 
		),
		QuadExtField::<ark_ff::Fp2ParamsWrapper::<ark_bn254::Fq2Parameters>>::new(
			ark_ff::Fp256::<ark_bn254::FqParameters>::new(BigInteger256::new([8293420630437024052,906012460451927877, 7274872336199602261, 3200969234168092076])), 
			ark_ff::Fp256::<ark_bn254::FqParameters>::new(BigInteger256::new([8748212146551957112,5559855786371989681, 13352696152914145855, 3129624666344510392])) 
 		)
 	)
}

pub fn get_delta_g2_neg_pc_65() -> (QuadExtField::<ark_ff::Fp2ParamsWrapper::<ark_bn254::Fq2Parameters>>, QuadExtField::<ark_ff::Fp2ParamsWrapper::<ark_bn254::Fq2Parameters>>, QuadExtField::<ark_ff::Fp2ParamsWrapper::<ark_bn254::Fq2Parameters>>) { 
 	(QuadExtField::<ark_ff::Fp2ParamsWrapper::<ark_bn254::Fq2Parameters>>::new(
			ark_ff::Fp256::<ark_bn254::FqParameters>::new(BigInteger256::new([7642190826557514597,15128072202846291674, 312701483786938196, 1995466523814052632])), 
			ark_ff::Fp256::<ark_bn254::FqParameters>::new(BigInteger256::new([15515658890416108948,2430028407315426328, 13688701539976401455, 2915932649915959631])) 
		),
		QuadExtField::<ark_ff::Fp2ParamsWrapper::<ark_bn254::Fq2Parameters>>::new(
			ark_ff::Fp256::<ark_bn254::FqParameters>::new(BigInteger256::new([2117793091989471250,12699524521748805413, 10354762470186356287, 1367903296316092403])), 
			ark_ff::Fp256::<ark_bn254::FqParameters>::new(BigInteger256::new([15811677817140497024,9218661936316890410, 8176752950087952002, 2188149952228266552])) 
		),
		QuadExtField::<ark_ff::Fp2ParamsWrapper::<ark_bn254::Fq2Parameters>>::new(
			ark_ff::Fp256::<ark_bn254::FqParameters>::new(BigInteger256::new([6853825268030494089,17725582287569734656, 12809163531870209039, 1185493924767644680])), 
			ark_ff::Fp256::<ark_bn254::FqParameters>::new(BigInteger256::new([9724219627773628407,1246037428343881660, 7425969241946733832, 1798170100753080146])) 
 		)
 	)
}

pub fn get_delta_g2_neg_pc_66() -> (QuadExtField::<ark_ff::Fp2ParamsWrapper::<ark_bn254::Fq2Parameters>>, QuadExtField::<ark_ff::Fp2ParamsWrapper::<ark_bn254::Fq2Parameters>>, QuadExtField::<ark_ff::Fp2ParamsWrapper::<ark_bn254::Fq2Parameters>>) { 
 	(QuadExtField::<ark_ff::Fp2ParamsWrapper::<ark_bn254::Fq2Parameters>>::new(
			ark_ff::Fp256::<ark_bn254::FqParameters>::new(BigInteger256::new([15614991125482597258,11866565439582589957, 13681388995414241420, 2703465490739963505])), 
			ark_ff::Fp256::<ark_bn254::FqParameters>::new(BigInteger256::new([5472760648162679826,14531492225581390895, 8396518331255584757, 1964277925157063179])) 
		),
		QuadExtField::<ark_ff::Fp2ParamsWrapper::<ark_bn254::Fq2Parameters>>::new(
			ark_ff::Fp256::<ark_bn254::FqParameters>::new(BigInteger256::new([11500177725778870994,12862927444902103272, 4646868658059774345, 2652868903864281945])), 
			ark_ff::Fp256::<ark_bn254::FqParameters>::new(BigInteger256::new([11197570228924627335,530932008198019968, 12727493203354501745, 1423728392348551295])) 
		),
		QuadExtField::<ark_ff::Fp2ParamsWrapper::<ark_bn254::Fq2Parameters>>::new(
			ark_ff::Fp256::<ark_bn254::FqParameters>::new(BigInteger256::new([13724469258520893400,8910433804829848284, 4231502682917588927, 3456363073517798607])), 
			ark_ff::Fp256::<ark_bn254::FqParameters>::new(BigInteger256::new([8802080000273080138,13582415180319078882, 17653930134767541496, 1864350331342528119])) 
 		)
 	)
}

pub fn get_delta_g2_neg_pc_67() -> (QuadExtField::<ark_ff::Fp2ParamsWrapper::<ark_bn254::Fq2Parameters>>, QuadExtField::<ark_ff::Fp2ParamsWrapper::<ark_bn254::Fq2Parameters>>, QuadExtField::<ark_ff::Fp2ParamsWrapper::<ark_bn254::Fq2Parameters>>) { 
 	(QuadExtField::<ark_ff::Fp2ParamsWrapper::<ark_bn254::Fq2Parameters>>::new(
			ark_ff::Fp256::<ark_bn254::FqParameters>::new(BigInteger256::new([15680679940005148327,3888736873538967197, 9421039815790874713, 2121944406998788210])), 
			ark_ff::Fp256::<ark_bn254::FqParameters>::new(BigInteger256::new([11206477140986273649,12214236693624752254, 7498348593946086873, 2229460636863364730])) 
		),
		QuadExtField::<ark_ff::Fp2ParamsWrapper::<ark_bn254::Fq2Parameters>>::new(
			ark_ff::Fp256::<ark_bn254::FqParameters>::new(BigInteger256::new([9063428873011788410,767965555148757901, 1210876366570336240, 1457486060071973977])), 
			ark_ff::Fp256::<ark_bn254::FqParameters>::new(BigInteger256::new([5188596231586115827,15349162908340362506, 13285211891784399694, 2981428787749028849])) 
		),
		QuadExtField::<ark_ff::Fp2ParamsWrapper::<ark_bn254::Fq2Parameters>>::new(
			ark_ff::Fp256::<ark_bn254::FqParameters>::new(BigInteger256::new([14478284353504280121,9202911653362750232, 4441208075005186443, 848476252625796736])), 
			ark_ff::Fp256::<ark_bn254::FqParameters>::new(BigInteger256::new([4081272803710612083,7527873396178681521, 14021061423193813090, 35231693692507416])) 
 		)
 	)
}

pub fn get_delta_g2_neg_pc_68() -> (QuadExtField::<ark_ff::Fp2ParamsWrapper::<ark_bn254::Fq2Parameters>>, QuadExtField::<ark_ff::Fp2ParamsWrapper::<ark_bn254::Fq2Parameters>>, QuadExtField::<ark_ff::Fp2ParamsWrapper::<ark_bn254::Fq2Parameters>>) { 
 	(QuadExtField::<ark_ff::Fp2ParamsWrapper::<ark_bn254::Fq2Parameters>>::new(
			ark_ff::Fp256::<ark_bn254::FqParameters>::new(BigInteger256::new([9569941619389283107,8934045265434880661, 16245487018879008005, 3023548121048096772])), 
			ark_ff::Fp256::<ark_bn254::FqParameters>::new(BigInteger256::new([3738828867106955207,1120764103913669360, 1308477742891105908, 812154553524576491])) 
		),
		QuadExtField::<ark_ff::Fp2ParamsWrapper::<ark_bn254::Fq2Parameters>>::new(
			ark_ff::Fp256::<ark_bn254::FqParameters>::new(BigInteger256::new([14842583117989608660,9815231105019588588, 6572410462077196636, 2813869036738696925])), 
			ark_ff::Fp256::<ark_bn254::FqParameters>::new(BigInteger256::new([16515310894827043561,11078041681291696150, 1467019934200945330, 1999575666153004512])) 
		),
		QuadExtField::<ark_ff::Fp2ParamsWrapper::<ark_bn254::Fq2Parameters>>::new(
			ark_ff::Fp256::<ark_bn254::FqParameters>::new(BigInteger256::new([9698557253356796353,13190508605372086479, 9288140043068527826, 1254800391426062079])), 
			ark_ff::Fp256::<ark_bn254::FqParameters>::new(BigInteger256::new([4316683671687271458,17784355010220526832, 9021651512699539158, 279755140228338072])) 
 		)
 	)
}

pub fn get_delta_g2_neg_pc_69() -> (QuadExtField::<ark_ff::Fp2ParamsWrapper::<ark_bn254::Fq2Parameters>>, QuadExtField::<ark_ff::Fp2ParamsWrapper::<ark_bn254::Fq2Parameters>>, QuadExtField::<ark_ff::Fp2ParamsWrapper::<ark_bn254::Fq2Parameters>>) { 
 	(QuadExtField::<ark_ff::Fp2ParamsWrapper::<ark_bn254::Fq2Parameters>>::new(
			ark_ff::Fp256::<ark_bn254::FqParameters>::new(BigInteger256::new([13428955462840332812,7340336291477892878, 2702984821509468917, 123663588175887586])), 
			ark_ff::Fp256::<ark_bn254::FqParameters>::new(BigInteger256::new([8518681763761454385,4062377525643115438, 16532470403615280461, 1005063823654620452])) 
		),
		QuadExtField::<ark_ff::Fp2ParamsWrapper::<ark_bn254::Fq2Parameters>>::new(
			ark_ff::Fp256::<ark_bn254::FqParameters>::new(BigInteger256::new([12676364525844579209,1625136867696572446, 1057552460580684184, 3424414878238859904])), 
			ark_ff::Fp256::<ark_bn254::FqParameters>::new(BigInteger256::new([853961806553620827,4584467533039179846, 4325937633199594646, 2103028363333485202])) 
		),
		QuadExtField::<ark_ff::Fp2ParamsWrapper::<ark_bn254::Fq2Parameters>>::new(
			ark_ff::Fp256::<ark_bn254::FqParameters>::new(BigInteger256::new([6881933419389679650,972297595092834515, 10550741278460985601, 2350615909017432697])), 
			ark_ff::Fp256::<ark_bn254::FqParameters>::new(BigInteger256::new([18334948005738804968,5110631709861264002, 4637186569844438345, 299867697171891404])) 
 		)
 	)
}

pub fn get_delta_g2_neg_pc_70() -> (QuadExtField::<ark_ff::Fp2ParamsWrapper::<ark_bn254::Fq2Parameters>>, QuadExtField::<ark_ff::Fp2ParamsWrapper::<ark_bn254::Fq2Parameters>>, QuadExtField::<ark_ff::Fp2ParamsWrapper::<ark_bn254::Fq2Parameters>>) { 
 	(QuadExtField::<ark_ff::Fp2ParamsWrapper::<ark_bn254::Fq2Parameters>>::new(
			ark_ff::Fp256::<ark_bn254::FqParameters>::new(BigInteger256::new([2150487965559582880,10722455534017385496, 8966837525662829457, 1278956537171042346])), 
			ark_ff::Fp256::<ark_bn254::FqParameters>::new(BigInteger256::new([7423553117089653422,3106841967723596827, 1183567717161037259, 2013142632965960040])) 
		),
		QuadExtField::<ark_ff::Fp2ParamsWrapper::<ark_bn254::Fq2Parameters>>::new(
			ark_ff::Fp256::<ark_bn254::FqParameters>::new(BigInteger256::new([1967924351416796917,15041842255838744656, 330947254412132450, 570707966264592325])), 
			ark_ff::Fp256::<ark_bn254::FqParameters>::new(BigInteger256::new([9618400682245984849,11620055666428110543, 7007973568719416017, 2398461523678724828])) 
		),
		QuadExtField::<ark_ff::Fp2ParamsWrapper::<ark_bn254::Fq2Parameters>>::new(
			ark_ff::Fp256::<ark_bn254::FqParameters>::new(BigInteger256::new([13425750275578713040,14350150751289892668, 4557143972211096182, 2393031648549502541])), 
			ark_ff::Fp256::<ark_bn254::FqParameters>::new(BigInteger256::new([4070592702902425674,15138864133076685436, 6810837985080266369, 1337632381203763538])) 
 		)
 	)
}

pub fn get_delta_g2_neg_pc_71() -> (QuadExtField::<ark_ff::Fp2ParamsWrapper::<ark_bn254::Fq2Parameters>>, QuadExtField::<ark_ff::Fp2ParamsWrapper::<ark_bn254::Fq2Parameters>>, QuadExtField::<ark_ff::Fp2ParamsWrapper::<ark_bn254::Fq2Parameters>>) { 
 	(QuadExtField::<ark_ff::Fp2ParamsWrapper::<ark_bn254::Fq2Parameters>>::new(
			ark_ff::Fp256::<ark_bn254::FqParameters>::new(BigInteger256::new([11129288092075796769,6707931745535362705, 12801966098762845824, 2775606312078011439])), 
			ark_ff::Fp256::<ark_bn254::FqParameters>::new(BigInteger256::new([2586953307543252666,783032907751182325, 12481497654239544975, 1951603378486173770])) 
		),
		QuadExtField::<ark_ff::Fp2ParamsWrapper::<ark_bn254::Fq2Parameters>>::new(
			ark_ff::Fp256::<ark_bn254::FqParameters>::new(BigInteger256::new([10958120437763340160,4593409507438644265, 2590895375468322772, 192955333757931064])), 
			ark_ff::Fp256::<ark_bn254::FqParameters>::new(BigInteger256::new([4614508163741796002,18222146532083983976, 14695817233609267596, 979776186714921640])) 
		),
		QuadExtField::<ark_ff::Fp2ParamsWrapper::<ark_bn254::Fq2Parameters>>::new(
			ark_ff::Fp256::<ark_bn254::FqParameters>::new(BigInteger256::new([7922740146943727359,2693251839353557938, 16519543304651722770, 2417394690391226576])), 
			ark_ff::Fp256::<ark_bn254::FqParameters>::new(BigInteger256::new([13493879814205324997,10244723029475476809, 14404949462842389317, 1690470349653280052])) 
 		)
 	)
}

pub fn get_delta_g2_neg_pc_72() -> (QuadExtField::<ark_ff::Fp2ParamsWrapper::<ark_bn254::Fq2Parameters>>, QuadExtField::<ark_ff::Fp2ParamsWrapper::<ark_bn254::Fq2Parameters>>, QuadExtField::<ark_ff::Fp2ParamsWrapper::<ark_bn254::Fq2Parameters>>) { 
 	(QuadExtField::<ark_ff::Fp2ParamsWrapper::<ark_bn254::Fq2Parameters>>::new(
			ark_ff::Fp256::<ark_bn254::FqParameters>::new(BigInteger256::new([8257450303070028388,3727668651624517930, 13273852051368320727, 3262774587864148962])), 
			ark_ff::Fp256::<ark_bn254::FqParameters>::new(BigInteger256::new([2322975268750382201,16343495863627332645, 3750473546052456135, 503434737325941611])) 
		),
		QuadExtField::<ark_ff::Fp2ParamsWrapper::<ark_bn254::Fq2Parameters>>::new(
			ark_ff::Fp256::<ark_bn254::FqParameters>::new(BigInteger256::new([2317096163856653983,9665426620122704681, 18310109264019730660, 2694106539543886833])), 
			ark_ff::Fp256::<ark_bn254::FqParameters>::new(BigInteger256::new([6214976002924404428,4621559698305790002, 1164825654188524033, 2855049932777603806])) 
		),
		QuadExtField::<ark_ff::Fp2ParamsWrapper::<ark_bn254::Fq2Parameters>>::new(
			ark_ff::Fp256::<ark_bn254::FqParameters>::new(BigInteger256::new([7585400266594869426,13726154031475097414, 15175231601467217043, 778794154419632520])), 
			ark_ff::Fp256::<ark_bn254::FqParameters>::new(BigInteger256::new([9703954554156027226,15293026638306935869, 510055217799364587, 1089575674316848628])) 
 		)
 	)
}

pub fn get_delta_g2_neg_pc_73() -> (QuadExtField::<ark_ff::Fp2ParamsWrapper::<ark_bn254::Fq2Parameters>>, QuadExtField::<ark_ff::Fp2ParamsWrapper::<ark_bn254::Fq2Parameters>>, QuadExtField::<ark_ff::Fp2ParamsWrapper::<ark_bn254::Fq2Parameters>>) { 
 	(QuadExtField::<ark_ff::Fp2ParamsWrapper::<ark_bn254::Fq2Parameters>>::new(
			ark_ff::Fp256::<ark_bn254::FqParameters>::new(BigInteger256::new([14434298153452920065,997828537290524470, 16558817216250831828, 3433601083195901973])), 
			ark_ff::Fp256::<ark_bn254::FqParameters>::new(BigInteger256::new([2450296677331436216,3439245026730142161, 15895834633564376279, 2654660821756286822])) 
		),
		QuadExtField::<ark_ff::Fp2ParamsWrapper::<ark_bn254::Fq2Parameters>>::new(
			ark_ff::Fp256::<ark_bn254::FqParameters>::new(BigInteger256::new([11295374342263728895,16277972433993242170, 956286266101177748, 2436221099695800598])), 
			ark_ff::Fp256::<ark_bn254::FqParameters>::new(BigInteger256::new([671037080753221309,1460396606019727602, 5761655931651148471, 3017009687017902610])) 
		),
		QuadExtField::<ark_ff::Fp2ParamsWrapper::<ark_bn254::Fq2Parameters>>::new(
			ark_ff::Fp256::<ark_bn254::FqParameters>::new(BigInteger256::new([17519091205481055976,3845290315776411633, 14002167512060573958, 3192619322838605521])), 
			ark_ff::Fp256::<ark_bn254::FqParameters>::new(BigInteger256::new([15118841883526529286,8775069536067184062, 15527317128659548390, 2144969790273149785])) 
 		)
 	)
}

pub fn get_delta_g2_neg_pc_74() -> (QuadExtField::<ark_ff::Fp2ParamsWrapper::<ark_bn254::Fq2Parameters>>, QuadExtField::<ark_ff::Fp2ParamsWrapper::<ark_bn254::Fq2Parameters>>, QuadExtField::<ark_ff::Fp2ParamsWrapper::<ark_bn254::Fq2Parameters>>) { 
 	(QuadExtField::<ark_ff::Fp2ParamsWrapper::<ark_bn254::Fq2Parameters>>::new(
			ark_ff::Fp256::<ark_bn254::FqParameters>::new(BigInteger256::new([14373629761456288132,323452708626626318, 8153717303022652966, 573864481491426857])), 
			ark_ff::Fp256::<ark_bn254::FqParameters>::new(BigInteger256::new([1614831269921957012,435533330042422184, 9654542741046473991, 164831531612544795])) 
		),
		QuadExtField::<ark_ff::Fp2ParamsWrapper::<ark_bn254::Fq2Parameters>>::new(
			ark_ff::Fp256::<ark_bn254::FqParameters>::new(BigInteger256::new([10728939146760911839,5811823233576966517, 16037219852257425507, 609462013525295831])), 
			ark_ff::Fp256::<ark_bn254::FqParameters>::new(BigInteger256::new([4996025113901905134,10530172561872303880, 714996221826549891, 1664896733699941611])) 
		),
		QuadExtField::<ark_ff::Fp2ParamsWrapper::<ark_bn254::Fq2Parameters>>::new(
			ark_ff::Fp256::<ark_bn254::FqParameters>::new(BigInteger256::new([10834624815267669361,13462051903978740737, 14127059015651983858, 597965099620744137])), 
			ark_ff::Fp256::<ark_bn254::FqParameters>::new(BigInteger256::new([2397766443754223178,10121339040943231833, 5393032778502241234, 2337659306603448676])) 
 		)
 	)
}

pub fn get_delta_g2_neg_pc_75() -> (QuadExtField::<ark_ff::Fp2ParamsWrapper::<ark_bn254::Fq2Parameters>>, QuadExtField::<ark_ff::Fp2ParamsWrapper::<ark_bn254::Fq2Parameters>>, QuadExtField::<ark_ff::Fp2ParamsWrapper::<ark_bn254::Fq2Parameters>>) { 
 	(QuadExtField::<ark_ff::Fp2ParamsWrapper::<ark_bn254::Fq2Parameters>>::new(
			ark_ff::Fp256::<ark_bn254::FqParameters>::new(BigInteger256::new([16932790721536315631,12821696455340143280, 10397123840522725525, 2009278735685649017])), 
			ark_ff::Fp256::<ark_bn254::FqParameters>::new(BigInteger256::new([12606626516056788592,4108673578623555420, 11093007702843559867, 3134105007923978336])) 
		),
		QuadExtField::<ark_ff::Fp2ParamsWrapper::<ark_bn254::Fq2Parameters>>::new(
			ark_ff::Fp256::<ark_bn254::FqParameters>::new(BigInteger256::new([18427380859506365708,1104965085391543571, 7756860462291306565, 3067747101510412806])), 
			ark_ff::Fp256::<ark_bn254::FqParameters>::new(BigInteger256::new([17004621133301561296,7183232559955282458, 13885511302883058245, 3398659501298928998])) 
		),
		QuadExtField::<ark_ff::Fp2ParamsWrapper::<ark_bn254::Fq2Parameters>>::new(
			ark_ff::Fp256::<ark_bn254::FqParameters>::new(BigInteger256::new([15513677691265764920,2439608674237256243, 15265370838210571121, 3418149319019206303])), 
			ark_ff::Fp256::<ark_bn254::FqParameters>::new(BigInteger256::new([9992008420111873106,9446386351478067078, 4541372426681985538, 1147504317192868142])) 
 		)
 	)
}

pub fn get_delta_g2_neg_pc_76() -> (QuadExtField::<ark_ff::Fp2ParamsWrapper::<ark_bn254::Fq2Parameters>>, QuadExtField::<ark_ff::Fp2ParamsWrapper::<ark_bn254::Fq2Parameters>>, QuadExtField::<ark_ff::Fp2ParamsWrapper::<ark_bn254::Fq2Parameters>>) { 
 	(QuadExtField::<ark_ff::Fp2ParamsWrapper::<ark_bn254::Fq2Parameters>>::new(
			ark_ff::Fp256::<ark_bn254::FqParameters>::new(BigInteger256::new([4609322106461656675,6690723515279071690, 17991135860578930208, 760659984354128180])), 
			ark_ff::Fp256::<ark_bn254::FqParameters>::new(BigInteger256::new([2582317090686613417,3243354389645242660, 7344522682146053129, 2796061218828215474])) 
		),
		QuadExtField::<ark_ff::Fp2ParamsWrapper::<ark_bn254::Fq2Parameters>>::new(
			ark_ff::Fp256::<ark_bn254::FqParameters>::new(BigInteger256::new([12177944329022269186,14409252625842510674, 11422136103142102848, 1402643843253742785])), 
			ark_ff::Fp256::<ark_bn254::FqParameters>::new(BigInteger256::new([9478381081907099586,7786777132956883650, 12817473336736735787, 807672185470974579])) 
		),
		QuadExtField::<ark_ff::Fp2ParamsWrapper::<ark_bn254::Fq2Parameters>>::new(
			ark_ff::Fp256::<ark_bn254::FqParameters>::new(BigInteger256::new([14161210742059923110,10156731599537670620, 16464295275593178964, 3292187877790225615])), 
			ark_ff::Fp256::<ark_bn254::FqParameters>::new(BigInteger256::new([6738679261782316956,9562202797492280921, 8232974744016148926, 1672303152695803670])) 
 		)
 	)
}

pub fn get_delta_g2_neg_pc_77() -> (QuadExtField::<ark_ff::Fp2ParamsWrapper::<ark_bn254::Fq2Parameters>>, QuadExtField::<ark_ff::Fp2ParamsWrapper::<ark_bn254::Fq2Parameters>>, QuadExtField::<ark_ff::Fp2ParamsWrapper::<ark_bn254::Fq2Parameters>>) { 
 	(QuadExtField::<ark_ff::Fp2ParamsWrapper::<ark_bn254::Fq2Parameters>>::new(
			ark_ff::Fp256::<ark_bn254::FqParameters>::new(BigInteger256::new([12920828727575523881,11945819995754419680, 581415192652834293, 192313874917375119])), 
			ark_ff::Fp256::<ark_bn254::FqParameters>::new(BigInteger256::new([1760446763824823134,7063391922954715253, 10981034373335738426, 913931553482547326])) 
		),
		QuadExtField::<ark_ff::Fp2ParamsWrapper::<ark_bn254::Fq2Parameters>>::new(
			ark_ff::Fp256::<ark_bn254::FqParameters>::new(BigInteger256::new([248262477234626206,3098292592454664098, 12313648169866194919, 2793678162227299852])), 
			ark_ff::Fp256::<ark_bn254::FqParameters>::new(BigInteger256::new([16889481244227913914,12380822541726108010, 18224756368615573411, 2100497869109679261])) 
		),
		QuadExtField::<ark_ff::Fp2ParamsWrapper::<ark_bn254::Fq2Parameters>>::new(
			ark_ff::Fp256::<ark_bn254::FqParameters>::new(BigInteger256::new([18058799938910008983,9110998172925236534, 5502582537286889897, 3452175846832989290])), 
			ark_ff::Fp256::<ark_bn254::FqParameters>::new(BigInteger256::new([3107719153046209671,11638145607267170160, 7652311597635313121, 535013139729186756])) 
 		)
 	)
}

pub fn get_delta_g2_neg_pc_78() -> (QuadExtField::<ark_ff::Fp2ParamsWrapper::<ark_bn254::Fq2Parameters>>, QuadExtField::<ark_ff::Fp2ParamsWrapper::<ark_bn254::Fq2Parameters>>, QuadExtField::<ark_ff::Fp2ParamsWrapper::<ark_bn254::Fq2Parameters>>) { 
 	(QuadExtField::<ark_ff::Fp2ParamsWrapper::<ark_bn254::Fq2Parameters>>::new(
			ark_ff::Fp256::<ark_bn254::FqParameters>::new(BigInteger256::new([14964174581370162623,1186110770372899307, 14943591763560117433, 2440923303517286593])), 
			ark_ff::Fp256::<ark_bn254::FqParameters>::new(BigInteger256::new([8207602730559312201,1643272504888599377, 18036758254399052567, 738816963467604392])) 
		),
		QuadExtField::<ark_ff::Fp2ParamsWrapper::<ark_bn254::Fq2Parameters>>::new(
			ark_ff::Fp256::<ark_bn254::FqParameters>::new(BigInteger256::new([2928781363790210312,16815540836582095785, 14829581169494618092, 2627491092414313027])), 
			ark_ff::Fp256::<ark_bn254::FqParameters>::new(BigInteger256::new([17617620573849693180,13088326910527481129, 1970903932189984874, 3379557505337996898])) 
		),
		QuadExtField::<ark_ff::Fp2ParamsWrapper::<ark_bn254::Fq2Parameters>>::new(
			ark_ff::Fp256::<ark_bn254::FqParameters>::new(BigInteger256::new([6147263725515907325,5426477224178154509, 10735180113415782571, 854133296593012694])), 
			ark_ff::Fp256::<ark_bn254::FqParameters>::new(BigInteger256::new([17726596367171218601,3415199580499609995, 13549027663913217170, 766538569508982707])) 
 		)
 	)
}

pub fn get_delta_g2_neg_pc_79() -> (QuadExtField::<ark_ff::Fp2ParamsWrapper::<ark_bn254::Fq2Parameters>>, QuadExtField::<ark_ff::Fp2ParamsWrapper::<ark_bn254::Fq2Parameters>>, QuadExtField::<ark_ff::Fp2ParamsWrapper::<ark_bn254::Fq2Parameters>>) { 
 	(QuadExtField::<ark_ff::Fp2ParamsWrapper::<ark_bn254::Fq2Parameters>>::new(
			ark_ff::Fp256::<ark_bn254::FqParameters>::new(BigInteger256::new([8978633528487487347,10973997531673481526, 13257406452446135136, 1216255165050299909])), 
			ark_ff::Fp256::<ark_bn254::FqParameters>::new(BigInteger256::new([6860946242941082142,4843234879890294162, 12293518670472478979, 2685914646992275685])) 
		),
		QuadExtField::<ark_ff::Fp2ParamsWrapper::<ark_bn254::Fq2Parameters>>::new(
			ark_ff::Fp256::<ark_bn254::FqParameters>::new(BigInteger256::new([2999756350378595052,861558176136978148, 14829325331697993509, 3281191694396198391])), 
			ark_ff::Fp256::<ark_bn254::FqParameters>::new(BigInteger256::new([9778859881372165644,10406118792536704698, 5435431381451326563, 1200242157202727794])) 
		),
		QuadExtField::<ark_ff::Fp2ParamsWrapper::<ark_bn254::Fq2Parameters>>::new(
			ark_ff::Fp256::<ark_bn254::FqParameters>::new(BigInteger256::new([2285367325423137074,8022652315155827400, 9941103897712344053, 1867180309699246231])), 
			ark_ff::Fp256::<ark_bn254::FqParameters>::new(BigInteger256::new([5833058159203343876,6383799817670126481, 1201634304883733563, 2973757196139008077])) 
 		)
 	)
}

pub fn get_delta_g2_neg_pc_80() -> (QuadExtField::<ark_ff::Fp2ParamsWrapper::<ark_bn254::Fq2Parameters>>, QuadExtField::<ark_ff::Fp2ParamsWrapper::<ark_bn254::Fq2Parameters>>, QuadExtField::<ark_ff::Fp2ParamsWrapper::<ark_bn254::Fq2Parameters>>) { 
 	(QuadExtField::<ark_ff::Fp2ParamsWrapper::<ark_bn254::Fq2Parameters>>::new(
			ark_ff::Fp256::<ark_bn254::FqParameters>::new(BigInteger256::new([14892034424153290220,16946188910341640030, 7930034235992470143, 1105395310913739673])), 
			ark_ff::Fp256::<ark_bn254::FqParameters>::new(BigInteger256::new([16532399116922426892,13551848446342748283, 12050747271537368861, 734345071935804936])) 
		),
		QuadExtField::<ark_ff::Fp2ParamsWrapper::<ark_bn254::Fq2Parameters>>::new(
			ark_ff::Fp256::<ark_bn254::FqParameters>::new(BigInteger256::new([5594671061052871190,9482334456116404333, 16264288085950247186, 1326237640298935260])), 
			ark_ff::Fp256::<ark_bn254::FqParameters>::new(BigInteger256::new([15163043302307960551,13373175346845931663, 17462600383434163821, 956357512513507961])) 
		),
		QuadExtField::<ark_ff::Fp2ParamsWrapper::<ark_bn254::Fq2Parameters>>::new(
			ark_ff::Fp256::<ark_bn254::FqParameters>::new(BigInteger256::new([11223759258990895447,2902569245574421069, 965603888987147585, 3052226370815532881])), 
			ark_ff::Fp256::<ark_bn254::FqParameters>::new(BigInteger256::new([156034092096523245,8826939944802961527, 16733757769910763643, 2192148940465742113])) 
 		)
 	)
}

pub fn get_delta_g2_neg_pc_81() -> (QuadExtField::<ark_ff::Fp2ParamsWrapper::<ark_bn254::Fq2Parameters>>, QuadExtField::<ark_ff::Fp2ParamsWrapper::<ark_bn254::Fq2Parameters>>, QuadExtField::<ark_ff::Fp2ParamsWrapper::<ark_bn254::Fq2Parameters>>) { 
 	(QuadExtField::<ark_ff::Fp2ParamsWrapper::<ark_bn254::Fq2Parameters>>::new(
			ark_ff::Fp256::<ark_bn254::FqParameters>::new(BigInteger256::new([13110524776202145911,11474437910866371335, 167683614173800606, 727355160850194558])), 
			ark_ff::Fp256::<ark_bn254::FqParameters>::new(BigInteger256::new([10042592712718886854,2549114426979564647, 4605404778183084249, 1790998557157640813])) 
		),
		QuadExtField::<ark_ff::Fp2ParamsWrapper::<ark_bn254::Fq2Parameters>>::new(
			ark_ff::Fp256::<ark_bn254::FqParameters>::new(BigInteger256::new([3452239199092111973,10597303762322159764, 9839557647523208123, 1506329741448837953])), 
			ark_ff::Fp256::<ark_bn254::FqParameters>::new(BigInteger256::new([3295444752716816348,9135782556210693012, 11209291906352269655, 1679786569206969209])) 
		),
		QuadExtField::<ark_ff::Fp2ParamsWrapper::<ark_bn254::Fq2Parameters>>::new(
			ark_ff::Fp256::<ark_bn254::FqParameters>::new(BigInteger256::new([16047143398489435160,5962297690997233983, 10004532628320283308, 1288772353691003605])), 
			ark_ff::Fp256::<ark_bn254::FqParameters>::new(BigInteger256::new([901053318699255015,1402137840717995949, 5394897779865142960, 1986892790999546529])) 
 		)
 	)
}

pub fn get_delta_g2_neg_pc_82() -> (QuadExtField::<ark_ff::Fp2ParamsWrapper::<ark_bn254::Fq2Parameters>>, QuadExtField::<ark_ff::Fp2ParamsWrapper::<ark_bn254::Fq2Parameters>>, QuadExtField::<ark_ff::Fp2ParamsWrapper::<ark_bn254::Fq2Parameters>>) { 
 	(QuadExtField::<ark_ff::Fp2ParamsWrapper::<ark_bn254::Fq2Parameters>>::new(
			ark_ff::Fp256::<ark_bn254::FqParameters>::new(BigInteger256::new([12379842962101902197,10915561733519804161, 12405536867020901813, 1584107471505881512])), 
			ark_ff::Fp256::<ark_bn254::FqParameters>::new(BigInteger256::new([12885392261409438570,1275936610151403899, 12834206405057055014, 2129444426451995068])) 
		),
		QuadExtField::<ark_ff::Fp2ParamsWrapper::<ark_bn254::Fq2Parameters>>::new(
			ark_ff::Fp256::<ark_bn254::FqParameters>::new(BigInteger256::new([18387730431806947363,2102123249559779529, 7459978096520641365, 1252810400169045847])), 
			ark_ff::Fp256::<ark_bn254::FqParameters>::new(BigInteger256::new([8543157443257431477,15807671166910346917, 10927179736880211592, 2928769696912685934])) 
		),
		QuadExtField::<ark_ff::Fp2ParamsWrapper::<ark_bn254::Fq2Parameters>>::new(
			ark_ff::Fp256::<ark_bn254::FqParameters>::new(BigInteger256::new([252996083041934406,16107744310580866499, 9507020634377223751, 2746356444018488555])), 
			ark_ff::Fp256::<ark_bn254::FqParameters>::new(BigInteger256::new([16841423498448721050,13125759474063846274, 4548429610884781273, 2355444179036725693])) 
 		)
 	)
}

pub fn get_delta_g2_neg_pc_83() -> (QuadExtField::<ark_ff::Fp2ParamsWrapper::<ark_bn254::Fq2Parameters>>, QuadExtField::<ark_ff::Fp2ParamsWrapper::<ark_bn254::Fq2Parameters>>, QuadExtField::<ark_ff::Fp2ParamsWrapper::<ark_bn254::Fq2Parameters>>) { 
 	(QuadExtField::<ark_ff::Fp2ParamsWrapper::<ark_bn254::Fq2Parameters>>::new(
			ark_ff::Fp256::<ark_bn254::FqParameters>::new(BigInteger256::new([5312631234298100030,11716941937432886463, 2491825612013374843, 824697631863411142])), 
			ark_ff::Fp256::<ark_bn254::FqParameters>::new(BigInteger256::new([4246619989074962573,5835365590113873875, 18082252337964039807, 2479287896999071962])) 
		),
		QuadExtField::<ark_ff::Fp2ParamsWrapper::<ark_bn254::Fq2Parameters>>::new(
			ark_ff::Fp256::<ark_bn254::FqParameters>::new(BigInteger256::new([11915097981082640188,13806129048446359280, 12396134515278894255, 1571393665683447951])), 
			ark_ff::Fp256::<ark_bn254::FqParameters>::new(BigInteger256::new([17084731106590922697,10653334343195577125, 293215667882182658, 2877815251701441629])) 
		),
		QuadExtField::<ark_ff::Fp2ParamsWrapper::<ark_bn254::Fq2Parameters>>::new(
			ark_ff::Fp256::<ark_bn254::FqParameters>::new(BigInteger256::new([4656006837148601494,1945836953550288944, 2512542808871021900, 1406227923112978799])), 
			ark_ff::Fp256::<ark_bn254::FqParameters>::new(BigInteger256::new([10824513256009271707,12888985876601652453, 4667882996647128220, 948650613078293082])) 
 		)
 	)
}

pub fn get_delta_g2_neg_pc_84() -> (QuadExtField::<ark_ff::Fp2ParamsWrapper::<ark_bn254::Fq2Parameters>>, QuadExtField::<ark_ff::Fp2ParamsWrapper::<ark_bn254::Fq2Parameters>>, QuadExtField::<ark_ff::Fp2ParamsWrapper::<ark_bn254::Fq2Parameters>>) { 
 	(QuadExtField::<ark_ff::Fp2ParamsWrapper::<ark_bn254::Fq2Parameters>>::new(
			ark_ff::Fp256::<ark_bn254::FqParameters>::new(BigInteger256::new([2567636064893810212,2120133376049152991, 9066572176518332913, 2060594707245808101])), 
			ark_ff::Fp256::<ark_bn254::FqParameters>::new(BigInteger256::new([12262004912741666586,8679330636705983337, 16114857433321806765, 399142303437148341])) 
		),
		QuadExtField::<ark_ff::Fp2ParamsWrapper::<ark_bn254::Fq2Parameters>>::new(
			ark_ff::Fp256::<ark_bn254::FqParameters>::new(BigInteger256::new([8199206254834995870,16014196654615515547, 6777414222060902748, 287093113465125493])), 
			ark_ff::Fp256::<ark_bn254::FqParameters>::new(BigInteger256::new([16282091064387786803,13015009873951037773, 14418304853902105376, 1131283577347523421])) 
		),
		QuadExtField::<ark_ff::Fp2ParamsWrapper::<ark_bn254::Fq2Parameters>>::new(
			ark_ff::Fp256::<ark_bn254::FqParameters>::new(BigInteger256::new([8943824775840845299,1790694678257699433, 12923856712122216913, 1474039196694405791])), 
			ark_ff::Fp256::<ark_bn254::FqParameters>::new(BigInteger256::new([8667176011090119291,6649658854358069771, 7847152941206437380, 2807317224096673196])) 
 		)
 	)
}

pub fn get_delta_g2_neg_pc_85() -> (QuadExtField::<ark_ff::Fp2ParamsWrapper::<ark_bn254::Fq2Parameters>>, QuadExtField::<ark_ff::Fp2ParamsWrapper::<ark_bn254::Fq2Parameters>>, QuadExtField::<ark_ff::Fp2ParamsWrapper::<ark_bn254::Fq2Parameters>>) { 
 	(QuadExtField::<ark_ff::Fp2ParamsWrapper::<ark_bn254::Fq2Parameters>>::new(
			ark_ff::Fp256::<ark_bn254::FqParameters>::new(BigInteger256::new([14750275757509745864,10755695589598693564, 16494003185620296494, 2471720295821557522])), 
			ark_ff::Fp256::<ark_bn254::FqParameters>::new(BigInteger256::new([13667666276727080171,4416993090555506872, 9387683063425188330, 1776958724976388910])) 
		),
		QuadExtField::<ark_ff::Fp2ParamsWrapper::<ark_bn254::Fq2Parameters>>::new(
			ark_ff::Fp256::<ark_bn254::FqParameters>::new(BigInteger256::new([11174054300258045463,12454273042204412077, 10688235244532991623, 2935978738029767979])), 
			ark_ff::Fp256::<ark_bn254::FqParameters>::new(BigInteger256::new([15666663511233925534,277484480223750722, 2388502715421011153, 450244619558118938])) 
		),
		QuadExtField::<ark_ff::Fp2ParamsWrapper::<ark_bn254::Fq2Parameters>>::new(
			ark_ff::Fp256::<ark_bn254::FqParameters>::new(BigInteger256::new([4684279901362212516,11205760746035417220, 6938863243161950862, 2069147255032706510])), 
			ark_ff::Fp256::<ark_bn254::FqParameters>::new(BigInteger256::new([17430656801384773759,4398661035117611121, 13798455144861788596, 1569022895003767198])) 
 		)
 	)
}

pub fn get_delta_g2_neg_pc_86() -> (QuadExtField::<ark_ff::Fp2ParamsWrapper::<ark_bn254::Fq2Parameters>>, QuadExtField::<ark_ff::Fp2ParamsWrapper::<ark_bn254::Fq2Parameters>>, QuadExtField::<ark_ff::Fp2ParamsWrapper::<ark_bn254::Fq2Parameters>>) { 
 	(QuadExtField::<ark_ff::Fp2ParamsWrapper::<ark_bn254::Fq2Parameters>>::new(
			ark_ff::Fp256::<ark_bn254::FqParameters>::new(BigInteger256::new([1323576690374388979,18151566564489169892, 3535049841255529028, 706216706285682408])), 
			ark_ff::Fp256::<ark_bn254::FqParameters>::new(BigInteger256::new([2118035749218095373,1905470041006084568, 13513526848872444103, 1883110930250308756])) 
		),
		QuadExtField::<ark_ff::Fp2ParamsWrapper::<ark_bn254::Fq2Parameters>>::new(
			ark_ff::Fp256::<ark_bn254::FqParameters>::new(BigInteger256::new([2300443829524376440,2517245980843103887, 2854034725925395015, 1977472205004814992])), 
			ark_ff::Fp256::<ark_bn254::FqParameters>::new(BigInteger256::new([14091012087586211135,9518274012656288985, 16774749715608220537, 1946083299754333884])) 
		),
		QuadExtField::<ark_ff::Fp2ParamsWrapper::<ark_bn254::Fq2Parameters>>::new(
			ark_ff::Fp256::<ark_bn254::FqParameters>::new(BigInteger256::new([14148478403870052634,15206113949386969497, 12543053763242500680, 3272956378099086281])), 
			ark_ff::Fp256::<ark_bn254::FqParameters>::new(BigInteger256::new([3428140735820425433,5712942626179535869, 6155562605319067451, 1629357995773168674])) 
 		)
 	)
}

pub fn get_delta_g2_neg_pc_87() -> (QuadExtField::<ark_ff::Fp2ParamsWrapper::<ark_bn254::Fq2Parameters>>, QuadExtField::<ark_ff::Fp2ParamsWrapper::<ark_bn254::Fq2Parameters>>, QuadExtField::<ark_ff::Fp2ParamsWrapper::<ark_bn254::Fq2Parameters>>) { 
 	(QuadExtField::<ark_ff::Fp2ParamsWrapper::<ark_bn254::Fq2Parameters>>::new(
			ark_ff::Fp256::<ark_bn254::FqParameters>::new(BigInteger256::new([8208884621949897177,7555957922753680555, 13023827390874810976, 2889390190721899306])), 
			ark_ff::Fp256::<ark_bn254::FqParameters>::new(BigInteger256::new([299000396904163862,3867351235667446992, 9266103063757127170, 2157474462661326293])) 
		),
		QuadExtField::<ark_ff::Fp2ParamsWrapper::<ark_bn254::Fq2Parameters>>::new(
			ark_ff::Fp256::<ark_bn254::FqParameters>::new(BigInteger256::new([17786179704898184671,5933684878971116373, 1390689255945799305, 2170292431801824886])), 
			ark_ff::Fp256::<ark_bn254::FqParameters>::new(BigInteger256::new([12323787773425319616,14582698123153247030, 6086767041618124506, 1209146097099209326])) 
		),
		QuadExtField::<ark_ff::Fp2ParamsWrapper::<ark_bn254::Fq2Parameters>>::new(
			ark_ff::Fp256::<ark_bn254::FqParameters>::new(BigInteger256::new([10314692057133230520,2554023937628881502, 5478197838948946497, 1287793488992878909])), 
			ark_ff::Fp256::<ark_bn254::FqParameters>::new(BigInteger256::new([2557784279034143705,8547390946507051859, 6477594919919947832, 1894616331827675355])) 
 		)
 	)
}

pub fn get_delta_g2_neg_pc_88() -> (QuadExtField::<ark_ff::Fp2ParamsWrapper::<ark_bn254::Fq2Parameters>>, QuadExtField::<ark_ff::Fp2ParamsWrapper::<ark_bn254::Fq2Parameters>>, QuadExtField::<ark_ff::Fp2ParamsWrapper::<ark_bn254::Fq2Parameters>>) { 
 	(QuadExtField::<ark_ff::Fp2ParamsWrapper::<ark_bn254::Fq2Parameters>>::new(
			ark_ff::Fp256::<ark_bn254::FqParameters>::new(BigInteger256::new([13425876809351905290,11738959873724558653, 15410256298521573811, 3260398944556145089])), 
			ark_ff::Fp256::<ark_bn254::FqParameters>::new(BigInteger256::new([16374025260220492308,17670626361161275475, 4692167100556444983, 2894155745041782997])) 
		),
		QuadExtField::<ark_ff::Fp2ParamsWrapper::<ark_bn254::Fq2Parameters>>::new(
			ark_ff::Fp256::<ark_bn254::FqParameters>::new(BigInteger256::new([15995431544145117069,11225509666610668943, 1708605869402677335, 1518406290253792515])), 
			ark_ff::Fp256::<ark_bn254::FqParameters>::new(BigInteger256::new([6989645637553289909,9481545702582754972, 8895714862808608705, 2144021714653961521])) 
		),
		QuadExtField::<ark_ff::Fp2ParamsWrapper::<ark_bn254::Fq2Parameters>>::new(
			ark_ff::Fp256::<ark_bn254::FqParameters>::new(BigInteger256::new([14767509891797308640,6799065049312583282, 5538902604438257248, 334697376498695344])), 
			ark_ff::Fp256::<ark_bn254::FqParameters>::new(BigInteger256::new([6735600457912134420,434929994718433406, 14140552276741118194, 1518979087721777281])) 
 		)
 	)
}

pub fn get_delta_g2_neg_pc_89() -> (QuadExtField::<ark_ff::Fp2ParamsWrapper::<ark_bn254::Fq2Parameters>>, QuadExtField::<ark_ff::Fp2ParamsWrapper::<ark_bn254::Fq2Parameters>>, QuadExtField::<ark_ff::Fp2ParamsWrapper::<ark_bn254::Fq2Parameters>>) { 
 	(QuadExtField::<ark_ff::Fp2ParamsWrapper::<ark_bn254::Fq2Parameters>>::new(
			ark_ff::Fp256::<ark_bn254::FqParameters>::new(BigInteger256::new([1612457146301554209,11147714134374141064, 9031296231498803236, 360726622843347276])), 
			ark_ff::Fp256::<ark_bn254::FqParameters>::new(BigInteger256::new([11884421434877509676,873682257198103666, 11753911566336892434, 2492963132775097851])) 
		),
		QuadExtField::<ark_ff::Fp2ParamsWrapper::<ark_bn254::Fq2Parameters>>::new(
			ark_ff::Fp256::<ark_bn254::FqParameters>::new(BigInteger256::new([492612028337379958,2583551071993685596, 13761471185056567422, 1051359626425232069])), 
			ark_ff::Fp256::<ark_bn254::FqParameters>::new(BigInteger256::new([11631465522362623510,6694027535960402896, 2300432935430145851, 2775133187767911653])) 
		),
		QuadExtField::<ark_ff::Fp2ParamsWrapper::<ark_bn254::Fq2Parameters>>::new(
			ark_ff::Fp256::<ark_bn254::FqParameters>::new(BigInteger256::new([4322555386982339744,1507888651163549575, 17123512513965322170, 2227472495995274711])), 
			ark_ff::Fp256::<ark_bn254::FqParameters>::new(BigInteger256::new([8399296790818619369,8569066378949900379, 12053360414718486896, 2623680133006086555])) 
 		)
 	)
}

pub fn get_delta_g2_neg_pc_90() -> (QuadExtField::<ark_ff::Fp2ParamsWrapper::<ark_bn254::Fq2Parameters>>, QuadExtField::<ark_ff::Fp2ParamsWrapper::<ark_bn254::Fq2Parameters>>, QuadExtField::<ark_ff::Fp2ParamsWrapper::<ark_bn254::Fq2Parameters>>) { 
 	(QuadExtField::<ark_ff::Fp2ParamsWrapper::<ark_bn254::Fq2Parameters>>::new(
			ark_ff::Fp256::<ark_bn254::FqParameters>::new(BigInteger256::new([2009483888294858663,11317137219685997412, 14750423886585175811, 100356646364177841])), 
			ark_ff::Fp256::<ark_bn254::FqParameters>::new(BigInteger256::new([8923692095407831574,13485564776938283142, 14682809119710647766, 2258879033980229699])) 
		),
		QuadExtField::<ark_ff::Fp2ParamsWrapper::<ark_bn254::Fq2Parameters>>::new(
			ark_ff::Fp256::<ark_bn254::FqParameters>::new(BigInteger256::new([4521097552376757443,18040048504141656427, 9114856189151282088, 561024827325637966])), 
			ark_ff::Fp256::<ark_bn254::FqParameters>::new(BigInteger256::new([7375130300304749998,12324356134752573784, 3567088708414507239, 2251460961962716545])) 
		),
		QuadExtField::<ark_ff::Fp2ParamsWrapper::<ark_bn254::Fq2Parameters>>::new(
			ark_ff::Fp256::<ark_bn254::FqParameters>::new(BigInteger256::new([10885334821250115786,16793934523551144152, 1337247719422478815, 508908536463948872])), 
			ark_ff::Fp256::<ark_bn254::FqParameters>::new(BigInteger256::new([8708792952964737790,12756425184800319449, 6337504365365344500, 1915983856791476133])) 
 		)
 	)
}