use groth16_solana::groth16::Groth16Verifyingkey;

pub const VERIFYINGKEY: Groth16Verifyingkey =  Groth16Verifyingkey {
	nr_pubinputs: 16,

	vk_alpha_g1: [
		45,77,154,167,227,2,217,223,65,116,157,85,7,148,157,5,219,234,51,251,177,108,100,59,34,245,153,162,190,109,242,226,
		20,190,221,80,60,55,206,176,97,216,236,96,32,159,227,69,206,137,131,10,25,35,3,1,240,118,202,255,0,77,25,38,
	],

	vk_beta_g2: [
		9,103,3,47,203,247,118,209,175,201,133,248,136,119,241,130,211,132,128,166,83,242,222,202,169,121,76,188,59,243,6,12,
		14,24,120,71,173,76,121,131,116,208,214,115,43,245,1,132,125,214,139,192,224,113,36,30,2,19,188,127,193,61,183,171,
		48,76,251,209,224,138,112,74,153,245,232,71,217,63,140,60,170,253,222,196,107,122,13,55,157,166,154,77,17,35,70,167,
		23,57,193,177,164,87,168,199,49,49,35,210,77,47,145,146,248,150,183,198,62,234,5,169,213,127,6,84,122,208,206,200,
	],

	vk_gamme_g2: [
		25,142,147,147,146,13,72,58,114,96,191,183,49,251,93,37,241,170,73,51,53,169,231,18,151,228,133,183,174,243,18,194,
		24,0,222,239,18,31,30,118,66,106,0,102,94,92,68,121,103,67,34,212,247,94,218,221,70,222,189,92,217,146,246,237,
		9,6,137,208,88,95,240,117,236,158,153,173,105,12,51,149,188,75,49,51,112,179,142,243,85,172,218,220,209,34,151,91,
		18,200,94,165,219,140,109,235,74,171,113,128,141,203,64,143,227,209,231,105,12,67,211,123,76,230,204,1,102,250,125,170,
	],

	vk_delta_g2: [
		19,25,194,91,190,4,19,139,89,158,72,63,194,0,154,163,190,244,198,158,27,19,118,29,111,165,198,75,108,211,99,114,
		11,212,69,13,4,19,233,106,32,100,2,56,69,73,215,156,160,104,64,50,252,137,240,120,180,170,99,120,126,230,23,154,
		13,42,32,180,50,135,234,182,41,36,174,239,205,247,23,221,212,229,13,246,130,17,35,146,250,219,169,120,149,165,30,142,
		23,172,171,166,243,220,194,12,108,20,184,143,32,233,104,166,45,94,25,37,90,117,68,123,28,58,90,166,158,164,41,52,
	],

	vk_ic: &[
		[
			40,191,215,34,188,71,45,220,128,116,255,117,204,45,251,56,28,109,125,29,169,230,20,171,78,218,104,51,9,27,247,87,
			40,189,202,2,49,229,146,157,13,68,13,30,214,163,73,133,215,74,176,116,81,141,101,103,176,218,75,121,151,17,198,1,
		],
		[
			4,249,97,195,10,150,236,51,93,211,112,142,10,221,179,154,93,161,212,199,86,126,33,90,144,11,121,202,130,37,142,7,
			28,15,33,99,151,189,161,173,236,116,125,3,181,8,65,105,239,212,88,238,166,255,225,41,228,237,12,170,140,107,1,239,
		],
		[
			22,245,161,73,3,197,12,18,8,120,0,161,169,101,126,74,29,87,150,57,220,2,54,103,249,176,146,210,135,122,184,145,
			28,207,97,16,120,2,192,145,154,162,75,162,210,230,74,83,236,11,24,236,94,77,243,252,90,95,67,80,72,45,16,241,
		],
		[
			7,217,123,9,63,32,146,141,249,164,207,64,19,228,161,253,205,195,244,56,242,159,58,20,11,15,132,187,108,10,113,183,
			47,231,12,147,114,4,145,34,58,108,124,216,203,93,238,241,84,66,82,155,110,112,179,127,68,119,209,151,107,248,77,174,
		],
		[
			12,138,96,65,4,242,127,116,41,29,244,161,241,39,95,166,234,197,68,39,202,34,21,30,125,57,85,73,141,47,171,223,
			1,177,13,252,188,12,166,121,116,85,93,202,175,209,28,49,90,210,34,138,179,31,198,127,244,124,149,143,80,143,67,76,
		],
		[
			8,158,50,222,48,230,140,96,77,251,199,118,19,187,126,251,248,22,39,215,52,212,122,49,139,248,66,113,20,122,35,217,
			14,81,188,73,127,8,39,223,215,111,104,79,90,188,244,87,248,30,122,55,16,49,42,116,23,150,34,181,180,135,62,202,
		],
		[
			2,197,137,245,248,9,158,119,70,234,155,168,223,51,63,83,179,92,98,40,171,125,245,118,191,152,78,57,130,237,28,58,
			6,109,183,34,100,212,65,13,186,253,94,179,226,181,122,20,116,126,208,15,153,111,70,209,13,163,226,90,115,132,247,94,
		],
		[
			22,22,250,70,234,75,67,189,208,137,5,48,198,78,53,217,129,220,32,180,47,67,51,94,246,102,185,24,87,248,213,236,
			8,115,42,74,117,63,117,87,245,247,194,241,228,186,241,92,33,187,84,242,222,105,129,65,178,179,209,159,112,237,144,139,
		],
		[
			28,200,19,58,48,97,164,246,63,8,117,102,236,104,137,131,155,2,157,180,165,202,42,9,248,144,67,236,164,179,251,150,
			0,34,196,7,136,58,193,117,248,24,216,222,104,57,81,163,135,197,219,169,29,143,147,251,12,98,198,19,118,90,108,59,
		],
		[
			31,215,162,221,180,152,72,120,146,55,51,230,72,202,29,98,121,39,157,144,244,145,107,175,98,234,65,0,166,165,82,105,
			4,73,94,211,209,150,181,11,96,159,221,138,72,20,241,145,170,0,173,243,190,97,239,248,5,16,189,119,96,143,11,25,
		],
		[
			25,119,161,221,99,8,248,207,174,143,48,83,68,119,89,42,162,109,156,114,206,240,75,72,206,91,190,202,219,59,126,82,
			46,240,199,189,219,230,123,188,116,63,56,2,243,29,230,178,99,214,106,206,51,217,239,231,71,21,131,109,38,105,25,196,
		],
		[
			47,136,107,243,192,250,199,248,253,63,8,254,120,90,82,200,19,121,251,18,251,61,246,108,113,78,50,51,29,212,124,39,
			0,8,20,239,5,177,23,111,76,145,22,45,202,92,209,190,182,150,71,61,98,142,254,13,90,123,253,145,237,234,192,166,
		],
		[
			45,249,18,120,64,59,227,249,107,68,39,137,158,161,67,57,32,174,163,147,33,153,235,53,153,245,143,112,191,203,220,24,
			34,177,26,221,120,248,87,23,165,124,66,107,219,51,69,139,167,7,167,222,179,209,157,76,95,244,201,211,111,250,76,172,
		],
		[
			43,233,25,107,68,215,128,192,122,134,82,189,209,47,74,148,149,223,19,251,104,127,189,3,159,184,236,215,97,137,207,169,
			11,34,50,171,110,42,46,98,100,252,216,21,96,108,142,93,38,103,171,33,157,220,24,16,87,133,138,89,220,229,28,141,
		],
		[
			17,87,166,100,145,174,95,1,166,13,54,60,156,83,52,199,98,82,121,60,29,51,43,65,138,51,216,218,94,149,61,113,
			18,120,6,38,233,178,197,174,242,165,206,140,83,255,39,29,81,15,81,1,87,109,199,128,73,77,85,1,232,178,64,23,
		],
		[
			25,210,229,49,197,216,22,41,200,64,182,8,123,173,46,152,13,92,21,227,133,166,26,237,144,81,223,251,144,37,176,76,
			39,226,63,104,247,225,83,172,249,125,1,114,114,236,15,223,197,240,237,126,241,21,10,208,27,23,206,189,214,128,82,183,
		],
	]
};