use groth16_solana::groth16::Groth16Verifyingkey;

pub const VERIFYINGKEY: Groth16Verifyingkey = Groth16Verifyingkey {
    nr_pubinputs: 3,

    vk_alpha_g1: [
        45, 77, 154, 167, 227, 2, 217, 223, 65, 116, 157, 85, 7, 148, 157, 5, 219, 234, 51, 251,
        177, 108, 100, 59, 34, 245, 153, 162, 190, 109, 242, 226, 20, 190, 221, 80, 60, 55, 206,
        176, 97, 216, 236, 96, 32, 159, 227, 69, 206, 137, 131, 10, 25, 35, 3, 1, 240, 118, 202,
        255, 0, 77, 25, 38,
    ],

    vk_beta_g2: [
        9, 103, 3, 47, 203, 247, 118, 209, 175, 201, 133, 248, 136, 119, 241, 130, 211, 132, 128,
        166, 83, 242, 222, 202, 169, 121, 76, 188, 59, 243, 6, 12, 14, 24, 120, 71, 173, 76, 121,
        131, 116, 208, 214, 115, 43, 245, 1, 132, 125, 214, 139, 192, 224, 113, 36, 30, 2, 19, 188,
        127, 193, 61, 183, 171, 48, 76, 251, 209, 224, 138, 112, 74, 153, 245, 232, 71, 217, 63,
        140, 60, 170, 253, 222, 196, 107, 122, 13, 55, 157, 166, 154, 77, 17, 35, 70, 167, 23, 57,
        193, 177, 164, 87, 168, 199, 49, 49, 35, 210, 77, 47, 145, 146, 248, 150, 183, 198, 62,
        234, 5, 169, 213, 127, 6, 84, 122, 208, 206, 200,
    ],

    vk_gamme_g2: [
        25, 142, 147, 147, 146, 13, 72, 58, 114, 96, 191, 183, 49, 251, 93, 37, 241, 170, 73, 51,
        53, 169, 231, 18, 151, 228, 133, 183, 174, 243, 18, 194, 24, 0, 222, 239, 18, 31, 30, 118,
        66, 106, 0, 102, 94, 92, 68, 121, 103, 67, 34, 212, 247, 94, 218, 221, 70, 222, 189, 92,
        217, 146, 246, 237, 9, 6, 137, 208, 88, 95, 240, 117, 236, 158, 153, 173, 105, 12, 51, 149,
        188, 75, 49, 51, 112, 179, 142, 243, 85, 172, 218, 220, 209, 34, 151, 91, 18, 200, 94, 165,
        219, 140, 109, 235, 74, 171, 113, 128, 141, 203, 64, 143, 227, 209, 231, 105, 12, 67, 211,
        123, 76, 230, 204, 1, 102, 250, 125, 170,
    ],

    vk_delta_g2: [
        47, 47, 203, 186, 64, 75, 72, 24, 240, 177, 216, 49, 193, 148, 200, 203, 48, 146, 171, 2,
        210, 104, 56, 23, 80, 26, 104, 171, 172, 107, 151, 129, 22, 70, 253, 144, 106, 238, 234,
        22, 250, 250, 93, 199, 93, 46, 254, 62, 189, 234, 124, 70, 245, 189, 50, 243, 117, 58, 81,
        107, 228, 121, 130, 89, 19, 184, 145, 107, 116, 133, 106, 105, 112, 176, 39, 253, 111, 192,
        236, 87, 46, 208, 41, 57, 102, 132, 108, 222, 211, 224, 94, 248, 142, 196, 128, 69, 28,
        177, 49, 160, 223, 62, 176, 7, 71, 188, 80, 16, 32, 176, 49, 159, 24, 124, 87, 217, 78, 98,
        236, 53, 124, 18, 189, 206, 112, 23, 192, 210,
    ],

    vk_ic: &[
        [
            21, 247, 68, 218, 90, 246, 84, 84, 168, 220, 94, 55, 108, 119, 53, 100, 56, 43, 156,
            211, 239, 69, 63, 94, 160, 23, 98, 93, 217, 113, 64, 131, 7, 137, 252, 203, 104, 184,
            194, 223, 72, 115, 16, 231, 238, 88, 106, 239, 174, 23, 116, 24, 235, 155, 131, 141,
            26, 174, 15, 62, 59, 176, 19, 123,
        ],
        [
            6, 206, 228, 146, 255, 33, 145, 47, 141, 178, 198, 219, 183, 229, 2, 70, 164, 54, 185,
            18, 230, 250, 70, 21, 242, 241, 84, 134, 228, 137, 102, 46, 30, 191, 44, 143, 21, 24,
            157, 20, 4, 24, 49, 176, 245, 200, 72, 193, 1, 155, 65, 229, 100, 139, 33, 114, 107,
            112, 89, 231, 29, 128, 11, 216,
        ],
        [
            24, 72, 213, 7, 154, 8, 234, 43, 87, 84, 187, 182, 255, 48, 42, 85, 233, 37, 34, 69,
            122, 158, 110, 254, 148, 96, 203, 120, 234, 117, 22, 101, 34, 74, 177, 134, 76, 111,
            223, 51, 244, 88, 22, 81, 118, 192, 34, 114, 255, 62, 23, 251, 157, 58, 52, 74, 160,
            225, 4, 208, 155, 201, 237, 199,
        ],
    ],
};