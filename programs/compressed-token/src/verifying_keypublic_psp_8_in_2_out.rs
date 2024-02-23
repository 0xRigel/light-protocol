use anchor_lang::prelude::*;
use groth16_solana::groth16::Groth16Verifyingkey;

pub const VERIFYINGKEY_PUBLIC_TRANSACTION8_IN2_OUT_MAIN: Groth16Verifyingkey =
    Groth16Verifyingkey {
        nr_pubinputs: 19,
        vk_alpha_g1: [
            45, 77, 154, 167, 227, 2, 217, 223, 65, 116, 157, 85, 7, 148, 157, 5, 219, 234, 51,
            251, 177, 108, 100, 59, 34, 245, 153, 162, 190, 109, 242, 226, 20, 190, 221, 80, 60,
            55, 206, 176, 97, 216, 236, 96, 32, 159, 227, 69, 206, 137, 131, 10, 25, 35, 3, 1, 240,
            118, 202, 255, 0, 77, 25, 38,
        ],

        vk_beta_g2: [
            9, 103, 3, 47, 203, 247, 118, 209, 175, 201, 133, 248, 136, 119, 241, 130, 211, 132,
            128, 166, 83, 242, 222, 202, 169, 121, 76, 188, 59, 243, 6, 12, 14, 24, 120, 71, 173,
            76, 121, 131, 116, 208, 214, 115, 43, 245, 1, 132, 125, 214, 139, 192, 224, 113, 36,
            30, 2, 19, 188, 127, 193, 61, 183, 171, 48, 76, 251, 209, 224, 138, 112, 74, 153, 245,
            232, 71, 217, 63, 140, 60, 170, 253, 222, 196, 107, 122, 13, 55, 157, 166, 154, 77, 17,
            35, 70, 167, 23, 57, 193, 177, 164, 87, 168, 199, 49, 49, 35, 210, 77, 47, 145, 146,
            248, 150, 183, 198, 62, 234, 5, 169, 213, 127, 6, 84, 122, 208, 206, 200,
        ],

        vk_gamme_g2: [
            25, 142, 147, 147, 146, 13, 72, 58, 114, 96, 191, 183, 49, 251, 93, 37, 241, 170, 73,
            51, 53, 169, 231, 18, 151, 228, 133, 183, 174, 243, 18, 194, 24, 0, 222, 239, 18, 31,
            30, 118, 66, 106, 0, 102, 94, 92, 68, 121, 103, 67, 34, 212, 247, 94, 218, 221, 70,
            222, 189, 92, 217, 146, 246, 237, 9, 6, 137, 208, 88, 95, 240, 117, 236, 158, 153, 173,
            105, 12, 51, 149, 188, 75, 49, 51, 112, 179, 142, 243, 85, 172, 218, 220, 209, 34, 151,
            91, 18, 200, 94, 165, 219, 140, 109, 235, 74, 171, 113, 128, 141, 203, 64, 143, 227,
            209, 231, 105, 12, 67, 211, 123, 76, 230, 204, 1, 102, 250, 125, 170,
        ],

        vk_delta_g2: [
            35, 43, 72, 166, 102, 47, 114, 190, 167, 169, 179, 134, 74, 222, 249, 245, 85, 58, 69,
            179, 183, 58, 236, 25, 94, 155, 36, 219, 117, 173, 21, 155, 30, 192, 65, 251, 152, 165,
            49, 52, 122, 226, 12, 174, 132, 154, 127, 194, 32, 241, 251, 119, 232, 195, 65, 162,
            232, 140, 104, 230, 119, 10, 252, 139, 41, 224, 93, 223, 152, 170, 90, 34, 238, 227,
            128, 65, 217, 244, 60, 207, 132, 119, 81, 247, 194, 95, 11, 55, 252, 208, 167, 116, 48,
            43, 31, 211, 13, 192, 30, 205, 176, 36, 55, 88, 161, 63, 231, 135, 247, 254, 157, 255,
            242, 225, 126, 138, 250, 132, 64, 167, 213, 122, 215, 53, 207, 2, 45, 225,
        ],

        vk_ic: &[
            [
                4, 233, 151, 101, 239, 97, 187, 118, 70, 92, 22, 77, 88, 105, 121, 88, 48, 121,
                241, 46, 116, 76, 56, 133, 250, 86, 102, 108, 29, 227, 34, 243, 18, 103, 28, 46,
                46, 249, 113, 32, 188, 194, 208, 236, 174, 35, 7, 118, 62, 226, 144, 66, 172, 73,
                158, 114, 99, 31, 30, 130, 15, 225, 188, 42,
            ],
            [
                17, 142, 64, 12, 56, 160, 189, 33, 69, 149, 210, 142, 221, 33, 124, 124, 121, 108,
                163, 194, 12, 85, 213, 109, 152, 99, 63, 241, 4, 160, 87, 66, 18, 250, 238, 234,
                70, 136, 254, 63, 195, 95, 229, 68, 34, 245, 122, 148, 19, 33, 234, 14, 127, 182,
                220, 16, 93, 193, 160, 184, 8, 139, 212, 39,
            ],
            [
                4, 108, 144, 170, 34, 99, 66, 7, 226, 218, 232, 227, 232, 27, 199, 47, 226, 87,
                117, 17, 47, 137, 0, 154, 105, 95, 174, 26, 181, 82, 203, 208, 18, 244, 252, 123,
                92, 181, 129, 119, 251, 176, 32, 233, 129, 128, 83, 230, 182, 160, 136, 179, 254,
                142, 245, 229, 33, 245, 174, 210, 128, 68, 125, 229,
            ],
            [
                15, 39, 239, 109, 197, 9, 130, 207, 166, 71, 127, 98, 55, 74, 167, 248, 202, 219,
                61, 217, 34, 11, 10, 6, 111, 195, 78, 234, 206, 8, 59, 107, 43, 12, 62, 234, 56,
                174, 213, 143, 126, 202, 230, 38, 118, 147, 210, 50, 207, 58, 106, 138, 237, 194,
                7, 62, 15, 176, 150, 7, 243, 191, 160, 150,
            ],
            [
                0, 25, 62, 226, 25, 107, 48, 239, 9, 197, 223, 17, 227, 32, 149, 115, 171, 215,
                184, 57, 13, 195, 245, 206, 18, 63, 105, 245, 120, 214, 104, 122, 37, 161, 70, 167,
                21, 6, 42, 65, 87, 150, 236, 122, 5, 155, 86, 248, 232, 17, 49, 66, 120, 192, 103,
                61, 223, 164, 54, 98, 50, 120, 41, 234,
            ],
            [
                34, 128, 64, 136, 38, 26, 247, 64, 54, 30, 254, 16, 153, 162, 14, 43, 97, 193, 77,
                192, 46, 91, 26, 55, 35, 101, 96, 172, 30, 54, 183, 39, 3, 242, 214, 38, 241, 177,
                232, 45, 91, 221, 157, 117, 135, 53, 76, 136, 114, 60, 143, 216, 253, 229, 54, 181,
                151, 240, 143, 44, 223, 49, 185, 131,
            ],
            [
                48, 46, 151, 57, 20, 104, 53, 194, 200, 119, 218, 237, 20, 155, 111, 7, 227, 73,
                22, 246, 7, 156, 31, 98, 73, 238, 133, 44, 133, 125, 243, 82, 31, 2, 184, 189, 100,
                126, 246, 93, 206, 79, 154, 250, 123, 172, 121, 10, 175, 166, 149, 156, 177, 212,
                73, 149, 23, 197, 132, 159, 84, 64, 42, 165,
            ],
            [
                0, 46, 79, 228, 118, 188, 136, 121, 74, 222, 152, 76, 73, 227, 148, 180, 246, 14,
                91, 245, 213, 53, 57, 101, 113, 103, 218, 45, 8, 134, 100, 157, 31, 33, 103, 128,
                53, 217, 68, 239, 192, 235, 77, 74, 103, 190, 76, 189, 3, 223, 151, 132, 153, 64,
                125, 243, 252, 184, 109, 232, 132, 156, 141, 141,
            ],
            [
                33, 8, 106, 212, 223, 24, 5, 76, 126, 149, 207, 105, 16, 85, 162, 41, 73, 45, 17,
                77, 187, 121, 136, 219, 38, 141, 176, 17, 233, 241, 34, 190, 31, 145, 253, 49, 56,
                46, 228, 22, 1, 160, 185, 116, 191, 153, 34, 66, 78, 208, 160, 10, 75, 9, 98, 233,
                15, 2, 235, 174, 39, 193, 171, 139,
            ],
            [
                13, 195, 250, 186, 221, 104, 213, 142, 53, 209, 53, 180, 166, 79, 73, 39, 129, 38,
                30, 194, 3, 211, 169, 188, 45, 135, 161, 14, 169, 8, 62, 106, 7, 52, 35, 43, 128,
                150, 19, 31, 220, 13, 162, 211, 188, 42, 50, 226, 84, 123, 205, 201, 162, 22, 168,
                214, 74, 59, 52, 145, 180, 130, 199, 72,
            ],
            [
                26, 182, 179, 150, 1, 29, 73, 56, 230, 218, 105, 65, 27, 201, 250, 38, 223, 189,
                26, 146, 8, 189, 26, 163, 117, 27, 73, 122, 204, 42, 153, 254, 14, 136, 14, 9, 119,
                134, 8, 177, 200, 43, 106, 44, 255, 234, 251, 50, 239, 15, 67, 22, 30, 219, 97,
                213, 106, 34, 105, 61, 92, 244, 255, 57,
            ],
            [
                0, 20, 173, 196, 170, 51, 131, 147, 54, 166, 231, 81, 220, 172, 108, 77, 240, 29,
                196, 222, 239, 224, 222, 116, 190, 108, 82, 28, 0, 217, 220, 25, 12, 212, 16, 20,
                207, 226, 85, 132, 152, 241, 166, 9, 24, 36, 158, 137, 84, 211, 186, 47, 43, 62,
                85, 145, 61, 212, 75, 190, 250, 163, 176, 7,
            ],
            [
                28, 143, 117, 78, 131, 93, 82, 87, 29, 165, 201, 138, 25, 113, 177, 62, 226, 11,
                48, 186, 170, 187, 50, 71, 95, 160, 111, 128, 246, 249, 64, 175, 25, 251, 145, 201,
                41, 198, 55, 38, 172, 64, 38, 56, 214, 27, 10, 199, 78, 226, 77, 4, 143, 196, 29,
                151, 129, 171, 4, 166, 239, 187, 23, 209,
            ],
            [
                12, 131, 49, 3, 244, 51, 177, 43, 186, 184, 101, 196, 217, 60, 243, 231, 193, 201,
                41, 239, 183, 163, 144, 87, 206, 179, 32, 63, 43, 18, 119, 15, 25, 77, 91, 164,
                218, 118, 62, 252, 10, 217, 47, 198, 75, 37, 210, 26, 132, 161, 7, 231, 20, 25, 73,
                181, 231, 129, 22, 51, 147, 65, 91, 67,
            ],
            [
                39, 117, 221, 197, 16, 147, 236, 207, 105, 245, 58, 36, 62, 150, 110, 236, 175, 55,
                234, 60, 152, 133, 106, 204, 173, 41, 54, 140, 181, 79, 153, 86, 21, 17, 203, 93,
                8, 213, 94, 164, 57, 160, 251, 0, 140, 139, 47, 113, 136, 216, 137, 53, 90, 230,
                94, 128, 50, 248, 115, 120, 87, 255, 63, 152,
            ],
            [
                19, 4, 29, 128, 171, 242, 76, 38, 160, 21, 209, 72, 223, 214, 173, 98, 201, 15, 65,
                48, 87, 178, 156, 56, 2, 129, 117, 186, 38, 75, 215, 155, 38, 123, 189, 255, 242,
                244, 57, 238, 115, 2, 77, 85, 117, 71, 253, 182, 26, 129, 255, 20, 103, 68, 88, 41,
                59, 182, 143, 212, 123, 223, 23, 237,
            ],
            [
                40, 168, 150, 126, 196, 160, 183, 69, 13, 166, 76, 57, 148, 219, 206, 34, 32, 224,
                97, 91, 208, 226, 69, 169, 34, 218, 80, 69, 244, 212, 218, 230, 3, 49, 58, 221, 47,
                224, 158, 131, 133, 112, 185, 41, 227, 98, 38, 116, 37, 79, 228, 112, 127, 46, 155,
                164, 88, 75, 51, 83, 104, 95, 95, 29,
            ],
            [
                18, 204, 223, 154, 187, 39, 172, 58, 3, 70, 24, 173, 245, 114, 246, 166, 38, 238,
                154, 43, 253, 52, 161, 204, 6, 244, 95, 25, 70, 249, 153, 141, 25, 107, 126, 35,
                224, 214, 123, 137, 244, 61, 78, 42, 213, 83, 30, 189, 187, 193, 253, 2, 65, 27,
                166, 38, 139, 132, 112, 24, 36, 217, 140, 154,
            ],
            [
                42, 154, 134, 130, 23, 189, 96, 156, 41, 251, 197, 28, 12, 24, 99, 136, 158, 85,
                135, 210, 49, 145, 226, 149, 208, 126, 228, 172, 182, 214, 53, 128, 31, 80, 245,
                217, 1, 249, 226, 37, 154, 173, 245, 21, 221, 170, 253, 208, 146, 223, 93, 253, 36,
                3, 154, 223, 160, 43, 62, 110, 83, 244, 226, 93,
            ],
            [
                0, 44, 254, 62, 108, 120, 159, 250, 8, 154, 189, 189, 217, 124, 239, 49, 194, 43,
                103, 79, 198, 214, 172, 6, 90, 40, 125, 30, 45, 219, 143, 202, 42, 78, 63, 228,
                176, 217, 109, 122, 196, 253, 238, 60, 123, 164, 173, 230, 3, 147, 134, 146, 218,
                68, 4, 122, 106, 102, 79, 60, 213, 88, 79, 229,
            ],
        ],
    };
#[account]
pub struct ZKpublicTransaction8In2OutMainProofInputs {
    public_state_root: [u8; 8],
    public_data_hash: u8,
    public_in_utxo_hash: [u8; 8],
    public_out_utxo_hash: [u8; 2],
    public_amount_sol: u8,
    asset_public_keys: [u8; 3],
    private_public_data_hash: u8,
    is_in_program_utxo: [u8; 8],
    in_owner: [u8; 8],
    in_amount: [[u8; 2]; 8],
    in_private_key: [u8; 8],
    in_blinding: [u8; 8],
    leaf_index: [u8; 8],
    merkle_proof: [[u8; 18]; 8],
    in_indices: [[[u8; 3]; 2]; 8],
    out_amount: [[u8; 2]; 2],
    out_owner: [u8; 2],
    out_blinding: [u8; 2],
    out_data_hash: [u8; 2],
    out_indices: [[[u8; 3]; 2]; 2],
}
#[account]
pub struct ZKpublicTransaction8In2OutMainPublicInputs {
    public_state_root: [u8; 8],
    public_data_hash: u8,
    public_in_utxo_hash: [u8; 8],
    public_out_utxo_hash: [u8; 2],
}
#[account]
pub struct InstructionDataLightInstructionPublicTransaction8In2OutMainSecond {
    public_state_root: [[u8; 32]; 8],
    public_data_hash: [u8; 32],
    public_in_utxo_hash: [[u8; 32]; 8],
    public_out_utxo_hash: [[u8; 32]; 2],
}