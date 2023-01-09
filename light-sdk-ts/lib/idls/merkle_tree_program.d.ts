export type MerkleTreeProgramIdl = {
    "version": "0.1.0";
    "name": "merkle_tree_program";
    "constants": [
        {
            "name": "ENCRYPTED_UTXOS_LENGTH";
            "type": {
                "defined": "usize";
            };
            "value": "174";
        },
        {
            "name": "MERKLE_TREE_TMP_PDA_SIZE";
            "type": {
                "defined": "usize";
            };
            "value": "2048";
        },
        {
            "name": "MERKLE_TREE_HISTORY_SIZE";
            "type": "u64";
            "value": "256";
        },
        {
            "name": "MERKLE_TREE_HEIGHT";
            "type": "u64";
            "value": "18";
        },
        {
            "name": "INITIAL_MERKLE_TREE_AUTHORITY";
            "type": {
                "array": [
                    "u8",
                    32
                ];
            };
            "value": "[2 , 99 , 226 , 251 , 88 , 66 , 92 , 33 , 25 , 216 , 211 , 185 , 112 , 203 , 212 , 238 , 105 , 144 , 72 , 121 , 176 , 253 , 106 , 168 , 115 , 158 , 154 , 188 , 62 , 255 , 166 , 81 ,]";
        },
        {
            "name": "ZERO_BYTES_MERKLE_TREE_18";
            "type": {
                "array": [
                    {
                        "array": [
                            "u8",
                            32
                        ];
                    },
                    19
                ];
            };
            "value": "[[40 , 66 , 58 , 227 , 48 , 224 , 249 , 227 , 188 , 18 , 133 , 168 , 156 , 214 , 220 , 144 , 244 , 144 , 67 , 82 , 76 , 6 , 135 , 78 , 64 , 186 , 52 , 113 , 234 , 47 , 27 , 32 ,] , [227 , 42 , 164 , 149 , 188 , 70 , 170 , 8 , 197 , 44 , 134 , 162 , 211 , 186 , 50 , 238 , 97 , 71 , 25 , 130 , 77 , 70 , 37 , 128 , 172 , 154 , 54 , 111 , 93 , 193 , 105 , 27 ,] , [25 , 241 , 255 , 33 , 65 , 214 , 48 , 229 , 38 , 116 , 134 , 103 , 44 , 146 , 163 , 214 , 31 , 238 , 148 , 206 , 34 , 137 , 144 , 221 , 184 , 11 , 5 , 213 , 10 , 188 , 143 , 18 ,] , [211 , 61 , 251 , 33 , 128 , 34 , 4 , 100 , 229 , 47 , 99 , 121 , 109 , 204 , 224 , 90 , 200 , 149 , 219 , 20 , 48 , 206 , 210 , 177 , 161 , 66 , 44 , 10 , 169 , 56 , 248 , 8 ,] , [200 , 15 , 65 , 80 , 151 , 74 , 72 , 69 , 229 , 131 , 25 , 215 , 86 , 36 , 195 , 74 , 67 , 59 , 117 , 179 , 51 , 60 , 181 , 13 , 242 , 192 , 228 , 228 , 189 , 238 , 70 , 8 ,] , [171 , 62 , 122 , 81 , 181 , 197 , 22 , 238 , 224 , 40 , 154 , 231 , 127 , 202 , 201 , 169 , 196 , 109 , 244 , 175 , 117 , 101 , 23 , 67 , 103 , 57 , 127 , 200 , 37 , 43 , 111 , 7 ,] , [59 , 78 , 126 , 104 , 199 , 143 , 213 , 10 , 2 , 158 , 64 , 78 , 153 , 25 , 107 , 190 , 32 , 122 , 123 , 211 , 116 , 179 , 175 , 172 , 70 , 54 , 175 , 59 , 201 , 120 , 64 , 44 ,] , [110 , 91 , 92 , 81 , 205 , 89 , 122 , 223 , 55 , 163 , 42 , 227 , 109 , 54 , 38 , 22 , 110 , 217 , 29 , 148 , 107 , 99 , 128 , 106 , 146 , 47 , 239 , 41 , 55 , 157 , 155 , 22 ,] , [18 , 231 , 42 , 5 , 245 , 159 , 211 , 227 , 239 , 89 , 35 , 142 , 223 , 69 , 166 , 224 , 14 , 114 , 128 , 14 , 123 , 123 , 215 , 2 , 241 , 185 , 191 , 60 , 252 , 61 , 146 , 12 ,] , [231 , 0 , 84 , 227 , 127 , 64 , 158 , 7 , 171 , 179 , 137 , 231 , 92 , 87 , 25 , 221 , 156 , 229 , 53 , 208 , 194 , 201 , 12 , 165 , 105 , 150 , 41 , 142 , 29 , 205 , 136 , 29 ,] , [195 , 2 , 103 , 231 , 62 , 207 , 214 , 105 , 214 , 210 , 108 , 23 , 28 , 151 , 77 , 100 , 78 , 194 , 210 , 29 , 227 , 14 , 17 , 242 , 211 , 50 , 33 , 194 , 106 , 18 , 246 , 45 ,] , [131 , 178 , 24 , 157 , 251 , 247 , 103 , 69 , 101 , 229 , 194 , 14 , 167 , 57 , 158 , 128 , 212 , 19 , 140 , 234 , 69 , 37 , 10 , 156 , 249 , 96 , 152 , 52 , 97 , 96 , 119 , 41 ,] , [30 , 223 , 20 , 181 , 108 , 110 , 112 , 102 , 234 , 54 , 99 , 29 , 213 , 3 , 55 , 225 , 125 , 185 , 223 , 234 , 188 , 108 , 83 , 89 , 27 , 3 , 100 , 6 , 65 , 107 , 3 , 24 ,] , [167 , 32 , 85 , 233 , 205 , 253 , 154 , 214 , 236 , 82 , 147 , 75 , 252 , 144 , 109 , 73 , 63 , 167 , 77 , 233 , 12 , 201 , 150 , 242 , 103 , 15 , 158 , 83 , 137 , 24 , 170 , 16 ,] , [45 , 98 , 238 , 69 , 136 , 141 , 101 , 226 , 94 , 209 , 58 , 215 , 212 , 14 , 210 , 135 , 110 , 96 , 52 , 16 , 101 , 177 , 121 , 109 , 134 , 81 , 189 , 146 , 113 , 243 , 97 , 42 ,] , [71 , 51 , 251 , 48 , 95 , 193 , 94 , 26 , 180 , 17 , 124 , 203 , 48 , 98 , 55 , 17 , 60 , 104 , 186 , 175 , 213 , 189 , 7 , 239 , 92 , 175 , 16 , 5 , 220 , 168 , 70 , 21 ,] , [35 , 92 , 72 , 197 , 23 , 142 , 16 , 200 , 136 , 38 , 44 , 255 , 162 , 115 , 11 , 1 , 248 , 182 , 236 , 78 , 90 , 24 , 128 , 245 , 168 , 17 , 130 , 2 , 73 , 51 , 196 , 6 ,] , [89 , 178 , 154 , 246 , 236 , 130 , 30 , 100 , 27 , 230 , 24 , 196 , 8 , 172 , 176 , 196 , 197 , 13 , 157 , 194 , 169 , 106 , 207 , 70 , 66 , 117 , 69 , 53 , 56 , 154 , 78 , 0 ,] , [231 , 174 , 226 , 37 , 211 , 160 , 187 , 178 , 149 , 82 , 17 , 60 , 110 , 116 , 28 , 61 , 58 , 145 , 58 , 71 , 25 , 42 , 67 , 46 , 189 , 214 , 248 , 234 , 182 , 251 , 238 , 34 ,] ,]";
        },
        {
            "name": "IX_ORDER";
            "type": {
                "array": [
                    "u8",
                    57
                ];
            };
            "value": "[34 , 14 , 0 , 1 , 2 , 0 , 1 , 2 , 0 , 1 , 2 , 0 , 1 , 2 , 0 , 1 , 2 , 0 , 1 , 2 , 0 , 1 , 2 , 0 , 1 , 2 , 0 , 1 , 2 , 0 , 1 , 2 , 0 , 1 , 2 , 0 , 1 , 2 , 0 , 1 , 2 , 0 , 1 , 2 , 0 , 1 , 2 , 0 , 1 , 2 , 0 , 1 , 2 , 0 , 1 , 2 , 241 ,]";
        },
        {
            "name": "AUTHORITY_SEED";
            "type": {
                "defined": "&[u8]";
            };
            "value": "b\"AUTHORITY_SEED\"";
        },
        {
            "name": "MERKLE_TREE_AUTHORITY_SEED";
            "type": {
                "defined": "&[u8]";
            };
            "value": "b\"MERKLE_TREE_AUTHORITY\"";
        },
        {
            "name": "TREE_ROOT_SEED";
            "type": {
                "defined": "&[u8]";
            };
            "value": "b\"TREE_ROOT_SEED\"";
        },
        {
            "name": "STORAGE_SEED";
            "type": {
                "defined": "&[u8]";
            };
            "value": "b\"storage\"";
        },
        {
            "name": "LEAVES_SEED";
            "type": {
                "defined": "&[u8]";
            };
            "value": "b\"leaves\"";
        },
        {
            "name": "NULLIFIER_SEED";
            "type": {
                "defined": "&[u8]";
            };
            "value": "b\"nf\"";
        },
        {
            "name": "POOL_TYPE_SEED";
            "type": {
                "defined": "&[u8]";
            };
            "value": "b\"pooltype\"";
        },
        {
            "name": "POOL_CONFIG_SEED";
            "type": {
                "defined": "&[u8]";
            };
            "value": "b\"pool-config\"";
        },
        {
            "name": "POOL_SEED";
            "type": {
                "defined": "&[u8]";
            };
            "value": "b\"pool\"";
        },
        {
            "name": "TOKEN_AUTHORITY_SEED";
            "type": {
                "defined": "&[u8]";
            };
            "value": "b\"spl\"";
        }
    ];
    "instructions": [
        {
            "name": "initializeNewMerkleTree";
            "accounts": [
                {
                    "name": "authority";
                    "isMut": true;
                    "isSigner": true;
                },
                {
                    "name": "merkleTree";
                    "isMut": true;
                    "isSigner": false;
                },
                {
                    "name": "systemProgram";
                    "isMut": false;
                    "isSigner": false;
                },
                {
                    "name": "rent";
                    "isMut": false;
                    "isSigner": false;
                },
                {
                    "name": "preInsertedLeavesIndex";
                    "isMut": true;
                    "isSigner": false;
                },
                {
                    "name": "merkleTreeAuthorityPda";
                    "isMut": true;
                    "isSigner": false;
                }
            ];
            "args": [
                {
                    "name": "lockDuration";
                    "type": "u64";
                }
            ];
        },
        {
            "name": "initializeMerkleTreeAuthority";
            "accounts": [
                {
                    "name": "merkleTreeAuthorityPda";
                    "isMut": true;
                    "isSigner": false;
                },
                {
                    "name": "authority";
                    "isMut": true;
                    "isSigner": true;
                },
                {
                    "name": "systemProgram";
                    "isMut": false;
                    "isSigner": false;
                },
                {
                    "name": "rent";
                    "isMut": false;
                    "isSigner": false;
                }
            ];
            "args": [];
        },
        {
            "name": "updateMerkleTreeAuthority";
            "accounts": [
                {
                    "name": "merkleTreeAuthorityPda";
                    "isMut": true;
                    "isSigner": false;
                },
                {
                    "name": "authority";
                    "isMut": false;
                    "isSigner": true;
                },
                {
                    "name": "newAuthority";
                    "isMut": false;
                    "isSigner": false;
                }
            ];
            "args": [];
        },
        {
            "name": "updateLockDuration";
            "accounts": [
                {
                    "name": "merkleTreeAuthorityPda";
                    "isMut": true;
                    "isSigner": false;
                },
                {
                    "name": "authority";
                    "isMut": false;
                    "isSigner": true;
                },
                {
                    "name": "merkleTree";
                    "isMut": true;
                    "isSigner": false;
                }
            ];
            "args": [
                {
                    "name": "lockDuration";
                    "type": "u64";
                }
            ];
        },
        {
            "name": "enableNfts";
            "accounts": [
                {
                    "name": "merkleTreeAuthorityPda";
                    "isMut": true;
                    "isSigner": false;
                },
                {
                    "name": "authority";
                    "isMut": false;
                    "isSigner": true;
                }
            ];
            "args": [
                {
                    "name": "enablePermissionless";
                    "type": "bool";
                }
            ];
        },
        {
            "name": "enablePermissionlessSplTokens";
            "accounts": [
                {
                    "name": "merkleTreeAuthorityPda";
                    "isMut": true;
                    "isSigner": false;
                },
                {
                    "name": "authority";
                    "isMut": false;
                    "isSigner": true;
                }
            ];
            "args": [
                {
                    "name": "enablePermissionless";
                    "type": "bool";
                }
            ];
        },
        {
            "name": "registerVerifier";
            "accounts": [
                {
                    "name": "registeredVerifierPda";
                    "isMut": true;
                    "isSigner": false;
                },
                {
                    "name": "authority";
                    "isMut": true;
                    "isSigner": true;
                },
                {
                    "name": "merkleTreeAuthorityPda";
                    "isMut": false;
                    "isSigner": false;
                },
                {
                    "name": "systemProgram";
                    "isMut": false;
                    "isSigner": false;
                },
                {
                    "name": "rent";
                    "isMut": false;
                    "isSigner": false;
                }
            ];
            "args": [
                {
                    "name": "verifierPubkey";
                    "type": "publicKey";
                }
            ];
        },
        {
            "name": "registerPoolType";
            "accounts": [
                {
                    "name": "registeredPoolTypePda";
                    "isMut": true;
                    "isSigner": false;
                },
                {
                    "name": "authority";
                    "isMut": true;
                    "isSigner": true;
                },
                {
                    "name": "systemProgram";
                    "isMut": false;
                    "isSigner": false;
                },
                {
                    "name": "rent";
                    "isMut": false;
                    "isSigner": false;
                },
                {
                    "name": "merkleTreeAuthorityPda";
                    "isMut": false;
                    "isSigner": false;
                }
            ];
            "args": [
                {
                    "name": "poolType";
                    "type": {
                        "array": [
                            "u8",
                            32
                        ];
                    };
                }
            ];
        },
        {
            "name": "registerSplPool";
            "accounts": [
                {
                    "name": "registeredAssetPoolPda";
                    "isMut": true;
                    "isSigner": false;
                },
                {
                    "name": "merkleTreePdaToken";
                    "isMut": true;
                    "isSigner": false;
                },
                {
                    "name": "authority";
                    "isMut": true;
                    "isSigner": true;
                },
                {
                    "name": "systemProgram";
                    "isMut": false;
                    "isSigner": false;
                },
                {
                    "name": "rent";
                    "isMut": false;
                    "isSigner": false;
                },
                {
                    "name": "mint";
                    "isMut": true;
                    "isSigner": false;
                },
                {
                    "name": "tokenAuthority";
                    "isMut": true;
                    "isSigner": false;
                },
                {
                    "name": "tokenProgram";
                    "isMut": false;
                    "isSigner": false;
                },
                {
                    "name": "registeredPoolTypePda";
                    "isMut": false;
                    "isSigner": false;
                },
                {
                    "name": "merkleTreeAuthorityPda";
                    "isMut": true;
                    "isSigner": false;
                }
            ];
            "args": [];
        },
        {
            "name": "registerSolPool";
            "accounts": [
                {
                    "name": "registeredAssetPoolPda";
                    "isMut": true;
                    "isSigner": false;
                },
                {
                    "name": "authority";
                    "isMut": true;
                    "isSigner": true;
                },
                {
                    "name": "systemProgram";
                    "isMut": false;
                    "isSigner": false;
                },
                {
                    "name": "rent";
                    "isMut": false;
                    "isSigner": false;
                },
                {
                    "name": "registeredPoolTypePda";
                    "isMut": false;
                    "isSigner": false;
                },
                {
                    "name": "merkleTreeAuthorityPda";
                    "isMut": true;
                    "isSigner": false;
                }
            ];
            "args": [];
        },
        {
            "name": "initializeMerkleTreeUpdateState";
            "accounts": [
                {
                    "name": "authority";
                    "isMut": true;
                    "isSigner": true;
                },
                {
                    "name": "merkleTreeUpdateState";
                    "isMut": true;
                    "isSigner": false;
                },
                {
                    "name": "merkleTree";
                    "isMut": true;
                    "isSigner": false;
                },
                {
                    "name": "systemProgram";
                    "isMut": false;
                    "isSigner": false;
                },
                {
                    "name": "rent";
                    "isMut": false;
                    "isSigner": false;
                }
            ];
            "args": [];
        },
        {
            "name": "updateMerkleTree";
            "accounts": [
                {
                    "name": "authority";
                    "isMut": true;
                    "isSigner": true;
                },
                {
                    "name": "merkleTreeUpdateState";
                    "isMut": true;
                    "isSigner": false;
                },
                {
                    "name": "merkleTree";
                    "isMut": true;
                    "isSigner": false;
                }
            ];
            "args": [
                {
                    "name": "bump";
                    "type": "u64";
                }
            ];
        },
        {
            "name": "insertRootMerkleTree";
            "accounts": [
                {
                    "name": "authority";
                    "isMut": true;
                    "isSigner": true;
                },
                {
                    "name": "merkleTreeUpdateState";
                    "isMut": true;
                    "isSigner": false;
                },
                {
                    "name": "merkleTree";
                    "isMut": true;
                    "isSigner": false;
                }
            ];
            "args": [
                {
                    "name": "bump";
                    "type": "u64";
                }
            ];
        },
        {
            "name": "closeMerkleTreeUpdateState";
            "accounts": [
                {
                    "name": "authority";
                    "isMut": true;
                    "isSigner": true;
                },
                {
                    "name": "merkleTreeUpdateState";
                    "isMut": true;
                    "isSigner": false;
                }
            ];
            "args": [];
        },
        {
            "name": "insertTwoLeaves";
            "accounts": [
                {
                    "name": "authority";
                    "isMut": true;
                    "isSigner": true;
                },
                {
                    "name": "twoLeavesPda";
                    "isMut": true;
                    "isSigner": false;
                },
                {
                    "name": "preInsertedLeavesIndex";
                    "isMut": true;
                    "isSigner": false;
                },
                {
                    "name": "systemProgram";
                    "isMut": false;
                    "isSigner": false;
                },
                {
                    "name": "registeredVerifierPda";
                    "isMut": false;
                    "isSigner": false;
                }
            ];
            "args": [
                {
                    "name": "leafLeft";
                    "type": {
                        "array": [
                            "u8",
                            32
                        ];
                    };
                },
                {
                    "name": "leafRight";
                    "type": {
                        "array": [
                            "u8",
                            32
                        ];
                    };
                },
                {
                    "name": "encryptedUtxo";
                    "type": {
                        "array": [
                            "u8",
                            256
                        ];
                    };
                },
                {
                    "name": "merkleTreePdaPubkey";
                    "type": "publicKey";
                }
            ];
        },
        {
            "name": "withdrawSol";
            "accounts": [
                {
                    "name": "authority";
                    "isMut": true;
                    "isSigner": true;
                },
                {
                    "name": "merkleTreeToken";
                    "isMut": true;
                    "isSigner": false;
                },
                {
                    "name": "registeredVerifierPda";
                    "isMut": false;
                    "isSigner": false;
                },
                {
                    "name": "recipient";
                    "isMut": true;
                    "isSigner": false;
                }
            ];
            "args": [
                {
                    "name": "amount";
                    "type": "u64";
                }
            ];
        },
        {
            "name": "withdrawSpl";
            "accounts": [
                {
                    "name": "authority";
                    "isMut": true;
                    "isSigner": true;
                },
                {
                    "name": "merkleTreeToken";
                    "isMut": true;
                    "isSigner": false;
                },
                {
                    "name": "recipient";
                    "isMut": true;
                    "isSigner": false;
                },
                {
                    "name": "tokenProgram";
                    "isMut": false;
                    "isSigner": false;
                },
                {
                    "name": "tokenAuthority";
                    "isMut": true;
                    "isSigner": false;
                },
                {
                    "name": "registeredVerifierPda";
                    "isMut": false;
                    "isSigner": false;
                }
            ];
            "args": [
                {
                    "name": "amount";
                    "type": "u64";
                }
            ];
        },
        {
            "name": "initializeNullifiers";
            "accounts": [
                {
                    "name": "authority";
                    "isMut": true;
                    "isSigner": true;
                },
                {
                    "name": "systemProgram";
                    "isMut": false;
                    "isSigner": false;
                },
                {
                    "name": "registeredVerifierPda";
                    "isMut": false;
                    "isSigner": false;
                }
            ];
            "args": [
                {
                    "name": "nullifiers";
                    "type": {
                        "vec": "bytes";
                    };
                }
            ];
        }
    ];
    "accounts": [
        {
            "name": "RegisteredAssetPool";
            "type": {
                "kind": "struct";
                "fields": [
                    {
                        "name": "assetPoolPubkey";
                        "type": "publicKey";
                    },
                    {
                        "name": "poolType";
                        "type": {
                            "array": [
                                "u8",
                                32
                            ];
                        };
                    },
                    {
                        "name": "index";
                        "type": "u64";
                    }
                ];
            };
        },
        {
            "name": "RegisteredPoolType";
            "type": {
                "kind": "struct";
                "fields": [
                    {
                        "name": "poolType";
                        "type": {
                            "array": [
                                "u8",
                                32
                            ];
                        };
                    }
                ];
            };
        },
        {
            "name": "MerkleTreeAuthority";
            "type": {
                "kind": "struct";
                "fields": [
                    {
                        "name": "pubkey";
                        "type": "publicKey";
                    },
                    {
                        "name": "merkleTreeIndex";
                        "type": "u64";
                    },
                    {
                        "name": "registeredAssetIndex";
                        "type": "u64";
                    },
                    {
                        "name": "enableNfts";
                        "type": "bool";
                    },
                    {
                        "name": "enablePermissionlessSplTokens";
                        "type": "bool";
                    },
                    {
                        "name": "enablePermissionlessMerkleTreeRegistration";
                        "type": "bool";
                    }
                ];
            };
        },
        {
            "name": "RegisteredVerifier";
            "type": {
                "kind": "struct";
                "fields": [
                    {
                        "name": "pubkey";
                        "type": "publicKey";
                    }
                ];
            };
        },
        {
            "name": "MerkleTreePdaToken";
            "type": {
                "kind": "struct";
                "fields": [];
            };
        },
        {
            "name": "PreInsertedLeavesIndex";
            "type": {
                "kind": "struct";
                "fields": [
                    {
                        "name": "nextIndex";
                        "type": "u64";
                    }
                ];
            };
        },
        {
            "name": "MerkleTree";
            "type": {
                "kind": "struct";
                "fields": [
                    {
                        "name": "filledSubtrees";
                        "type": {
                            "array": [
                                {
                                    "array": [
                                        "u8",
                                        32
                                    ];
                                },
                                18
                            ];
                        };
                    },
                    {
                        "name": "currentRootIndex";
                        "type": "u64";
                    },
                    {
                        "name": "nextIndex";
                        "type": "u64";
                    },
                    {
                        "name": "roots";
                        "type": {
                            "array": [
                                {
                                    "array": [
                                        "u8",
                                        32
                                    ];
                                },
                                256
                            ];
                        };
                    },
                    {
                        "name": "pubkeyLocked";
                        "type": "publicKey";
                    },
                    {
                        "name": "timeLocked";
                        "type": "u64";
                    },
                    {
                        "name": "height";
                        "type": "u64";
                    },
                    {
                        "name": "merkleTreeNr";
                        "type": "u64";
                    },
                    {
                        "name": "lockDuration";
                        "type": "u64";
                    }
                ];
            };
        },
        {
            "name": "TwoLeavesBytesPda";
            "type": {
                "kind": "struct";
                "fields": [
                    {
                        "name": "nodeLeft";
                        "type": {
                            "array": [
                                "u8",
                                32
                            ];
                        };
                    },
                    {
                        "name": "nodeRight";
                        "type": {
                            "array": [
                                "u8",
                                32
                            ];
                        };
                    },
                    {
                        "name": "merkleTreePubkey";
                        "type": "publicKey";
                    },
                    {
                        "name": "encryptedUtxos";
                        "type": {
                            "array": [
                                "u8",
                                256
                            ];
                        };
                    },
                    {
                        "name": "leftLeafIndex";
                        "type": "u64";
                    }
                ];
            };
        },
        {
            "name": "MerkleTreeUpdateState";
            "type": {
                "kind": "struct";
                "fields": [
                    {
                        "name": "nodeLeft";
                        "type": {
                            "array": [
                                "u8",
                                32
                            ];
                        };
                    },
                    {
                        "name": "nodeRight";
                        "type": {
                            "array": [
                                "u8",
                                32
                            ];
                        };
                    },
                    {
                        "name": "leafLeft";
                        "type": {
                            "array": [
                                "u8",
                                32
                            ];
                        };
                    },
                    {
                        "name": "leafRight";
                        "type": {
                            "array": [
                                "u8",
                                32
                            ];
                        };
                    },
                    {
                        "name": "relayer";
                        "type": "publicKey";
                    },
                    {
                        "name": "merkleTreePdaPubkey";
                        "type": "publicKey";
                    },
                    {
                        "name": "state";
                        "type": {
                            "array": [
                                "u8",
                                96
                            ];
                        };
                    },
                    {
                        "name": "currentRound";
                        "type": "u64";
                    },
                    {
                        "name": "currentRoundIndex";
                        "type": "u64";
                    },
                    {
                        "name": "currentInstructionIndex";
                        "type": "u64";
                    },
                    {
                        "name": "currentIndex";
                        "type": "u64";
                    },
                    {
                        "name": "currentLevel";
                        "type": "u64";
                    },
                    {
                        "name": "currentLevelHash";
                        "type": {
                            "array": [
                                "u8",
                                32
                            ];
                        };
                    },
                    {
                        "name": "tmpLeavesIndex";
                        "type": "u64";
                    },
                    {
                        "name": "filledSubtrees";
                        "type": {
                            "array": [
                                {
                                    "array": [
                                        "u8",
                                        32
                                    ];
                                },
                                18
                            ];
                        };
                    },
                    {
                        "name": "leaves";
                        "type": {
                            "array": [
                                {
                                    "array": [
                                        {
                                            "array": [
                                                "u8",
                                                32
                                            ];
                                        },
                                        2
                                    ];
                                },
                                16
                            ];
                        };
                    },
                    {
                        "name": "numberOfLeaves";
                        "type": "u8";
                    },
                    {
                        "name": "insertLeavesIndex";
                        "type": "u8";
                    }
                ];
            };
        }
    ];
    "errors": [
        {
            "code": 6000;
            "name": "MtTmpPdaInitFailed";
            "msg": "Merkle tree tmp account init failed wrong pda.";
        },
        {
            "code": 6001;
            "name": "MerkleTreeInitFailed";
            "msg": "Merkle tree tmp account init failed.";
        },
        {
            "code": 6002;
            "name": "ContractStillLocked";
            "msg": "Contract is still locked.";
        },
        {
            "code": 6003;
            "name": "InvalidMerkleTree";
            "msg": "InvalidMerkleTree.";
        },
        {
            "code": 6004;
            "name": "InvalidMerkleTreeOwner";
            "msg": "InvalidMerkleTreeOwner.";
        },
        {
            "code": 6005;
            "name": "PubkeyCheckFailed";
            "msg": "PubkeyCheckFailed";
        },
        {
            "code": 6006;
            "name": "CloseAccountFailed";
            "msg": "CloseAccountFailed";
        },
        {
            "code": 6007;
            "name": "WithdrawalFailed";
            "msg": "WithdrawalFailed";
        },
        {
            "code": 6008;
            "name": "MerkleTreeUpdateNotInRootInsert";
            "msg": "MerkleTreeUpdateNotInRootInsert";
        },
        {
            "code": 6009;
            "name": "MerkleTreeUpdateNotInRootInsertState";
            "msg": "MerkleTreeUpdateNotInRootInsert";
        },
        {
            "code": 6010;
            "name": "InvalidNumberOfLeaves";
            "msg": "InvalidNumberOfLeaves";
        },
        {
            "code": 6011;
            "name": "LeafAlreadyInserted";
            "msg": "LeafAlreadyInserted";
        },
        {
            "code": 6012;
            "name": "WrongLeavesLastTx";
            "msg": "WrongLeavesLastTx";
        },
        {
            "code": 6013;
            "name": "FirstLeavesPdaIncorrectIndex";
            "msg": "FirstLeavesPdaIncorrectIndex";
        },
        {
            "code": 6014;
            "name": "NullifierAlreadyExists";
            "msg": "NullifierAlreadyExists";
        },
        {
            "code": 6015;
            "name": "LeavesOfWrongTree";
            "msg": "LeavesOfWrongTree";
        },
        {
            "code": 6016;
            "name": "InvalidAuthority";
            "msg": "InvalidAuthority";
        },
        {
            "code": 6017;
            "name": "InvalidVerifier";
            "msg": "InvalidVerifier";
        }
    ];
};
export declare const MerkleTreeProgram: MerkleTreeProgramIdl;
export default MerkleTreeProgram;
