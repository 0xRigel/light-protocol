import { expect, test } from "@oclif/test";
import { Keypair } from "@solana/web3.js";

describe("shield", async() => {
   
    test
    .stdout()
    .command(['shield', '--amount-sol=1.1'])
    .it("shielding 1.1 SOL with the main cli", async (ctx) => {
      expect(ctx.stdout).to.contain('Successfully shielded 1.1 SOL ✔');
    });

    test
    .stdout()
    .command(['shield', '--amount-spl=5', '--token=USDC'])
    .it("shielding 5 SPL:USDC with the main cli", async (ctx) => {
      expect(ctx.stdout).to.contain('Successfully shielded 5 USDC ✔');
    });
})

describe("shield sol and spl", async() => {
  test
    .stdout()
    .command(['shield', '--amount-sol=1.5', '--amount-spl=3', '--token=USDC'])
    .it("shielding 1.5 SOL & 4 SPL:USDC at the same time with the main cli", async (ctx) => {
      expect(ctx.stdout).to.contain('Successfully shielded 1.5 SOL & 3 USDC ✔');
    });

  /* test
    .stdout()
    .command(["balance"])
    .it("Should have balance of 11.1 SOL", (ctx) => {
      console.log(ctx.stdout);
      expect(ctx.stdout).to.contain("Total Sol Balance: 11100000000");
    }); */
});

/* describe("Unshield SOL", () => {
  let recipient = Keypair.generate().publicKey;
  test
    .stdout()
    .command([
      "unshield",
      "--token=SOL",
      "--amountSol=1.1",
      `--recipientSol=${recipient.toString()}`,
      `--recipientSpl=${recipient.toString()}`,
    ])
    .it("Unshield 2.8 SOL", (ctx) => {
      console.log(ctx.stdout);
      expect(ctx.stdout).to.contain("Successfully unshielded");
    });
});

describe("Transfer Sol", () => {
  let recipient =
    "sKRXAPf5cAzA28WcMASpEUTVZjc87HSHqVxrGNEW19TjEduQgfFitiVhCnc4EjMhKXSJ15uhTSCRuDUMDmdHhsAt";
  test
    .stdout()
    .command(["transfer", "--token=SOL", "--amountSol=1.5", recipient])
    .it("Transfer 1.5 SOL", (ctx) => {
      console.log(ctx.stdout);
      expect(ctx.stdout).to.contain("Tokens successfully transferred");
    });
});

describe("Shield USDC", () => {
  test
    .stdout()
    .command(["shield", "--token=USDC", `--amountSol=17.8`])
    .it("Should shield 17.8 USDC", (ctx) => {
      console.log(ctx.stdout);
      expect(ctx.stdout).to.contain("Successfully shielded");
    });
});

describe("Unshield Sol", () => {
  let recipient = Keypair.generate().publicKey;
  test
    .stdout()
    .command([
      "unshield",
      "--token=USDC",
      "--amountSpl=6.6",
      `--recipientSol=${recipient.toString()}`,
      `--recipientSpl=${recipient.toString()}`,
    ])
    .it("Unshield 6.6 USDC", (ctx) => {
      console.log(ctx.stdout);
      expect(ctx.stdout).to.contain("Successfully unshielded");
    });
});

describe("Transfer USDC", () => {
  let recipient =
    "sKRXAPf5cAzA28WcMASpEUTVZjc87HSHqVxrGNEW19TjEduQgfFitiVhCnc4EjMhKXSJ15uhTSCRuDUMDmdHhsAt";
  test
    .stdout()
    .command(["transfer", "--token=USDC", "--amountSol=0.89", recipient])
    .it("Transfer 1.5 USDC", (ctx) => {
      console.log(ctx.stdout);
      expect(ctx.stdout).to.contain("Tokens successfully transferred");
    });
});

describe.skip("Merge Utxos", () => {
  test
    .stdout()
    .command([
      "shield",
      "--token=SOL",
      "--amountSol=4",
      "--recipient=sKRXAPf5cAzA28WcMASpEUTVZjc87HSHqVxrGNEW19TjEduQgfFitiVhCnc4EjMhKXSJ15uhTSCRuDUMDmdHhsAt",
    ])
    .it("SHIELD 4 sol to address", (ctx) => {
      console.log(ctx.stdout);
      expect(ctx.stdout).to.contain("Tokens successfully transferred");
    });
  test
    .stdout()
    .command([
      "config",
      "--secretKey=4roFuZvNJeh9KwZcRYEedsUsh3E8NTY26RvBgqivBbaYA93aCa1bPe4eRFuX6i7p3GwpyfjNvMYNm1t84PoA5g12",
    ])
    .it("runs user update cmd", (ctx) => {
      expect(ctx.stdout).to.contain(
        "Configuration values updated successfully"
      );
    });

  //TODO: find a way to get the commitment from the inbox balance command and then merge it
  // test
  //   .stdout()
  //   .command([
  //     "utxo",
  //     "--token=SOL",
  //     "17863225529163624094949960837831973135282069025808310217647542102196003863196",
  //   ])
  //   .it("should merge the utxo", (ctx) => {
  //     expect(ctx.stdout).to.contain("UTXOs merged successfully!");
  //   });
}); */