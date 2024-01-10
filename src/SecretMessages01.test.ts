import { SecretMessages } from './SecretMessages01';
import { Field, Mina, PrivateKey, PublicKey, AccountUpdate, Bool } from 'o1js';


let proofsEnabled = false;

describe('SecretMessages', () => {
  let deployerAccount: PublicKey,
    deployerKey: PrivateKey,
    senderAccount: PublicKey,
    senderKey: PrivateKey,
    zkAppAddress: PublicKey,
    zkAppPrivateKey: PrivateKey,
    zkApp: SecretMessages;

  beforeAll(async () => {
    if (proofsEnabled) await SecretMessages.compile();
  });

  beforeEach(() => {
    const Local = Mina.LocalBlockchain({ proofsEnabled });
    Mina.setActiveInstance(Local);
    ({ privateKey: deployerKey, publicKey: deployerAccount } =
      Local.testAccounts[0]);
    ({ privateKey: senderKey, publicKey: senderAccount } =
      Local.testAccounts[1]);
    zkAppPrivateKey = PrivateKey.random();
    zkAppAddress = zkAppPrivateKey.toPublicKey();
    zkApp = new SecretMessages(zkAppAddress);
  });

  async function localDeploy() {
    const txn = await Mina.transaction(deployerAccount, () => {
      AccountUpdate.fundNewAccount(deployerAccount);
      zkApp.deploy();
    });
    await txn.prove();
    // this tx needs .sign(), because `deploy()` adds an account update that requires signature authorization
    await txn.sign([deployerKey, zkAppPrivateKey]).send();
  }

  it('correctly builds flags', async () => {
    // Both of these should result in flags which are ALL TRUE
    const messageAllTrue1 = Field(1 + 2 + 4 + 8 + 16 + 32)
    const messageAllTrue2 = Field(1 + 2 + 4 + 8 + 16 + 32 + 64 + 128)

    // Both of these should result in flags which are ALL FALSE
    const messageAllFalse1 = Field(0)
    const messageAllFalse2 = Field(64 + 128)

    const messageSomeTrue = Field(1 + 2 + 16 + 32 + 64 + 128)

    let [flag1, flag2, flag3, flag4, flag5, flag6] = zkApp.buildFlags(messageAllTrue1)
    for (let flag of [flag1, flag2, flag3, flag4, flag5, flag6]) {
      expect(flag.toBoolean()).toBeTruthy()
    }
    [flag1, flag2, flag3, flag4, flag5, flag6] = zkApp.buildFlags(messageAllTrue2)
    for (let flag of [flag1, flag2, flag3, flag4, flag5, flag6]) {
      expect(flag.toBoolean()).toBeTruthy()
    }

    [flag1, flag2, flag3, flag4, flag5, flag6] = zkApp.buildFlags(messageAllFalse1)
    for (let flag of [flag1, flag2, flag3, flag4, flag5, flag6]) {
      expect(flag.toBoolean()).toBeFalsy()
    }

    [flag1, flag2, flag3, flag4, flag5, flag6] = zkApp.buildFlags(messageAllFalse2)
    for (let flag of [flag1, flag2, flag3, flag4, flag5, flag6]) {
      expect(flag.toBoolean()).toBeFalsy()
    }

    [flag1, flag2, flag3, flag4, flag5, flag6] = zkApp.buildFlags(messageAllFalse1)
    for (let flag of [flag1, flag2, flag3, flag4, flag5, flag6]) {
      expect(flag.toBoolean()).toBeFalsy()
    }

    [flag1, flag2, flag3, flag4, flag5, flag6] = zkApp.buildFlags(messageSomeTrue)
    // From (1 + 2 + 16 + 32 + 64 + 128)
    // Flags 1, 2, 5, 6 should be true
    for (let flag of [flag1, flag2, flag5, flag6]) {
      expect(flag.toBoolean()).toBeTruthy()
    }
    for (let flag of [flag3, flag4]) {
      expect(flag.toBoolean()).toBeFalsy()
    }
  })

  it.only('correctly validates flags', async () => {
    // Test each branch of this:
    // If flag 2 is true, then flag 3 must also be true.
    // If flag 4 is true, then flags 5 and 6 must be false.
    const flagT = Bool(true);
    const flagF = Bool(false);

    // First test positive cases - 
    // flag 2 true, flag 3 true (and flag 4 false so we don't check that condition)
    const v1 = zkApp.validateFlags(flagT, flagT, flagT, flagF, flagT, flagT)
    expect(v1.toBoolean()).toBeTruthy()
    // flag 2 true, flag 3 true
    const v2 = zkApp.validateFlags(flagT, flagT, flagF, flagF, flagT, flagT)
    expect(v2.toBoolean()).toBeFalsy()

    // If flag 4 is true, then flags 5 and 6 must be false. (and flag 2 false so we don't check)
    const v3 = zkApp.validateFlags(flagT, flagF, flagT, flagT, flagF, flagF)
    expect(v3.toBoolean()).toBeTruthy()
    // if 5 or 6 or both are true, then should not be valid
    const v4 = zkApp.validateFlags(flagT, flagF, flagT, flagT, flagT, flagT)
    expect(v4.toBoolean()).toBeFalsy()
    const v5 = zkApp.validateFlags(flagT, flagF, flagT, flagT, flagF, flagT)
    expect(v5.toBoolean()).toBeFalsy()
    const v6 = zkApp.validateFlags(flagT, flagF, flagT, flagT, flagT, flagF)
    expect(v6.toBoolean()).toBeFalsy()

    // And now enumerate all cases with flag2 and flag4 false - all should be valid!
    for (let flag1 of [flagT, flagF]) {
      for (let flag3 of [flagT, flagF]) {
        for (let flag5 of [flagT, flagF]) {
          for (let flag6 of [flagT, flagF]) {
            const v = zkApp.validateFlags(flag1, flagF, flag3, flagF, flag5, flag6)
            expect(v.toBoolean()).toBeTruthy()
          }
        }
      }
    }
  })


});
