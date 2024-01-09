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

  it.todo('correctly validates flags');

});
