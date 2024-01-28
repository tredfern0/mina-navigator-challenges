import { SecretMessages, appendFlags } from './SecretMessages01';
import { Field, Mina, PrivateKey, PublicKey, AccountUpdate, Bool, MerkleMap, MerkleMapWitness, Gadgets, UInt32 } from 'o1js';


let proofsEnabled = false;

describe('SecretMessages', () => {
  let deployerAccount: PublicKey,
    deployerKey: PrivateKey,
    // this will be the account of the admin - person who can access contract
    adminAccount: PublicKey,
    adminKey: PrivateKey,
    // this will be a separate account that should not be able to access contract
    outsiderAccount: PublicKey,
    outsiderKey: PrivateKey,
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
    ({ privateKey: adminKey, publicKey: adminAccount } =
      Local.testAccounts[1]);
    ({ privateKey: outsiderKey, publicKey: outsiderAccount } =
      Local.testAccounts[2]);
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

  it('correctly validates flags', async () => {
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


  it('storeAddress() stores new addresses', async () => {
    await localDeploy()

    const address = PrivateKey.random().toPublicKey().toFields()[0];

    const map = new MerkleMap();
    const keyWitness: MerkleMapWitness = map.getWitness(address);
    map.set(address, Field(1));

    const txnA = await Mina.transaction(deployerAccount, () => {
      zkApp.storeAddress(address, keyWitness)
    });
    await txnA.prove();
    await txnA.sign([deployerKey]).send();

    const numAddresses = Number(zkApp.numAddresses.get().toBigInt()) as number;
    // Roots should match and we should have stored one address
    expect(numAddresses).toEqual(1);
    expect(zkApp.mapRoot.get()).toEqual(map.getRoot())

    // And confirm if we try to store the same address again, it fails
    let failed = false;
    try {
      const txnB = await Mina.transaction(deployerAccount, () => {
        zkApp.storeAddress(address, keyWitness)
      });
      await txnB.prove();
      await txnB.sign([deployerKey]).send();

    } catch (e: any) {
      failed = true;
    }
    expect(failed).toBeTruthy()
  })

  it('properly appends flags', async () => {
    // make sure round trips are good, and make sure if we have a message
    const message = Field(123456);
    const flags = Field(0b001100);
    const messageWFlags = appendFlags(message, flags);
    const messageFinal = Gadgets.rightShift(messageWFlags, 6);

    // Should be a valid round trip
    expect(messageFinal.toString()).toMatch(message.toString());
  })


  it('wont append flags to oversized message', async () => {
    const message = Field(2 ** 64 - 1);
    const flags = Field(0b001100);
    let failed = false;
    try {
      appendFlags(message, flags);
    } catch (e: any) {
      failed = true;
    }
    expect(failed).toBeTruthy()
  })


  it.only('storeMessage() stores new messages', async () => {
    // Note - this is somewhat of an integration test as it relies on 
    // flagg appending and storeAddress to work
    await localDeploy()

    // Need to add it to the map first
    const address = PrivateKey.random().toPublicKey().toFields()[0];
    const map = new MerkleMap();
    let keyWitness: MerkleMapWitness = map.getWitness(address);
    map.set(address, Field(1));
    const txnA = await Mina.transaction(deployerAccount, () => {
      zkApp.storeAddress(address, keyWitness)
    });
    await txnA.prove();
    await txnA.sign([deployerKey]).send();

    // Part 1 - add an initial message, make sure it worked
    const message = Field(123456);
    // setting all flags to false will pass checks
    const flags = Field(0b000000);
    keyWitness = map.getWitness(address);
    let messageCurrent = Field(1);
    let messageWFlags: Field = appendFlags(message, flags)

    const txnB = await Mina.transaction(deployerAccount, () => {
      zkApp.
        storeMessage(
          keyWitness,
          address,
          messageCurrent,
          messageWFlags)
    });
    await txnB.prove();
    await txnB.sign([deployerKey]).send();

    map.set(address, message);

    // Make sure we've now received 1 message and roots match
    let messagesReceived = Number(zkApp.messagesReceived.get().toBigInt()) as number;
    expect(messagesReceived).toEqual(1);
    expect(zkApp.mapRoot.get()).toEqual(map.getRoot())

    // Part 2 - update message
    const messageNew = Field(7891011);
    // setting all flags to false will pass checks
    keyWitness = map.getWitness(address);
    messageCurrent = message;
    messageWFlags = appendFlags(messageNew, flags)

    const txnC = await Mina.transaction(deployerAccount, () => {
      zkApp.
        storeMessage(
          keyWitness,
          address,
          messageCurrent,
          messageWFlags)
    });
    await txnC.prove();
    await txnC.sign([deployerKey]).send();

    map.set(address, messageNew);

    // Should STILL be 1 message received, and roots should match
    messagesReceived = Number(zkApp.messagesReceived.get().toBigInt()) as number;
    expect(messagesReceived).toEqual(1);
    expect(zkApp.mapRoot.get()).toEqual(map.getRoot())


    // TODO - add test for events?
    // const events = await zkApp.fetchEvents(UInt32.from(0));
    // console.log(events)
  })


});
