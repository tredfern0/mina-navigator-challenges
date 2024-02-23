import { BatchMessages, SecretMessage } from './SecretMessages02';
import { Field, Mina, PrivateKey, PublicKey, AccountUpdate, UInt64, Bool, MerkleMap, MerkleMapWitness, Gadgets, UInt32 } from 'o1js';

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
        zkApp: BatchMessages;

    beforeAll(async () => {
        if (proofsEnabled) await BatchMessages.compile();
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
        zkApp = new BatchMessages(zkAppAddress);
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

    it('checks range values with rangeCheck()', async () => {
        // Have a positive case, and a negative case for each one

        let agentId: Field = Field(100)
        let agentXLocation: Field = Field(123);
        let agentYLocation: Field = Field(5345);
        let ok = zkApp.rangeCheck(agentId, agentXLocation, agentYLocation)
        expect(ok.toBoolean()).toBeTruthy()

        // Case 1 - negative agent case should fail
        agentId = Field(-100);
        ok = zkApp.rangeCheck(agentId, agentXLocation, agentYLocation)
        expect(ok.toBoolean()).toBeFalsy()

        // Case 2 - high agentXLocation should fail
        agentId = Field(100);
        agentXLocation = Field(20000);
        ok = zkApp.rangeCheck(agentId, agentXLocation, agentYLocation)
        expect(ok.toBoolean()).toBeFalsy()

        // Case 3 - low agentYLocation should fail
        agentXLocation = Field(5345);
        agentYLocation = Field(123);
        ok = zkApp.rangeCheck(agentId, agentXLocation, agentYLocation)
        expect(ok.toBoolean()).toBeFalsy()

        // Case 4 - agentYLocation less than agentXLocation should fail
        agentXLocation = Field(6000);
        agentYLocation = Field(5345);
        ok = zkApp.rangeCheck(agentId, agentXLocation, agentYLocation)
        expect(ok.toBoolean()).toBeFalsy()

    })

    it.only('checks checksum with checksumCheck()', async () => {
        // CheckSum is the sum of Agent ID, Agent XLocation ,and Agent YLocation

        // Create a positive and negative case
        let agentId: Field = Field(100)
        let agentXLocation: Field = Field(123);
        let agentYLocation: Field = Field(5345);
        // 100 + 123 + 5345 = 5568
        let checkSumGood: Field = Field(5568);
        let checkSumBad: Field = Field(5500);
        let ok = zkApp.checksumCheck(agentId, agentXLocation, agentYLocation, checkSumBad);
        expect(ok.toBoolean()).toBeFalsy();

        ok = zkApp.checksumCheck(agentId, agentXLocation, agentYLocation, checkSumGood);
        expect(ok.toBoolean()).toBeTruthy();
    })



});
