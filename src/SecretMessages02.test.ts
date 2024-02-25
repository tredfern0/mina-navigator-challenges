import { BatchMessages, SecretMessage, processBatch } from './SecretMessages02';
import { Field, Mina, PrivateKey, PublicKey, AccountUpdate, UInt64, Bool } from 'o1js';

let proofsEnabled = false;


function buildBatch(maxMessageNum: number, numMessages: number) {
    // Create a batch in which the max messageNumber is 'maxMessageNum'
    let batch: SecretMessage[] = [];
    // Make it so final message is 'maxMessageNum'
    const startI = maxMessageNum - numMessages;
    for (let i = startI; i <= maxMessageNum; i++) {
        const message: SecretMessage = {
            messageNumber: UInt64.from(i),
            agentId: Field(100),
            agentXLocation: Field(123),
            agentYLocation: Field(5345),
            checkSum: Field(5568),
        }
        batch.push(message)
    }
    return batch;
}



describe('SecretMessages02', () => {
    let deployerAccount: PublicKey,
        deployerKey: PrivateKey,
        // this will be the account of the admin - person who can access contract
        adminAccount: PublicKey,
        adminKey: PrivateKey,
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

        const txnB = await Mina.transaction(deployerAccount, () => {
            zkApp.setAdmin(adminKey)
        });
        await txnB.prove();
        await txnB.sign([deployerKey]).send();
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

    it('checks checksum with checksumCheck()', async () => {
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


    it('processes edge cases with isValid()', async () => {
        // Make sure that the two edge cases override the checksum and range checks
        // isValid(message: SecretMessage, prevMessageNumber: UInt64)

        // First positive case - valid message should be fine
        const messageValid: SecretMessage = {
            messageNumber: UInt64.from(23),
            agentId: Field(100),
            agentXLocation: Field(123),
            agentYLocation: Field(5345),
            checkSum: Field(5568),
        }

        // Not hitting any edge cases - 
        // agentId is above 0
        // and prevMessageNumber is lower...
        let prevMessageNumber: UInt64 = UInt64.from(22);
        let ok = zkApp.isValid(messageValid, prevMessageNumber);
        expect(ok.toBoolean()).toBeTruthy();

        // Now the edge cases - 
        // If agentId is 0, message should pass EVEN IF message is invalid
        const messageInvalid0: SecretMessage = {
            messageNumber: UInt64.from(23),
            agentId: Field(0),
            agentXLocation: Field(123),
            agentYLocation: Field(5345),
            // Incorrect checksum
            checkSum: Field(0),
        }
        ok = zkApp.isValid(messageInvalid0, prevMessageNumber);
        expect(ok.toBoolean()).toBeTruthy();

        // And similarly, if messageNumber is not greater than prevMessageNumber, 
        // message should pass EVEN IF message is invalid
        const messageInvalid1: SecretMessage = {
            messageNumber: UInt64.from(23),
            agentId: Field(20),
            agentXLocation: Field(123),
            agentYLocation: Field(5345),
            // Incorrect checksum again
            checkSum: Field(0),
        }
        prevMessageNumber = UInt64.from(24);
        ok = zkApp.isValid(messageInvalid1, prevMessageNumber);
        expect(ok.toBoolean()).toBeTruthy();

        // And finally - make sure vanilla invalid message still fails
        prevMessageNumber = UInt64.from(22);
        ok = zkApp.isValid(messageInvalid1, prevMessageNumber);
        expect(ok.toBoolean()).toBeFalsy();
    })


    it('dispatches message with dispatchIfValid()', async () => {
        await localDeploy();

        const prevMessageNumber = UInt64.from(22);
        const messageValid: SecretMessage = {
            messageNumber: UInt64.from(23),
            agentId: Field(100),
            agentXLocation: Field(123),
            agentYLocation: Field(5345),
            checkSum: Field(5568),
        }
        const messageInvalid: SecretMessage = {
            messageNumber: UInt64.from(24),
            agentId: Field(20),
            agentXLocation: Field(123),
            agentYLocation: Field(5345),
            // Incorrect checksum
            checkSum: Field(0),
        }

        const txn0 = await Mina.transaction(adminAccount, () => {
            zkApp.dispatchIfValid(adminKey, messageValid, prevMessageNumber)
        });
        await txn0.prove();
        await txn0.sign([adminKey]).send();

        const txn1 = await Mina.transaction(adminAccount, () => {
            zkApp.dispatchIfValid(adminKey, messageInvalid, prevMessageNumber)
        });
        await txn1.prove();
        await txn1.sign([adminKey]).send();

        const pendingActions = zkApp.reducer.getActions();
        // So first one should be valid, with messageNumber of 23
        const pa0 = pendingActions[0][0];
        // Second one should be invalid, with messageNumber of 24
        const pa1 = pendingActions[1][0];
        expect(pa0.isValid.toBoolean()).toBeTruthy();
        expect(pa1.isValid.toBoolean()).toBeFalsy();
        expect(pa0.messageNumber).toEqual(UInt64.from(23));
        expect(pa1.messageNumber).toEqual(UInt64.from(24));
    })

    it('reduces batch with runReduce()', async () => {
        await localDeploy();

        // Add 4 valid messages, one invalid message
        const messageValid0: SecretMessage = {
            messageNumber: UInt64.from(1),
            agentId: Field(100),
            agentXLocation: Field(123),
            agentYLocation: Field(5345),
            checkSum: Field(5568),
        }
        const messageValid1: SecretMessage = {
            messageNumber: UInt64.from(2),
            agentId: Field(100),
            agentXLocation: Field(123),
            agentYLocation: Field(5345),
            checkSum: Field(5568),
        }
        const messageValid2: SecretMessage = {
            messageNumber: UInt64.from(3),
            agentId: Field(100),
            agentXLocation: Field(123),
            agentYLocation: Field(5345),
            checkSum: Field(5568),
        }
        const messageValid3: SecretMessage = {
            messageNumber: UInt64.from(4),
            agentId: Field(100),
            agentXLocation: Field(123),
            agentYLocation: Field(5345),
            checkSum: Field(5568),
        }
        const messageInvalid: SecretMessage = {
            messageNumber: UInt64.from(5),
            agentId: Field(20),
            agentXLocation: Field(123),
            agentYLocation: Field(5345),
            // Incorrect checksum
            checkSum: Field(0),
        }

        const txn0 = await Mina.transaction(adminAccount, () => {
            zkApp.dispatchIfValid(adminKey, messageValid0, UInt64.from(0))
        });
        await txn0.prove();
        await txn0.sign([adminKey]).send();

        const txn1 = await Mina.transaction(adminAccount, () => {
            zkApp.dispatchIfValid(adminKey, messageValid1, messageValid0.messageNumber)
        });
        await txn1.prove();
        await txn1.sign([adminKey]).send();

        const txn2 = await Mina.transaction(adminAccount, () => {
            zkApp.dispatchIfValid(adminKey, messageValid2, messageValid1.messageNumber)
        });
        await txn2.prove();
        await txn2.sign([adminKey]).send();

        const txn3 = await Mina.transaction(adminAccount, () => {
            zkApp.dispatchIfValid(adminKey, messageValid3, messageValid2.messageNumber)
        });
        await txn3.prove();
        await txn3.sign([adminKey]).send();

        const txn4 = await Mina.transaction(adminAccount, () => {
            zkApp.dispatchIfValid(adminKey, messageInvalid, messageValid3.messageNumber)
        });
        await txn4.prove();
        await txn4.sign([adminKey]).send();

        // Now reduce and we should see 
        const txn5 = await Mina.transaction(adminAccount, () => {
            zkApp.runReduce(adminKey, Bool(false))
        });
        await txn5.prove();
        await txn5.sign([adminKey]).send();

        // message 5 was invalid so it should equal 4
        const messageNum = zkApp.messageNumber.get();
        expect(messageNum).toEqual(UInt64.from(4));

        // And now confirm that our setup works as expectd:
        // Processing batch should completely overwrite the previous message number,
        // even if highest number in that batch is lower
        // So test it by resubmitting the same batch except for messageNumber 4

        const txn6 = await Mina.transaction(adminAccount, () => {
            zkApp.dispatchIfValid(adminKey, messageValid0, UInt64.from(0))
        });
        await txn6.prove();
        await txn6.sign([adminKey]).send();

        const txn7 = await Mina.transaction(adminAccount, () => {
            zkApp.dispatchIfValid(adminKey, messageValid1, messageValid0.messageNumber)
        });
        await txn7.prove();
        await txn7.sign([adminKey]).send();

        const txn8 = await Mina.transaction(adminAccount, () => {
            zkApp.dispatchIfValid(adminKey, messageValid2, messageValid1.messageNumber)
        });
        await txn8.prove();
        await txn8.sign([adminKey]).send();

        const txn9 = await Mina.transaction(adminAccount, () => {
            zkApp.dispatchIfValid(adminKey, messageInvalid, messageValid2.messageNumber)
        });
        await txn9.prove();
        await txn9.sign([adminKey]).send();

        // Now reduce and we should see 
        const txn10 = await Mina.transaction(adminAccount, () => {
            zkApp.runReduce(adminKey, Bool(false))
        });
        await txn10.prove();
        await txn10.sign([adminKey]).send();

        const messageNumFinal = zkApp.messageNumber.get();
        expect(messageNumFinal).toEqual(UInt64.from(3));

        // Make sure splitBatch logic works -
        // If we add more messages with numbers LOWER than 3, it should NOT change
        // if they're part of the same batch!

        const txn11 = await Mina.transaction(adminAccount, () => {
            zkApp.dispatchIfValid(adminKey, messageValid0, UInt64.from(0))
        });
        await txn11.prove();
        await txn11.sign([adminKey]).send();

        const txn12 = await Mina.transaction(adminAccount, () => {
            zkApp.dispatchIfValid(adminKey, messageValid1, messageValid0.messageNumber)
        });
        await txn12.prove();
        await txn12.sign([adminKey]).send();

        const txn13 = await Mina.transaction(adminAccount, () => {
            // calling with splitBatch = true
            zkApp.runReduce(adminKey, Bool(true))
        });
        await txn13.prove();
        await txn13.sign([adminKey]).send();

        const messageNumSame = zkApp.messageNumber.get();
        expect(messageNumSame).toEqual(UInt64.from(3));
    })

    it('passes integration test using processBatch()', async () => {
        await localDeploy();

        // Process two batches, make sure each one works...
        let maxMessageNum = 20;
        let numMessages = 15;
        const batchLimit1 = 10;
        const batch1: SecretMessage[] = buildBatch(maxMessageNum, numMessages)
        maxMessageNum = 30
        numMessages = 20;
        const batchLimit2 = 30;
        const batch2: SecretMessage[] = buildBatch(maxMessageNum, numMessages)
        maxMessageNum = 10;
        numMessages = 5;
        const batchLimit3 = 10;
        const batch3: SecretMessage[] = buildBatch(maxMessageNum, numMessages)

        // set batchLimit to 10 so we split batch into two...
        await processBatch(batch1, batchLimit1, zkApp, adminAccount, adminKey)
        let messageNum = zkApp.messageNumber.get();
        expect(messageNum).toEqual(UInt64.from(20));

        await processBatch(batch2, batchLimit2, zkApp, adminAccount, adminKey)
        messageNum = zkApp.messageNumber.get();
        expect(messageNum).toEqual(UInt64.from(30));

        await processBatch(batch3, batchLimit3, zkApp, adminAccount, adminKey)
        messageNum = zkApp.messageNumber.get();
        expect(messageNum).toEqual(UInt64.from(10));
    })

});
