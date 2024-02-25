import { Mina, Field, Reducer, Struct, SmartContract, state, State, method, Bool, Provable, UInt64, PrivateKey, PublicKey, Poseidon } from 'o1js';

// SecretMessage will be the input to the contract. In order to satisfy this condition:
// "The message details should be private inputs."
// We will verify the validity of the message, but then ONLY save the messageNumber
// for the reducer to process.
export class SecretMessage extends Struct({ messageNumber: UInt64, agentId: Field, agentXLocation: Field, agentYLocation: Field, checkSum: Field }) { }

// This will be the format of the message saved for the reducer to process
export class PublicMessage extends Struct({ isValid: Bool, messageNumber: UInt64 }) { }

// Helper function for processing batch of messages
export async function processBatch(batch: SecretMessage[],
    batchLimit: number,
    zkApp: BatchMessages,
    adminAccount: PublicKey,
    adminKey: PrivateKey) {
    // batchLimit is a parameter to subdivide the batch in order to allow
    // for running on low spec hardware

    let prevMessageNumber: UInt64 = UInt64.from(0);
    let counter = 0;
    let splitBatch = Bool(false);

    for (const message of batch) {
        const txn = await Mina.transaction(adminAccount, () => {
            zkApp.dispatchIfValid(adminKey, message, prevMessageNumber)
        });
        await txn.prove();
        await txn.sign([adminKey]).send();
        counter += 1

        prevMessageNumber = message.messageNumber;

        // Repeatedly reduce whenever we exceed batchLimit
        if (counter >= batchLimit) {
            const txn = await Mina.transaction(adminAccount, () => {
                zkApp.runReduce(adminKey, splitBatch)
            });
            await txn.prove();
            await txn.sign([adminKey]).send();
            // After the FIRST time we runReduce, we need to run with runReduce
            // the rest of the time...
            splitBatch = Bool(true);
            // And reset counter...
            counter = 0;
        }
    }

    // Edge case would be we runReduce due to batch limit and have no other transactions
    if (counter > 0) {
        const txn = await Mina.transaction(adminAccount, () => {
            zkApp.runReduce(adminKey, splitBatch)
        });
        await txn.prove();
        await txn.sign([adminKey]).send();
    }
}


export class BatchMessages extends SmartContract {
    // Highest message number received...
    @state(UInt64) messageNumber = State<UInt64>();
    // Store the action state so we can efficiently filter out the actions that have already been processed
    @state(Field) actionState = State<Field>();
    @state(Field) adminHash = State<Field>();

    reducer = Reducer({ actionType: PublicMessage });

    init() {
        super.init();
        this.messageNumber.set(UInt64.from(0));
        // Initialize with initialActionState so we can always filter based on this param
        this.actionState.set(Reducer.initialActionState);
    }

    getPKeyHash(pKey: PrivateKey): Field {
        return Poseidon.hash(pKey.toPublicKey().toFields());
    }

    // Not explicitly a part of the instructions but seems like we'd want to restrict access to admit
    @method setAdmin(pKey: PrivateKey) {
        // If it's anything besides 0 it was already set
        const adminHash = this.adminHash.getAndRequireEquals();
        adminHash.assertEquals(Field(0)), "Admin already set";
        // needs to be called immediately after init to set the admin
        const adminHashWrite: Field = this.getPKeyHash(pKey)
        this.adminHash.set(adminHashWrite)
    }

    @method dispatchIfValid(pKey: PrivateKey, message: SecretMessage, prevMessageNumber: UInt64) {
        // Admin check...
        const adminHash = this.adminHash.getAndRequireEquals();
        adminHash.assertNotEquals(Field(0)), "Admin not set";
        adminHash.assertEquals(this.getPKeyHash(pKey)), "Wrong admin key";


        const validBool = this.isValid(message, prevMessageNumber);
        this.reducer.dispatch({ isValid: validBool, messageNumber: message.messageNumber });
    }

    isValid(message: SecretMessage, prevMessageNumber: UInt64): Bool {

        // In case the message number is not greater than the previous one, 
        // this means that this is a duplicate message.  
        // In this case it still should be processed but the message details 
        // do not need to be checked.
        const duplicateMessage = message.messageNumber.greaterThan(prevMessageNumber).not();
        // If Agent ID is zero we don't need to check the other values, but this is still a valid message
        const agent0 = message.agentId.equals(0);

        const check1 = this.checksumCheck(message.agentId, message.agentXLocation, message.agentYLocation, message.checkSum);
        const check2 = this.rangeCheck(message.agentId, message.agentXLocation, message.agentYLocation);
        const checksOk: Bool = check1.and(check2);

        // agent0 or duplicateMessage = automatic approval
        // If both of those are false, then checksOk must be true
        // So condition is: duplicateMessage OR agent0 OR checksOk
        const wasValid = agent0.or(duplicateMessage).or(checksOk);
        return wasValid;
    }

    rangeCheck(agentId: Field, agentXLocation: Field, agentYLocation: Field): Bool {
        // the 4 message details numbers are in the correct range
        // Agent ID (should be between 0 and 3000)
        // Agent XLocation (should be between 0 and 15000)
        // Agent YLocation (should be between 5000 and 20000
        // Agent YLocation should be greater than Agent XLocation
        const cond1 = agentId.greaterThanOrEqual(0).and(agentId.lessThanOrEqual(3000));
        const cond2 = agentXLocation.greaterThanOrEqual(0).and(agentXLocation.lessThanOrEqual(15000));
        const cond3 = agentYLocation.greaterThanOrEqual(5000).and(agentYLocation.lessThanOrEqual(20000));
        const cond4 = agentYLocation.greaterThan(agentXLocation);
        const condAll = cond1.and(cond2).and(cond3).and(cond4);
        return condAll;
    }

    checksumCheck(agentId: Field, agentXLocation: Field, agentYLocation: Field, checkSum: Field): Bool {
        // CheckSum is the sum of Agent ID, Agent XLocation ,and Agent YLocation
        const checkSumExpected = agentId.add(agentXLocation).add(agentYLocation);
        return checkSum.equals(checkSumExpected);
    }

    @method runReduce(pKey: PrivateKey, splitBatch: Bool) {
        // Admin check...
        const adminHash = this.adminHash.getAndRequireEquals();
        adminHash.assertNotEquals(Field(0)), "Admin not set";
        adminHash.assertEquals(this.getPKeyHash(pKey)), "Wrong admin key";

        // In order to satisfy this condition:
        // --- This program is needed to run on low spec hardware so you need to find a 
        // --- way to process the batch so that the circuit size remains low.
        // We have the functionality to subdivide a batch while still processing
        // it as a single batch, which will keep circuit size low.
        // This only difference is that if 'splitBatch' is true, we need to
        // continue on from the previously committed messageNumber.
        // If it's false, we start from 0.

        const actionState = this.actionState.getAndRequireEquals();

        // Interpreting instructions to mean that we find/process highest
        // message number in each batch - even if it's lower than the previously
        // committed message number!
        // So setting initial state to be 0, lowest possible message number
        // and then processing all messages in the batch

        const pendingActions = this.reducer.getActions({
            fromActionState: actionState,
        });

        // So if it's a split batch - it means we need to continue on from the
        // previously committed messageNumber.
        // Otherwise start from 0.
        const messageNumber = this.messageNumber.getAndRequireEquals();
        const startMessageNumber: UInt64 = Provable.if(splitBatch, messageNumber, UInt64.from(0))

        const initial = {
            state: startMessageNumber,
            actionState: actionState,
        }

        let { state: newMessage, actionState: newActionState } = this.reducer.reduce(
            pendingActions,
            // state type we're aggregating over - we just want the max messageNumber, which is UInt64
            UInt64,
            // function that says how to apply an action
            (state: UInt64, action: PublicMessage) => {
                // So if our action 'isValid' bool is true, then take max...
                const maxValue = Provable.if(state.greaterThan(action.messageNumber), state, action.messageNumber);
                const retValue = Provable.if(action.isValid, maxValue, state);
                return retValue;
            },
            initial
        );

        this.messageNumber.set(newMessage);
        this.actionState.set(newActionState);
    }
}