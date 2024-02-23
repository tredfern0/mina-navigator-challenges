import { Field, Reducer, Struct, SmartContract, state, State, method, Bool, Provable, UInt64 } from 'o1js';

// SecretMessage will be the input to the contract. In order to satisfy this condition:
// "The message details should be private inputs."
// We will verify the validity of the message, but then ONLY save the messageNumber
// for the reducer to process.
export class SecretMessage extends Struct({ messageNumber: UInt64, agentId: Field, agentXLocation: Field, agentYLocation: Field, checkSum: Field }) { }

// This will be the format of the message saved for the reducer to process
export class PublicMessage extends Struct({ isValid: Bool, messageNumber: UInt64 }) { }


// 2. This program is needed to run on low spec hardware so you need to find a way to process the batch so that the circuit size remains low.

export class BatchMessages extends SmartContract {
    // Highest message number received...
    @state(UInt64) messageNumber = State<UInt64>();
    // Store the action state so we can efficiently filter out the actions that have already been processed
    @state(Field) actionState = State<Field>();

    // reducer = Reducer({ actionType: SecretMessage });
    reducer = Reducer({ actionType: PublicMessage });

    init() {
        super.init();
        this.messageNumber.set(UInt64.from(0));
    }

    @method dispatchIfValid(message: SecretMessage, prevMessageNumber: UInt64) {
        const validBool = this.isValid(message, prevMessageNumber);
        this.reducer.dispatch({ isValid: validBool, messageNumber: message.messageNumber });
    }

    isValid(message: SecretMessage, prevMessageNumber: UInt64): Bool {
        // In case the message number is not greater than the previous one, 
        // this means that this is a duplicate message.  
        // In this case it still should be processed but the message details 
        // do not need to be checked.
        const messageNew = message.messageNumber.greaterThan(prevMessageNumber);
        // If Agent ID is zero we don't need to check the other values, but this is still a valid message
        const agent0 = message.agentId.equals(0);

        const check1 = this.checksumCheck(message.agentId, message.agentXLocation, message.agentYLocation, message.checkSum);
        const check2 = this.rangeCheck(message.agentId, message.agentXLocation, message.agentYLocation);
        const checksOk: Bool = check1.and(check2);

        // agent0 or messageNew = automatic approval
        // If both of those are false, then checksOk must be true
        // So condition is: messageNew OR agent0 OR checksOk
        const wasValid = agent0.or(messageNew).or(checksOk);
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

    @method runReduce(splitBatch: Bool) {

        const actionState = this.actionState.getAndRequireEquals();

        // Interpreting instructions to mean that we find/process highest
        // message number in each batch - even if it's lower than the previously
        // committed message number!
        // So setting initial state to be 0, lowest possible message number
        // and then processing all messages in the batch
        // So we will not event get messageNumber - we'll just overwrite it
        // const messageNumber = this.messageNumber.getAndRequireEquals();

        const pendingActions = this.reducer.getActions({
            fromActionState: actionState,
        });

        const initial = {
            state: UInt64.from(0),
            // TODO - understand what exactly this is...
            actionState: Reducer.initialActionState,
        }

        let { state: newMessage, actionState: newActionState } = this.reducer.reduce(
            pendingActions,
            // state type
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

        this.messageNumber.set(newMessage.messageNumber);
        this.actionState.set(newActionState);
    }
}