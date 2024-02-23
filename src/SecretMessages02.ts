import { Field, Reducer, Struct, SmartContract, state, State, method, Bool, Provable, UInt64 } from 'o1js';


export class SecretMessage extends Struct({ messageNumber: UInt64, agentId: Field, agentXLocation: Field, agentYLocation: Field, checkSum: Field }) {
    // Can we move the other functions into here?
    static isValid(message: SecretMessage): Bool {
        return Bool(true);
    }
}


export class BatchMessages extends SmartContract {
    // Highest message number received...
    @state(UInt64) messageNumber = State<UInt64>();
    reducer = Reducer({ actionType: SecretMessage });

    init() {
        super.init();
        this.messageNumber.set(UInt64.from(0));
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


    @method validateMessage(messageNumber: UInt64, agentId: Field, agentXLocation: Field, agentYLocation: Field, checkSum: Field) {
        const check1 = this.checksumCheck(agentId, agentXLocation, agentYLocation, checkSum);
        const check2 = this.rangeCheck(agentId, agentXLocation, agentYLocation);
        const checksOk: Bool = check1.and(check2);

        // If Agent ID is zero we don't need to check the other values, but this is still a valid message
        agentId.equals(0).or(checksOk).assertTrue("Invalid message");

        this.messageNumber.set(messageNumber);
    }

}