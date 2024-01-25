import { Field, Gadgets, SmartContract, state, State, method, Bool, Provable, UInt64, PublicKey, PrivateKey, MerkleMapWitness, MerkleMap } from 'o1js';


export class SecretMessages extends SmartContract {
  @state(UInt64) numAddresses = State<UInt64>();
  @state(UInt64) messagesReceived = State<UInt64>();
  @state(Field) mapRoot = State<Field>();

  events = {
    "message-received": Field,
  }

  init() {
    super.init();
    this.messagesReceived.set(UInt64.from(0));
    this.numAddresses.set(UInt64.from(0));

    // Initialize empty map to store addresses
    const map = new MerkleMap();
    this.mapRoot.set(map.getRoot());
  }

  @method storeAddress(address: Field) {
    /*
    There will be a maximum of 100 eligible addresses.
    You need to write a function in a contract to store the
    addresses, the function will have one parameter which is
    the address.
    Eligible addresses should be stored in a suitable data
    structure.
    */

    // TODO - restrict access to administrator...
    const numAddresses = this.numAddresses.getAndRequireEquals();
    // if it's 99 we can still add one more, so LT 100 is correct condition
    numAddresses.assertLessThan(UInt64.from(100)), "Too many addresses";

    // Use a merkle map to store addresses
    this.numAddresses.set(numAddresses.add(1));
  }

  buildFlags(message: Field): [Bool, Bool, Bool, Bool, Bool, Bool] {
    /*
    The message contains 6 flags at the end, each of size 1
    bit. The rest of the message can be any number.
    You need to write a function to store the messages, the
    function will have one parameter which is the message.
    The message should be a Field, we use the last 6 bits as
    flags.
    */

    const bit6 = Field(1);    // ... 000001 = 1
    const bit5 = Field(2);    // ... 000010 = 2
    const bit4 = Field(4);    // ... 000100 = 4
    const bit3 = Field(8);    // ... 001000 = 8
    const bit2 = Field(16);   // ... 010000 = 16
    const bit1 = Field(32);   // ... 100000 = 32

    const g6 = Gadgets.and(message, bit6, 1);    // ... 000001
    const g5 = Gadgets.and(message, bit5, 2);    // ... 000010
    const g4 = Gadgets.and(message, bit4, 3);    // ... 000100
    const g3 = Gadgets.and(message, bit3, 4);    // ... 001000
    const g2 = Gadgets.and(message, bit2, 5);    // ... 010000
    const g1 = Gadgets.and(message, bit1, 6);    // ... 100000

    const flag6: Bool = g6.equals(bit6);
    const flag5: Bool = g5.equals(bit5);
    const flag4: Bool = g4.equals(bit4);
    const flag3: Bool = g3.equals(bit3);
    const flag2: Bool = g2.equals(bit2);
    const flag1: Bool = g1.equals(bit1);

    return [flag1, flag2, flag3, flag4, flag5, flag6]
  }


  validateFlags(
    _flag1: Bool,
    flag2: Bool,
    flag3: Bool,
    flag4: Bool,
    flag5: Bool,
    flag6: Bool,
  ): Bool {
    /*
    3. The flags should be checked according to the following
    If flag 2 is true, then flag 3 must also be true.
    If flag 4 is true, then flags 5 and 6 must be false.
    */

    // If flag 2 is true, then flag 3 must also be true.
    const cond1: Bool = Provable.if(
      flag2.equals(true),
      flag3.equals(true),
      Bool(true)
    )

    // If flag 4 is true, then flags 5 and 6 must be false.
    const cond2: Bool = Provable.if(
      flag4.equals(true),
      flag5.equals(false).and(flag6.equals(false)),
      Bool(true)
    )
    return cond1.and(cond2)
  }

  @method storeMessage(
    keyWitness: MerkleMapWitness,
    keyToChange: Field,
    messageBefore: Field,
    messageAfterWFlags: Field,
  ) {
    const [flag1, flag2, flag3, flag4, flag5, flag6] = this.buildFlags(messageAfterWFlags);
    const flagsOk: Bool = this.validateFlags(flag1, flag2, flag3, flag4, flag5, flag6)
    flagsOk.assertTrue("Invalid flags!");

    // Get rid of the bits
    const messageAfter = Gadgets.rightShift(messageAfterWFlags, 6);

    ////  Merkle Map update logic
    const mapRoot = this.mapRoot.getAndRequireEquals();
    // check the initial state matches what we expect
    const [rootBefore, key] = keyWitness.computeRootAndKey(messageBefore);
    rootBefore.assertEquals(mapRoot);
    key.assertEquals(keyToChange);
    // compute the root after updating
    const [rootAfter, _] = keyWitness.computeRootAndKey(messageAfter);
    this.mapRoot.set(rootAfter);
  }

}