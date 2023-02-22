# Introduction
The audit of **Litra protocol** was done by [**Ian Miller**](https://t.me/J0anix)
# Litra
## Project overview
Litra is a dao governance protocol built on Aragon framework that allows users to vote for any change in the protocol using the native ERC20 Litra Token (LA)

1.  **DAO**. The governance of protocol is managed and controlled by admin of contracts. He is responsible for mint and burn process.
2.  **Litra Token**. Litra Token (LA) is ERC20 token is used in voting process.
# Finding Severity breakdown
All vulnerabilities discovered during the audit are classified based on their potential severity and have the following classification:

Severity | Description
--- | ---
Critical | Bugs leading to assets theft, fund access locking, or any other loss funds to be transferred to any party.
High     | Bugs that can trigger a contract failure. Further recovery is possible only by manual modification of the contract state or replacement.
Medium   | Bugs that can break the intended contract logic or expose it to DoS attacks, but do not cause direct loss funds.
Low   | Bugs that can not significantly affect the operation of the protocol and can be easily fixed. Basically, these are recommendations for improving the code.

# Security Assessment Summary

**_review commit hash_ - [26eb98aa2709707db72c9d9d065eba7f6616486c](https://github.com/litrafi/litra-contract)**
The following number of issues were found, categorized by their severity:
-   High: 1 issue
-   Medium: 4 issues
-   Low: 37 issues

# Findings
| ID     | Title                                                                                        | Severity      |
| ------ | -------------------------------------------------------------------------------------------- | ------------- |
| [H-01] | Functions from interfaces are not implemented in`SimpleBurner.sol` | High          |
| [M-01] | Transfer zero amount can be reverted                     | Medium        |
| [M-02] | Use ``safeCast`` for changing types                     | Medium        |
| [M-03] | You should add ``365 days``                     | Medium        |
| [M-04] | Call to ``mintableInTimeframe()`` in ``contracts/LA.sol`` errored                    | Medium        |
| [L-01] | Unused import `SafeMath.sol` in `contracts/WrappedNFT.sol`                                    | Low           |
| [L-02] | ``safeMint()`` should be used rather than ``mint()`` wherever possible                                                  | Low           |
| [L-03] | Use custom errors rather than ``revert()``/``require()`` strings to save gas                                                 | Low           |
| [L-04] | There’s no need to set default values for variables    | Low           |
| [L-05] | Draft Openzeppelin Dependencies                                    | Low           |
| [L-06] | Using storage instead of memory for structs/arrays saves gas                                   | Low           |
| [L-07] | Immutable addresses lack zero-address check                                  | Low   
| [L-08] | Missing contract-existence checks before low-level calls                                  | Low
| [L-09] | Unsafe use of transfer()/transferFrom() with IERC20                           | Low
| [L-10] | Unchecked return value of ``transferFrom()`` can allow a user to withdraw native token for free                     | Low         
| [L-11] | The contract should ``approve(0)`` first                         | Low
| [L-12] | ``constructor`` should be ``payable``                        | Low
| [L-13] | Ownership may be burned                      | Low
| [L-14] | SPDX license identifier not provided                        | Low
| [L-15] | Using ``e`` is more gas efficient than ``**``for exponentiation                      | Low
| [L-16] | Use ``private`` rather than ``public`` for constants                      | Low
| [L-17] | ``bytes32`` constants are more efficient than string constants                    | Low
| [L-18] | Usage of ``uint/int`` smaller than 32 bytes (256 bits) incurs overhead                      | Low
| [L-19] | Events should be ``indexed``                   | Low
| [L-20] | Splitting ``require()`` statements that use ``&&`` saves gas                      | Low
| [L-21] | Use ``require`` instead of ``assert``                       | Low
| [L-22] | Use previously created modifiers instead of repeating the same require statements                 | Low
| [L-23] | Use ``safeDecimals()``                      | Low
| [L-24] | Add Timelock to critical functions                      | Low
| [L-25] | Use ``assembly`` for simple setters functions                     | Low
| [L-26] | Loss of precision                     | Low
| [L-27] | Don't create a new state variable with the same value                      | Low
| [L-28] | You shouldn't use ``_msgSender()``                     | Low
| [L-29] | Unchecking arithmetics operations that can’t underflow/overflow                    | Low
| [L-30] | ``<x> += <y>`` costs more gas than ``<x> = <x> + <y>``                   | Low
| [L-31] | You don't need to define variable with default value                | Low
| [L-32] | ``++i/i++`` Should Be ``unchecked{++i}/unchecked{i++}``                   | Low
| [L-33] | Underflow variable in ``contracts/LA.sol``                   | Low
| [L-34] | Functions guaranteed to revert when called by normal users can be marked ``payable``             | Low
| [L-35] | Use ``assembly`` for zero checking                   | Low
| [L-36] | Error in name of function                   | Low
| [L-37] | There is no check that token already exists                 | Low
# Detailed Findings
### Critical
Not found
### High
#### [H-01]  FUNCTIONS_FROM_INTERFACES_ARE_ NOT_IMPLEMENTED_IN_``SimpleBurner.sol``
#####  Description
Function ``exchange()`` and ``find_pool_for_coins()`` that are inherited from interface ``ICurvePool``, ``IPoolFactory`` are using in ``contracts/SimpleBurner.sol`` without some implementation and realization of business logic in this contract that can lead to trigger a contract failure. In this case, pool will be not created and found for coins. Also, exchange logic will not be provided and  function``burn()`` does not work as intended.
https://github.com/litrafi/litra-contract/blob/main/contracts/interfaces/ICurve.sol#:~:text=interface%20ICurvePool%20%7B,%7D
https://github.com/litrafi/litra-contract/blob/main/contracts/interfaces/ICurve.sol#:~:text=interface%20IPoolFactory%20%7B,%7D
https://github.com/litrafi/litra-contract/blob/main/contracts/dao/burner/SimpleBurner.sol#:~:text=address%20poolAddr%20%3D%20IPoolFactory(poolFactory).find_pool_for_coins(_wnft%2C%20weth)%3B
https://github.com/litrafi/litra-contract/blob/main/contracts/dao/burner/SimpleBurner.sol#:~:text=address%20token0%20%3D%20pool.coins(0)%3B
https://github.com/litrafi/litra-contract/blob/main/contracts/dao/burner/SimpleBurner.sol#:~:text=pool.exchange(i%2C%20j%2C%20inAmount%2C%200%2C%20true%2C%20receiver)%3B
```solidity
interface  ICurvePool {
    function  exchange(uint256 i, uint256 j, uint256 dx, uint256 minDy, bool
    use_eth, address  payable _receiver) external  payable;
    function  coins(uint256 i) external  view  returns(address);
}
```
```solidity
interface  IPoolFactory {
    function  find_pool_for_coins(address _from, address _to) external  view
          returns(address);
}
```
```solidity
address poolAddr = IPoolFactory(poolFactory).find_pool_for_coins(_wnft, weth);
```
```solidity
address token0 = pool.coins(0);
```
```solidity
pool.exchange(i, j, inAmount, 0, true, receiver);
```
#####  Recommendation
Developers should define, override functions in ``SimpleBurner.sol`` from inherited interfaces and create business logic. Then, add these functions in order to provide the main functionality in ``burn()``

### Medium
#### [M-01]TRANSFER_ZERO_AMOUNT_CAN_BE_REVERTED  
##### Description
Now there are no checks for the amounts to be transferred via ``burn``  using ``transferFrom``in ``SimpleBurner`` . As token list is external and an arbitrary token can end up there, in the case when such token doesn't allow for zero amount transfers, the reward retrieval can become unavailable.
https://github.com/litrafi/litra-contract/blob/main/contracts/dao/burner/SimpleBurner.sol#:~:text=function%20burn(,this)%2C%20inAmount)%3B
```solidity
function burn(address _wnft) external override onlyNotStopped {
     uint256 inAmount = IERC20(_wnft).balanceOf(msg.sender);
     IERC20(_wnft).transferFrom(msg.sender, address(this), inAmount);
```
##### Recommendation
Consider running the ``transferFrom`` in ``burn()`` only when ``inAmount`` is positive:
```solidity
function burn(address _wnft) external override onlyNotStopped {
    if (inAmount > 0) {
         uint256 inAmount = IERC20(_wnft).balanceOf(msg.sender);
         IERC20(_wnft).transferFrom(msg.sender, address(this), inAmount);
         // find pool
         address poolAddr = IPoolFactory(poolFactory).find_pool_for_coins(_wnft, weth);
         ICurvePool pool = ICurvePool(poolAddr);
         uint256 i;
         uint256 j;
         address token0 = pool.coins(0);
         if(token0 == _wnft) {
            i = 0;
            j = 1;
         } else {
             i = 1;
             j = 0;
         }
         // swap for eth
         IERC20(_wnft).approve(poolAddr, inAmount);
         pool.exchange(i, j, inAmount, 0, true, receiver);
    }
}
```
####  [M-02] USE_ ``safeCast``_FOR_CHANGING_TYPES   
##### Description
A value that passed into the ``initialize``, ``_vote``, ``_decodeData`` functions, downcasting it to uint256 will silently overflow.
https://github.com/litrafi/litra-contract/blob/main/contracts/dao/Voting.sol#:~:text=uint256%20decimalsMul%20%3D%20uint256(10)%20**%20token.decimals()%3B
https://github.com/litrafi/litra-contract/blob/main/contracts/dao/Voting.sol#:~:text=uint256%20voterStake%20%3D%20uint256(2).mul(balance).mul(vote_.startDate.add(voteTime).sub(getTimestamp64())).div(voteTime)%3B
https://github.com/litrafi/litra-contract/blob/main/contracts/dao/Voting.sol#:~:text=return%20uint256((_value%20%3E%3E%20_shiftValue)%20%26%20_maskValue)%3B
```solidity
uint256 decimalsMul = uint256(10) ** token.decimals();
```
```solidity
uint256 voterStake = uint256(2).mul(balance).mul(vote_.startDate.add(voteTime).sub(getTimestamp64())).div(voteTime);
```
```solidity
return uint256((_value >> _shiftValue) & _maskValue);
```
##### Recommendation
Use a safe downcast function
```solidity
function _safeUint256(uint256 x) internal pure returns (uint256) {
    require(x <= uint256(type(uint256).max));
    return uint256(x);
}
```
#### [M-03] YOU_SHOULD_ADD_``365 days``    
##### Description
Not defining constant variable ``YEAR`` with ``86400 * 365 days`` leads to inaccurate calculation
https://github.com/litrafi/litra-contract/blob/main/contracts/dao/LA.sol#:~:text=uint256%20constant%20private%20YEAR%20%3D%2086400%20*%20365%3B
```solidity
uint256 constant private YEAR = 86400 * 365;
```
##### Recommendation
Better using ``365 days`` for more precise calculation
#### [M-04] CALL_TO_ ``mintableInTimeframe()`` _IN_ ``contracts/LA.sol``_EXECUTE_WITH_ERROR  
##### Description
Call to ``mintableInTimeframe()`` in ``contracts/LA.sol`` leads to `` VM error: revert``The transaction has been reverted to the initial state. 
https://github.com/litrafi/litra-contract/blob/main/contracts/dao/LA.sol#:~:text=function%20mintableInTimeframe(uint256%20start%2C%20uint256%20end)%20external%20view%20returns(uint256)%20%7B
```solidity
function mintableInTimeframe(uint256 start, uint256 end) external view returns(uint256) {
```
##### Recommendation
The called function should be payable if you send value and the value you send should be less than your current balance.
### Low
#### [L-01] UNUSED_IMPORT_`SafeMath.sol`_IN_`contracts/WrappedNFT.sol` 
##### Description
There are unused ``@openzeppelin/contracts/utils/math/SafeMath.sol`` in ``contract/WrappedNFT.sol``
##### Recommendation
If you don't use ``@openzeppelin/contracts/utils/math/SafeMath.sol`` in contract, you should delete this line of code
#### [L-02]  ``safeMint()``_SHOULD_ __BE_USED_RATHER_THAN___``mint()``_WHEREVER_POSSIBLE     
##### Description
_mint() is [discouraged](https://github.com/OpenZeppelin/openzeppelin-contracts/blob/d4d8d2ed9798cc3383912a23b5e8d5cb602f7d4b/contracts/token/ERC721/ERC721.sol#L271) in favor of _safeMint() which ensures that the recipient is either an EOA or implements IERC721Receiver. Both [OpenZeppelin](https://github.com/OpenZeppelin/openzeppelin-contracts/blob/d4d8d2ed9798cc3383912a23b5e8d5cb602f7d4b/contracts/token/ERC721/ERC721.sol#L238-L250) and [solmate](https://github.com/Rari-Capital/solmate/blob/4eaf6b68202e36f67cab379768ac6be304c8ebde/src/tokens/ERC721.sol#L180) have versions of this function
https://github.com/litrafi/litra-contract/blob/main/contracts/dao/LA.sol#:~:text=_mint(_msgSender()%2C%20initSupply)%3B
https://github.com/litrafi/litra-contract/blob/main/contracts/dao/LA.sol#:~:text=%7D-,_mint(_to%2C%20_value)%3B,-%7D
https://github.com/litrafi/litra-contract/blob/main/contracts/tokenize/WrappedNFT.sol#:~:text=_mint(_for%2C%20_amount)%3B
```solidity
_mint(_to, _value);
```
```solidity
_mint(_msgSender(), initSupply);
```
```solidity
_mint(_for, _amount);
```
##### Recommendation
Use:
```solidity
function _safeMint(address to, uint256 tokenId) internal virtual { _safeMint(to, tokenId, ""); } /** * @dev Same as {xref-ERC721-_safeMint-address-uint256-}[`_safeMint`], with an additional `data` parameter which is * forwarded in {IERC721Receiver-onERC721Received} to contract recipients. */ function _safeMint( address to, uint256 tokenId, bytes memory _data ) internal virtual { _mint(to, tokenId); require( _checkOnERC721Received(address(0), to, tokenId, _data), "ERC721: transfer to non ERC721Receiver implementer" ); }
```
#### [L-03] USE_CUSTOM_ERRORS_RATHER_THAN_``revert()``/``require()``_STRINGS_TO_SAVE_GAS
##### Description
Custom errors are available from solidity version 0.8.4. Custom errors save ~50 gas each time they’re avoiding having to allocate and store the revert string. Not defining the strings also save deployment gas.
https://github.com/litrafi/litra-contract/blob/main/contracts/tokenize/WrappedNFT.sol#:~:text=function%20mint(,%22!creator%22)%3B
https://github.com/litrafi/litra-contract/blob/main/contracts/tokenize/WrappedNFT.sol#:~:text=function%20burn(,%22!creator%22)%3B
https://github.com/litrafi/litra-contract/blob/main/contracts/dao/Voting.sol#:~:text=require(_minBalance%20%3E%3D%20minBalanceLowerLimit%20%26%26%20_minBalance%20%3C%3D%20minBalanceUpperLimit%2C%20%22Min%20balance%20should%20be%20within%20initialization%20hardcoded%20limits%22)%3B
https://github.com/litrafi/litra-contract/blob/main/contracts/dao/Voting.sol#:~:text=require(_minTime%20%3E%3D%20minTimeLowerLimit%20%26%26%20_minTime%20%3C%3D%20minTimeUpperLimit%2C%20%22Min%20time%20should%20be%20within%20initialization%20hardcoded%20limits%22)%3B
```solidity
function mint(address _for, uint256 _amount) external {
    require(creator == msg.sender, "!creator");
```
```solidity
function burn(address _account, uint256 _amount) external {
    require(creator == msg.sender, "!creator");
```
```solidity
require(_minBalance >= minBalanceLowerLimit && _minBalance <= minBalanceUpperLimit, "Min balance should be within initialization hardcoded limits");
```
```solidity
require(_minTime >= minTimeLowerLimit && _minTime <= minTimeUpperLimit, "Min time should be within initialization hardcoded limits");
```
##### Recommendation
Use custom errors in order to save gas:
```solidity
error NotCreator();
```
```solidity
error MinBalanceHardcoded();
```
```solidity
error MinTimeHardcoded();
```
#### [L-04] THERE'S_NO_NEED_TO_SET_DEFAULT_VALUES_FOR_VARIABLES
##### Description
It's not necessary to define variable with setting default value to it because it increase cost of gas. If a variable is not set/initialized, the default value is assumed (0, false, 0x0 … depending on the data type). You are simply wasting gas if you directly initialize it with its default value.
https://github.com/litrafi/litra-contract/blob/main/contracts/dao/LA.sol#:~:text=function%20mintableInTimeframe(,%3D%200%3B
https://github.com/litrafi/litra-contract/blob/main/contracts/dao/LA.sol#:~:text=for%20(uint256%20index%20%3D%200%3B%20index%20%3C%201000%3B%20index%2B%2B)%20%7B
https://github.com/litrafi/litra-contract/blob/main/contracts/dao/LA.sol#:~:text=start%20%3E%20end%22)%3B-,uint256%20toMint%20%3D%200%3B,-uint256%20currentEpochTime%20%3D
```solidity
uint256 toMint = 0;
```
```solidity
for (uint256 index =  0; index <  1000; index++) {
```
##### Recommendation
Don't define state variables with default values:
```solidity
uint256 toMint;
```
```solidity
for (uint256 index; index <  1000; index++) {
```
#### [L-05] DRAFT_OPENZEPPELIN_DEPENDENCIES       
##### Description
``WrappedNFT.sol``contract utilised draft-ERC20PermitUpgradeable.sol , an OpenZeppelin contract. This contract is still a draft and is not considered ready for mainnet use. OpenZeppelin contracts may be considered draft contracts if they have not received adequate security auditing or are liable to change with future development.
https://github.com/litrafi/litra-contract/blob/main/contracts/tokenize/WrappedNFT.sol#:~:text=import%20%22%40openzeppelin/contracts/token/ERC20/extensions/draft%2DERC20Permit.sol%22%3B
```solidity
import "@openzeppelin/contracts/token/ERC20/extensions/draft-ERC20Permit.sol";
```
##### Recommendation
Don't use draft versions of ``Openzeppelin`` contracts
#### [L-06] USING_STORAGE_INSTEAD_OF_MEMORY_ FOR_STRUCTS/ARRAYS_SAVES_GAS 
##### Description
When fetching data from a storage location, assigning the data to a memory variable causes all fields of the struct/array to be read from storage, which incurs a Gcoldsload (2100 gas) for each field of the struct/array. If the fields are read from the new memory variable, they incur an additional MLOAD rather than a cheap stack read. Instead of declearing the variable with the memory keyword, declaring the variable with the storage keyword and caching any fields that need to be re-read in stack variables, will be much cheaper, only incuring the Gcoldsload for the fields actually read. The only time it makes sense to read the whole struct/array into a memory variable, is if the full struct/array is being returned by the function, is being passed to a function that requires memory, or if the array/struct is being read from another memory array/struct
https://github.com/litrafi/litra-contract/blob/main/contracts/interfaces/IConvex.sol#:~:text=LockedBalance%5B%5D%20memory%20lockData
```solidity
LockedBalance[] memory lockData
```
##### Recommendation
Use storage instead of memory for struct array for saving gas
```solidity
LockedBalance[] storage lockData
```
#### [L-07] IMMUTABLE_ADDRESS_LACK_ZERO-ADDRESS_CHECK   
##### Description
Constructors should check the address written in an immutable address variable is not the zero address.
Note: while it has been indicated by the sponsor input validation will be on the front-end side to relieve users from unnecessary gas spending, this issue here concerns constructor functions, when the contract is deployed by the team.
https://github.com/litrafi/litra-contract/blob/main/contracts/dao/burner/SimpleBurner.sol#:~:text=constructor(,%7D
```solidity
constructor(
    address _o,
    address _e,
    address  payable _receiver,
    address _weth,address _poolFactory
) OwnershipAdminManaged(_o) EmergencyAdminManaged(_e) {
     receiver = _receiver;
     weth = _weth;
     poolFactory = _poolFactory;
}
```
https://github.com/litrafi/litra-contract/blob/main/contracts/dao/admin/ParameterAdminManaged.sol#:~:text=constructor(address,%7D
```solidity
constructor(address _e) {
    parameterAdmin = _e;
}
```
https://github.com/litrafi/litra-contract/blob/main/contracts/dao/admin/OwnershipAdminManaged.sol#:~:text=constructor(address,%7D
```solidity
constructor(address _o) {
    ownershipAdmin = _o;
}
```
https://github.com/litrafi/litra-contract/blob/main/contracts/dao/admin/EmergencyAdminManaged.sol#:~:text=constructor(address,%7D
```solidity
constructor(address _e) {
     emergencyAdmin = _e;
}
```
##### Recommendation
Add a zero address check for the immutable variables aforementioned.
#### [L-08] MISSING_CONTRACT-EXISTENCE_CHECKS_BEFORE_LOW-LEVEL_CALLS 
##### Description
Low-level calls return success if there is no code present at the specified address. In addition to the zero-address checks, add a check to verify that ``<address>.code.length > 0``
https://github.com/litrafi/litra-contract/blob/main/contracts/dao/burner/SimpleBurner.sol#:~:text=function%20burn(,this)%2C%20inAmount)%3B
```solidity
function burn(address _wnft) external override onlyNotStopped {
    uint256 inAmount = IERC20(_wnft).balanceOf(msg.sender);
    IERC20(_wnft).transferFrom(msg.sender, address(this), inAmount);
```
##### Recommendation
```solidity
assembly { len := extcodesize(_wnft) } require(len == 0); _;
```
#### [L-09] UNSAFE_USE_OF_``transfer()``/``transferFrom()`` __WITH_IERC20
##### Description
Some tokens do not implement the ERC20 standard properly but are still accepted by most code that accepts ERC20 tokens. For example Tether (USDT)‘s ``transfer()`` and ``transferFrom()`` functions do not return booleans as the specification requires, and instead have no return value. When these sorts of tokens are cast to ``IERC20`` , their function signatures do not match and therefore the calls made, revert. 
https://github.com/litrafi/litra-contract/blob/main/contracts/dao/burner/SimpleBurner.sol#:~:text=IERC20(_wnft).transferFrom(msg.sender%2C%20address(this)%2C%20inAmount)%3B
```solidity
IERC20(_wnft).transferFrom(msg.sender, address(this), inAmount);
```
##### Recommendation
Use OpenZeppelin’s ``SafeERC20``’s ``safeTransfer()``/``safeTransferFrom()`` instead
#### [L-10] UNCHECKED_RETURN_VALUE_OF_ ``transferFrom()`` _CAN_ALLOW_AUSER_TO_WITHDRAW_NATIVE_TOKEN_FOR_FREE
##### Description
The ``SimpleBurner`` contract has a function ``burn()`` which calls an unsafe ``transferFrom()``. A call to ``transferFrom`` is frequently done without checking the results. For certain ERC20 tokens, if insufficient tokens are present, no revert occurs but a result of “false” is returned. As explained in **[](https://consensys.net/diligence/audits/2021/01/fei-protocol/#unchecked-return-value-for-iweth-transfer-call)[https://consensys.net/diligence/audits/2021/01/fei-protocol/#unchecked-return-value-for-iweth-transfer-call](https://consensys.net/diligence/audits/2021/01/fei-protocol/#unchecked-return-value-for-iweth-transfer-call)**

And in this function case, if the ``IERC20(_wnft).transferFrom()`` returns false, it would continue the call to withdraw token from the contract and send it to the caller. Thus a user could withdraw free tokens, and eventually some users will be unable to withdraw their tokens.
https://github.com/litrafi/litra-contract/blob/main/contracts/dao/burner/SimpleBurner.sol#:~:text=IERC20(_wnft).transferFrom(msg.sender%2C%20address(this)%2C%20inAmount)%3B
```solidity
IERC20(_wnft).transferFrom(msg.sender, address(this), inAmount);
```
Proof of concept:
-   Alice calls ``SimpleBurner.burn()`` with 100 as input.
-   Assume ``IERC20(_wnft).transferFrom()`` fails, returns false but does not revert.
-   External call from contract of Alice where implemented function ``withdraw`` that do this ``IERC20(_wnft.)withdraw()`` and  will run since there was no revert.
-   Alice receives 100 eth for free.
-   This may be possible in a direct call by Alice or a call from
##### Recommendation
Check the result of transferFrom and transfer. Or making use of SafeERC20 library: safeTransfer and safeTransferFrom would be recommended.
#### [L-11] THE_CONTRACT_SHOULD_``approve(0)`` _FIRSTLY   
##### Description
Some tokens (like USDT L199) do not work when changing the allowance from an existing non-zero allowance value. They must first be approved by zero and then the actual allowance must be approved.
https://github.com/litrafi/litra-contract/blob/main/contracts/dao/burner/SimpleBurner.sol#:~:text=IERC20(_wnft).approve(poolAddr%2C%20inAmount)%3B
```solidity
IERC20(_wnft).approve(poolAddr, inAmount);
```
##### Recommendation
Approve with a zero amount first before setting the actual amount.
```solidity
IERC20(_wnft).approve(poolAddr, 0);
IERC20(_wnft).approve(poolAddr, inAmount);
```
#### [L-12] ``constructor``_SHOULD_BE__``payable``  
##### Description
Setting the `constructor` to `payable` saves ~13 gas per instance
https://github.com/litrafi/litra-contract/blob/main/contracts/dao/admin/ParameterAdminManaged.sol#:~:text=constructor(address,%7D
```solidity
constructor(address _e) {
    parameterAdmin = _e;
}
```
https://github.com/litrafi/litra-contract/blob/main/contracts/dao/admin/OwnershipAdminManaged.sol#:~:text=constructor(address,%7D
```solidity
constructor(address _o) {
    ownershipAdmin = _o;
}
```
https://github.com/litrafi/litra-contract/blob/main/contracts/dao/admin/EmergencyAdminManaged.sol#:~:text=constructor(address,%7D
```solidity
constructor(address _e) {
    emergencyAdmin = _e;
}
```
https://github.com/litrafi/litra-contract/blob/main/contracts/dao/LA.sol#:~:text=constructor()%20ERC20(%27Litra%20Token%27%2C%20%27LA%27)%20%7B
```solidity
constructor() ERC20('Litra Token', 'LA') {
```
https://github.com/litrafi/litra-contract/blob/main/contracts/dao/burner/SimpleBurner.sol#:~:text=constructor(,%7D
```solidity
constructor(
    address _o,
    address _e,
    address payable _receiver,
    address _weth,
    address _poolFactory
) OwnershipAdminManaged(_o) EmergencyAdminManaged(_e) {
    receiver = _receiver;
    weth = _weth;
    poolFactory = _poolFactory;
}
```
https://github.com/litrafi/litra-contract/blob/main/contracts/tokenize/WrappedNFT.sol#:~:text=constructor(string,%7D
```solidity
constructor(string memory _name, string memory _symbol) ERC20Permit(_name) ERC20(_name, _symbol) {
creator = msg.sender;
}
```
##### Recommendation
Add ``payable`` to constructors
#### [L-13] OWNERSHIP_MAY_BE_BURNED    
##### Description
It was observed that the vault owner can transfer the ownership to address(0), which effectively burn the ownership.
https://github.com/litrafi/litra-contract/blob/main/contracts/dao/admin/ParameterAdminManaged.sol#:~:text=function%20commitParameterAdmin(,%7D
```solidity
function commitParameterAdmin(address _p) external onlyOwnershipAdmin {
    futureParameterAdmin = _p;
}
```
https://github.com/litrafi/litra-contract/blob/main/contracts/dao/admin/ParameterAdminManaged.sol#:~:text=function%20applyParameterAdmin(),%7D
```solidity
function applyParameterAdmin() external {
    require(msg.sender == futureParameterAdmin, "Access denied!");
    parameterAdmin = futureParameterAdmin;
}
```
https://github.com/litrafi/litra-contract/blob/main/contracts/dao/admin/OwnershipAdminManaged.sol#:~:text=function%20commitOwnershipAdmin(,%7D
```solidity
function commitOwnershipAdmin(address _o) external onlyOwnershipAdmin {
    futureOwnershipAdmin = _o;
}
```
https://github.com/litrafi/litra-contract/blob/main/contracts/dao/admin/OwnershipAdminManaged.sol#:~:text=function%20applyOwnershipAdmin(),%7D
```solidity
function applyOwnershipAdmin() external {
    require(msg.sender == futureOwnershipAdmin, "Access denied!");
    ownershipAdmin = futureOwnershipAdmin;
}
```
https://github.com/litrafi/litra-contract/blob/main/contracts/dao/admin/EmergencyAdminManaged.sol#:~:text=function%20commitEmergencyAdmin(,%7D
```solidity
function commitEmergencyAdmin(address _e) external onlyEmergencyAdmin {
    futureEmergencyAdmin = _e;
}
```
https://github.com/litrafi/litra-contract/blob/main/contracts/dao/admin/EmergencyAdminManaged.sol#:~:text=function%20applyEmergencyAdmin(),%7D
```solidity
function applyEmergencyAdmin() external {
    require(msg.sender == futureEmergencyAdmin, "! emergency admin");
    emergencyAdmin = futureEmergencyAdmin;
}
```
##### Recommendation
It is recommended to implement a validation check to ensure that the ownership is not transferred to address(0).
```solidity
function commitEmergencyAdmin(address _e) external onlyEmergencyAdmin {
  + require(_e != 0, "Invalid new owner: address(0)");
    futureEmergencyAdmin = _e;
}
```
```solidity
function commitOwnershipAdmin(address _o) external onlyOwnershipAdmin {
  + require(_o != 0, "Invalid new owner: address(0)");
    futureOwnershipAdmin = _o;
}
```
```solidity
function commitParameterAdmin(address _p) external onlyOwnershipAdmin {
  + require(_p != 0, "Invalid new owner: address(0)");
    futureParameterAdmin = _p;
}
```
#### [L-14] SPDX_LICENSE_IDENTIFIER_NOT_PROVIDED
##### Description
It's a bad idea to not provide SPDX license during compiling contracts of the whole project
https://github.com/litrafi/litra-contract/blob/main/contracts/dao/admin/EmergencyAdminManaged.sol#:~:text=pragma%20solidity%20%5E0.8.0%3B
```solidity
pragma solidity  ^0.8.0;
```
##### Recommendation
Better using SPDX license in the beginning your solidity file
#### [L-15] USING_``e``____IS_MORE_GAS_EFFICIENT_THAN___``**``__FOR_ EXPONENTIATION 
##### Description
When you use ``10e18`` , it's more gas efficient than ``10**18``
https://github.com/litrafi/litra-contract/blob/main/contracts/dao/Voting.sol#:~:text=uint128%20private%20constant%20MAX_UINT_128%20%3D%202%20**%20128%20%2D%201%3B
```solidity
uint128  private constant MAX_UINT_128 =  2  **  128  -  1;
```
https://github.com/litrafi/litra-contract/blob/main/contracts/dao/Voting.sol#:~:text=uint128%20private%20constant%20MAX_UINT_64%20%3D%202%20**%2064%20%2D%201%3B
```solidity
uint128 private constant MAX_UINT_64 = 2 ** 64 - 1;
```
https://github.com/litrafi/litra-contract/blob/main/contracts/dao/LA.sol#:~:text=uint256%20constant%20private%20RATE_DENOMINATOR%20%3D%2010%20**%2018%3B
```solidity
uint256 constant private RATE_DENOMINATOR = 10 ** 18;
```
##### Recommendation
Better using ``e`` for exponentiation:
 ```solidity
 uint128  private constant MAX_UINT_128 =  2e128  -  1;
 ```
 ```solidity
uint128 private constant MAX_UINT_64 = 2e64 - 1;
```
```solidity
uint256 constant private RATE_DENOMINATOR = 10e18;
```
#### [L-16] USE_PRIVATE_RATHER_THAN_PUBLIC_FOR_CONSTANTS
##### Description
If needed, the value can be read from the verified contract source code. Savings are due to the compiler not having to create non-payable getter functions for deployment calldata, and not adding another entry to the method ID table
https://github.com/litrafi/litra-contract/blob/main/contracts/dao/Voting.sol#:~:text=bytes32%20public%20constant%20CREATE_VOTES_ROLE%20%3D%200xe7dcd7275292e064d090fbc5f3bd7995be23b502c1fed5cd94cfddbbdcd32bbc%3B%20//keccak256(%22CREATE_VOTES_ROLE%22)%3B
```solidity
bytes32 public constant CREATE_VOTES_ROLE = 0xe7dcd7275292e064d090fbc5f3bd7995be23b502c1fed5cd94cfddbbdcd32bbc; //keccak256("CREATE_VOTES_ROLE");
```
https://github.com/litrafi/litra-contract/blob/main/contracts/dao/Voting.sol#:~:text=bytes32%20public%20constant%20MODIFY_SUPPORT_ROLE%20%3D%200xda3972983e62bdf826c4b807c4c9c2b8a941e1f83dfa76d53d6aeac11e1be650%3B%20//keccak256(%22MODIFY_SUPPORT_ROLE%22)%3B
```solidity
bytes32 public constant MODIFY_SUPPORT_ROLE = 0xda3972983e62bdf826c4b807c4c9c2b8a941e1f83dfa76d53d6aeac11e1be650; //keccak256("MODIFY_SUPPORT_ROLE");
```
https://github.com/litrafi/litra-contract/blob/main/contracts/dao/Voting.sol#:~:text=bytes32%20public%20constant%20MODIFY_QUORUM_ROLE%20%3D%200xad15e7261800b4bb73f1b69d3864565ffb1fd00cb93cf14fe48da8f1f2149f39%3B%20//keccak256(%22MODIFY_QUORUM_ROLE%22)%3B
```solidity
bytes32 public constant MODIFY_QUORUM_ROLE = 0xad15e7261800b4bb73f1b69d3864565ffb1fd00cb93cf14fe48da8f1f2149f39; //keccak256("MODIFY_QUORUM_ROLE");
```
https://github.com/litrafi/litra-contract/blob/main/contracts/dao/Voting.sol#:~:text=bytes32%20public%20constant%20SET_MIN_BALANCE_ROLE%20%3D%200xb1f3f26f63ad27cd630737a426f990492f5c674208299d6fb23bb2b0733d3d66%3B%20//keccak256(%22SET_MIN_BALANCE_ROLE%22)
```solidity
bytes32 public constant SET_MIN_BALANCE_ROLE = 0xb1f3f26f63ad27cd630737a426f990492f5c674208299d6fb23bb2b0733d3d66; //keccak256("SET_MIN_BALANCE_ROLE")
```
https://github.com/litrafi/litra-contract/blob/main/contracts/dao/Voting.sol#:~:text=bytes32%20public%20constant%20SET_MIN_TIME_ROLE%20%3D%200xe7ab0252519cd959720b328191bed7fe61b8e25f77613877be7070646d12daf0%3B%20//keccak256(%22SET_MIN_TIME_ROLE%22)
```solidity
bytes32 public constant SET_MIN_TIME_ROLE = 0xe7ab0252519cd959720b328191bed7fe61b8e25f77613877be7070646d12daf0; //keccak256("SET_MIN_TIME_ROLE")
```
https://github.com/litrafi/litra-contract/blob/main/contracts/dao/Voting.sol#:~:text=bytes32%20public%20constant%20ENABLE_VOTE_CREATION%20%3D%200xecb50dc3e77ba8a59697a3cc090a29b4cbd3c1f2b6b3aea524e0d166969592b9%3B%20//keccak256(%22ENABLE_VOTE_CREATION%22)
```solidity
bytes32 public constant ENABLE_VOTE_CREATION = 0xecb50dc3e77ba8a59697a3cc090a29b4cbd3c1f2b6b3aea524e0d166969592b9; //keccak256("ENABLE_VOTE_CREATION")
```
https://github.com/litrafi/litra-contract/blob/main/contracts/dao/Voting.sol#:~:text=bytes32%20public%20constant%20DISABLE_VOTE_CREATION%20%3D%200x40b01f8b31b51596de2eeab8c325ff77cc3695c1c1875d66ff31176e7148d2a1%3B%20//keccack256(%22DISABLE_VOTE_CREATION%22)
```solidity
bytes32 public constant DISABLE_VOTE_CREATION = 0x40b01f8b31b51596de2eeab8c325ff77cc3695c1c1875d66ff31176e7148d2a1; //keccack256("DISABLE_VOTE_CREATION")
```
https://github.com/litrafi/litra-contract/blob/main/contracts/dao/Voting.sol#:~:text=uint64%20public%20constant%20PCT_BASE%20%3D%2010%20**%2018%3B%20//%200%25%20%3D%200%3B%201%25%20%3D%2010%5E16%3B%20100%25%20%3D%2010%5E18
```solidity
uint64 public constant PCT_BASE = 10 ** 18; // 0% = 0; 1% = 10^16; 100% = 10^18
```
##### Recommendation
You should replace ``public`` with ``private`` in order to save gas
```solidity
bytes32 private constant CREATE_VOTES_ROLE = 0xe7dcd7275292e064d090fbc5f3bd7995be23b502c1fed5cd94cfddbbdcd32bbc; //keccak256("CREATE_VOTES_ROLE");
```
```solidity
bytes32 private constant MODIFY_SUPPORT_ROLE = 0xda3972983e62bdf826c4b807c4c9c2b8a941e1f83dfa76d53d6aeac11e1be650; //keccak256("MODIFY_SUPPORT_ROLE");
```
```solidity
bytes32 private constant MODIFY_QUORUM_ROLE = 0xad15e7261800b4bb73f1b69d3864565ffb1fd00cb93cf14fe48da8f1f2149f39; //keccak256("MODIFY_QUORUM_ROLE");
```
```solidity
bytes32 private constant SET_MIN_BALANCE_ROLE = 0xb1f3f26f63ad27cd630737a426f990492f5c674208299d6fb23bb2b0733d3d66; //keccak256("SET_MIN_BALANCE_ROLE")
```
```solidity
bytes32 private constant SET_MIN_TIME_ROLE = 0xe7ab0252519cd959720b328191bed7fe61b8e25f77613877be7070646d12daf0; //keccak256("SET_MIN_TIME_ROLE")
```
```solidity
bytes32 private constant ENABLE_VOTE_CREATION = 0xecb50dc3e77ba8a59697a3cc090a29b4cbd3c1f2b6b3aea524e0d166969592b9; //keccak256("ENABLE_VOTE_CREATION")
```
```solidity
bytes32 private constant DISABLE_VOTE_CREATION = 0x40b01f8b31b51596de2eeab8c325ff77cc3695c1c1875d66ff31176e7148d2a1; //keccack256("DISABLE_VOTE_CREATION")
```
```solidity
uint64 private constant PCT_BASE = 10 ** 18; // 0% = 0; 1% = 10^16; 100% = 10^18
```
#### [L-17] ``bytes32``_CONSTANTS_ARE_MORE_EFFICIENT_THAN_STRING_CONSTANTS 
##### Description
If data can fit into 32 bytes, then you should use bytes32 datatype rather than bytes or strings as it is cheaper in solidity.
https://github.com/litrafi/litra-contract/blob/main/contracts/dao/Voting.sol#:~:text=string%20private%20constant%20ERROR_NO_VOTE%20%3D%20%22VOTING_NO_VOTE%22%3B
```solidity
string private constant ERROR_NO_VOTE = "VOTING_NO_VOTE";
```
https://github.com/litrafi/litra-contract/blob/main/contracts/dao/Voting.sol#:~:text=string%20private%20constant%20ERROR_INIT_PCTS%20%3D%20%22VOTING_INIT_PCTS%22%3B
```solidity
string private constant ERROR_INIT_PCTS = "VOTING_INIT_PCTS";
```
https://github.com/litrafi/litra-contract/blob/main/contracts/dao/Voting.sol#:~:text=string%20private%20constant%20ERROR_CHANGE_SUPPORT_PCTS%20%3D%20%22VOTING_CHANGE_SUPPORT_PCTS%22%3B
```solidity
string private constant ERROR_CHANGE_SUPPORT_PCTS = "VOTING_CHANGE_SUPPORT_PCTS";
```
https://github.com/litrafi/litra-contract/blob/main/contracts/dao/Voting.sol#:~:text=string%20private%20constant%20ERROR_CHANGE_QUORUM_PCTS%20%3D%20%22VOTING_CHANGE_QUORUM_PCTS%22%3B
```solidity
string private constant ERROR_CHANGE_QUORUM_PCTS = "VOTING_CHANGE_QUORUM_PCTS";
```
https://github.com/litrafi/litra-contract/blob/main/contracts/dao/Voting.sol#:~:text=string%20private%20constant%20ERROR_INIT_SUPPORT_TOO_BIG%20%3D%20%22VOTING_INIT_SUPPORT_TOO_BIG%22%3B
```solidity
string private constant ERROR_INIT_SUPPORT_TOO_BIG = "VOTING_INIT_SUPPORT_TOO_BIG";
```
https://github.com/litrafi/litra-contract/blob/main/contracts/dao/Voting.sol#:~:text=string%20private%20constant%20ERROR_CHANGE_SUPPORT_TOO_BIG%20%3D%20%22VOTING_CHANGE_SUPP_TOO_BIG%22%3B
```solidity
string private constant ERROR_CHANGE_SUPPORT_TOO_BIG = "VOTING_CHANGE_SUPP_TOO_BIG";
```
https://github.com/litrafi/litra-contract/blob/main/contracts/dao/Voting.sol#:~:text=string%20private%20constant%20ERROR_CAN_NOT_VOTE%20%3D%20%22VOTING_CAN_NOT_VOTE%22%3B
```solidity
string private constant ERROR_CAN_NOT_VOTE = "VOTING_CAN_NOT_VOTE";
```
https://github.com/litrafi/litra-contract/blob/main/contracts/dao/Voting.sol#:~:text=string%20private%20constant%20ERROR_MALFORMED_CONTINUOUS_VOTE%20%3D%20%22MALFORMED_CONTINUOUS_VOTE%22%3B
```solidity
string private constant ERROR_MALFORMED_CONTINUOUS_VOTE = "MALFORMED_CONTINUOUS_VOTE";
```
https://github.com/litrafi/litra-contract/blob/main/contracts/dao/Voting.sol#:~:text=string%20private%20constant%20ERROR_CAN_NOT_EXECUTE%20%3D%20%22VOTING_CAN_NOT_EXECUTE%22%3B
```solidity
string private constant ERROR_CAN_NOT_EXECUTE = "VOTING_CAN_NOT_EXECUTE";
```
https://github.com/litrafi/litra-contract/blob/main/contracts/dao/Voting.sol#:~:text=string%20private%20constant%20ERROR_CAN_NOT_FORWARD%20%3D%20%22VOTING_CAN_NOT_FORWARD%22%3B
```solidity
string private constant ERROR_CAN_NOT_FORWARD = "VOTING_CAN_NOT_FORWARD";
```
https://github.com/litrafi/litra-contract/blob/main/contracts/dao/Voting.sol#:~:text=string%20private%20constant%20ERROR_NO_VOTING_POWER%20%3D%20%22VOTING_NO_VOTING_POWER%22%3B
```solidity
string private constant ERROR_NO_VOTING_POWER = "VOTING_NO_VOTING_POWER";
```
##### Recommendation
Use ``bytes32`` for string constants
```solidity
bytes32 private constant ERROR_NO_VOTE = "VOTING_NO_VOTE";
```
#### [L-18] USAGE_OF_``uint/int`` _SMALLER_THAN_32_BYTES_INCURS_OVERHEAD
##### Description
When using elements that are smaller than 32 bytes, your contract’s gas usage may be higher. This is because the EVM operates on 32 bytes at a time. Therefore, if the element is smaller than that, the EVM must use more operations in order to reduce the size of the element from 32 bytes to the desired size.

Each operation involving a uint8 costs an extra 22-28 gas (depending on whether the other operand is also a variable of type uint8) as compared to ones involving uint256, due to the compiler having to clear the higher bits of the memory word before operating on the uint8, as well as the associated stack operations of doing so. Use a larger size then downcast where needed.

**[](https://docs.soliditylang.org/en/v0.8.11/internals/layout_in_storage.html)[https://docs.soliditylang.org/en/v0.8.11/internals/layout_in_storage.html](https://docs.soliditylang.org/en/v0.8.11/internals/layout_in_storage.html)**

Use a larger size then downcast where needed.
https://github.com/litrafi/litra-contract/blob/main/contracts/dao/Voting.sol#:~:text=uint64%20public%20supportRequiredPct%3B
```solidity
uint64 public supportRequiredPct;
```
https://github.com/litrafi/litra-contract/blob/main/contracts/dao/Voting.sol#:~:text=uint64%20public%20minAcceptQuorumPct%3B
```solidity
uint64 public minAcceptQuorumPct;
```
https://github.com/litrafi/litra-contract/blob/main/contracts/dao/Voting.sol#:~:text=uint64%20public%20voteTime%3B
```solidity
uint64 public voteTime;
```
https://github.com/litrafi/litra-contract/blob/main/contracts/dao/Voting.sol#:~:text=uint64%20_supportRequiredPct%2C
```solidity
uint64 _supportRequiredPct,
```
https://github.com/litrafi/litra-contract/blob/main/contracts/dao/Voting.sol#:~:text=uint64%20_minAcceptQuorumPct%2C
```solidity
uint64 _minAcceptQuorumPct,
```
https://github.com/litrafi/litra-contract/blob/main/contracts/dao/Voting.sol#:~:text=uint64%20_minAcceptQuorumPct%2C-,uint64%20_voteTime%2C,-uint256%20_minBalance%2C
```solidity
uint64 _voteTime,
```
##### Recommendation
Use 256 bits for your variables in order to save gas
#### [L-19] EVENTS_SHOULD_BE_INDEXED
##### Description
The lack of indexed parameters for logged events is bad because it will not allow you to search for these events using the indexed parameters as filters.
https://github.com/litrafi/litra-contract/blob/main/contracts/dao/Voting.sol#:~:text=event%20ChangeSupportRequired(uint64%20supportRequiredPct)%3B
```solidity
event ChangeSupportRequired(uint64 supportRequiredPct);
```
https://github.com/litrafi/litra-contract/blob/main/contracts/dao/Voting.sol#:~:text=event%20ChangeMinQuorum(uint64%20minAcceptQuorumPct)%3B
```solidity
event ChangeMinQuorum(uint64 minAcceptQuorumPct);
```
https://github.com/litrafi/litra-contract/blob/main/contracts/dao/Voting.sol#:~:text=event%20MinimumBalanceSet(uint256%20minBalance)%3B
```solidity
event MinimumBalanceSet(uint256 minBalance);
```
https://github.com/litrafi/litra-contract/blob/main/contracts/dao/Voting.sol#:~:text=event%20StartVote(uint256%20indexed%20voteId%2C%20address%20indexed%20creator%2C%20string%20metadata%2C%20uint256%20minBalance%2C%20uint256%20minTime%2C%20uint256%20totalSupply%2C%20uint256%20creatorVotingPower)%3B
```solidity
event StartVote(uint256 indexed voteId, address indexed creator, string metadata, uint256 minBalance, uint256 minTime, uint256 totalSupply, uint256 creatorVotingPower);
```
https://github.com/litrafi/litra-contract/blob/main/contracts/dao/Voting.sol#:~:text=event%20CastVote(uint256%20indexed%20voteId%2C%20address%20indexed%20voter%2C%20bool%20supports%2C%20uint256%20stake)%3B
```solidity
event CastVote(uint256 indexed voteId, address indexed voter, bool supports, uint256 stake);
```
https://github.com/litrafi/litra-contract/blob/main/contracts/dao/Voting.sol#:~:text=event%20MinimumTimeSet(uint256%20minTime)%3B
```solidity
event MinimumTimeSet(uint256 minTime);
```
https://github.com/litrafi/litra-contract/blob/main/contracts/dao/LA.sol#:~:text=event%20UpdateMiningParameters(uint256%20rate%2C%20uint256%20supply)%3B
```solidity
event UpdateMiningParameters(uint256 rate, uint256 supply);
```
https://github.com/litrafi/litra-contract/blob/main/contracts/dao/LA.sol#:~:text=event%20SetMinter(address%20minter)%3B
```solidity
event SetMinter(address minter);
```
https://github.com/litrafi/litra-contract/blob/main/contracts/dao/LA.sol#:~:text=event%20SetAdmin(address%20minter)%3B
```solidity
event SetAdmin(address minter);
```
##### Recommendation
Use indexed parameters in events
#### [L-20] SPLITTING_``require()``_STATEMENTS_THAT_USE_``&&``_SAVES_GAS  
##### Description
Instead of using operator **`&&`** on a single **`require`**. Using a two **`require`** can save more gas.
https://github.com/litrafi/litra-contract/blob/main/contracts/dao/Voting.sol#:~:text=require(_minBalance%20%3E%3D%20minBalanceLowerLimit%20%26%26%20_minBalance%20%3C%3D%20minBalanceUpperLimit%2C%20%22Min%20balance%20should%20be%20within%20initialization%20hardcoded%20limits%22)%3B
```solidity
require(_minBalance >= minBalanceLowerLimit && _minBalance <= minBalanceUpperLimit, "Min balance should be within initialization hardcoded limits");
```
https://github.com/litrafi/litra-contract/blob/main/contracts/dao/Voting.sol#:~:text=require(_minTime%20%3E%3D%20minTimeLowerLimit%20%26%26%20_minTime%20%3C%3D%20minTimeUpperLimit%2C%20%22Min%20time%20should%20be%20within%20initialization%20hardcoded%20limits%22)%3B
```solidity
require(_minTime >= minTimeLowerLimit && _minTime <= minTimeUpperLimit, "Min time should be within initialization hardcoded limits");
```
https://github.com/litrafi/litra-contract/blob/main/contracts/dao/Voting.sol#:~:text=require(!_supports%20%26%26%20yeaPct.add(nayPct)%20%3C%3D%20PCT_BASE%2C%20ERROR_MALFORMED_CONTINUOUS_VOTE)%3B
```solidity
require(!_supports && yeaPct.add(nayPct) <= PCT_BASE, ERROR_MALFORMED_CONTINUOUS_VOTE);
```
##### Recommendation
Better using splitting ``require()``
```solidity
require(_minBalance >= minBalanceLowerLimit,"Min balance should be within initialization hardcoded limits");
require(_minBalance <= minBalanceUpperLimit,"Min balance should be within initialization hardcoded limits")
```
```solidity
require(_minTime >= minTimeLowerLimit,"Min time should be within initialization hardcoded limits");
require(_minTime <= minTimeUpperLimit,"Min time should be within initialization hardcoded limits")
```
```solidity
require(!_supports, ERROR_MALFORMED_CONTINUOUS_VOTE);
require(yeaPct.add(nayPct) <= PCT_BASE, ERROR_MALFORMED_CONTINUOUS_VOTE)
```
#### [L-21] USE_``require``_INSTEAD_OF__``assert``    
##### Description
The big difference between the two is that the **`assert()`** function when false, **uses up all the remaining gas and reverts all the changes made.**

Meanwhile, a **`require()`** function when false, also reverts back all the changes made to the contract but **does refund all the remaining gas fees we offered to pay**. This is the most common Solidity function used by developers for debugging and error handling.
https://github.com/litrafi/litra-contract/blob/main/contracts/dao/Voting.sol#:~:text=assert(CREATE_VOTES_ROLE%20%3D%3D%20keccak256(%22CREATE_VOTES_ROLE%22))%3B
```solidity
assert(CREATE_VOTES_ROLE == keccak256("CREATE_VOTES_ROLE"));
```
https://github.com/litrafi/litra-contract/blob/main/contracts/dao/Voting.sol#:~:text=assert(MODIFY_SUPPORT_ROLE%20%3D%3D%20keccak256(%22MODIFY_SUPPORT_ROLE%22))%3B
```solidity
assert(MODIFY_SUPPORT_ROLE == keccak256("MODIFY_SUPPORT_ROLE"));
```
https://github.com/litrafi/litra-contract/blob/main/contracts/dao/Voting.sol#:~:text=assert(MODIFY_QUORUM_ROLE%20%3D%3D%20keccak256(%22MODIFY_QUORUM_ROLE%22))%3B
```solidity
assert(MODIFY_QUORUM_ROLE == keccak256("MODIFY_QUORUM_ROLE"));
```
https://github.com/litrafi/litra-contract/blob/main/contracts/dao/Voting.sol#:~:text=assert(SET_MIN_BALANCE_ROLE%20%3D%3D%20keccak256(%22SET_MIN_BALANCE_ROLE%22))%3B
```solidity
assert(SET_MIN_BALANCE_ROLE == keccak256("SET_MIN_BALANCE_ROLE"));
```
https://github.com/litrafi/litra-contract/blob/main/contracts/dao/Voting.sol#:~:text=assert(SET_MIN_TIME_ROLE%20%3D%3D%20keccak256(%22SET_MIN_TIME_ROLE%22))%3B
```solidity
assert(SET_MIN_TIME_ROLE == keccak256("SET_MIN_TIME_ROLE"));
```
https://github.com/litrafi/litra-contract/blob/main/contracts/dao/Voting.sol#:~:text=assert(DISABLE_VOTE_CREATION%20%3D%3D%20keccak256(%22DISABLE_VOTE_CREATION%22))%3B
```solidity
assert(DISABLE_VOTE_CREATION == keccak256("DISABLE_VOTE_CREATION"));
```
https://github.com/litrafi/litra-contract/blob/main/contracts/dao/Voting.sol#:~:text=assert(ENABLE_VOTE_CREATION%20%3D%3D%20keccak256(%22ENABLE_VOTE_CREATION%22))%3B
```solidity
assert(ENABLE_VOTE_CREATION == keccak256("ENABLE_VOTE_CREATION"));
```
##### Recommendation
Better replacing ``assert()`` with ``require()``
#### [L-22] USE_PREVIOUSLY_CREATED_MODIFIERS_INSTEAD_OF_REPEATING_THE_SAME_REQUIRE_STATEMENTS  
##### Description
You shouldn't waste gas on declaring the same requirements that are already in the modifiers.
https://github.com/litrafi/litra-contract/blob/main/contracts/dao/Voting.sol#:~:text=require(_minBalance%20%3E%3D%20_minBalanceLowerLimit%20%26%26%20_minBalance%20%3C%3D%20_minBalanceUpperLimit)%3B
```solidity
require(_minBalance >= _minBalanceLowerLimit && _minBalance <= _minBalanceUpperLimit);
```
https://github.com/litrafi/litra-contract/blob/main/contracts/dao/Voting.sol#:~:text=require(_minTime%20%3E%3D%20_minTimeLowerLimit%20%26%26%20_minTime%20%3C%3D%20_minTimeUpperLimit)%3B
```solidity
require(_minTime >= _minTimeLowerLimit && _minTime <= _minTimeUpperLimit);
```
##### Recommendation
Use your defined modifiers instead of repeating ``require()`` statements:
```solidity
modifier minBalanceCheck(uint256 _minBalance) {
    require(_minBalance >= minBalanceLowerLimit && _minBalance <= minBalanceUpperLimit, "Min balance should be within initialization hardcoded limits");
    _;
}

modifier minTimeCheck(uint256 _minTime) {
    require(_minTime >= minTimeLowerLimit && _minTime <= minTimeUpperLimit, "Min time should be within initialization hardcoded limits");
    _;
}
```
#### [L-23]  USE_``safeDecimals()``   
##### Description
``Voting.sol`` should not assume that the asset will always be IERC20Detailed(not all ERC20 contracts define decimals()since it’s optional in the spec). 
https://github.com/litrafi/litra-contract/blob/main/contracts/dao/Voting.sol#:~:text=uint256%20decimalsMul%20%3D%20uint256(10)%20**%20token.decimals()%3B
```solidity
uint256 decimalsMul = uint256(10) ** token.decimals();
```
##### Recommendation
Use [safeDecimals()](https://github.com/boringcrypto/BoringSolidity/blob/ccb743d4c3363ca37491b87c6c9b24b1f5fa25dc/contracts/libraries/BoringERC20.sol#L33-L55) instead
#### [L-24] ADD_TIMELOCK_TO_CRITICAL_FUNCTIONS  
##### Description
It is a good practice to give time for users to react and adjust to critical changes. A timelock provides more guarantees and reduces the level of trust required, thus decreasing risk for users. It also indicates that the project is legitimate (less risk of a malicious owner making a sandwich attack on a user).
https://github.com/litrafi/litra-contract/blob/main/contracts/dao/Voting.sol#:~:text=function%20changeSupportRequiredPct(,%7B
```solidity
function changeSupportRequiredPct(uint64 _supportRequiredPct) external
authP(MODIFY_SUPPORT_ROLE, arr(uint256(_supportRequiredPct), uint256(supportRequiredPct)))
{
require(minAcceptQuorumPct <= _supportRequiredPct, ERROR_CHANGE_SUPPORT_PCTS);

require(_supportRequiredPct < PCT_BASE, ERROR_CHANGE_SUPPORT_TOO_BIG);

supportRequiredPct = _supportRequiredPct;

emit ChangeSupportRequired(_supportRequiredPct);

}
```
https://github.com/litrafi/litra-contract/blob/main/contracts/dao/Voting.sol#:~:text=function%20changeMinAcceptQuorumPct(,%7D
```solidity
function changeMinAcceptQuorumPct(uint64 _minAcceptQuorumPct) external
authP(MODIFY_QUORUM_ROLE, arr(uint256(_minAcceptQuorumPct), uint256(minAcceptQuorumPct)))
{
require(_minAcceptQuorumPct <= supportRequiredPct, ERROR_CHANGE_QUORUM_PCTS);
minAcceptQuorumPct = _minAcceptQuorumPct;
emit ChangeMinQuorum(_minAcceptQuorumPct);
}
```
https://github.com/litrafi/litra-contract/blob/main/contracts/dao/Voting.sol#:~:text=function%20setMinBalance(,%7D
```solidity
function setMinBalance(uint256 _minBalance) external auth(SET_MIN_BALANCE_ROLE) minBalanceCheck(_minBalance) {
     minBalance = _minBalance;
     emit MinimumBalanceSet(_minBalance);
}
```
https://github.com/litrafi/litra-contract/blob/main/contracts/dao/Voting.sol#:~:text=function%20setMinTime(,%7D
```solidity
function setMinTime(uint256 _minTime) external auth(SET_MIN_TIME_ROLE) minTimeCheck(_minTime) {
     minTime = _minTime;
     emit MinimumTimeSet(_minTime);
}
```
https://github.com/litrafi/litra-contract/blob/main/contracts/dao/LA.sol#:~:text=function%20updateMiningParamters(),%7D
```solidity
function updateMiningParamters() external {
    require(block.timestamp >= startEpochTime + RATE_REDUCTION_TIME, 'Not time');
    _updateMiningParamters();
}
```
https://github.com/litrafi/litra-contract/blob/main/contracts/dao/LA.sol#:~:text=%7D-,function%20startEpochTimeWrite()%20external%20returns(uint256)%20%7B,%7D,-function%20futureEpochTimeWrite()
```solidity
function startEpochTimeWrite() external returns(uint256) {
    uint256 _startEpochTime = startEpochTime;
    if(block.timestamp >= startEpochTime + RATE_REDUCTION_TIME) {
        _updateMiningParamters();
        return startEpochTime;
    } else {
        return _startEpochTime;
    }
}
```
https://github.com/litrafi/litra-contract/blob/main/contracts/dao/LA.sol#:~:text=function%20setMinter(,%7D
```solidity
function setMinter(address _minter) external {
    require(_msgSender() == admin, "!admin");
    require(minter == address(0), "Already set");
    minter = _minter;
    emit SetMinter(_minter);
}
```
https://github.com/litrafi/litra-contract/blob/main/contracts/dao/LA.sol#:~:text=function%20setAmind(,%7D
```solidity
function setAmind(address _admin) external {
    require(_msgSender() == admin, "!admin");
    admin = _admin;
    emit SetAdmin(_admin);
}
```
##### Recommendation
Consider adding a timelock to these functions in order to secure protocol from attacks
#### [L-25] USE_``assembly``_FOR_SIMPLE_SETTERS_FUNCTIONS   
##### Description
Where it does not affect readability, using assembly allows to save gas not only on deployment, but also on function calls. This is the case for instance for simple admin setters.
https://github.com/litrafi/litra-contract/blob/main/contracts/dao/Voting.sol#:~:text=%3C%20PCT_BASE%2C%20ERROR_CHANGE_SUPPORT_TOO_BIG)%3B-,supportRequiredPct%20%3D%20_supportRequiredPct%3B,-emit%20ChangeSupportRequired(_supportRequiredPct
```solidity
supportRequiredPct = _supportRequiredPct;
```
https://github.com/litrafi/litra-contract/blob/main/contracts/dao/Voting.sol#:~:text=%3C%3D%20supportRequiredPct%2C%20ERROR_CHANGE_QUORUM_PCTS)%3B-,minAcceptQuorumPct%20%3D%20_minAcceptQuorumPct%3B,-emit%20ChangeMinQuorum(_minAcceptQuorumPct
```solidity
minAcceptQuorumPct = _minAcceptQuorumPct;
```
https://github.com/litrafi/litra-contract/blob/main/contracts/dao/Voting.sol#:~:text=minBalance%20%3D%20_minBalance%3B
```solidity
minBalance = _minBalance;
```
https://github.com/litrafi/litra-contract/blob/main/contracts/dao/Voting.sol#:~:text=initialized%20hardcoded%20limits-,minTime%20%3D%20_minTime%3B,-emit%20MinimumTimeSet(_minTime
```solidity
minTime = _minTime;
```
https://github.com/litrafi/litra-contract/blob/main/contracts/dao/LA.sol#:~:text=Already%20set%22)%3B-,minter%20%3D%20_minter%3B,-emit%20SetMinter(_minter
```solidity
minter = _minter;
```
https://github.com/litrafi/litra-contract/blob/main/contracts/dao/LA.sol#:~:text=%22!admin%22)%3B-,admin%20%3D%20_admin%3B,-emit%20SetAdmin(_admin
```solidity
admin = _admin;
```
##### Recommendation
Use ``assembly`` for simple setters functions:
```solidity
- supportRequiredPct = _supportRequiredPct;
+ assembly {
+   sstore(supportRequiredPct.slot, _supportRequiredPct);
  }
```
```solidity
- minAcceptQuorumPct = _minAcceptQuorumPct;
+ assembly {
+   sstore(minAcceptQuorumPct.slot, _minAcceptQuorumPct);
}
```
```solidity
- minBalance = _minBalance;
+ assembly {
+   sstore(minBalance.slot, _minBalance);
  }
```
```solidity
- minTime = _minTime;
+ assembly {
+   sstore(minTime.slot, _minTime);
}
```
```solidity
- minter = _minter;
+ assembly {
+   sstore(minter.slot, _minter);
}
```
```solidity
- admin = _admin;
+ assembly {
+   sstore(admin.slot, _admin);
  }
```
#### [L-26] LOSS_OF_PRECISION  
##### Description
There is a loss of precision during math operations with multiplying and dividing
https://github.com/litrafi/litra-contract/blob/main/contracts/dao/LA.sol#:~:text=uint256%20constant%20private%20INITIAL_RATE%20%3D%20100638977635782747603833865%20/%20YEAR%3B
```solidity
uint256 constant private INITIAL_RATE = 100638977635782747603833865 / YEAR;
```
https://github.com/litrafi/litra-contract/blob/main/contracts/dao/LA.sol#:~:text=_rate%20%3D%20_rate%20*%20RATE_DENOMINATOR%20/%20RATE_REDUCTION_COEFFICIENT%3B
```solidity
_rate = _rate * RATE_DENOMINATOR / RATE_REDUCTION_COEFFICIENT;
```
https://github.com/litrafi/litra-contract/blob/main/contracts/dao/LA.sol#:~:text=currentRate%20%3D%20currentRate%20*%20RATE_DENOMINATOR%20/%20RATE_REDUCTION_COEFFICIENT%3B
```solidity
currentRate = currentRate * RATE_DENOMINATOR / RATE_REDUCTION_COEFFICIENT;
```
https://github.com/litrafi/litra-contract/blob/main/contracts/dao/LA.sol#:~:text=currentRate%20%3D%20currentRate%20*%20RATE_REDUCTION_COEFFICIENT%20/%20RATE_DENOMINATOR%3B
```solidity
currentRate = currentRate * RATE_REDUCTION_COEFFICIENT / RATE_DENOMINATOR;
```
##### Recommendation
Multiply to the required accuracy
#### [L-27] DON'T_CREATE_A_NEW_STATE_VARIABLE_WITH_THE_SAME_VALUE 
##### Description
There is no objective reason to create a new state variable with the same value
https://github.com/litrafi/litra-contract/blob/main/contracts/dao/LA.sol#:~:text=uint256%20constant%20private%20YEAR%20%3D%2086400%20*%20365%3B
https://github.com/litrafi/litra-contract/blob/main/contracts/dao/LA.sol#:~:text=uint256%20constant%20private%20RATE_REDUCTION_TIME%20%3D%20YEAR%3B
```solidity
uint256 constant private YEAR = 86400 * 365;
uint256 constant private RATE_REDUCTION_TIME = YEAR;
```
##### Recommendation
You shouldn't create new state variable with the same value
#### [L-28] YOU_SHOULDN'T_USE_``_msgSender()``   
##### Description
Don’t use  `_msgSender()`  if not supporting EIP-2771.
You shouldn't use  `_msgSender()`  when working with Biconomy because they call the contract for you and their address would always be the  `msg.sender`  so you have to structure the function so that it receives a signature and then gets the minter address from the signature.
Example using EIP712 Standard:
```solidity
function mint(Sig memory _sig, address _minter) external  {
        // Perform EIP712 hashing for address retrieval
        bytes32 digest = keccak256(
            abi.encodePacked(
                "\x19\x01",
                _domainSeparatorV4(),
                keccak256(
                    abi.encode(
                        _META_TRANSACTION_SIGNATURE_TYPE_HASH,
                        _minter
                    )
                )
            )
        );

        address recoveredAddress = ecrecover(digest, _sig.v, _sig.r, _sig.s);
}
```
https://github.com/litrafi/litra-contract/blob/main/contracts/dao/LA.sol#:~:text=_mint(_msgSender()%2C%20initSupply)%3B
```solidity
_mint(_msgSender(), initSupply);
```
##### Recommendation
Use `msg.sender` if the code does not implement [EIP-2771 trusted forwarder](https://eips.ethereum.org/EIPS/eip-2771) support
#### [L-29] UNCHECKING_ARITHMETICS_OPERATIONS_THAT_CAN'T_UNDERFLOW/OVERFLOW  
##### Description
While this is inside an external view function, consider wrapping this in an unchecked statement so that external contracts calling this might save some gas:
https://github.com/litrafi/litra-contract/blob/main/contracts/dao/Voting.sol#:~:text=uint256%20computedPct%20%3D%20_value.mul(PCT_BASE)%20/%20_total%3B
```solidity
uint256 computedPct = _value.mul(PCT_BASE) / _total;
```
https://github.com/litrafi/litra-contract/blob/main/contracts/dao/LA.sol#:~:text=startEpochTime%20%3D%20block.timestamp%20%2B%20INFLATION_DELAY%20%2D%20RATE_REDUCTION_TIME%3B
```solidity
startEpochTime = block.timestamp + INFLATION_DELAY - RATE_REDUCTION_TIME;
```
##### Recommendation
Use ``unchecked {}`` statement
#### [L-30] ``<x> += <y>`` _COSTS_MORE_GAS_THAN__``<x> = <x> + <y>``  
##### Description
 `<x> += <y>`  Costs More Gas Than  `<x> = <x> + <y>`  For State Variables
 https://github.com/litrafi/litra-contract/blob/main/contracts/dao/LA.sol#:~:text=_startEpochSupply%20%2B%3D%20_rate%20*%20RATE_REDUCTION_TIME%3B
 ```solidity
_startEpochSupply += _rate * RATE_REDUCTION_TIME;
 ```
 https://github.com/litrafi/litra-contract/blob/main/contracts/dao/LA.sol#:~:text=toMint%20%2B%3D%20currentRate%20*%20(currentEnd%20%2D%20currentStart)%3B
 ```solidity
 toMint += currentRate * (currentEnd - currentStart);
 ```
 https://github.com/litrafi/litra-contract/blob/main/contracts/dao/LA.sol#:~:text=currentEpochTime%20%2D%3D%20RATE_REDUCTION_TIME%3B
 ```solidity
 currentEpochTime -= RATE_REDUCTION_TIME;
 ```
##### Recommendation
Better using ``<x> = <x> + <y>``  statement
#### [L-31] YOU_DON'T_NEED_TO_DEFINE_VARIABLE_WITH_DEFAULT_VALUE  
##### Description
If a variable is not set/initialized, the default value is assumed (0, false, 0x0 … depending on the data type). You are simply wasting gas if you directly initialize it with its default value.
Gas saving executing:  **8 per entry**
https://github.com/litrafi/litra-contract/blob/main/contracts/dao/LA.sol#:~:text=start%20%3E%20end%22)%3B-,uint256%20toMint%20%3D%200%3B,-uint256%20currentEpochTime%20%3D
```solidity
uint256 toMint = 0;
```
https://github.com/litrafi/litra-contract/blob/main/contracts/dao/LA.sol#:~:text=for%20(uint256%20index%20%3D%200%3B%20index%20%3C%201000%3B%20index%2B%2B)%20%7B
```solidity
for (uint256 index =  0; index <  1000; index++) {
```
##### Recommendation
Don't initialize variable with default value because it's pointless
#### [L-32] ``++i/i++`` SHOULD_BE_``unchecked{++i}/unchecked{i++}``  
##### Description
`++i`/`i++` Should Be `unchecked{++i}`/`unchecked{i++}` When It Is Not Possible For Them To Overflow, As Is The Case When Used In For- And While-loops

The unchecked keyword is new in solidity version 0.8.0, so this only applies to that version or higher, which these instances are. This saves 30-40 gas PER LOOP
https://github.com/litrafi/litra-contract/blob/main/contracts/dao/LA.sol#:~:text=for%20(uint256%20index%20%3D%200%3B%20index%20%3C%201000%3B%20index%2B%2B)%20%7B
```solidity
for (uint256 index =  0; index <  1000; index++) {
```
##### Recommendation
Better using ``unchecked{}``:
```solidity
for (uint256 index =  0; index <  1000;) {
      unchecked{ ++index; }
}
```
#### [L-33] ADD_`unchecked {}`_FOR_SUBTRACTIONS_WHERE_THE_OPERANDS_CANNOT_UNDERFLOW_BECAUSE_OF_A_PREVIOUS_REQUIRE()_OR_IF() _STATEMENT
##### Description
`require(a <= b); x = b - a => require(a <= b); unchecked { x = b - a } if(a <= b); x = b - a => if(a <= b); unchecked { x = b - a }`
This will stop the check for overflow and underflow so it will save gas.

https://github.com/litrafi/litra-contract/blob/main/contracts/dao/LA.sol#:~:text=if(end%20%3E%3D%20currentEpochTime)%20%7B,*%20(currentEnd%20%2D%20currentStart)%3B
```solidity
toMint += currentRate * (currentEnd - currentStart);
```
https://github.com/litrafi/litra-contract/blob/main/contracts/dao/LA.sol#:~:text=currentEpochTime%20%2D%3D%20RATE_REDUCTION_TIME%3B
```solidity
currentEpochTime -= RATE_REDUCTION_TIME;
```
##### Recommendation
Better adding ``unchecked{}`` statement
#### [L-34] FUNCTIONS_GUARANTEED_TO_REVERT_WHEN_CALLED_BY_NORMAL_ USERS_CAN_BE_MARKED_``payable``
##### Description
If a function modifier or require such as onlyOwner/onlyX is used, the function will revert if a normal user tries to pay the function. Marking the function as payable will lower the gas cost for legitimate callers because the compiler will not include checks for whether a payment was provided. The extra opcodes avoided are CALLVALUE(2), DUP1(3), ISZERO(3), PUSH2(3), JUMPI(10), PUSH1(3), DUP1(3), REVERT(0), JUMPDEST(1), POP(2) which costs an average of about 21 gas per call to the function, in addition to the extra deployment cost.
https://github.com/litrafi/litra-contract/blob/main/contracts/dao/LA.sol#:~:text=function%20setMinter(,%7D
```solidity
function setMinter(address _minter) external {
    require(_msgSender() == admin, "!admin");
    require(minter == address(0), "Already set");
    minter = _minter;
    emit SetMinter(_minter);
}
```
https://github.com/litrafi/litra-contract/blob/main/contracts/dao/LA.sol#:~:text=function%20setAmind(,%7D
```solidity
function setAmind(address _admin) external {
    require(_msgSender() == admin, "!admin");
    admin = _admin;
    emit SetAdmin(_admin);
}
```
https://github.com/litrafi/litra-contract/blob/main/contracts/dao/LA.sol#:~:text=function%20mint(,Zero%20address%22)%3B
```solidity
function mint(address _to, uint256 _value) external {
    require(_msgSender() == minter, "!minter");
    require(_to != address(0), "Zero address");
```
https://github.com/litrafi/litra-contract/blob/main/contracts/dao/Voting.sol#:~:text=function%20changeSupportRequiredPct(,%7D
```solidity
function changeSupportRequiredPct(uint64 _supportRequiredPct)
external
authP(MODIFY_SUPPORT_ROLE, arr(uint256(_supportRequiredPct), uint256(supportRequiredPct)))
{
require(minAcceptQuorumPct <= _supportRequiredPct, ERROR_CHANGE_SUPPORT_PCTS);
require(_supportRequiredPct < PCT_BASE, ERROR_CHANGE_SUPPORT_TOO_BIG);
supportRequiredPct = _supportRequiredPct;
emit ChangeSupportRequired(_supportRequiredPct);
}
```
https://github.com/litrafi/litra-contract/blob/main/contracts/dao/Voting.sol#:~:text=function%20changeMinAcceptQuorumPct(,%7D
```solidity
function changeMinAcceptQuorumPct(uint64 _minAcceptQuorumPct)
external
authP(MODIFY_QUORUM_ROLE, arr(uint256(_minAcceptQuorumPct), uint256(minAcceptQuorumPct)))
{
require(_minAcceptQuorumPct <= supportRequiredPct, ERROR_CHANGE_QUORUM_PCTS);
minAcceptQuorumPct = _minAcceptQuorumPct;
emit ChangeMinQuorum(_minAcceptQuorumPct);
}
```
https://github.com/litrafi/litra-contract/blob/main/contracts/dao/Voting.sol#:~:text=function%20setMinBalance(,%7D
```solidity
function setMinBalance(uint256 _minBalance) external auth(SET_MIN_BALANCE_ROLE) minBalanceCheck(_minBalance) {
minBalance = _minBalance;
emit MinimumBalanceSet(_minBalance);
}
```
https://github.com/litrafi/litra-contract/blob/main/contracts/dao/Voting.sol#:~:text=function%20setMinTime(,%7D
```solidity
function setMinTime(uint256 _minTime) external auth(SET_MIN_TIME_ROLE) minTimeCheck(_minTime) {
minTime = _minTime;
emit MinimumTimeSet(_minTime);
}
```
https://github.com/litrafi/litra-contract/blob/main/contracts/dao/Voting.sol#:~:text=function%20disableVoteCreationOnce(),%7D
```solidity
function disableVoteCreationOnce() external auth(DISABLE_VOTE_CREATION) {
    enableVoteCreation = false;
}
```
https://github.com/litrafi/litra-contract/blob/main/contracts/dao/Voting.sol#:~:text=function%20enableVoteCreationOnce(),%7D
```solidity
function enableVoteCreationOnce() external auth(ENABLE_VOTE_CREATION) {
     enableVoteCreation = true;
}
```
##### Recommendation
Functions guaranteed to revert when called by normal users can be marked ``payable``
#### [L-35] USE_ASSEMBLY_FOR_ ZERO_CHECKING 
##### Description
In order to save 6 gas per instance, you should use assembly to check for  `address(0)`
https://github.com/litrafi/litra-contract/blob/main/contracts/dao/LA.sol#:~:text=require(minter%20%3D%3D%20address(0)%2C%20%22Already%20set%22)%3B
```solidity
require(minter == address(0), "Already set");
```
https://github.com/litrafi/litra-contract/blob/main/contracts/dao/LA.sol#:~:text=require(_to%20!%3D%20address(0)%2C%20%22Zero%20address%22)%3B
```solidity
require(_to != address(0), "Zero address");
```
##### Recommendation
Better using ``assembly`` for checking zero address
```solidity
- require(minter == address(0), "Already set");
+ assembly {
+  if iszero(minter) {
+    mstore(0x00, "Already set")
+    revert(0x00, 0x20)
   }
}
```
```solidity
- require(_to != address(0), "Zero address");
+ assembly {
+  if iszero(_to) {
+    mstore(0x00, "Zero address")
+    revert(0x00, 0x20)
   }
}
```
#### [L-36] ERROR_IN_NAME_OF_FUNCTION  
##### Description
There is a spelling error in naming function ``setAmind`` in ``contarcts/LA.sol``
https://github.com/litrafi/litra-contract/blob/main/contracts/dao/LA.sol#:~:text=function%20setAmind(address%20_admin)%20external%20%7B
```solidity
function setAmind(address  _admin) external {
```
##### Recommendation
You should write ``setAdmin()``
#### [L-37] THERE_IS_NO_CHECK_THAT_TOKEN_ALREADY_EXISTS  
##### Description
Consider checking that token already exists before ``_mint()``
https://github.com/litrafi/litra-contract/blob/main/contracts/dao/LA.sol#:~:text=function%20mint(,(_to%2C%20_value)%3B
```solidity
function mint(address _to, uint256 _value) external {
    require(_msgSender() == minter, "!minter");
    require(_to != address(0), "Zero address");
    if(block.timestamp >= startEpochTime + RATE_REDUCTION_TIME) {
         _updateMiningParamters();
    }
    _mint(_to, _value);
}
```
##### Recommendation
You should make check token's existence:
```solidity
function mint(address _to, uint256 _value) external {
    require(_msgSender() == minter, "!minter");
  + require(msg.sender[_value] == address(0), 'Token already exists');
    require(_to != address(0), "Zero address");
    if(block.timestamp >= startEpochTime + RATE_REDUCTION_TIME) {
         _updateMiningParamters();
    }
    _mint(_to, _value);
}
```