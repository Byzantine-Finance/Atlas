// SPDX-License-Identifier: UNLICENSE
pragma solidity 0.8.30;

interface IAtlas {
    event CallExecuted(address indexed sender, address indexed to, uint256 value, bytes data);
    event BatchExecuted(uint256 indexed nonce, Call[] calls);

    error InvalidSignature();
    error ExpiredSignature();
    error Unauthorized();

    /// @notice Represents a single call within a batch.
    struct Call {
        address to;
        uint256 value;
        bytes data;
    }

    function execute(Call[] calldata calls, uint256 deadline, uint8 v, bytes32 r, bytes32 s) external payable;
}

contract Atlas is IAtlas {
    uint256 public nonce;
    mapping(address => bool) public sponsors;

    bytes32 constant DOMAIN_TYPEHASH = keccak256("EIP712Domain(uint256 chainId,address verifyingContract)");
    address constant OWNER = address(0x0000000000000000000000000000000000000000);

    /*
        Modifiers
    */

    modifier onlyOwner() {
        require(msg.sender == OWNER, Unauthorized());
        _;
    }

    modifier onlySponsor() {
        require(sponsors[msg.sender], Unauthorized());
        _;
    }

    /*
        External functions
    */

    function execute(Call[] calldata calls, uint256 deadline, uint8 v, bytes32 r, bytes32 s)
        external
        payable
        onlySponsor
    {
        bytes memory encodedCalls;

        // Verify if the execution has not expired
        require(block.timestamp < deadline, ExpiredSignature());

        // Encode the calls to calculate the digest
        for (uint256 i = 0; i < calls.length; i++) {
            encodedCalls = abi.encodePacked(encodedCalls, calls[i].to, calls[i].value, calls[i].data);
        }

        // EIP 712 compliant message digest. The digest also include the "nonce" and "deadline" to verify the instructions.
        bytes32 digest = keccak256(
            abi.encodePacked(hex"1901", DOMAIN_SEPARATOR(), keccak256(abi.encodePacked(deadline, nonce, encodedCalls)))
        );

        // Recover the signer from the provided signature and the digest of the message signed
        address recoveredAddress = ecrecover(digest, v, r, s);
        require(recoveredAddress == address(this), InvalidSignature());

        _executeBatch(calls);
    }

    function addSponsor(address sponsor) external onlyOwner {
        sponsors[sponsor] = true;
    }

    function removeSponsor(address sponsor) external onlyOwner {
        sponsors[sponsor] = false;
    }

    /*
        Internal functions
    */

    function _executeBatch(Call[] calldata calls) internal {
        uint256 currentNonce = nonce;
        nonce++; // Increment nonce to protect against replay attacks

        for (uint256 i = 0; i < calls.length; i++) {
            _executeCall(calls[i]);
        }

        emit BatchExecuted(currentNonce, calls);
    }

    function _executeCall(Call calldata callItem) internal {
        // address(this) in the contract equals the EOA address NOT the contract address
        (bool success,) = callItem.to.call{value: callItem.value}(callItem.data);
        require(success, "Call reverted");
        emit CallExecuted(msg.sender, callItem.to, callItem.value, callItem.data);
    }

    /*
        Views
    */

    function DOMAIN_SEPARATOR() public view returns (bytes32) {
        return keccak256(abi.encode(DOMAIN_TYPEHASH, block.chainid, address(this)));
    }
}
