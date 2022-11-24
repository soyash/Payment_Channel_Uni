// SPDX-License-Identifier: MIT

pragma solidity ^0.8.13;

import "OpenZeppelin/openzeppelin-contracts@4.7.3/contracts/utils/cryptography/ECDSA.sol";
import "OpenZeppelin/openzeppelin-contracts@4.7.3/contracts/security/ReentrancyGuard.sol";

contract unidirectional is ReentrancyGuard {

    using ECDSA for bytes32;

    address payable public owner;
    address payable public receiver;

    // naming convention constants CAPS
    uint private constant DURATION = 7 * 24 * 60 * 60;
    uint public expiresAt;

    constructor(address _receiver) payable {
        require(_receiver != address(0), "Receiver address cannot be Zero address");
        owner = payable(msg.sender);
        receiver = payable(_receiver);
        expiresAt = block.timestamp + DURATION;
    }

    // function to create hash that will be signed by the owner - owners signs hash of (address of this contract and amount)
    function _getHash(uint _amount) private view returns(bytes32) {
        require(address(this).balance >= _amount, "Contract needs more funds");
        return keccak256(abi.encodePacked(address(this), _amount));
    }

    function getHash(uint _amount) external view returns(bytes32) {
        return _getHash(_amount);
    }

    function _getEthSignedHash(uint _amount) private view returns (bytes32) {
        bytes32 data = _getHash(_amount);
        return keccak256(abi.encodePacked("\x19Ethereum Signed Message:\n32", data));
    }

    function getEthSignedHash(uint _amount) external view returns (bytes32) {
        return _getEthSignedHash(_amount);
    }

    function _verify(uint _amount, bytes memory _sig) private view returns(bool) {
        return _getEthSignedHash(_amount).recover(_sig) == owner;
    }

    function verify(uint _amount, bytes memory _sig) external view returns(bool) {
        return _verify(_amount, _sig);
    }

    function close(uint _amount, bytes memory _sig) external nonReentrant {
        require(msg.sender == receiver || msg.sender == owner, "Contract can only be closed by receiver or owner");
        require(_verify(_amount, _sig), "Invalid sign");

        (bool sent, ) = receiver.call{value: _amount}("");
        require(sent, "Failed to send ETH");
        selfdestruct(owner);
    }

    function cancel() external {
        require(msg.sender == owner);
        require(block.timestamp >= expiresAt, "Cant cancel contract before expiry");
        selfdestruct(owner);
    }

}