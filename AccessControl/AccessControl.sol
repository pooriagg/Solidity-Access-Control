// SPDX-License-Identifier: GPL-3.0
pragma solidity ^0.8.0;

contract AccessControl {

    string public name;

    mapping (bytes32 => mapping(address => bool)) public roles;

    event GrantRole(bytes32 indexed role, address indexed grantedAddress, uint indexed time);
    event RevokRole(bytes32 indexed role, address indexed revokedAddress, uint indexed time);
    event NameSet(address indexed executer, string indexed newName, uint indexed time);

    bytes32 private constant ADMIN = keccak256(bytes("ADMIN"));
    bytes32 private constant USER = keccak256(bytes("USER"));

    constructor() {
        roles[ADMIN][msg.sender] = true;
    }

    modifier onlyThisRole(bytes32 _role) {
        require(roles[_role][msg.sender] == true, "You don't have the role.");
        _;
    }

    /// @dev admins can grant role to a arbitrary account
    /// @param _role specify the role
    /// @param _target the account you want to grant role to
    function grantRole(bytes32 _role, address _target) external onlyThisRole(ADMIN) {
        roles[_role][_target] = true;

        emit GrantRole(_role, _target, block.timestamp);
    }

    /// @dev admins can revoke role to a account
    /// @param _role specify the role
    /// @param _target the account you want to grant role to
    function revokeRole(bytes32 _role, address _target) external onlyThisRole(ADMIN) {
        roles[_role][_target] = false;

        emit RevokRole(_role, _target, block.timestamp);
    }

    /// @dev the admins of this contract can set the name state variable
    /// @param _name the string that you wish to set
    /// Note the string must not be empty
    function setName(string calldata _name) external onlyThisRole(ADMIN) {
        require(bytes(_name).length > 5, "Name must have more than 5 characters.");

        name = _name;

        emit NameSet(msg.sender, _name, block.timestamp);
    }

}
