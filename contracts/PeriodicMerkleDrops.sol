pragma solidity ^0.7;
pragma abicoder v2;

import "@openzeppelin/contracts/access/Ownable.sol";
import "@openzeppelin/contracts/token/ERC20/IERC20.sol";

contract PeriodicMerkleDrops is Ownable {

    struct Claim {
        uint256 index;
        uint256 period;
        uint256 balance;
        bytes32[] merkleProof;
    }

    IERC20 public immutable token;
    // Recorded periods
    mapping(uint256 => bytes32) public merkleRoots;
    mapping(uint256 => mapping(uint256 => uint256)) public claimedBitMap;

    event Claimed(uint256 indexed period, uint256 index, address indexed account, uint256 amount);

    constructor(address _token) {
        token = IERC20(_token);
    }

    function claimPeriod(
        uint256 _index,
        address _account,
        uint256 _period,
        uint256 _claimedBalance,
        bytes32[] calldata _merkleProof
    )
        external
    {
        uint256 claimedWordIndex = _index / 256;
        uint256 claimedBitIndex = _index % 256;
        uint256 claimedWord = claimedBitMap[_period][claimedWordIndex];
        uint256 mask = (1 << claimedBitIndex);

        // Check if drop was already claimed
        require(claimedWord & mask != mask, 'Drop already claimed.');

        // Verify the merkle proof.
        bytes32 leaf = keccak256(abi.encodePacked(_index, _account, _claimedBalance));
        require(verifyProof(_merkleProof, merkleRoots[_period], leaf), 'Invalid proof.');

        // Mark it claimed and send the token.
        claimedBitMap[_period][claimedWordIndex] = claimedWord | mask;
        require(IERC20(token).transfer(_account, _claimedBalance), 'Transfer failed.');
        emit Claimed(_period, _index, _account, _claimedBalance);
    }

    function claimMultiplePeriods(
        address _account,
        Claim[] calldata claims
    )
        external
    {
        uint256 totalBalance = 0;
        uint256 totalClaims = claims.length;
        Claim calldata claim;
        for(uint256 i = 0; i < totalClaims; i++) {
            claim = claims[i];
            
            uint256 claimedWordIndex = claim.index / 256;
            uint256 claimedBitIndex = claim.index % 256;
            uint256 claimedWord = claimedBitMap[claim.period][claimedWordIndex];
            uint256 mask = (1 << claimedBitIndex);

            // Check if drop was already claimed
            require(claimedWord & mask != mask, 'Drop already claimed.');

            // Verify the merkle proof.
            bytes32 leaf = keccak256(abi.encodePacked(claim.index, _account, claim.balance));
            require(verifyProof(claim.merkleProof, merkleRoots[claim.period], leaf), 'Invalid proof.');

            // Mark it claimed and send the token.
            claimedBitMap[claim.period][claimedWordIndex] = claimedWord | mask;
            emit Claimed(claim.period, claim.index, _account, claim.balance);

            totalBalance += claim.balance;
        }
        require(IERC20(token).transfer(_account, totalBalance), 'Transfer failed.');
    }

    function claimStatus(uint256[] calldata _indices, uint256 _begin, uint256 _end)
        external
        view
        returns (bool[] memory)
    {
        uint256 size = 1 + _end - _begin;
        require(size == _indices.length, "Total periods and total indices must be equal.");

        bool[] memory arr = new bool[](size);
        for(uint256 i = 0; i < size; i++) {
            arr[i] = isClaimed(_indices[i], _begin + i);
        }
        return arr;
    }

    function getMerkleRoots(uint256 _begin, uint256 _end) 
        external
        view 
        returns (bytes32[] memory)
    {
        uint256 size = 1 + _end - _begin;
        bytes32[] memory arr = new bytes32[](size);
        for(uint256 i = 0; i < size; i++) {
            arr[i] = merkleRoots[_begin + i];
        }
        return arr;
    }

    function seedAllocations(
        uint256 _period,
        bytes32 _merkleRoot,
        uint256 _totalAllocation,
        address _contributor
    )
        external
        onlyOwner
    {
        require(merkleRoots[_period] == bytes32(0), "Cannot overwrite merkle root.");
        merkleRoots[_period] = _merkleRoot;

        require(token.transferFrom(_contributor, address(this), _totalAllocation), "Transfer failed.");
    }

    function isClaimed(uint256 _index, uint256 _period) public view returns (bool) {
        uint256 claimedWordIndex = _index / 256;
        uint256 claimedBitIndex = _index % 256;
        uint256 claimedWord = claimedBitMap[_period][claimedWordIndex];
        uint256 mask = (1 << claimedBitIndex);
        return claimedWord & mask == mask;
    }

    function verifyProof(bytes32[] calldata proof, bytes32 root, bytes32 leaf) internal pure returns (bool) {
        bytes32 computedHash = leaf;

        uint256 proofLength = proof.length;
        for (uint256 i = 0; i < proofLength; i++) {
            bytes32 proofElement = proof[i];

            if (computedHash <= proofElement) {
                // Hash(current computed hash + current element of the proof)
                computedHash = keccak256(abi.encodePacked(computedHash, proofElement));
            } else {
                // Hash(current element of the proof + current computed hash)
                computedHash = keccak256(abi.encodePacked(proofElement, computedHash));
            }
        }

        // Check if the computed hash (root) is equal to the provided root
        return computedHash == root;
    }
}