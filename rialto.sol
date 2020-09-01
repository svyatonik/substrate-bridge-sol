// Copyright 2019-2020 Parity Technologies (UK) Ltd.
// This file is part of Parity Bridges Common.

// Parity Bridges Common is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.

// Parity Bridges Common is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU General Public License for more details.

// You should have received a copy of the GNU General Public License
// along with Parity Bridges Common.  If not, see <http://www.gnu.org/licenses/>.

pragma solidity ^0.7.0;

/// @title Rialto-specific methods and structs.
contract Rialto {
	// ========================================================================
	// === Chain-specific methods and functions ===============================
	// ========================================================================

	// Maximal validators set id supported by the contract.
	uint32 constant GRANDPA_ENGINE_ID = 0x46524e4b;

	/// Parsed header.
	struct ParsedHeader {
		// Header hash.
		bytes32 hash;
		// Parent header hash.
		bytes32 parentHash;
		// Header number.
		uint256 number;
		// Validators set change signal delay.
		uint256 signalDelay;
		// Validators set change signal.
		Authority[] signal;
	}

	/// GRANDPA authority.
	struct Authority {
		// Authority id (ed25519 public key).
		bytes32 id;
		// Authority weight.
		uint64 weight;
	}

	/// Ephemeral precommit.
	struct Precommit {
		// Block number.
		uint256 number;
		// Block hash.
		bytes32 hash;
	}

	/// Ephemeral vote.
	struct Vote {
		// Block number.
		uint256 number;
		// Block hash.
		bytes32 hash;
		// Cumulative weight of authorities voted for given block.
		uint64 weight;
	}

	/// Parse Rialto header.
	function parseHeader(bytes memory rawHeader) internal pure returns (ParsedHeader memory) {
		EncodedBuffer memory buffer;
		buffer.buffer = rawHeader; // TODO: is it copied here???
		return doParseHeader(buffer);
	}

	/// Verify Rialto finality proof.
	function verifyFinalityProof(
		uint256 finalityTargetNumber,
		bytes32 finalityTargetHash,
		uint64 bestSetId,
		uint64 authoritiesWeight,
		Authority[] memory authorities,
		bytes memory rawFinalityProof
	) private view returns (bytes32) {
		// prepare buffer to decode
		EncodedBuffer memory buffer;
		buffer.buffer = rawFinalityProof; // TODO: is it copied here?

		// decode and verify justification 'header'
		skipFixed_u64(buffer); // round
		bytes32 commitTargetHash = decodeBytes32(buffer);
		uint256 commitTargetNumber = decodeFixed_u32(buffer);
		if (commitTargetNumber != finalityTargetNumber || commitTargetHash != finalityTargetHash) {
			revert("invalid commit target in GRANDPA justification");
		}

		// validate GRANDPA commit (fn finality_grandpa::validate_commit())
		bytes32[] memory votedAuthorities = new bytes32[](authorities.length);
		uint256 numVotedAuthorities = 0;
		uint64 precommitsWeight = 0;
		uint256 precommitsCount = decodeCompactInt(buffer);
		Precommit[] memory precommits = new Precommit[](precommitsCount);
		for (uint256 precommitIndex = 0; precommitIndex < precommitsCount; ++precommitIndex) {
			bytes32 precommitTargetHash = decodeBytes32(buffer);
			uint64 precommitTargetNumber = decodeFixed_u32(buffer);
			(bytes32 precommitSignatureHi, bytes32 precommitSignatureLo) = decodeBytes64(buffer);
			bytes32 precommitAuthorityId = decodeBytes32(buffer);

			require(
				precommitTargetNumber >= commitTargetNumber,
				"all precommits must be descendants of commit"
			);

			// TODO: require that precommitTargetHash should be descendent of equal to commitTargetHash
			// (i.e. there should be path from precommitTargetHash to commitTargetHash by parents in ancestry)

			// TODO: check signature

			// check if authority is in the set
			uint256 authorityIndex = 0;
			for (; authorityIndex < authorities.length; ++authorityIndex) {
				if (authorities[authorityIndex].id == precommitAuthorityId) {
					break;
				}
			}
			require(
				authorityIndex < authorities.length,
				"signed by unknown authority"
			);

			// check if authority has already voted
			uint256 votedAuthorityIndex = 0;
			for (; votedAuthorityIndex < numVotedAuthorities; ++votedAuthorityIndex) {
				if (votedAuthorities[votedAuthorityIndex] == precommitAuthorityId) {
					revert("double vote");
				}
			}

			// remember that this authority has voted
			votedAuthorities[votedAuthorityIndex] = precommitAuthorityId;
			numVotedAuthorities += 1;
			precommitsWeight += authorities[authorityIndex].weight;

			// remember precommit
			uint256 precommitInsertIndex = precommitIndex;
			for (; precommitInsertIndex > 0; --precommitInsertIndex) {
				if (precommits[precommitInsertIndex - 1].number <= precommitTargetNumber) {
					break;
				}
			}
			for (
				uint256 precommitMoveIndex = precommitIndex + 1;
				precommitMoveIndex > precommitInsertIndex + 1;
				--precommitMoveIndex
			) {
				precommits[precommitMoveIndex] = precommits[precommitMoveIndex - 1];
			}
			precommits[precommitInsertIndex].number = precommitTargetNumber;
			precommits[precommitInsertIndex].hash = precommitTargetHash;
		}

		// fail if weight is not enough
		uint64 requiredWeight = authoritiesWeight - (authoritiesWeight - 1) / 3;
		require (
			precommitsWeight >= requiredWeight,
			"weight is not enough"
		);

		// now traverse ancestry
		uint256 ancestryCount = decodeCompactInt(buffer);
		Vote[] memory votes = new Vote[](ancestryCount);
		for (uint256 ancestorIndex = 0; ancestorIndex < ancestryCount; ++ancestorIndex) {
			ParsedHeader memory ancestor = doParseHeader(buffer);

			uint256 voteInsertIndex = ancestorIndex;
			for (; voteInsertIndex > 0; --voteInsertIndex) {
				if (votes[voteInsertIndex - 1].number <= ancestor.number) {
					break;
				}
			}
			for (
				uint256 voteMoveIndex = ancestorIndex + 1;
				voteMoveIndex > voteInsertIndex + 1;
				--voteMoveIndex
			) {
				votes[voteMoveIndex] = votes[voteMoveIndex - 1];
			}
			votes[voteInsertIndex].number = ancestor.number;
			votes[voteInsertIndex].hash = ancestor.hash;
		}

		// TODO: something wrong with weight calculation + equivocation
		// update votes with weights

		// TODO: the idea is to update every entry in votes with weights from precommits
		// (both arrays are sorted) && then start search from the back of votes && select
		// header with largest number (naturally, because vecs are sorted) and weight >= requiredWeight
	}

	/// Parse Rialto header.
	function doParseHeader(EncodedBuffer memory buffer) internal pure returns (ParsedHeader memory) {
		ParsedHeader memory result;

		// compute header hash using builtin
		result.hash = bytes32(0); // TODO: builtin

		// decode/skip basic header fields
		result.parentHash = decodeBytes32(buffer);
		result.number = decodeFixed_u32(buffer);
		skipBytes32(buffer); // stateRoot
		skipBytes32(buffer); // extrinsicsRoot

		// now parse digest and get change signal
		uint256 digestCount = decodeCompactInt(buffer);
		for (uint256 digestIndex = 0; digestIndex < digestCount; ++digestIndex) {
			uint8 digestType = decodeFixed_u8(buffer);
			if (digestType == 0) { // ChangesTrieRoot
				skipBytes32(buffer); // changes trie root
			} else if (digestType == 1) { // PreRuntime
				skipFixed_u32(buffer); // consensus engine id
				skipBytesVector(buffer); // digest data
			} else if (digestType == 2) { // Consensus
				uint32 consensusEngine = decodeFixed_u32(buffer);
				if (consensusEngine == GRANDPA_ENGINE_ID) {
					uint8 consensusLogType = decodeFixed_u8(buffer);
					if (consensusLogType == 0) { // ScheduledChange
						uint256 nextAuthoritiesCount = decodeCompactInt(buffer);
						result.signal = new Authority[](nextAuthoritiesCount);
						for (uint256 nextAuthorityIndex = 0; nextAuthorityIndex < nextAuthoritiesCount; ++nextAuthorityIndex) {
							bytes32 nextAuthorityId = decodeBytes32(buffer);
							uint64 nextAuthorityWeight = decodeFixed_u64(buffer);
							result.signal[nextAuthorityIndex].id = nextAuthorityId;
							result.signal[nextAuthorityIndex].weight = nextAuthorityWeight;
						}

						result.signalDelay = decodeFixed_u32(buffer);
					} else if (consensusLogType == 1) { // ForcedChange
						skipFixed_u32(buffer); // delay
						uint256 nextAuthoritiesCount = decodeCompactInt(buffer);
						skipBytes(buffer, nextAuthoritiesCount * 40 + 4);
					} else if (consensusLogType == 2) { // OnDisabled
						skipFixed_u64(buffer); // delay
					} else if (consensusLogType == 3) { // Pause
						skipFixed_u32(buffer); // delay
					} else if (consensusLogType == 4) { // Resume
						skipFixed_u32(buffer); // delay
					} else {
						revert("unexpected GRANDPA consensus log type");
					}
				} else {
					skipBytesVector(buffer); // digest data
				}
			} else if (digestType == 3) { // Seal
				skipFixed_u32(buffer); // consensus engine id
				skipBytesVector(buffer); // digest data
			} else if (digestType == 4) { // ChangesTrieSignal
				revert("TODO");
			} else if (digestType == 5) { // Other
				skipBytesVector(buffer); // digest data
			} else {
				revert("unexpected digest type");
			}
		}
	}

	// ========================================================================
	// === General Decode structs and methods =================================
	// ========================================================================

	struct EncodedBuffer {
		bytes buffer;
		uint256 offset;
	}

	/// Decode u8.
	/// @return Decoded value.
	function decodeFixed_u8(EncodedBuffer memory encoded) internal pure returns (uint8) {
		uint8 decoded = uint8(encoded.buffer[encoded.offset]);
		encoded.offset += 1;
		return (decoded);
	}

	/// Skip fixed u32.
	function skipFixed_u32(EncodedBuffer memory encoded) internal pure {
		encoded.offset += 4;
	}

	/// Decode u32.
	/// @return Decoded value and updated offset.
	function decodeFixed_u32(EncodedBuffer memory encoded) internal pure returns (uint32) {
		uint32 decoded = uint32(uint8(encoded.buffer[encoded.offset + 3])) << 24 |
			uint32(uint8(encoded.buffer[encoded.offset + 2])) << 16 |
			uint32(uint8(encoded.buffer[encoded.offset + 1])) << 8 |
			uint32(uint8(encoded.buffer[encoded.offset]));
		encoded.offset += 4;
		return (decoded);
	}

	/// Skip fixed u64.
	function skipFixed_u64(EncodedBuffer memory encoded) internal pure {
		encoded.offset += 8;
	}

	/// Decode u64.
	/// @return Decoded value and updated offset.
	function decodeFixed_u64(EncodedBuffer memory encoded) internal pure returns (uint64) {
		uint64 decoded = uint64(uint8(encoded.buffer[encoded.offset + 7])) << 56 |
			uint64(uint8(encoded.buffer[encoded.offset + 6])) << 48 |
			uint64(uint8(encoded.buffer[encoded.offset + 5])) << 40 |
			uint64(uint8(encoded.buffer[encoded.offset + 4])) << 32 |
			uint64(uint8(encoded.buffer[encoded.offset + 3])) << 24 |
			uint64(uint8(encoded.buffer[encoded.offset + 2])) << 16 |
			uint64(uint8(encoded.buffer[encoded.offset + 1])) << 8 |
			uint64(uint8(encoded.buffer[encoded.offset]));
		encoded.offset += 8;
		return (decoded);
	}

	/// Decode u128.
	/// @return Decoded value and updated offset.
	function decodeFixed_u128(EncodedBuffer memory encoded) internal pure returns (uint128) {
		uint128 decodedHi = uint128(uint8(encoded.buffer[encoded.offset + 15])) << 120 |
			uint128(uint8(encoded.buffer[encoded.offset + 14])) << 112 |
			uint128(uint8(encoded.buffer[encoded.offset + 13])) << 104 |
			uint128(uint8(encoded.buffer[encoded.offset + 12])) << 96 |
			uint128(uint8(encoded.buffer[encoded.offset + 11])) << 88 |
			uint128(uint8(encoded.buffer[encoded.offset + 10])) << 80 |
			uint128(uint8(encoded.buffer[encoded.offset + 9])) << 72 |
			uint128(uint8(encoded.buffer[encoded.offset + 8])) << 64;
		uint128 decodedLo = uint128(uint8(encoded.buffer[encoded.offset + 7])) << 56 |
			uint128(uint8(encoded.buffer[encoded.offset + 6])) << 48 |
			uint128(uint8(encoded.buffer[encoded.offset + 5])) << 40 |
			uint128(uint8(encoded.buffer[encoded.offset + 4])) << 32 |
			uint128(uint8(encoded.buffer[encoded.offset + 3])) << 24 |
			uint128(uint8(encoded.buffer[encoded.offset + 2])) << 16 |
			uint128(uint8(encoded.buffer[encoded.offset + 1])) << 8 |
			uint128(uint8(encoded.buffer[encoded.offset]));
		encoded.offset += 16;
		return (decodedHi | decodedLo);
	}

	/// Decode compact integer.
	/// @return Decoded value and updated offset.
	function decodeCompactInt(EncodedBuffer memory encoded) internal pure returns (uint256) {
		uint8 b0 = uint8(encoded.buffer[encoded.offset]);

		// single-byte mode; upper six bits are the LE encoding of the value (valid only for values of 0-63).
		if (b0 & 0x03 == 0x00) {
			encoded.offset += 1;
			return uint256((b0 & 0xFC) >> 2);
		}

		// two-byte mode: upper six bits and the following byte is the LE encoding of the value
		// (valid only for values 64-(2**14-1)).
		if (b0 & 0x03 == 0x01) {
			uint256 decoded = (uint256(uint8(encoded.buffer[encoded.offset + 1])) << 8 |
				uint256(b0)
			) >> 2;
			require (decoded > 0x0000003F && decoded <= 0x003FFFFF, "Out of range");
			encoded.offset += 2;
			return decoded;
		}

		// four-byte mode: upper six bits and the following three bytes are the LE encoding of the
		// value (valid only for values (2**14-1)-(2**30-1)).
		if (b0 & 0x03 == 0x02) {
			uint256 decoded = (uint256(uint8(encoded.buffer[encoded.offset + 3])) << 24 |
				uint256(uint8(encoded.buffer[encoded.offset + 2])) << 16 |
				uint256(uint8(encoded.buffer[encoded.offset + 1])) << 8 |
				uint256(b0)
			) >> 2;
			require (decoded > 0x003FFFFF && decoded <= 0x3FFFFFFF, "Out of range");
			encoded.offset += 4;
			return decoded;
		}

		// Big-integer mode: The upper six bits are the number of bytes following, less four. The value
		// is contained, LE encoded, in the bytes following. The final (most significant) byte must be
		// non-zero. Valid only for values (2**30-1)-(2**536-1)

		uint8 valueBytes = (b0 >> 2) + 4;

		// in Rust we only support u128 for now => ignore everything that may be larger
		require (valueBytes <= 16, "Unexpected compact encoding prefix");

		encoded.offset += 1;
		if (valueBytes == 16) {
			uint256 decoded = decodeFixed_u128(encoded);
			require (decoded > 0x00FFFFFFFFFFFFFFFFFFFFFFFFFFFFFF, "Out of range");
			return decoded;
		} else if (valueBytes == 8) {
			uint256 decoded = decodeFixed_u64(encoded);
			require (decoded > 0x00FFFFFFFFFFFFFF, "Out of range");
			return decoded;
		} else if (valueBytes > 8) {
			uint256 decoded = decodeFixed_u64(encoded);
			decoded = decoded | uint256(uint8(encoded.buffer[encoded.offset])) << 64;
			if (valueBytes >= 10) {
				decoded = decoded | uint256(uint8(encoded.buffer[encoded.offset + 1])) << 72;
			}
			if (valueBytes >= 11) {
				decoded = decoded | uint256(uint8(encoded.buffer[encoded.offset + 2])) << 80;
			}
			if (valueBytes >= 12) {
				decoded = decoded | uint256(uint8(encoded.buffer[encoded.offset + 3])) << 88;
			}
			if (valueBytes >= 13) {
				decoded = decoded | uint256(uint8(encoded.buffer[encoded.offset + 4])) << 96;
			}
			if (valueBytes >= 14) {
				decoded = decoded | uint256(uint8(encoded.buffer[encoded.offset + 5])) << 104;
			}
			if (valueBytes == 15) {
				decoded = decoded | uint256(uint8(encoded.buffer[encoded.offset + 6])) << 112;
			}
			require (
				decoded > (uint256(0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF) >> (16 - valueBytes + 1) * 8),
				"Out of range"
			);
			encoded.offset += valueBytes - 8;
			return decoded;
		} else if (valueBytes == 4) {
			uint256 decoded = decodeFixed_u32(encoded);
			require (decoded > 0x00FFFFFFFFFFFFFF, "Out of range");
			return decoded;
		}

		// else: valueBytes in [5; 7]
		uint256 decoded = decodeFixed_u32(encoded);
		decoded = decoded | uint256(uint8(encoded.buffer[encoded.offset])) << 32;
		if (valueBytes >= 6) {
			decoded = decoded | uint256(uint8(encoded.buffer[encoded.offset + 1])) << 40;
		}
		if (valueBytes == 7) {
			decoded = decoded | uint256(uint8(encoded.buffer[encoded.offset + 2])) << 48;
		}
		require (
			decoded > (uint256(0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF) >> (16 - valueBytes + 1) * 8),
			"Out of range"
		);
		encoded.offset += valueBytes - 4;
		return decoded;
	}

	/// Skip fixed 32-bytes array.
	function skipBytes32(EncodedBuffer memory encoded) internal pure {
		encoded.offset += 32;
	}

	/// Decode fixed 32-bytes array.
	/// @return Decoded value and updated offset.
	function decodeBytes32(EncodedBuffer memory encoded) internal pure returns (bytes32) {
		bytes32 rawArray = bytes32(0);
		assembly {
			let bufferAddr := mload(encoded)
			let bufferOffset := mload(add(encoded, 0x20))
			let arrayAddr := add(bufferAddr, bufferOffset)
			mstore(rawArray, mload(arrayAddr))
		}
		encoded.offset += 32;
		return rawArray;
	}

	/// Decode fixed 64-bytes array.
	/// @return Decoded value and updated offset.
	function decodeBytes64(EncodedBuffer memory encoded) internal pure returns (bytes32, bytes32) {
		bytes32 hi = decodeBytes32(encoded);
		bytes32 lo = decodeBytes32(encoded);
		return (hi, lo);
	}

	/// Skip encoded Vec<u8>.
	function skipBytesVector(EncodedBuffer memory encoded) internal pure {
		uint256 bytesCount = decodeCompactInt(encoded);
		encoded.offset += bytesCount;
	}

	/// Skip arbitrary number of bytes.
	function skipBytes(EncodedBuffer memory encoded, uint256 bytesToSkip) internal pure {
		encoded.offset += bytesToSkip;
	}
}
