import Foundation

/// Centralized runtime decoding for values that should not appear as readable
/// plaintext in the compiled binary. Each byte uses a position-dependent mask,
/// which also avoids storing a recognizable plain hex/ASCII sequence.
enum ProtectedConfiguration {
    /// Decodes a value protected with a random per-byte mask and a second
    /// position-dependent transform. This avoids embedding the token as a
    /// plaintext string or as a single trivially XORed byte sequence.
    private static func decodeMasked(
        cipher: [UInt8],
        mask: [UInt8],
        checksum: UInt64
    ) -> String {
        guard cipher.count == mask.count else { return "" }
        let bytes = zip(cipher, mask).enumerated().map { index, pair -> UInt8 in
            let position = UInt8(truncatingIfNeeded: (index &* 29) &+ 0x53)
            return (pair.0 &- position) ^ pair.1
        }
        guard let value = String(bytes: bytes, encoding: .utf8) else { return "" }
        var hash: UInt64 = 0xcbf29ce484222325
        for byte in value.utf8 {
            hash ^= UInt64(byte)
            hash = hash &* 0x100000001b3
        }
        return hash == checksum ? value : ""
    }

    private static func decode(_ bytes: [UInt8], seed: UInt8) -> String {
        let decoded = bytes.enumerated().map { index, byte in
            byte ^ (seed &+ UInt8(truncatingIfNeeded: index &* 17))
        }
        return String(bytes: decoded, encoding: .utf8) ?? ""
    }

    private static func verified(
        _ bytes: [UInt8],
        seed: UInt8,
        checksum: UInt64
    ) -> String {
        let value = decode(bytes, seed: seed)
        var hash: UInt64 = 0xcbf29ce484222325
        for byte in value.utf8 {
            hash ^= UInt64(byte)
            hash = hash &* 0x100000001b3
        }
        return hash == checksum ? value : ""
    }

    static var packageToken: String {
        decodeMasked(
            cipher: [
                168, 117, 93, 9, 226, 217, 147, 142, 98, 48, 47, 209, 168, 104,
                56, 47, 33, 207, 154, 85, 49, 197, 238, 230, 215, 63, 29, 239,
                145, 214, 157, 102, 246, 221, 234, 87
            ],
            mask: [
                37, 110, 183, 0, 73, 146, 219, 36, 109, 182, 255, 72, 145, 218,
                35, 108, 181, 254, 71, 144, 217, 34, 107, 180, 253, 70, 143, 216,
                33, 106, 179, 252, 69, 142, 215, 32
            ],
            checksum: 0xD5E374B223FE1676
        )
    }

    static var catalogURL: URL? {
        URL(string: verified([
            3, 8, 249, 238, 220, 250, 254, 205, 158, 109, 123, 78, 94, 39,
            42, 68, 26, 252, 248, 214, 207, 162, 142, 138, 122, 58, 86, 66,
            40, 42, 12, 85, 232, 243, 195, 216, 166, 135, 223, 114, 123, 84
        ], seed: 0x6B, checksum: 0xE6838EDB09563D4F))
    }

    static var updateAPIURL: URL {
        URL(string: verified([
            53, 26, 11, 224, 210, 136, 236, 251, 132, 134, 110, 54, 78, 83,
            63, 52, 24, 28, 161, 195, 222, 175, 252, 150, 144, 118, 120, 91,
            22, 19, 58, 2, 26, 196, 246, 217, 168, 187, 204, 199, 52, 38, 18,
            23, 59, 63, 7, 25, 236, 237, 202, 179, 254, 142, 146, 112, 112, 85, 67
        ], seed: 0x5D, checksum: 0x411FC465623DC1A9))!
    }

    static var updateFallbackURL: URL {
        URL(string: verified([
            171, 160, 145, 134, 116, 34, 6, 21, 44, 53, 25, 22, 250, 194,
            159, 161, 188, 137, 218, 95, 118, 70, 94, 0, 50, 5, 20, 231, 176,
            131, 240, 226, 214, 219, 119, 115, 75, 93, 40, 41, 14, 15, 162,
            242, 206, 180, 180, 145, 135
        ], seed: 0xC3, checksum: 0xEAF0544AC60ADCAD))!
    }
}
