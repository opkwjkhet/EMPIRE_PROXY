import Foundation

/// Centralized runtime decoding for values that should not appear as readable
/// plaintext in the compiled binary. Each byte uses a position-dependent mask,
/// which also avoids storing a recognizable plain hex/ASCII sequence.
enum ProtectedConfiguration {
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
        verified([
            73, 33, 60, 51, 47, 233, 214, 228, 139, 188, 166, 131, 109, 80,
            75, 125, 2, 43, 17, 55, 206, 173, 217, 140, 224, 179, 164, 81,
            38, 118, 96, 36, 31, 41, 17, 161
        ], seed: 0x39, checksum: 0xD5E374B223FE1676)
    }

    static var catalogURL: URL? {
        URL(string: verified([
            207, 204, 189, 170, 152, 198, 34, 49, 66, 41, 63, 10, 26, 235,
            230, 136, 214, 184, 188, 146, 139, 126, 114, 86, 70, 126, 18, 6,
            236, 230, 192, 153, 164, 183, 135, 156, 98, 123, 3, 78, 39, 16
        ], seed: 0xA7, checksum: 0xE6838EDB09563D4F))
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
