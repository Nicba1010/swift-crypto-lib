import BigInt

public extension UInt8 {
    public func pow(exp: UInt8) -> UInt8 {
        var result: UInt8 = 1

        for _ in 0..<exp {
            result *= self
        }

        return result
    }
}

public extension BigInt {
    public func to_bytes_le() -> Array<UInt8> {
        var bits: Array<Bool> = Array<Bool>()

        var copy: BigInt = self

        while (copy > 0) {
            if (copy % 2 == 1) {
                bits.append(true)
            } else {
                bits.append(false)
            }

            copy /= 2
        }

        if (bits.count % 8 != 0) {
            for entry in Array<Bool>(repeating: false, count: 8 - (bits.count % 8)) {
                bits.append(entry)
            }
        }
        bits = bits.reversed()

        var bytes: Array<UInt8> = Array<UInt8>()
        for byte_i in 0..<(bits.count / 8) {
            var byte: UInt8 = 0

            let bits_sub: Array<Bool> = bits[(byte_i * 8)..<((byte_i + 1)*8)].reversed()

            for bit_i in 0..<8 {
                if bits_sub[bit_i] {
                    byte += UInt8(2).pow(exp: UInt8(bit_i))
                }
            }

            bytes.append(byte)
        }

        return bytes.reversed()
    }
}

public struct mod_int: AdditiveArithmetic, Equatable, CustomStringConvertible {
    public let value: BigInt
    public let modulus: BigInt

    public var description: String {"(val: \(value), mod: \(modulus))"}

    public static func from(value: BigInt) -> mod_int {
        mod_int(
                value: value,
                modulus: 0
        )
    }

    public init(value: BigInt, modulus: BigInt) {
        if (modulus == 0) {
            self.value = value
        } else {
            self.value = value % modulus
        }
        self.modulus = modulus
    }

    public static var zero: mod_int {
        mod_int(value: 0, modulus: 0)
    }

    public var magnitude: mod_int {
        mod_int(value: BigInt(value.magnitude), modulus: modulus)
    }

    public func to_bytes() -> Array<UInt8> {
        var bytes: Array<UInt8> = Array<UInt8>();
        bytes.append(sign_to_u8(sign: value.sign))
        bytes.append(contentsOf: value.to_bytes_le())
        bytes.append(sign_to_u8(sign: modulus.sign))
        bytes.append(contentsOf: modulus.to_bytes_le())
        return bytes
    }

    public func normalize() -> mod_int {
        if (modulus > 0) {
            return mod_int(value: value % modulus, modulus: modulus)
        } else {
            return self
        }
    }

    public static func +(lhs: mod_int, rhs: mod_int) -> mod_int {
        mod_int(
                value: lhs.value + rhs.value,
                modulus: lhs.modulus
        ).normalize()
    }

    public static func -(lhs: mod_int, rhs: mod_int) -> mod_int {
        if (lhs.modulus == 0) {
            return mod_int(
                    value: lhs.value - rhs.value,
                    modulus: lhs.modulus
            ).normalize()
        } else {
            return (lhs + (-rhs)).normalize()
        }
    }

    public static func *(lhs: mod_int, rhs: mod_int) -> mod_int {
        mod_int(
                value: lhs.value * rhs.value,
                modulus: lhs.modulus
        ).normalize()
    }

    public prefix static func -(operand: mod_int) -> mod_int {
        mod_int(
                value: operand.modulus == 0
                        ? -operand.value
                        : operand.modulus - operand.value,
                modulus: operand.modulus
        )
    }

    public static func /(lhs: mod_int, rhs: mod_int) -> mod_int {
        assert(rhs.value != BigInt.zero)

        if (lhs.modulus == 0) {
            return mod_int(
                    value: lhs.value / rhs.value,
                    modulus: lhs.modulus
            ).normalize()
        } else {
            guard let inverse: BigInt = rhs.value.inverse(lhs.modulus) else {
                fatalError("could not calculate modular multiplicative inverse")
            }

            return mod_int(
                    value: lhs.value * inverse,
                    modulus: lhs.modulus
            ).normalize()
        }
    }

    public static func %(lhs: mod_int, rhs: mod_int) -> mod_int {
        assert(rhs.value != BigInt.zero)

        return mod_int(
                value: (lhs.value % rhs.value),
                modulus: lhs.modulus
        )
    }

    public func pow(power: mod_int) -> mod_int {
        if (modulus == 0) {
            return mod_int(
                    value: value.power(Int(power.value)),
                    modulus: modulus
            ).normalize()
        } else {
            return mod_int(
                    value: value.power(power.value, modulus: modulus),
                    modulus: modulus
            ).normalize()
        }
    }

    public static func ==(lhs: mod_int, rhs: mod_int) -> Bool {
        return lhs.value == rhs.value
    }

    public static func rand(upper_bound: BigInt) -> mod_int {
        rand(
                upper_bound: upper_bound,
                modulus: upper_bound
        )
    }

    public static func rand(upper_bound: BigInt, modulus: BigInt) -> mod_int {
        mod_int(
                value: BigInt(BigUInt.randomInteger(lessThan: BigUInt(upper_bound))),
                modulus: upper_bound
        )
    }
}

func sign_to_u8(sign: BigInt.Sign) -> UInt8 {
    switch (sign) {
    case .minus: return 0
    case .plus: return 2
    }
}

