import BigInt

public typealias PlainText = mod_int

public struct CipherText {
    public let g_r: mod_int
    public let g_v__s: mod_int
    public let random: mod_int

    public static func +(lhs: CipherText, rhs: CipherText) -> CipherText {
        CipherText(
                g_r: lhs.g_r * rhs.g_r,
                g_v__s: lhs.g_v__s * rhs.g_v__s,
                random: lhs.random + rhs.random
        )
    }
}

public struct PublicKey {
    public let p: mod_int
    public let q: mod_int
    public let h: mod_int
    public let g: mod_int

    public func encrypt(plain_text: PlainText) -> CipherText {
        let random: mod_int = mod_int.rand(upper_bound: q.value)

        return CipherText(
                g_r: g.pow(power: random),
                g_v__s: h.pow(power: random) * g.pow(power: plain_text),
                random: random
        )
    }

    public func make_message(value: BigInt) -> PlainText {
        mod_int(value: value, modulus: g.modulus)
    }

    public static let default_key: PublicKey =
            PublicKey(
                    p: PrivateKey.default_key.p,
                    q: PrivateKey.default_key.q,
                    h: mod_int(
                            value: PrivateKey.default_key.g.pow(power: PrivateKey.default_key.x).value,
                            modulus: PrivateKey.default_key.p.value
                    ),
                    g: PrivateKey.default_key.g
            )

}

public struct PrivateKey {
    public let p: mod_int
    public let q: mod_int
    public let g: mod_int
    public let x: mod_int

    public func decrypt(cipher_text: CipherText) -> PlainText {
        let g_to_m: mod_int = cipher_text.g_v__s / cipher_text.g_r.pow(power: x)

        var i: BigInt = BigInt(0)

        while true {
            let target: mod_int = mod_int(
                    value: g.value,
                    modulus: g_to_m.modulus
            ).pow(power: mod_int(
                    value: i,
                    modulus: g_to_m.modulus
            ))

            if (target == g_to_m) {
                return mod_int(value: i, modulus: g_to_m.modulus);
            }

            i += 1;
        }
    }

    public func make_message(value: BigInt) -> PlainText {
        mod_int(value: value, modulus: p.value)
    }

    public static var default_key: PrivateKey {
        let p: mod_int = mod_int(value: BigInt("1449901879557492303016150949425292606294424240059"), modulus: 0)
        let q: mod_int = (p - mod_int.from(value: 1)) / mod_int.from(value: 2)
        return PrivateKey(
                p: p,
                q: q,
                g: mod_int(value: BigInt("650614565471833138727952492078522919745801716191"), modulus: p.value),
                x: mod_int(value: BigInt("896771263533775491364511200158444196377569745583"), modulus: p.value)
        )
    }
}