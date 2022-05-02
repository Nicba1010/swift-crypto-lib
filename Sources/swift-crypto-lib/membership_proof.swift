//
// Created by roberto on 4/30/22.
//

import BigInt
import CryptoKit
import Foundation

struct MembershipProof {
    let s: Array<mod_int>
    let c: Array<mod_int>

    init(public_key: PublicKey, plain_text: PlainText, cipher_text: CipherText, domain: Array<mod_int>) {
        var s: Array<mod_int> = Array<mod_int>(repeating: mod_int.zero, count: domain.count)
        var c: Array<mod_int> = Array<mod_int>(repeating: mod_int.zero, count: domain.count)

        let s_for_valid: mod_int = mod_int.rand(upper_bound: public_key.q.value)

        var sha512: SHA512 = SHA512()
        sha512.update(data: public_key.g.to_bytes())
        sha512.update(data: public_key.h.to_bytes())
        sha512.update(data: cipher_text.g_r.to_bytes())
        sha512.update(data: cipher_text.g_v__s.to_bytes())

        var chosen_domain_element_idx: Int = 0

        for domain_element_idx in domain.indices {
            let a, b: mod_int

            let domain_element: mod_int = domain[domain_element_idx]

            if domain_element == plain_text {
                a = public_key.g.pow(power: s_for_valid)
                b = public_key.h.pow(power: s_for_valid)
                chosen_domain_element_idx = domain_element_idx
            } else {
                s[domain_element_idx] = mod_int.rand(upper_bound: public_key.q.value)
                c[domain_element_idx] = mod_int.rand(upper_bound: public_key.q.value)

                a = public_key.g.pow(power: s[domain_element_idx]) * cipher_text.g_r.pow(power: -c[domain_element_idx])
                b = public_key.h.pow(power: s[domain_element_idx]) * (cipher_text.g_v__s / (public_key.g.pow(power: domain_element))).pow(power: -c[domain_element_idx])
            }

            sha512.update(data: a.to_bytes())
            sha512.update(data: b.to_bytes())
        }

        var h_b: Array<UInt8> = Array<UInt8>()
        h_b.append(2)
        h_b.append(contentsOf: sha512.finalize())

        var c_0: mod_int = mod_int(value: [BigInt(Data(h_b)), BigInt(0)].last!, modulus: public_key.q.value)
        c.forEach { c_ in
            c_0 = c_0 - c_
        }

        s[chosen_domain_element_idx] = c_0 * cipher_text.random + s_for_valid
        c[chosen_domain_element_idx] = c_0

        self.s = s
        self.c = c
    }

    func verify(public_key: PublicKey, cipher_text: CipherText, domain: Array<mod_int>) -> Bool {
        assert(s.count == domain.count)

        var sha512: SHA512 = SHA512()
        sha512.update(data: public_key.g.to_bytes())
        sha512.update(data: public_key.h.to_bytes())
        sha512.update(data: cipher_text.g_r.to_bytes())
        sha512.update(data: cipher_text.g_v__s.to_bytes())

        for c_i in c.indices {
            let domain_element: mod_int = domain[c_i]

            let s_ = s[c_i]
            let c_ = c[c_i]

            let a = public_key.g.pow(power: s_) * cipher_text.g_r.pow(power: -c_)
            let b = public_key.h.pow(power: s_) * (cipher_text.g_v__s / public_key.g.pow(power: domain_element)).pow(power: -c_)
            sha512.update(data: a.to_bytes())
            sha512.update(data: b.to_bytes())
        }

        var h_b: Array<UInt8> = Array<UInt8>()
        h_b.append(2)
        h_b.append(contentsOf: sha512.finalize())

        let new_c: mod_int = mod_int(value: [BigInt(Data(h_b)), BigInt(0)].last!, modulus: public_key.q.value)
        let c_sum = c.reduce(mod_int(value: 0, modulus: c.first!.modulus), +)

        return c_sum == new_c
    }
}