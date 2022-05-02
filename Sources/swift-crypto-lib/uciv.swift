//
// Created by Troido Zagreb 2 on 5/1/22.
//

import BigInt
import CryptoKit
import Foundation

struct PreImages {
    let pre_images: Array<mod_int>

    init(public_key: PublicKey, domain: Array<mod_int>) {
        pre_images = domain.map { element in mod_int.rand(upper_bound: public_key.q.value) }
    }
}

struct Images {
    let images: Array<mod_int>

    init(generator: mod_int, pre_images: PreImages) {
        images = pre_images.pre_images.map { pre_image in
            generator.pow(power: pre_image)
        }
    }
}

struct CastAsIntendedProof {
    let s1, s2, h1, h2: Array<mod_int>
    let hash_result: mod_int

    init(public_key: PublicKey, plain_text: PlainText, cipher_text: CipherText, domain: Array<mod_int>, pre_images: PreImages, images: Images) {
        assert(domain.count == pre_images.pre_images.count)
        assert(pre_images.pre_images.count == images.images.count)

        let chosen_domain_element_i: Int = domain.firstIndex(of: domain.first { element in
            element == plain_text
        }!)!
        var s1: Array<mod_int> = Array<mod_int>(repeating: mod_int.zero, count: domain.count)
        var s2: Array<mod_int> = Array<mod_int>(repeating: mod_int.zero, count: domain.count)
        var h1: Array<mod_int> = Array<mod_int>(repeating: mod_int.zero, count: domain.count)
        var h2: Array<mod_int> = Array<mod_int>(repeating: mod_int.zero, count: domain.count)
        var z: Array<mod_int> = Array<mod_int>(repeating: mod_int.zero, count: domain.count)
        var sha512: SHA512 = SHA512()

        sha512.update(data: cipher_text.g_r.description.data(using: String.Encoding.ascii)!)
        sha512.update(data: cipher_text.g_v__s.description.data(using: String.Encoding.ascii)!)

        for i in domain.indices {
            let r1_i: mod_int = mod_int.rand(upper_bound: public_key.q.value)
            let r2_i: mod_int = mod_int.rand(upper_bound: public_key.q.value)
            let r3_i: mod_int = mod_int.rand(upper_bound: public_key.q.value)

            z[i] = r3_i

            if i != chosen_domain_element_i {
                s1[i] = r1_i
                h1[i] = r2_i

                let c1_i = public_key.g.pow(power: r1_i) * cipher_text.g_r.pow(power: -r2_i)
                let c2_i = public_key.h.pow(power: r1_i) * (cipher_text.g_v__s / public_key.g.pow(power: domain[i])).pow(power: -r2_i)
                let r_i = public_key.g.pow(power: r3_i)

                sha512.update(data: c1_i.description.data(using: String.Encoding.ascii)!)
                sha512.update(data: c2_i.description.data(using: String.Encoding.ascii)!)
                sha512.update(data: r_i.description.data(using: String.Encoding.ascii)!)
            } else {
                s2[i] = r1_i
                h2[i] = r2_i

                let c1_i = public_key.g.pow(power: r3_i)
                let c2_i = public_key.h.pow(power: r3_i)
                let r_i = public_key.g.pow(power: r1_i) * images.images[i].pow(power: -r2_i)

                sha512.update(data: c1_i.description.data(using: String.Encoding.ascii)!)
                sha512.update(data: c2_i.description.data(using: String.Encoding.ascii)!)
                sha512.update(data: r_i.description.data(using: String.Encoding.ascii)!)
            }
        }

        let hash_output = sha512.finalize().description.split(separator: ":").last!.trimmingCharacters(in: .whitespacesAndNewlines)
        print(hash_output)
        let s: mod_int = mod_int(value: BigInt(hash_output, radix: 16)!, modulus: public_key.q.value)

        for i in domain.indices {
            if i != chosen_domain_element_i {
                let r1_i: mod_int = s - h1[i]
                h2[i] = r1_i

                let r2_i: mod_int = z[i] + pre_images.pre_images[i] * r1_i
                s2[i] = r2_i
            } else {
                let r1_i: mod_int = s - h2[i]
                let r2_i: mod_int = z[i] + cipher_text.random * r1_i

                h1[i] = r1_i
                s1[i] = r2_i
            }
        }

        self.s1 = s1
        self.s2 = s2
        self.h1 = h1
        self.h2 = h2
        self.hash_result = s
    }

    func verify(public_key: PublicKey,cipher_text: CipherText, domain: Array<mod_int>, images: Images) -> Bool{
        let c1 = cipher_text.g_r
        let c2 = cipher_text.g_v__s

        var sha512: SHA512 = SHA512()
        sha512.update(data: cipher_text.g_r.description.data(using: String.Encoding.ascii)!)
        sha512.update(data: cipher_text.g_v__s.description.data(using: String.Encoding.ascii)!)

        for i in domain.indices {
            let c1_i = public_key.g.pow(power: s1[i]) * c1.pow(power: -h1[i])
            let c2_i = public_key.h.pow(power: s1[i]) * (c2 / public_key.g.pow(power: domain[i])).pow(power: -h1[i])
            let r_i = public_key.g.pow(power: s2[i]) * images.images[i].pow(power: -h2[i])

            sha512.update(data: c1_i.description.data(using: String.Encoding.ascii)!)
            sha512.update(data: c2_i.description.data(using: String.Encoding.ascii)!)
            sha512.update(data: r_i.description.data(using: String.Encoding.ascii)!)
        }

        let hash_output = sha512.finalize().description.split(separator: ":").last!.trimmingCharacters(in: .whitespacesAndNewlines)
        print(hash_output)
        let s: mod_int = mod_int(value: BigInt(hash_output, radix: 16)!, modulus: public_key.q.value)

        return self.hash_result == s
    }


}
