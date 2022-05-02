import XCTest
import BigInt
@testable import swift_crypto_lib

final class swift_crypto_libTests: XCTestCase {

    func test_mod_int_add() throws {
        XCTAssertEqual(mod_int(value: 5, modulus: 10) + mod_int(value: 10, modulus: 10) , mod_int(value: 5, modulus: 10))
    }

    func test_mod_int_sub() throws {
        XCTAssertEqual(mod_int(value: 5, modulus: 10) - mod_int(value: 9, modulus: 10) , mod_int(value: 6, modulus: 10))
    }

    func test_mod_int_mul() throws {
        XCTAssertEqual(mod_int(value: 6, modulus: 10) * mod_int(value: 9, modulus: 10) , mod_int(value: 4, modulus: 10))
    }

    func test_mod_int_div() throws {
        XCTAssertEqual(mod_int(value: 6, modulus: 10) * mod_int(value: 9, modulus: 10) , mod_int(value: 4, modulus: 10))
    }

    func test_mod_int_pow() throws {
        XCTAssertEqual(mod_int(value: 6, modulus: 10).pow(power: mod_int(value: 9, modulus: 10)) , mod_int(value: 6, modulus: 10))
    }

    func test_mod_int_rem() throws {
        XCTAssertEqual(mod_int(value: 6, modulus: 10) % mod_int(value: 5, modulus: 10) , mod_int(value: 1, modulus: 10))
    }

    func test_mod_int_neg() throws {
        XCTAssertEqual(-mod_int(value: 6, modulus: 10) , mod_int(value: 4, modulus: 10))
    }

    func test_mod_int_eq() throws {
        XCTAssertEqual(mod_int(value: 6, modulus: 10) , mod_int(value: 6, modulus: 10))
    }

    func test_elgamal() throws {
        let private_key: PrivateKey = PrivateKey.default_key
        let public_key: PublicKey = PublicKey.default_key

        let message1: mod_int = public_key.make_message(value: 1)
        let cipher_text1: CipherText = public_key.encrypt(plain_text: message1)
        let plain_text1: PlainText = private_key.decrypt(cipher_text: cipher_text1)

        XCTAssertEqual(message1, plain_text1)

        let message2: mod_int = public_key.make_message(value: 2)
        let cipher_text2: CipherText = public_key.encrypt(plain_text: message2)
        let plain_text2: PlainText = private_key.decrypt(cipher_text: cipher_text2)

        XCTAssertEqual(message2, plain_text2)

        let plain_text3: PlainText = private_key.decrypt(cipher_text: cipher_text1 + cipher_text2)
        XCTAssertEqual(plain_text3.value, 3)
    }

    func test_uciv() throws {
        let private_key: PrivateKey = PrivateKey.default_key
        let public_key: PublicKey = PublicKey.default_key

        let message: mod_int = public_key.make_message(value: 1)
        let cipher_text: CipherText = public_key.encrypt(plain_text: message)
        let domain: Array<mod_int> = [mod_int.zero, mod_int(value: 1, modulus: 0)]

        let pre_images: PreImages = PreImages(public_key: public_key, domain: [mod_int(value: 0, modulus: 0), mod_int(value: 1, modulus: 0)])
        let images: Images = Images(generator: public_key.g, pre_images: pre_images)

        let pre_images_json: String = String(data: try JSONEncoder().encode(pre_images), encoding: .utf8)!
        let pre_images_1: PreImages = try JSONDecoder().decode(PreImages.self, from: pre_images_json.data(using: .utf8)!)
        print(pre_images_json)
        print(pre_images)
        XCTAssertEqual(pre_images, pre_images_1)

        let proof: CastAsIntendedProof = CastAsIntendedProof(
                public_key: public_key,
                plain_text: message,
                cipher_text: cipher_text,
                domain: domain,
                pre_images: pre_images,
                images: images
        )

        let is_proven = proof.verify(
                public_key: public_key,
                cipher_text: cipher_text,
                domain: domain,
                images: images
        )

        XCTAssert(is_proven)
    }

    func test_membership_proof() throws {
        let private_key: PrivateKey = PrivateKey.default_key
        let public_key: PublicKey = PublicKey.default_key

        print(private_key.x)
        print(private_key)
        print(public_key)

        let message: mod_int = public_key.make_message(value: 1)
        let cipher_text: CipherText = public_key.encrypt(plain_text: message)

        let domain: Array<mod_int> = [mod_int.zero, mod_int(value: 1, modulus: 0)]

        let proof: MembershipProof = MembershipProof(
                public_key: public_key,
                plain_text: message,
                cipher_text: cipher_text,
                domain: domain
        )

        print(proof.verify(public_key: public_key, cipher_text: cipher_text, domain: domain))

        XCTAssert(proof.verify(public_key: public_key, cipher_text: cipher_text, domain: domain))
    }
}
