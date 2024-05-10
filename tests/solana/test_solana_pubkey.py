import unittest

from pydantic import BaseModel

from common.solana.pubkey import SolPubKey, SolPubKeyField


class TestSolPubKey(unittest.TestCase):
    _ALT_PUBLIC_KEY = "AddressLookupTab1e1111111111111111111111111"

    def test_new_unique(self):
        key = SolPubKey.new_unique()
        self.assertIsInstance(key.to_bytes(), bytes)
        self.assertIsInstance(key.to_string(), str)

    def test_default(self):
        key = SolPubKey.default()
        self.assertIsInstance(key.to_bytes(), bytes)
        self.assertIsInstance(key.to_string(), str)

    def test_from_string(self):
        key = SolPubKey.from_raw(self._ALT_PUBLIC_KEY)
        self.assertIsInstance(key.to_bytes(), bytes)
        self.assertIsInstance(key.to_string(), str)

    def test_create_with_seed(self):
        base = SolPubKey.new_unique()
        seed = "seed"
        prog_id = SolPubKey.new_unique()
        key = SolPubKey.create_with_seed(base, seed, prog_id)
        self.assertIsInstance(key.to_bytes(), bytes)
        self.assertIsInstance(key.to_string(), str)

    def test_create_prog_address(self):
        seeds = [b"seed1", b"seed2", b"seed3"]
        prog_id = SolPubKey.new_unique()
        program_address = SolPubKey.create_program_address(seeds, prog_id)
        self.assertIsInstance(program_address.to_bytes(), bytes)
        self.assertIsInstance(program_address.to_string(), str)

    def test_find_program_address(self):
        seeds = [b"seed1", b"seed2", b"seed3"]
        prog_id = SolPubKey.new_unique()
        program_address, nonce = SolPubKey.find_program_address(seeds, prog_id)
        self.assertIsInstance(program_address.to_bytes(), bytes)
        self.assertIsInstance(program_address.to_string(), str)
        self.assertIsInstance(nonce, int)

    def test_from_bytes(self):
        byte = SolPubKey.new_unique().to_bytes()
        key = SolPubKey.from_bytes(byte)
        self.assertIsInstance(key.to_bytes(), bytes)
        self.assertIsInstance(key.to_string(), str)

    def test_from_json(self):
        raw_json = SolPubKey.new_unique().to_json()
        key = SolPubKey.from_json(raw_json)
        self.assertIsInstance(key.to_bytes(), bytes)
        self.assertIsInstance(key.to_string(), str)

    def test_from_raw(self):
        spk = SolPubKey.new_unique()
        self.assertTrue(SolPubKey.from_raw(spk) is spk)

        self.assertEqual(SolPubKey.from_raw(None), SolPubKey.default())

        self.assertEqual(SolPubKey.from_raw(self._ALT_PUBLIC_KEY).to_string(), self._ALT_PUBLIC_KEY)

        self.assertEqual(
            SolPubKey.from_raw(
                SolPubKey.from_string(self._ALT_PUBLIC_KEY).to_bytes(),
            ).to_string(),
            self._ALT_PUBLIC_KEY,
        )

        self.assertEqual(
            SolPubKey.from_raw(bytearray(SolPubKey.from_string(self._ALT_PUBLIC_KEY).to_bytes())).to_string(),
            self._ALT_PUBLIC_KEY,
        )

        with self.assertRaises(ValueError):
            SolPubKey.from_raw(1235)  # noqa

        with self.assertRaises(ValueError):
            SolPubKey.from_raw(dict())

        with self.assertRaises(ValueError):
            SolPubKey.from_raw(list())

    def test_to_string(self):
        key = SolPubKey.new_unique()
        string = key.to_string()
        self.assertIsInstance(string, str)

    def test_to_bytes(self):
        key = SolPubKey.new_unique()
        byte = key.to_bytes()
        self.assertIsInstance(byte, bytes)

    def test_pydantic(self):
        class TestPydanticModel(BaseModel):
            pubkey: SolPubKeyField

        src1_model = TestPydanticModel(pubkey=SolPubKey.new_unique())
        src1_dump = src1_model.model_dump(mode="json")
        self.assertTrue("pubkey" in src1_dump)
        dst1_model = TestPydanticModel.model_validate(src1_dump)

        self.assertIsNotNone(src1_model.pubkey.to_bytes())
        self.assertIsNotNone(dst1_model.pubkey.to_string())
        self.assertEqual(
            src1_model.pubkey,
            dst1_model.pubkey,
        )


if __name__ == "__main__":
    unittest.main()
