"""Тесты Camellia (Участник 3). Запуск: pytest -v   или   python -m unittest -v """

import os
import random
import tempfile
import unittest

import camellia_engine as engine
from camellia_core import _F, generate_subkeys

# ------------------------------------------------------------- ADAPTER
def enc_block(key: bytes, block: bytes) -> bytes:
    return engine.encrypt_block(block, key)


def dec_block(key: bytes, block: bytes) -> bytes:
    return engine.decrypt_block(block, key)


def enc_file(src, dst, key):
    engine.encrypt_file(src, dst, key)


def dec_file(src, dst, key):
    engine.decrypt_file(src, dst, key)


# ------------------------------------------------------- RFC 3713, App. A
PLAIN = bytes.fromhex("0123456789abcdeffedcba9876543210")
K128 = bytes.fromhex("0123456789abcdeffedcba9876543210")
K192 = bytes.fromhex("0123456789abcdeffedcba98765432100011223344556677")
K256 = bytes.fromhex(
    "0123456789abcdeffedcba987654321000112233445566778899aabbccddeeff")

VECTORS = [
    ("128", K128, bytes.fromhex("67673138549669730857065648eabe43")),
    ("192", K192, bytes.fromhex("b4993401b3e996f84ee5cee7d79b09b9")),
    ("256", K256, bytes.fromhex("9acc237dff16d76c20ef7c919e3a7509")),
]
MASK64 = (1 << 64) - 1


# ------------------------------------------------ 1. F-функция
class TestF(unittest.TestCase):
    # В RFC нет отдельного вектора F: её корректность проверяют
    # сквозные тесты ниже. Здесь — базовые свойства.
    def test_range_and_determinism(self):
        for x, k in [(0, 0), (MASK64, MASK64), (0x0123456789ABCDEF, 0xFEDCBA9876543210)]:
            r = _F(x, k)
            self.assertIsInstance(r, int)
            self.assertTrue(0 <= r <= MASK64)
            self.assertEqual(r, _F(x, k))

    def test_depends_on_both_inputs(self):
        base = _F(0x0123456789ABCDEF, 0xFEDCBA9876543210)
        self.assertNotEqual(base, _F(0x0123456789ABCDEE, 0xFEDCBA9876543210))
        self.assertNotEqual(base, _F(0x0123456789ABCDEF, 0xFEDCBA9876543211))


# ------------------------------------------- 2. Ключевое расписание
class TestSubkeys(unittest.TestCase):
    def test_lengths(self):
        self.assertEqual(len(generate_subkeys(K128)), 26)
        self.assertEqual(len(generate_subkeys(K192)), 32)
        self.assertEqual(len(generate_subkeys(K256)), 32)

    def test_values_are_64bit(self):
        for key in (K128, K192, K256):
            for sk in generate_subkeys(key):
                self.assertTrue(0 <= sk <= MASK64)

    def test_deterministic_and_key_dependent(self):
        self.assertEqual(generate_subkeys(K128), generate_subkeys(K128))
        other = bytes([K128[0] ^ 1]) + K128[1:]
        self.assertNotEqual(generate_subkeys(K128), generate_subkeys(other))

    def test_bad_key_length(self):
        for n in (0, 1, 15, 17, 23, 25, 31, 33, 64):
            with self.assertRaises(ValueError, msg=f"len={n}"):
                generate_subkeys(bytes(n))


# ------------------------------------- 3. Сквозные векторы RFC 3713
class TestRFCVectors(unittest.TestCase):
    def test_encrypt(self):
        for name, key, ct in VECTORS:
            with self.subTest(bits=name):
                self.assertEqual(enc_block(key, PLAIN), ct)

    def test_decrypt(self):
        for name, key, ct in VECTORS:
            with self.subTest(bits=name):
                self.assertEqual(dec_block(key, ct), PLAIN)

    def test_block_roundtrip_random(self):
        rnd = random.Random(1)
        for key in (K128, K192, K256):
            for _ in range(20):
                blk = bytes(rnd.getrandbits(8) for _ in range(16))
                self.assertEqual(dec_block(key, enc_block(key, blk)), blk)


# ----------------------------------------- 4. Round-trip для файлов
class TestFileRoundTrip(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.dir = self.tmp.name

    def tearDown(self):
        self.tmp.cleanup()

    def _roundtrip(self, data: bytes, key=K128, name="f.bin"):
        src = os.path.join(self.dir, name)
        enc = src + ".cam"
        out = src + ".out"
        with open(src, "wb") as f:
            f.write(data)
        enc_file(src, enc, key)
        dec_file(enc, out, key)
        with open(enc, "rb") as f:
            encrypted = f.read()
        with open(out, "rb") as f:
            restored = f.read()
        return encrypted, restored

    def test_text(self):
        data = "Привет, Camellia! Hello, world.\n".encode("utf-8") * 50
        enc, back = self._roundtrip(data, name="a.txt")
        self.assertEqual(back, data)
        self.assertNotEqual(enc, data)

    def test_random_bytes(self):
        data = random.Random(2).randbytes(100_000)
        _, back = self._roundtrip(data)
        self.assertEqual(back, data)

    def test_image_like(self):
        # PNG-сигнатура + случайное содержимое
        data = b"\x89PNG\r\n\x1a\n" + random.Random(3).randbytes(50_000)
        _, back = self._roundtrip(data, name="pic.png")
        self.assertEqual(back, data)

    def test_boundary_sizes(self):
        for n in (0, 1, 15, 16, 17, 31, 32, 33, 4096):
            with self.subTest(size=n):
                data = bytes(range(256)) * (n // 256 + 1)
                data = data[:n]
                _, back = self._roundtrip(data, name=f"s{n}.bin")
                self.assertEqual(back, data)

    def test_all_key_sizes(self):
        data = random.Random(4).randbytes(1000)
        for key in (K128, K192, K256):
            with self.subTest(key_bits=len(key) * 8):
                _, back = self._roundtrip(data, key=key, name=f"k{len(key)}.bin")
                self.assertEqual(back, data)

    def test_ciphertext_does_not_contain_plaintext(self):
        data = b"SECRET-MARKER-" * 100
        enc, _ = self._roundtrip(data)
        self.assertNotIn(b"SECRET-MARKER-", enc)

    def test_wrong_key_does_not_restore(self):
        data = random.Random(5).randbytes(500)
        src = os.path.join(self.dir, "w.bin")
        with open(src, "wb") as f:
            f.write(data)
        enc_file(src, src + ".cam", K128)
        out = src + ".out"
        try:
            dec_file(src + ".cam", out, K256)
        except Exception:
            return  # ошибка при неверном ключе — допустимое поведение
        with open(out, "rb") as f:
            self.assertNotEqual(f.read(), data)


# ------------------------------------------------ GUI-логика ключей
class TestParseKey(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        try:
            import main  # noqa: F401
            cls.parse_key = staticmethod(main.parse_key)
        except Exception as e:  # tkinter может быть недоступен
            raise unittest.SkipTest(f"main.py не импортируется: {e}")

    def test_valid(self):
        self.assertEqual(self.parse_key(K128.hex()), K128)
        self.assertEqual(self.parse_key(" ".join([K256.hex()[i:i + 8]
                                                  for i in range(0, 64, 8)])), K256)

    def test_invalid(self):
        for bad in ("", "zz" * 16, "00" * 15, "00" * 20, "0"):
            with self.subTest(bad=bad):
                with self.assertRaises(ValueError):
                    self.parse_key(bad)


if __name__ == "__main__":
    unittest.main(verbosity=2)
  
