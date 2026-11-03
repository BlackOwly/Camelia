"""
Ядро алгоритма Camellia (RFC 3713).
Реализует S-боксы, F-функцию, P-функцию и ключевое расписание
для ключей 128, 192 и 256 бит.
"""

# =============================================================================
# 1. БАЗОВЫЕ КОНСТАНТЫ И ВСПОМОГАТЕЛЬНЫЕ ФУНКЦИИ
# =============================================================================

MASK8 = 0xff
MASK32 = 0xffffffff
MASK64 = 0xffffffffffffffff
MASK128 = 0xffffffffffffffffffffffffffffffff

# Константы Sigma для ключевого расписания (RFC 3713, раздел 2.2)
SIGMA1 = 0xA09E667F3BCC908B
SIGMA2 = 0xB67AE8584CAA73B2
SIGMA3 = 0xC6EF372FE94F82BE
SIGMA4 = 0x54FF53A5F1D36F1C
SIGMA5 = 0x10E527FADE682D1D
SIGMA6 = 0xB05688C2B3E6C1FD

def _rotl8(x: int, n: int) -> int:
    """Циклический сдвиг влево для 8-битного значения."""
    n %= 8
    return ((x << n) | (x >> (8 - n))) & MASK8

def _rotl128(x: int, n: int) -> int:
    """Циклический сдвиг влево для 128-битного значения."""
    n %= 128
    return ((x << n) | (x >> (128 - n))) & MASK128

# =============================================================================
# 2. S-БОКСЫ (Таблицы нелинейной замены)
# =============================================================================

# SBOX1 — базовая таблица (256 значений), взята из RFC 3713 / эталонных реализаций.
SBOX1 = [
    112, 130,  44, 236, 179,  39, 192, 229, 228, 133,  87,  53, 234,  12, 174,  65,
     35, 239, 107, 147,  69,  25, 165,  33, 237,  14,  79,  78,  29, 101, 146, 189,
    134, 184, 175, 143, 124, 235,  31, 206,  62,  48, 220,  95,  94, 197,  11,  26,
    166, 225,  57, 202, 213,  71,  93,  61, 217,   1,  90, 214,  81,  86, 108,  77,
    139,  13, 154, 102, 251, 204, 176,  45, 116,  18,  43,  32, 240, 177, 132, 153,
    223,  76, 203, 194,  52, 126, 118,   5, 109, 183, 169,  49, 209,  23,   4, 215,
     20,  88,  58,  97, 222,  27,  17,  28,  50,  15, 156,  22,  83,  24, 242,  34,
    254,  68, 207, 178, 195, 181, 122, 145,  36,   8, 232, 168,  96, 252, 105,  80,
    170, 208, 160, 125, 161, 137,  98, 151,  84,  91,  30, 149, 224, 255, 100, 210,
     16, 196,   0,  72, 163, 247, 117, 219, 138,   3, 230, 218,   9,  63, 221, 148,
    135,  92, 131,   2, 205,  74, 144,  51, 115, 103, 246, 243, 157, 127, 191, 226,
     82, 155, 216,  38, 200,  55, 198,  59, 129, 150, 111,  75,  19, 190,  99,  46,
    233, 121, 167, 140, 159, 110, 188, 142,  41, 245, 249, 182,  47, 253, 180,  89,
    120, 152,   6, 106, 231,  70, 113, 186, 212,  37, 171,  66, 136, 162, 141, 250,
    114,   7, 185,  85, 248, 238, 172,  10,  54,  73,  42, 104,  60,  56, 241, 164,
     64,  40, 211, 123, 187, 201,  67, 193,  21, 227, 173, 244, 119, 199, 128, 158
]

# SBOX2, SBOX3, SBOX4 генерируются из SBOX1 согласно RFC 3713 (раздел 2.3)
SBOX2 = [_rotl8(x, 1) for x in SBOX1]
SBOX3 = [_rotl8(x, 7) for x in SBOX1]
SBOX4 = [SBOX1[_rotl8(x, 1)] for x in range(256)]

# =============================================================================
# 3. F-ФУНКЦИЯ (Сердце Camellia)
# =============================================================================

def _F(f_in: int, ke: int) -> int:
    """
    Реализация F-функции из RFC 3713 (раздел 2.4.1).

    Args:
        f_in: 64-битные входные данные.
        ke:   64-битный раундовый ключ.

    Returns:
        64-битный результат F-функции.
    """
    # 1. XOR с ключом
    x = (f_in ^ ke) & MASK64

    # 2. Разбиение на 8 байт
    t1 = (x >> 56) & MASK8
    t2 = (x >> 48) & MASK8
    t3 = (x >> 40) & MASK8
    t4 = (x >> 32) & MASK8
    t5 = (x >> 24) & MASK8
    t6 = (x >> 16) & MASK8
    t7 = (x >> 8) & MASK8
    t8 = x & MASK8

    # 3. Нелинейная замена через S-боксы
    t1 = SBOX1[t1]
    t2 = SBOX2[t2]
    t3 = SBOX3[t3]
    t4 = SBOX4[t4]
    t5 = SBOX2[t5]
    t6 = SBOX3[t6]
    t7 = SBOX4[t7]
    t8 = SBOX1[t8]

    # 4. Линейное преобразование (P-функция)
    y1 = t1 ^ t3 ^ t4 ^ t6 ^ t7 ^ t8
    y2 = t1 ^ t2 ^ t4 ^ t5 ^ t7 ^ t8
    y3 = t1 ^ t2 ^ t3 ^ t5 ^ t6 ^ t8
    y4 = t2 ^ t3 ^ t4 ^ t5 ^ t6 ^ t7
    y5 = t1 ^ t2 ^ t6 ^ t7 ^ t8
    y6 = t2 ^ t3 ^ t5 ^ t7 ^ t8
    y7 = t3 ^ t4 ^ t5 ^ t6 ^ t8
    y8 = t1 ^ t4 ^ t5 ^ t6 ^ t7

    # 5. Сборка результата обратно в 64-битное слово
    f_out = ((y1 << 56) | (y2 << 48) | (y3 << 40) | (y4 << 32) |
             (y5 << 24) | (y6 << 16) | (y7 << 8) | y8)

    return f_out & MASK64

# =============================================================================
# 4. КЛЮЧЕВОЕ РАСПИСАНИЕ (Генерация подключей)
# =============================================================================

def generate_subkeys(key: bytes) -> list[int]:
    """
    Генерирует полный список подключей для алгоритма Camellia.

    Поддерживаются ключи длиной 16, 24 и 32 байта (128, 192 и 256 бит).

    Args:
        key: Байтовая строка с ключом.

    Returns:
        Список 64-битных подключей в порядке, необходимом для раундов
        шифрования (и дешифрования, если использовать в обратном порядке).

    Raises:
        ValueError: Если длина ключа не равна 16, 24 или 32 байтам.
    """
    key_len = len(key)
    if key_len not in (16, 24, 32):
        raise ValueError("Ключ должен быть длиной 16, 24 или 32 байта (128, 192 или 256 бит).")

    # 1. Преобразование байтового ключа в целое число
    K = int.from_bytes(key, byteorder='big')

    # 2. Инициализация KL и KR в зависимости от длины ключа (RFC 3713, раздел 2.2)
    if key_len == 16:
        # 128-битный ключ: KL = K, KR = 0
        KL = K
        KR = 0
    elif key_len == 24:
        # 192-битный ключ: KL = старшие 128 бит, KR = младшие 64 бита + дополнение
        KL = K >> 64
        KR_low = K & MASK64
        KR = (KR_low << 64) | ((~KR_low) & MASK64)
    else: # key_len == 32
        # 256-битный ключ: KL = старшие 128 бит, KR = младшие 128 бит
        KL = K >> 128
        KR = K & MASK128

    # 3. Генерация промежуточных значений KA и KB
    #    (RFC 3713, раздел 2.2)
    D1 = (KL ^ KR) >> 64
    D2 = (KL ^ KR) & MASK64
    D2 = D2 ^ _F(D1, SIGMA1)
    D1 = D1 ^ _F(D2, SIGMA2)
    D1 = D1 ^ (KL >> 64)
    D2 = D2 ^ (KL & MASK64)
    D2 = D2 ^ _F(D1, SIGMA3)
    D1 = D1 ^ _F(D2, SIGMA4)
    KA = (D1 << 64) | D2

    if key_len != 16:
        D1 = (KA ^ KR) >> 64
        D2 = (KA ^ KR) & MASK64
        D2 = D2 ^ _F(D1, SIGMA5)
        D1 = D1 ^ _F(D2, SIGMA6)
        KB = (D1 << 64) | D2
    else:
        KB = 0 # Для 128-битного ключа KB не используется

    # 4. Формирование списка подключей в порядке, определённом RFC 3713
    subkeys = []

    if key_len == 16:
        # Для 128-битного ключа (18 раундов)
        subkeys.append((_rotl128(KL, 0) >> 64) & MASK64)   # kw1
        subkeys.append(_rotl128(KL, 0) & MASK64)            # kw2
        subkeys.append((_rotl128(KA, 0) >> 64) & MASK64)   # k1
        subkeys.append(_rotl128(KA, 0) & MASK64)            # k2
        subkeys.append((_rotl128(KL, 15) >> 64) & MASK64)  # k3
        subkeys.append(_rotl128(KL, 15) & MASK64)           # k4
        subkeys.append((_rotl128(KA, 15) >> 64) & MASK64)  # k5
        subkeys.append(_rotl128(KA, 15) & MASK64)           # k6
        subkeys.append((_rotl128(KA, 30) >> 64) & MASK64)  # ke1
        subkeys.append(_rotl128(KA, 30) & MASK64)           # ke2
        subkeys.append((_rotl128(KL, 45) >> 64) & MASK64)  # k7
        subkeys.append(_rotl128(KL, 45) & MASK64)           # k8
        subkeys.append((_rotl128(KA, 45) >> 64) & MASK64)  # k9
        subkeys.append(_rotl128(KL, 60) & MASK64)           # k10
        subkeys.append((_rotl128(KA, 60) >> 64) & MASK64)  # k11
        subkeys.append(_rotl128(KA, 60) & MASK64)           # k12
        subkeys.append((_rotl128(KL, 77) >> 64) & MASK64)  # ke3
        subkeys.append(_rotl128(KL, 77) & MASK64)           # ke4
        subkeys.append((_rotl128(KL, 94) >> 64) & MASK64)  # k13
        subkeys.append(_rotl128(KL, 94) & MASK64)           # k14
        subkeys.append((_rotl128(KA, 94) >> 64) & MASK64)  # k15
        subkeys.append(_rotl128(KA, 94) & MASK64)           # k16
        subkeys.append((_rotl128(KL, 111) >> 64) & MASK64) # k17
        subkeys.append(_rotl128(KL, 111) & MASK64)          # k18
        subkeys.append((_rotl128(KA, 111) >> 64) & MASK64) # kw3
        subkeys.append(_rotl128(KA, 111) & MASK64)          # kw4
    else:
        # Для 192/256-битного ключа (24 раунда)
        subkeys.append((_rotl128(KL, 0) >> 64) & MASK64)   # kw1
        subkeys.append(_rotl128(KL, 0) & MASK64)            # kw2
        subkeys.append((_rotl128(KB, 0) >> 64) & MASK64)   # k1
        subkeys.append(_rotl128(KB, 0) & MASK64)            # k2
        subkeys.append((_rotl128(KR, 15) >> 64) & MASK64)  # k3
        subkeys.append(_rotl128(KR, 15) & MASK64)           # k4
        subkeys.append((_rotl128(KA, 15) >> 64) & MASK64)  # k5
        subkeys.append(_rotl128(KA, 15) & MASK64)           # k6
        subkeys.append((_rotl128(KR, 30) >> 64) & MASK64)  # ke1
        subkeys.append(_rotl128(KR, 30) & MASK64)           # ke2
        subkeys.append((_rotl128(KB, 30) >> 64) & MASK64)  # k7
        subkeys.append(_rotl128(KB, 30) & MASK64)           # k8
        subkeys.append((_rotl128(KL, 45) >> 64) & MASK64)  # k9
        subkeys.append(_rotl128(KL, 45) & MASK64)           # k10
        subkeys.append((_rotl128(KA, 45) >> 64) & MASK64)  # k11
        subkeys.append(_rotl128(KA, 45) & MASK64)           # k12
        subkeys.append((_rotl128(KL, 60) >> 64) & MASK64)  # ke3
        subkeys.append(_rotl128(KL, 60) & MASK64)           # ke4
        subkeys.append((_rotl128(KR, 60) >> 64) & MASK64)  # k13
        subkeys.append(_rotl128(KR, 60) & MASK64)           # k14
        subkeys.append((_rotl128(KB, 60) >> 64) & MASK64)  # k15
        subkeys.append(_rotl128(KB, 60) & MASK64)           # k16
        subkeys.append((_rotl128(KL, 77) >> 64) & MASK64)  # k17
        subkeys.append(_rotl128(KL, 77) & MASK64)           # k18
        subkeys.append((_rotl128(KA, 77) >> 64) & MASK64)  # k19
        subkeys.append(_rotl128(KA, 77) & MASK64)           # k20
        subkeys.append((_rotl128(KR, 94) >> 64) & MASK64)  # k21
        subkeys.append(_rotl128(KR, 94) & MASK64)           # k22
        subkeys.append((_rotl128(KA, 94) >> 64) & MASK64)  # k23
        subkeys.append(_rotl128(KA, 94) & MASK64)           # k24
        subkeys.append((_rotl128(KL, 111) >> 64) & MASK64) # kw3
        subkeys.append(_rotl128(KL, 111) & MASK64)          # kw4

    return subkeys
