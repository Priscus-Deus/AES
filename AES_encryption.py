from secrets import token_hex
from math import ceil

nb = 4  # Количество столбцов (32-битных слов), составляющих State. Для данного стандарта Nb = 4.
nk = 4  # Количество 32-битных слов, составляющих ключ шифрования. Для данного стандарта Nk = 4.
nr = 10  # Количество раундов, которое является функцией Nk и Nb. Для данного стандарта Nr = 10.

s_box_string = '637c777bf26b6fc53001672bfed7ab76' \
               'ca82c97dfa5947f0add4a2af9ca472c0' \
               'b7fd9326363ff7cc34a5e5f171d83115' \
               '04c723c31896059a071280e2eb27b275' \
               '09832c1a1b6e5aa0523bd6b329e32f84' \
               '53d100ed20fcb15b6acbbe394a4c58cf' \
               'd0efaafb434d338545f9027f503c9fa8' \
               '51a3408f929d38f5bcb6da2110fff3d2' \
               'cd0c13ec5f974417c4a77e3d645d1973' \
               '60814fdc222a908846eeb814de5e0bdb' \
               'e0323a0a4906245cc2d3ac629195e479' \
               'e7c8376d8dd54ea96c56f4ea657aae08' \
               'ba78252e1ca6b4c6e8dd741f4bbd8b8a' \
               '703eb5664803f60e613557b986c11d9e' \
               'e1f8981169d98e949b1e87e9ce5528df' \
               '8ca1890dbfe6426841992d0fb054bb16'


s_box = bytearray.fromhex(s_box_string)  # Нелинейная таблица подстановок, используемая в нескольких преобразованиях
# замены байтов и в процедуре расширения ключа для осуществления однозначной замены значения байта.

def sub_word(word):
    """
    Функция, используемая в процедуре расширения ключа,
    которая принимает четырехбайтовое входное слово и применяет S-блок к каждому из четырех байтов
    для формирования выходного слова.

    SubWord() is a function that takes a four-byte input word and applies the S-box (Sec. 5.1.1,
    Fig. 7) to each of the four bytes to produce an output word.
    """
    sub_word = [s_box[i] for i in word]
    return sub_word


def rcon(i):

    """
    Массив слов раундовых констант.
    """
    rcon_const = bytearray.fromhex('01020408102040801b36')
    rcon_res = [rcon_const[i-1], 0, 0, 0]
    return rcon_res


def xor(a, b):
    """
    Операция исключающего ИЛИ (XOR).
    """
    return bytearray([x ^ y for (x, y) in zip(a, b)])


def rot_word(word):
    """
    Функция, используемая в процедуре расширения ключа,
    которая принимает четырехбайтовое слово и выполняет циклическую перестановку.

    The function RotWord() takes a
    word [a0,a1,a2,a3] as input, performs a cyclic permutation, and returns the word [a1,a2,a3,a0].
    """
    return bytearray([word[1], word[2], word[3], word[0]])


def key_expansion(key):
    """
    Процедура, используемая для генерации серии раундовых ключей из ключа шифра.
    """

    w = bytes_to_state(key)
    for i in range(nk, nb * (nr + 1)):
        temp = w[i-1]
        if i % nk == 0:
            temp = xor(sub_word(rot_word(temp)), rcon(i // nk))
        elif nk > 6 and i % nk == 4:
            temp = sub_word(temp)
        w.append(xor(w[i - nk], temp))
    return [w[i*4:(i+1)*4] for i in range(11)]


def add_round_key(state, key_schedule, round):

    """
    Преобразование в шифре и обратном шифре,
    при котором Раундовый Ключ добавляется к Состоянию с использованием операции XOR.
    Длина Раундового Ключа равна размеру Состояния (т.е. при Nb = 4, длина Раундового Ключа составляет 128 бит/16 байт).
    """
    round_key = key_schedule[round]  # Раундовые ключи - это значения,
    # полученные из Ключа Шифра с использованием процедуры расширения ключа;
    # они применяются к State в Шифре и Обратном Шифре.
    for column in range(4):
        state[column] = list(xor(state[column], round_key[column]))


def sub_bytes(state):
    """
    Преобразование в шифре, которое обрабатывает State, используя нелинейную таблицу замены байтов (S-блок),
    действующую независимо на каждом байте State.
    """
    for column in range(4):
        state[column] = [s_box[state[column][row]] for row in range(4)]


def shift_rows(state):
    """
    Преобразование в шифре, которое обрабатывает State путем циклического сдвига
     последних трех строк State на различные смещения.

    """
    # [00, 10, 20, 30]     [00, 10, 20, 30]
    # [01, 11, 21, 31] --> [11, 21, 31, 01]
    # [02, 12, 22, 32]     [22, 32, 02, 12]
    # [03, 13, 23, 33]     [33, 03, 13, 23]

    state[0][1], state[1][1], state[2][1], state[3][1] = state[1][1], state[2][1], state[3][1], state[0][1]
    state[0][2], state[1][2], state[2][2], state[3][2] = state[2][2], state[3][2], state[0][2], state[1][2]
    state[0][3], state[1][3], state[2][3], state[3][3] = state[3][3], state[0][3], state[1][3], state[2][3]


def xtime(a):
    """
    Следовательно, умножение на x (то есть {00000010} или {02}) может быть реализовано на уровне байта
    как левый сдвиг и последующее условное побитовое XOR с {1b}. Эта операция над байтами обозначается как xtime().
    """
    if a & 0x80:
        return ((a << 1) ^ 0x1b) & 0xff
    return a << 1


def mix_columns(state):
    """
     Преобразование в шифре, которое берет все столбцы State и перемешивает их данные (независимо друг от друга),
     чтобы создать новые столбцы.
     n*{02} =   Следовательно, умножение на x (то есть {00000010} или {02}) может быть реализовано на уровне байта
    как левый сдвиг и последующее условное побитовое XOR с {1b}. Эта операция над байтами обозначается как xtime().
     n*{03} = n*({02} + {01}) = n*{02} + n*{01}
    """
    # print(state, "Input")
    for i in range(4):

        elem0 = xtime(state[i][0]) ^ (xtime(state[i][1]) ^ state[i][1]) ^ state[i][2] ^ state[i][3]
        elem1 = state[i][0] ^ xtime(state[i][1]) ^ (xtime(state[i][2]) ^ state[i][2]) ^ state[i][3]
        elem2 = state[i][0] ^ state[i][1] ^ xtime(state[i][2]) ^ (xtime(state[i][3]) ^ state[i][3])
        elem3 = (xtime(state[i][0]) ^ state[i][0]) ^ state[i][1] ^ state[i][2] ^ xtime(state[i][3])

        state[i][0] = elem0
        state[i][1] = elem1
        state[i][2] = elem2
        state[i][3] = elem3
    # print(state, "Output")
    return state


def bytes_to_state(data):
    state = [data[i*4:(i+1)*4] for i in range(4)]  # Промежуточный результат шифрования,
    # который может быть представлен в виде прямоугольного массива байтов, имеющего четыре строки и Nb столбцов.
    return state


def state_to_bytes(state):
    return bytearray(state[0] + state[1] + state[2] + state[3])


def aes_encryption(data, key):

    state = bytes_to_state(data)
    key_schedule = key_expansion(key)
    add_round_key(state, key_schedule, round=0)
    for round in range(1, nr):
        sub_bytes(state)
        shift_rows(state)
        mix_columns(state)
        add_round_key(state, key_schedule, round)
    sub_bytes(state)
    shift_rows(state)
    add_round_key(state, key_schedule, round=nr)
    cipher = state_to_bytes(state)
    return cipher


def prb_encryption(data, key, r):
    """
    c = r || m xor Ek(r)
    """
    return r + xor(data, aes_encryption(r, key))


def prb_decryption(ciphertext, key):
    return xor(aes_encryption(ciphertext[:16], key), ciphertext[16:])

#random_hex = bytearray.fromhex(token_hex(16))
# def prb(key, data=None, r=None, C=None):
#     return r + xor(data, aes_encryption(r, key)) if r else xor(aes_encryption(C[:16], key), C[16:])


# plaintext = bytearray.fromhex('00112233445566778899aabbccddeeff')
# print(plaintext, "plaintext")
key = b'1234567890qazwsxedcrfvtgbyhnujmi'
# print(key, "key")
# aes_ciphertext = bytearray.fromhex('69c4e0d86a7b0430d8cdb78070b4c55a')
# print(aes_ciphertext, "aes_ciphertext")
# ciphertext = aes_encryption(plaintext, key)
# print(ciphertext, "ciphertext")
# #assert (ciphertext == aes_ciphertext)

plaintext2 = b'1234567890qazwsxedcrfvtgbyhnujmiggsfhoithjsepgjkf;ld,leatjrj'
# print(len(bytearray("errh", "utf-8")), "errh")
# print("\nPRB_________________________\n")
#print(len(bytearray(plaintext2)), "bytearray(plaintext)")
#print(bin.())
text = [plaintext2[i*16:(i+1)*16] for i in range(ceil(len(bytearray(plaintext2)) / 16))]
print(text, "text")
#prb_cipher = prb_encryption()
prb_ciphertext = []
for plaintext_block in text:
    random_hex = bytearray.fromhex(token_hex(16))
    prb_cipher = prb_encryption(plaintext_block, key, random_hex)
    print(prb_cipher, "prb_cipher")
    prb_ciphertext.append(prb_cipher)
print(prb_ciphertext, "prb_ciphertext")
for i in prb_ciphertext:
    m = prb_decryption(i, key)
    print(m, "m")

# b = b'1234567890qazwsxedcrfvtgbyhnujmi'
# print(aes_encryption(b, b'1234567890qazwsxedcrfvtgbyhnujmi'))






# random_hex = bytearray.fromhex(token_hex(16))
# print(random_hex, "random_hex")
# PRB_cipher = prb_encryption(plaintext, key, random_hex)
# print(PRB_cipher, "PRB_cipher")
# print(prb_decryption(PRB_cipher, key), "prb_decryption(PRB_cipher, key)")
# print(plaintext, "plaintext")
# #assert (plaintext == prb_decryption(PRB_cipher, key))

