from secrets import token_hex
import AES_encryption
from AES_encryption import *

b = b'1234567890qazwsxedcrfvtgayhnujmi'
print(aes_encryption(b, b'1234567890qazwsxedcrfvtgbyhnujmi'))
# print(hex(99))
# print(int('63', 16))
# p = b"\xd7\xabv\xfe"
# print(p)
#
# [[99, 83, 224, 140], [9, 96, 225, 4], [205, 112, 183, 81], [186, 202, 208, 231]] Input
# [[95, 114, 100, 21], [87, 245, 188, 146], [247, 190, 59, 41], [29, 185, 249, 26]] - Ожидаемые выходные данные
#
# [[170, 188, 132, 185], [135, 201, 43, 144], [62, 150, 31, 24], [14, 106, 214, 15]] - Данные, которые выводит мой код
# a = [[2],[4],[6]]
# b = [2,4,6]
# print(bytearray(a[0] + a[1] + a[2]))
# print(bytearray(b + a[0] + a[1] + a[2]))

# s_box_string = '63 7c 77 7b f2 6b 6f c5 30 01 67 2b fe d7 ab 76' \
#                'ca 82 c9 7d fa 59 47 f0 ad d4 a2 af 9c a4 72 c0' \
#                'b7 fd 93 26 36 3f f7 cc 34 a5 e5 f1 71 d8 31 15' \
#                '04 c7 23 c3 18 96 05 9a 07 12 80 e2 eb 27 b2 75' \
#                '09 83 2c 1a 1b 6e 5a a0 52 3b d6 b3 29 e3 2f 84' \
#                '53 d1 00 ed 20 fc b1 5b 6a cb be 39 4a 4c 58 cf' \
#                'd0 ef aa fb 43 4d 33 85 45 f9 02 7f 50 3c 9f a8' \
#                '51 a3 40 8f 92 9d 38 f5 bc b6 da 21 10 ff f3 d2' \
#                'cd 0c 13 ec 5f 97 44 17 c4 a7 7e 3d 64 5d 19 73' \
#                '60 81 4f dc 22 2a 90 88 46 ee b8 14 de 5e 0b db' \
#                'e0 32 3a 0a 49 06 24 5c c2 d3 ac 62 91 95 e4 79' \
#                'e7 c8 37 6d 8d d5 4e a9 6c 56 f4 ea 65 7a ae 08' \
#                'ba 78 25 2e 1c a6 b4 c6 e8 dd 74 1f 4b bd 8b 8a' \
#                '70 3e b5 66 48 03 f6 0e 61 35 57 b9 86 c1 1d 9e' \
#                'e1 f8 98 11 69 d9 8e 94 9b 1e 87 e9 ce 55 28 df' \
#                '8c a1 89 0d bf e6 42 68 41 99 2d 0f b0 54 bb 16'.replace(" ", "")
#
#
# s_box = bytearray.fromhex(s_box_string)
#
# sub_word = s_box[int("53",16)]
# print(hex(sub_word))
# a = bytearray.fromhex("0123456789abcdef")
# print(a)
# print(a[1:]+bytearray.fromhex(str(a[0])))
# x = [1,2,34,5,6,7,8]
# y = '12345678'
# print(x[1:] + x[:1])
# print(y[1:] + y[:1])
# print(len(bytes(34)))
# random_hex = token_hex(16)
#
# # print(random_hex)
#
# print("\x15\x9d\tF\xbfJ\xeaU\x04\x19D\x89\xffj\xbbE")
# print("\x15\x8c+u\xfb\x1f\x8c\"\x8c\x80\xee23\xb7U\xba")
# print("\xc2\x0c\"\xbb;0q\xac>R7\xe7\x80\x0fR\xae")
#
#

# [0, 16, 32, 48]
# [64, 80, 96, 112]
# [128, 144, 160, 176]
# [192, 208, 224, 240]
# [0, 16, 32, 48] state[row] До замены
# [99, 202, 183, 4] state[row] после замены
# [64, 80, 96, 112] state[row] До замены
# [9, 83, 208, 81] state[row] после замены
# [128, 144, 160, 176] state[row] До замены
# [205, 96, 224, 231] state[row] после замены
# [192, 208, 224, 240] state[row] До замены
# [186, 112, 225, 140] state[row] после замены
# [99, 202, 183, 4]
# [9, 83, 208, 81]
# [205, 96, 224, 231]
# [186, 112, 225, 140]
#
# [99, 202, 183, 4]
# [9, 83, 208, 81]
# [205, 96, 224, 231]
# [186, 112, 225, 140]

