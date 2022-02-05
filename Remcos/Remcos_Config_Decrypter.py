from os import path
from sys import argv
from Crypto.Cipher import ARC4
from string import printable
import colorama


def print_help():
    print("[-] Usage: {} <settings-file>".format(argv[0]))
    exit(1)


def hexdump(src, length=16, sep='.'):
    FILTER = ''.join([(len(repr(chr(x))) == 3) and chr(x) or sep for x in range(256)])
    lines = []
    for c in range(0, len(src), length):
        chars = src[c: c + length]
        hex_ = ' '.join(['{:02x}'.format(x) for x in chars])
        if len(hex_) > 24:
            hex_ = '{} {}'.format(hex_[:24], hex_[24:])
        printable = ''.join(['{}'.format((x <= 127 and FILTER[x]) or sep) for x in chars])
        lines.append('{0:08x}  {1:{2}s} |{3:{4}s}|'.format(c, hex_, length * 3, printable, length))
    return '\n'.join(lines)


def main():
    if len(argv) != 2 or not (path.isfile(argv[1])):
        print_help()
    with open(argv[1], "rb") as settings_file:
        settings_data = settings_file.read()

    # first byte in settings = key length
    key_length = settings_data[0]
    # then the key
    key = settings_data[1:key_length + 1]
    # then the encrypted data
    encrypted_data = settings_data[(key_length + 1):]

    # create rc4 object and decrypt
    rc4 = ARC4.new(key)
    decrypted = rc4.decrypt(encrypted_data)

    colorama.init(autoreset=True)

    # print hexdump
    print(colorama.Fore.LIGHTGREEN_EX + "\n###### Hexdump ######\n")
    print(hexdump(decrypted))
    print("\n")

    # print values in settings
    print(colorama.Fore.LIGHTGREEN_EX + "###### Values ######\n")
    printable_data = ""
    for byte in bytearray(decrypted):
        if chr(byte) in printable:
            printable_data += chr(byte)
    splited_data = printable_data.split("|")
    for value in splited_data:
        if len(value) > 0:
            print("[#] {}".format(value))
    print("\n")


main()
