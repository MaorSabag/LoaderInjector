import sys

KEY = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"

def xor(data, key):
	
	key = str(key)
	l = len(key)
	output_str = ""

	for i in range(len(data)):
		current = data[i]
		current_key = key[i % len(key)]
		try:
			output_str += chr(current ^ ord(current_key))
		except:
			output_str += chr(ord(current) ^ ord(current_key))
	
	return output_str


def printCiphertext(ciphertext):
	print('{ 0x' + ', 0x'.join(hex(ord(x))[2:] for x in ciphertext) + ' };')


def main():
    if len(sys.argv) != 3:
        print(f"File arguments needed! {sys.argv[0]} <raw payload file> <output file name>")
        exit(1)


    plaintext = open(sys.argv[1], "rb").read()



    ciphertext = xor(plaintext, KEY)
    hex_cipher = '\\x' + '\\x'.join(hex(ord(x))[2:].zfill(2) for x in ciphertext) + ''

    python_file = """a=b"((replace_me))"
    with open("((name_replace))", "wb") as h: h.write(a)""".replace(r"((replace_me))", hex_cipher).replace(r"((name_replace))", sys.argv[2])

    exec(python_file)


if __name__ == "__main__":
    main()
