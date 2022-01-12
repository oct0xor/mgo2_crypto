import sys, os, struct	
from Crypto.Cipher import Blowfish
from Crypto.Hash import MD5

ptsys_keys = {
	0: "74F66DC28598F5D172AC2DCACE5544D665F11D05BEA20568E76C529DEB35890EC332FF24FE5D9C3FB34189CF47055B26F9E4CC639A46B5465404DF41E65B8E4E",
	3: "53085788720CC955D1A75FCA0A988CED84CFBA8BFDDA9A046AF0FB4DE027DC24B2B636110D27CA284E0AB15912212593B52D945C633A0B5397D41B64F70ED1EE",
	6: "24B0DB82FD2366D428BEF3BE915BFDFF998EBFC4B549C1ECBB8A633CF57046001DE1AD7CBE8381DBEF1342768E3D629F2059AE61B4DFFB1DA2FF1A0264487E7A", # "kit"
}

def get_patch_system_key(key_id):

	if (key_id not in ptsys_keys):
		print("ptsys: invalid key type %d\n", key_id)
		exit(0)

	return bytes.fromhex(ptsys_keys[key_id])

def patch_system_cbcblowfish(ciphertext, key):

	bs = Blowfish.block_size
	
	iv = key[:bs]
	key = key[bs:]
	
	cipher = Blowfish.new(key, Blowfish.MODE_CBC, iv)
	return cipher.decrypt(ciphertext)

def get_path_digest(path):

	path = path.replace('\\', '/')

	if ("/o/stage/" not in path):
		print("not able to find \"/o/stage/\" or \"\\o\\stage\\\" in file path")
		exit(0)

	path = path[path.find("/o/stage/")+3:]
	path = path[:path.rfind("/")]

	h = MD5.new()
	h.update(path.encode('utf-8'))
	return h.digest()

def generate_xor_stream(digest):

	key = get_patch_system_key(0)
	ciphertext = get_patch_system_key(3)

	sbox = patch_system_cbcblowfish(ciphertext, key)

	xor_stream = bytearray(b"")
	for i in range(0x40):
		xor_stream.append(sbox[i] ^ digest[i & 0xF])
	
	return xor_stream

def decrypt_file(path):

	digest = get_path_digest(path)
	xor_stream = generate_xor_stream(digest)
	
	with open(path, 'rb') as f:
		data = f.read()[:-0x10]
	
		iv = struct.unpack(">Q", xor_stream[0:8])[0]
		xor_stream = xor_stream[8:]
	
		out = b""
		offset = 0
		xor_stream_pos = 0
		while (offset + 8 < len(data)):
	
			enc_qword = struct.unpack(">Q", data[offset:offset+8])[0]
			xor_qword = struct.unpack(">Q", xor_stream[xor_stream_pos:xor_stream_pos+8])[0]
			dec_qword = enc_qword ^ xor_qword ^ iv
			iv = enc_qword
			out += struct.pack(">Q", dec_qword)
	
			xor_stream_pos += 8
			if (xor_stream_pos >= len(xor_stream)):
				xor_stream_pos = 0
	
			offset += 8
	
			if (offset + 8 > len(data)):
				pad_size = dec_qword & 0xFF
				if (pad_size <= 8):
					out = out[:-pad_size]

		dir_name = os.path.dirname(os.path.abspath(path))
		file_name = os.path.basename(path)
		out_dir = os.path.join(dir_name, "out")

		if (not os.path.exists(out_dir)):
			os.mkdir(out_dir)

		with open(os.path.join(out_dir, file_name), 'wb') as o:	
			o.write(out)
	
if __name__ == '__main__':

	if (len(sys.argv) < 2):
		print("Usage: ")
		print("\t%s file_path" % (os.path.basename(sys.argv[0])))
		print("\t%s directory_path" % (os.path.basename(sys.argv[0])))
		exit(0)

	path = sys.argv[1]

	if (os.path.isfile(path)):
		decrypt_file(path)
	
	elif (os.path.isdir(path)):
	
		for root, dirs, files in os.walk(path):
			
			for file in files:
				file_path = os.path.join(root, file)
			
				dir_name = os.path.dirname(os.path.abspath(file_path))
				if (dir_name == "out"):
					continue
		
				decrypt_file(file_path)
	
	else:
		print("Error! Bad path")
