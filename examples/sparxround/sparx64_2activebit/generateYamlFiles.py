#!/usr/bin/env python3




def generateContent(bit1, bit2, rnd, blocksize):
    content = ""

    content += "# Example input file for SPARX" + str(blocksize) + " - " + str(rnd) +" rounds with 2-active output bits\n"
    content += "---\n"
    content += "cipher: sparxround\n"
    content += "sweight: 0\n"
    content += "rounds: " + str(rnd) + "\n"
    content += "wordsize: 16\n"
    content += "mode: 1\n"
    content += "fixedVariables:\n"

    bitstring = ["0"]*64
    bitstring[bit1] = '1'
    bitstring[bit2] = '1'

    x0 = '0x{0:0{1}X}'.format(int(''.join(bitstring[0:16]),2),4)
    x1 = '0x{0:0{1}X}'.format(int(''.join(bitstring[16:32]),2),4)
    y0 = '0x{0:0{1}X}'.format(int(''.join(bitstring[32:48]),2),4)
    y1 = '0x{0:0{1}X}'.format(int(''.join(bitstring[48:64]),2),4)

    content += "- X0"+ str(rnd) + ": \"" + x0 + "\"\n"
    content += "- X1"+ str(rnd) + ": \"" + x1 + "\"\n"
    content += "- Y0"+ str(rnd) + ": \"" + y0 + "\"\n"
    content += "- Y1"+ str(rnd) + ": \"" + y1 + "\"\n"
    content += "...\n\n"

    return content

def main():

    print("start")

    rnd = 6
    blocksize = 64

    for bit1 in range(0, blocksize):
        for bit2 in range(0, blocksize):
            if bit1 == bit2:
                continue

            filename_yaml_file = "./"+ str(rnd) +"-rounds/sparx64-128-round-"+ str(rnd) + "-diff-bit-" + str(bit1) + "-" + str(bit2) + ".yaml"
            content = generateContent(bit1, bit2, rnd, blocksize)

            #print(filename_yaml_file)

            with open(filename_yaml_file,'w') as f:
                f.write(content)

    print("done!")


if __name__ == '__main__':
    main()