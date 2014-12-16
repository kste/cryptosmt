'''
Created on Mar 28, 2014

@author: stefan
'''

from parser import stpcommands
from ciphers.cipher import AbstractCipher

from parser.stpcommands import getStringLeftRotate as rotl
from parser.stpcommands import getStringRightRotate as rotr


class SimonKeyRcCipher(AbstractCipher):
    """
    Represents the SIMON block cipher and can be used
    to find recover a secret key from plaintext/ciphertexts.
    """

    CONST_Z = [1, 1, 1, 1, 1, 0, 1, 0, 0, 0, 1, 0, 0, 1, 0, 1, 0, 1, 1, 0, 0, 0,
               0, 1, 1, 1, 0, 0, 1, 1, 0, 1, 1, 1, 1, 1, 0, 1, 0, 0, 0, 1, 0, 0,
               1, 0, 1, 0, 1, 1, 0, 0, 0, 0, 1, 1, 1, 0, 0, 1, 1, 0]

    num_messages = 1

    def getName(self):
        """
        Returns the name of the cipher.
        """
        return "simon"

    def getFormatString(self):
        """
        Returns the print format.
        """
        format_string = []
        #Limit to a maximum of 4 messages to print for readability
        messages_print = (min(4, self.num_messages))
        for msg in range(messages_print):
            format_string.append('x{}r'.format(msg))
            format_string.append('y{}r'.format(msg))
        format_string += ['dx', 'dy', 'key']
        return format_string

    def createSTP(self, stp_filename, cipherParameters):
        """
        Creates an STP file for SIMON.
        """

        wordsize = cipherParameters[0]
        rot_alpha = cipherParameters[1]
        rot_beta = cipherParameters[2]
        rot_gamma = cipherParameters[3]
        rounds = cipherParameters[4]
        #weight = cipherParameters[5]
        #is_iterative = cipherParameters[6]
        fixed_vars = cipherParameters[7]
        chars_blocked = cipherParameters[8]
        self.num_messages = cipherParameters[9]

        with open(stp_filename, 'w') as stp_file:
            stp_file.write("% Input File for STP\n% Simon w={} alpha={} beta={} gamma={}"
                           " rounds={}\n\n\n".format(wordsize, rot_alpha, rot_beta,
                                                     rot_gamma, rounds))

            # Setup key
            key = ["key{}".format(i) for i in range(rounds + 1)]
            tmp_key = ["tmpkey{}".format(i) for i in range(rounds + 1)]

            stpcommands.setupVariables(stp_file, key, wordsize)
            stpcommands.setupVariables(stp_file, tmp_key, wordsize)

            #TODO Add constant addition
            self.setupKeySchedule(stp_file, key, tmp_key, rounds, wordsize)

            # Setup variables
            # x = left, y = right
            for msg in range(self.num_messages):
                x = ["x{}r{}".format(msg, i) for i in range(rounds + 1)]
                y = ["y{}r{}".format(msg, i) for i in range(rounds + 1)]
                and_out = ["andout{}r{}".format(msg, i) for i in range(rounds + 1)]
                stpcommands.setupVariables(stp_file, x, wordsize)
                stpcommands.setupVariables(stp_file, y, wordsize)
                stpcommands.setupVariables(stp_file, and_out, wordsize)

                #Setup Rounds
                for i in range(rounds):
                    self.setupSimonRound(stp_file, x[i], y[i], x[i+1], y[i+1],
                                         and_out[i], key[i], wordsize)

            #Differences between x_0 and x_i
            if self.num_messages > 1:
                delta_x = ["dx{}".format(i) for i in range(rounds + 1)]
                delta_y = ["dy{}".format(i) for i in range(rounds + 1)]
                stpcommands.setupVariables(stp_file, delta_x, wordsize)
                stpcommands.setupVariables(stp_file, delta_y, wordsize)
                for i in range(rounds + 1):
                    stp_file.write("ASSERT({} = BVXOR({}, {}));\n".format(
                        delta_x[i], "x0r{}".format(i), "x1r{}".format(i)))
                    stp_file.write("ASSERT({} = BVXOR({}, {}));\n".format(
                        delta_y[i], "y0r{}".format(i), "y1r{}".format(i)))

            if fixed_vars:
                for key, value in fixed_vars.iteritems():
                    stpcommands.assertVariableValue(stp_file, key, value)

            if chars_blocked:
                for char in chars_blocked:
                    stpcommands.blockCharacteristic(stp_file, char, wordsize)

            stpcommands.setupQuery(stp_file)

        return

    def getParamList(self, rounds, wordsize, weight):
        """
        Returns a list of the parameters for SIMON.
        """
        return [wordsize, 1, 8, 2, rounds, weight]

    def setupKeySchedule(self, stp_file, key, tmp_key, rounds, wordsize):
        command = ""
        const3 = "0x{}3".format("0"*(wordsize / 4 - 1))
        if(rounds > 4):
            for i in range(4, rounds):
                constz = "0x{}{}".format("0"*(wordsize / 4 - 1),
                                         self.CONST_Z[(i - 4) % 62])
                tmp = "BVXOR({}, {})".format(rotr(key[i-1], 3, wordsize), key[i-3])
                command += "ASSERT({} = BVXOR({}, {}));\n".format(
                    tmp_key[i], tmp, rotr(tmp, 1, wordsize))
                command += "ASSERT({} = BVXOR({}, BVXOR({}, BVXOR(~{}, {}))));\n".format(
                    key[i], constz, const3, key[i-4], tmp_key[i])
        stp_file.write(command)
        return

    def setupSimonRound(self, stp_file, x0_in, y0_in,  x0_out, y0_out,
                        and_out0, key, wordsize):
        """
        Returns a string representing one round of Simon in STP.
        y[i+1] = x[i]
        x[i+1] = (x[i] <<< 1) & (x[i] <<< 8) ^ y[i] ^ (x[i] << 2) ^ key
        """
        command = ""

        #Assert(y_out = x_in)
        command += "ASSERT({} = {});\n".format(y0_out, x0_in)

        #Assert AND Output
        command += "ASSERT({} = {} & {});\n".format(
            and_out0, rotl(x0_in, 1, wordsize), rotl(x0_in, 8, wordsize))

        #Assert x_out
        command += "ASSERT({} = BVXOR({}, BVXOR({}, BVXOR({}, {}))));\n".format(
            x0_out, y0_in, and_out0, key, rotl(x0_in, 2, wordsize))
        stp_file.write(command)
        return
