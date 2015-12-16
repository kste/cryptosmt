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

    name = "simonkeyrc"
    rot_alpha = 8
    rot_beta = 1
    rot_gamma = 2
    CONST_Z = [1, 1, 1, 1, 1, 0, 1, 0, 0, 0, 1, 0, 0, 1, 0, 1, 0, 1, 1, 0, 0, 0,
               0, 1, 1, 1, 0, 0, 1, 1, 0, 1, 1, 1, 1, 1, 0, 1, 0, 0, 0, 1, 0, 0,
               1, 0, 1, 0, 1, 1, 0, 0, 0, 0, 1, 1, 1, 0, 0, 1, 1, 0]

    num_messages = 1



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
        format_string += ['dx1r', 'dy1r', 'key']

        return format_string

    def createSTP(self, stp_filename, parameters):
        """
        Creates an STP file for SIMON.
        """

        wordsize = parameters["wordsize"]
        rounds = parameters["rounds"]
        weight = parameters["sweight"]

        # Replace with custom if set in parameters.
        if "rotationconstants" in parameters:
            self.rot_alpha = parameters["rotationconstants"][0] 
            self.rot_beta = parameters["rotationconstants"][1]
            self.rot_gamma = parameters["rotationconstants"][2]

        self.num_messages = parameters["nummessages"]

        with open(stp_filename, 'w') as stp_file:
            header = ("% Input File for STP\n% Simon w={} alpha={} beta={}"
                      " gamma={} rounds={}\n\n\n".format(wordsize,
                                                         self.rot_alpha,
                                                         self.rot_beta,
                                                         self.rot_gamma,
                                                         rounds))
            stp_file.write(header)

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
            for msg in range(1, self.num_messages):
                delta_x = ["dx{}r{}".format(msg, i) for i in range(rounds + 1)]
                delta_y = ["dy{}r{}".format(msg, i) for i in range(rounds + 1)]
                stpcommands.setupVariables(stp_file, delta_x, wordsize)
                stpcommands.setupVariables(stp_file, delta_y, wordsize)
                for i in range(rounds + 1):
                    stp_file.write("ASSERT({} = BVXOR({}, {}));\n".format(
                        delta_x[i], "x0r{}".format(i),
                        "x{}r{}".format(msg, i)))
                    stp_file.write("ASSERT({} = BVXOR({}, {}));\n".format(
                        delta_y[i], "y0r{}".format(i),
                        "y{}r{}".format(msg, i)))

            for key, value in parameters["fixedVariables"].items():
                stpcommands.assertVariableValue(stp_file, key, value)

            for char in parameters["blockedCharacteristics"]:
                stpcommands.blockCharacteristic(stp_file, char, wordsize)

            stpcommands.setupQuery(stp_file)

        return

    def setupKeySchedule(self, stp_file, key, tmp_key, rounds, wordsize):
        command = ""
        const3 = "0x{}3".format("0"*(wordsize // 4 - 1))
        if rounds > 4:
            for i in range(4, rounds):
                constz = "0x{}{}".format("0"*(wordsize // 4 - 1),
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
        command += "ASSERT({} = {} & {});\n".format(and_out0, 
            rotl(x0_in, self.rot_beta, wordsize), 
            rotl(x0_in, self.rot_alpha, wordsize))

        #Assert x_out
        command += "ASSERT({} = BVXOR({}, BVXOR({}, BVXOR({}, {}))));\n".format(
            x0_out, y0_in, and_out0, key, rotl(x0_in, self.rot_gamma, wordsize))
        stp_file.write(command)
        return
