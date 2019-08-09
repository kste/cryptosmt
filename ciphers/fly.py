'''
Created on Feb 21, 2017

@author: ralph
'''

from parser import stpcommands
from ciphers.cipher import AbstractCipher


class FlyCipher(AbstractCipher):
    """
    Represents the differential behaviour of Fly and can be used
    to find differential characteristics for the given parameters.
    """

    name = "fly"

    def getFormatString(self):
        """
        Returns the print format.
        """
        return ['S', 'P', 'w']

    def createSTP(self, stp_filename, parameters):
        """
        Creates an STP file to find a characteristic for FLY with
        the given parameters.
        """

        wordsize = parameters["wordsize"]
        rounds = parameters["rounds"]
        weight = parameters["sweight"]

        if wordsize != 64:
            print("Only wordsize of 64-bit supported.")
            exit(1)

        with open(stp_filename, 'w') as stp_file:
            header = ("% Input File for STP\n% FLY w={}"
                      "rounds={}\n\n\n".format(wordsize, rounds))
            stp_file.write(header)

            # Setup variables
            s = ["S{}".format(i) for i in range(rounds + 1)]
            p = ["P{}".format(i) for i in range(rounds)]

            # w = weight
            w = ["w{}".format(i) for i in range(rounds)]

            stpcommands.setupVariables(stp_file, s, wordsize)
            stpcommands.setupVariables(stp_file, p, wordsize)
            stpcommands.setupVariables(stp_file, w, wordsize)

            stpcommands.setupWeightComputation(stp_file, weight, w, wordsize)

            for i in range(rounds):
                self.setupFlyRound(stp_file, s[i], p[i], s[i+1], w[i], wordsize)

            # No all zero characteristic
            stpcommands.assertNonZero(stp_file, s, wordsize)

            # Iterative characteristics only
            # Input difference = Output difference
            if parameters["iterative"]:
                stpcommands.assertVariableValue(stp_file, s[0], s[rounds])

            for key, value in parameters["fixedVariables"].items():
                stpcommands.assertVariableValue(stp_file, key, value)

            for char in parameters["blockedCharacteristics"]:
                stpcommands.blockCharacteristic(stp_file, char, wordsize)

            stpcommands.setupQuery(stp_file)

        return

    def setupFlyRound(self, stp_file, s_in, p, s_out, w, wordsize):
        """
        Model for differential behaviour of one round FLY
        """
        command = ""

        #Permutation Layer
        #Rot(.) = (i+8*(i mod 8)) mod 64
        for i in range(64):
            command += "ASSERT({0}[{1}:{1}] = {2}[{3}:{3}]);\n".format(p, i, s_out, (i+8*(i%8))%64)

        # Substitution Layer
        fly_sbox = [0x00,0x9b,0xc2,0x67,0x38,0xef,0xb9,0xaa,0x36,0x12,0x5c,0x9a,0x2c,0x63,0x44,0xba,
                    0xe4,0x18,0x51,0x87,0xed,0xdf,0x90,0x6c,0xd5,0xf2,0x20,0xa6,0x41,0x8e,0x48,0xe6,
                    0x69,0xf3,0x05,0xcb,0xc4,0x3e,0x93,0x7b,0x8d,0xf1,0x1d,0x7f,0x07,0x2e,0xc9,0xa5,
                    0x76,0x21,0xab,0xdd,0x4f,0x53,0x83,0xc5,0x4e,0xf4,0xee,0x27,0xfe,0xa9,0x81,0x35,
                    0x72,0x99,0x0b,0x4d,0x75,0xc8,0x16,0xa0,0xe7,0x98,0x1a,0x0c,0xb3,0x3d,0xb2,0xdc,
                    0x5f,0x91,0xa7,0x74,0x6f,0x10,0xb8,0x59,0x2a,0x42,0x3a,0x54,0xec,0x80,0x6b,0xd6,
                    0x15,0xb0,0x78,0xd4,0xde,0x57,0xff,0x32,0x5b,0x79,0x8a,0x2d,0xac,0x06,0xb1,0x43,
                    0xfd,0x8c,0x09,0x61,0xc6,0x0a,0x23,0xbb,0x64,0xcf,0x30,0x1e,0xd7,0xe5,0x92,0xf8,
                    0x5d,0x7e,0x2f,0x89,0x02,0xa1,0xb5,0x46,0xcc,0xea,0x13,0xb4,0x40,0x17,0xdb,0x58,
                    0x6a,0xc0,0x14,0x3b,0xe8,0xd3,0x97,0xfc,0xae,0x55,0xf9,0x82,0x86,0x9d,0xc1,0x0f,
                    0x84,0x2b,0x6e,0xcd,0x96,0xf5,0xa8,0x03,0x31,0x9f,0x77,0xd0,0xe9,0x62,0xfa,0x3c,
                    0x3f,0x19,0x50,0x7a,0xbc,0x47,0xd2,0xe1,0x4b,0x28,0x0d,0x66,0x73,0xa4,0x25,0xbe,
                    0x4c,0xf6,0xe3,0x01,0x39,0x8b,0xca,0x7d,0x04,0x68,0x9e,0x37,0x22,0xbf,0x65,0xe0,
                    0xb7,0x95,0xd8,0xa2,0x1f,0x24,0x60,0x5e,0x71,0xd9,0x26,0x4a,0xfb,0x33,0xad,0x7c,
                    0xd1,0xa3,0xf7,0x45,0x70,0xce,0x1b,0x29,0xbd,0x1c,0xaf,0x52,0x56,0xda,0x88,0x94,
                    0xe2,0x08,0x9c,0xb6,0x5a,0x6d,0x34,0x8f,0x85,0xf0,0xc3,0xeb,0x0e,0xc7,0x49,0x11]

        for i in range(8):
            variables = ["{0}[{1}:{1}]".format(s_in, 8*i + 7),
                         "{0}[{1}:{1}]".format(s_in, 8*i + 6),
                         "{0}[{1}:{1}]".format(s_in, 8*i + 5),
                         "{0}[{1}:{1}]".format(s_in, 8*i + 4),
                         "{0}[{1}:{1}]".format(s_in, 8*i + 3),
                         "{0}[{1}:{1}]".format(s_in, 8*i + 2),
                         "{0}[{1}:{1}]".format(s_in, 8*i + 1),
                         "{0}[{1}:{1}]".format(s_in, 8*i + 0),
                         "{0}[{1}:{1}]".format(p, 8*i + 7),
                         "{0}[{1}:{1}]".format(p, 8*i + 6),
                         "{0}[{1}:{1}]".format(p, 8*i + 5),
                         "{0}[{1}:{1}]".format(p, 8*i + 4),
                         "{0}[{1}:{1}]".format(p, 8*i + 3),
                         "{0}[{1}:{1}]".format(p, 8*i + 2),
                         "{0}[{1}:{1}]".format(p, 8*i + 1),
                         "{0}[{1}:{1}]".format(p, 8*i + 0),
                         "{0}[{1}:{1}]".format(w, 8*i + 7),
                         "{0}[{1}:{1}]".format(w, 8*i + 6),
                         "{0}[{1}:{1}]".format(w, 8*i + 5),
                         "{0}[{1}:{1}]".format(w, 8*i + 4),
                         "{0}[{1}:{1}]".format(w, 8*i + 3),
                         "{0}[{1}:{1}]".format(w, 8*i + 2),
                         "{0}[{1}:{1}]".format(w, 8*i + 1),
                         "{0}[{1}:{1}]".format(w, 8*i + 0)]
            command += stpcommands.add8bitSbox(fly_sbox, variables)

        stp_file.write(command)
        return
