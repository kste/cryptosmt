'''
Created on Mar 28, 2014

@author: stefan
'''

from parser import stpcommands
from ciphers.cipher import AbstractCipher

from parser.stpcommands import getStringRightRotate as rotr
from parser.stpcommands import getStringLeftRotate as rotl


class SimonLinearCipher(AbstractCipher):
    """
    Represents the linear behaviour of SIMON and can be used
    to find differential characteristics for the given parameters.
    """

    name = "simonlinear"
    rot_alpha = 8
    rot_beta = 1
    rot_gamma = 2

    def getFormatString(self):
        """
        Returns the print format.
        """
        return ['x', 'y', 'w']

    def createSTP(self, stp_filename, parameters):
        """
        Creates an STP file to find a linear characteristic for SIMON with
        the given parameters.
        """

        wordsize = parameters["wordsize"]
        rounds = parameters["rounds"]
        weight = parameters["sweight"]

        # Replace with custom if set in parameters.
        if "rotationconstants" in parameters:
            self.rot_alpha = parameters["rotationconstants"][0] 
            self.rot_beta = parameters["rotationconstants"][1]
            self.rot_gamma = parameters["rotationconstants"][2]

        with open(stp_filename, 'w') as stp_file:
            header = ("% Input File for STP\n% Simon w={} alpha={} beta={}"
                      " gamma={} rounds={}\n\n\n".format(wordsize,
                                                         self.rot_alpha,
                                                         self.rot_beta,
                                                         self.rot_gamma,
                                                         rounds))
            stp_file.write(header)

            # Setup variable
            # x = left, y = right
            x = ["x{}".format(i) for i in range(rounds + 1)]
            y = ["y{}".format(i) for i in range(rounds + 1)]
            b = ["b{}".format(i) for i in range(rounds + 1)]
            c = ["c{}".format(i) for i in range(rounds + 1)]
            and_out = ["andout{}".format(i) for i in range(rounds + 1)]
            abits = ["abits{}".format(i) for i in range(rounds + 1)]

            #Create tmp variables for weight computation
            tmpWeight = ["tmp{}r{}".format(j, i) for i in range(rounds) 
                         for j in range(wordsize)]

            #Tmp variables for parity checks
            sbits = ["sbits{}r{}".format(j, i) for i in range(rounds) 
                     for j in range(wordsize)]
            pbits = ["pbits{}r{}".format(j, i) for i in range(rounds) 
                     for j in range(wordsize)]

            # w = weight
            w = ["w{}".format(i) for i in range(rounds)]

            stpcommands.setupVariables(stp_file, x, wordsize)
            stpcommands.setupVariables(stp_file, y, wordsize)
            stpcommands.setupVariables(stp_file, and_out, wordsize)
            stpcommands.setupVariables(stp_file, b, wordsize)
            stpcommands.setupVariables(stp_file, c, wordsize)
            stpcommands.setupVariables(stp_file, abits, wordsize)
            stpcommands.setupVariables(stp_file, w, wordsize)
            stpcommands.setupVariables(stp_file, tmpWeight, wordsize)
            stpcommands.setupVariables(stp_file, sbits, wordsize)
            stpcommands.setupVariables(stp_file, pbits, wordsize)

            stpcommands.setupWeightComputation(stp_file, weight, w, wordsize)

            for i in range(rounds):
                indicesFrom = i*wordsize
                indicesTo = (i+1)*wordsize
                self.setupSimonRound(stp_file, x[i], y[i], x[i+1], y[i+1], 
                                     and_out[i], b[i], c[i], abits[i], w[i],
                                     tmpWeight[indicesFrom:indicesTo],
                                     sbits[indicesFrom:indicesTo],
                                     pbits[indicesFrom:indicesTo],
                                     wordsize)

            # No all zero characteristic
            stpcommands.assertNonZero(stp_file, x + y, wordsize)

            # Iterative characteristics only
            # Input difference = Output difference
            if parameters["iterative"]:
                stpcommands.assertVariableValue(stp_file, x[0], x[rounds])
                stpcommands.assertVariableValue(stp_file, y[0], y[rounds])

            for key, value in parameters["fixedVariables"].items():
                stpcommands.assertVariableValue(stp_file, key, value)

            for char in parameters["blockedCharacteristics"]:
                stpcommands.blockCharacteristic(stp_file, char, wordsize)

            stpcommands.setupQuery(stp_file)

        return

    def setupSimonRound(self, stp_file, x_in, y_in, x_out, y_out, and_out, b, c,
                        abits, w, tmpWeight, sbits, pbits, wordsize):
        """
        Model for linear behaviour of one round SIMON.
        y[i+1] = x[i]
        x[i+1] = (x[i] <<< 1) & (x[i] <<< 8) ^ y[i] ^ (x[i] << 2)

        This is a loop unrolled version of the model presented in
        http://eprint.iacr.org/2015/145
        """
        command = ""

        deltarot = self.rot_alpha - self.rot_beta
        lout = y_in
        lin = "BVXOR(BVXOR({}, {}), {})".format(x_in, rotr(lout, self.rot_gamma, wordsize), y_out)
        #lin = "BVXOR({}, {})".format(x_in, rotr(lout, self.rot_gamma, wordsize))

        #Assert(y_out = x_in)
        command += "ASSERT({} = {});\n".format(x_out, y_in)

        #Assert for AND linear approximation
        tmp = "BVXOR(({0} | {1}), {2}) & {2}".format(
            rotr(lout, self.rot_alpha, wordsize),
            rotr(lout, self.rot_beta, wordsize),
            lin)

        command += "ASSERT({} = 0x{});\n".format(tmp, "0"*(wordsize // 4))

        #Assert for y_out
        # command += "ASSERT({0} = BVXOR({1}, BVXOR({2}, BVXOR({3}, {4}))));\n".format(
        #     y_out, x_in, rotr(lout, self.rot_alpha, wordsize), rotr(lout, self.rot_beta, wordsize),
        #     rotr(x_out, self.rot_gamma, wordsize))
        command += "ASSERT({0} = BVXOR({1}, BVXOR({2}, {3})));\n".format(
            y_out, x_in, rotr(x_out, self.rot_gamma, wordsize), lin)

        #For weight computation
        #Compute abits
        loutRotated = rotr(lout, deltarot, wordsize)

        command += "ASSERT({} = ({} & {}));\n".format(tmpWeight[0], lout, loutRotated)

        for i in range(1, wordsize):
            command += "ASSERT({} = ({} & {}));\n".format(
                tmpWeight[i], lout, rotr(tmpWeight[i - 1], deltarot, wordsize))

        abits = "BVXOR({}, {})".format(lout, tmpWeight[0])
        for i in range(1, wordsize):
            abits = "BVXOR({}, {})".format(tmpWeight[i], abits)

        #abits = y_in #only use weight

        #Weight computation
        #command += "ASSERT({0} = (IF {1} = 0x{3} THEN BVSUB({4},0x{3},0x{5}1) \
        #          ELSE {2} ENDIF));\n".format(
        #            w, y_in, abits, "f"*(wordsize / 4),
        #            wordsize, "0"*((wordsize / 4) - 1))

        command += "ASSERT({} = {});\n".format(w, abits)

        #Parity Checks
        command += "ASSERT({} = {});\n".format(
            sbits[0], rotr("({} & ~{} & ~{})".format(
                rotr(lout, deltarot, wordsize), lout, rotr(abits, deltarot, wordsize)),
                1, wordsize))

        command += "ASSERT({} = {});\n".format(
            pbits[0], rotl("({} & {})".format(sbits[0], lin), 2*deltarot, wordsize))

        for i in range(1, wordsize):
            command += "ASSERT({} = {});\n".format(
                sbits[i], rotl("({} & {})".format(
                    rotl(sbits[i - 1], deltarot, wordsize),
                    rotr(sbits[i-1], self.rot_beta, wordsize)),
                    deltarot, wordsize)
                )
            command += "ASSERT({} = {});\n".format(
                pbits[i], rotl("BVXOR({}, {} & {})".format(
                    pbits[i - 1], sbits[i], lin), 2*deltarot, wordsize)
                )

        command += "ASSERT({} = 0x{});\n".format(pbits[wordsize - 1], "0"*(wordsize // 4))

        stp_file.write(command)
        return
