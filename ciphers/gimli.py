'''
Created on Jan 6, 2017

@author: stefan
'''

from parser import stpcommands
from ciphers.cipher import AbstractCipher

from parser.stpcommands import getStringLeftRotate as rotl



class GimliCipher(AbstractCipher):
    """
    Represents the differential behaviour of the Gimli
    permutation.
    """

    name = "gimli"

    # Constants
    a = 2
    b = 1
    c = 3

    d = 0
    e = 9
    f = 24

    def getFormatString(self):
        """
        Returns the print format.
        """
        return ['x0r', 'y0r', 'z0r',
                'x1r', 'y1r', 'z1r',
                'x2r', 'y2r', 'z2r',
                'x3r', 'y3r', 'z3r',
                'rw']

    def createSTP(self, stp_filename, parameters):
        """
        Creates an STP file to find a differential trail for Gimli with
        the given parameters.
        """
        wordsize = parameters["wordsize"]
        rounds = parameters["rounds"]
        weight = parameters["sweight"]

        if "rotationconstants" in parameters:
            self.d = parameters["rotationconstants"][0]
            self.e = parameters["rotationconstants"][1]
            self.f = parameters["rotationconstants"][2]


        with open(stp_filename, 'w') as stp_file:
            stp_file.write("% Input File for STP\n% Gimli w={}"
                           "rounds={}\n\n\n".format(wordsize, rounds))

            # Setup variables
            x = ["x{}r{}".format(j, i) for i in range(rounds + 1) for j in range(4)]
            xsb = ["xsb{}r{}".format(j, i) for i in range(rounds) for j in range(4)]
            y = ["y{}r{}".format(j, i) for i in range(rounds + 1) for j in range(4)]
            ysb = ["ysb{}r{}".format(j, i) for i in range(rounds) for j in range(4)]
            z = ["z{}r{}".format(j, i) for i in range(rounds + 1) for j in range(4)]
            zsb = ["zsb{}r{}".format(j, i) for i in range(rounds + 1) for j in range(4)]
            w = ["rw{}".format(i) for i in range(rounds)]
            wp = ["rwp{}r{}".format(j, i) for i in range(rounds) for j in range(4)]

            xtmp = ["xtmp{}r{}".format(j, i) for i in range(rounds) for j in range(4)]
            ytmp = ["ytmp{}r{}".format(j, i) for i in range(rounds) for j in range(4)]
            ztmp = ["ztmp{}r{}".format(j, i) for i in range(rounds) for j in range(4)]

            stpcommands.setupVariables(stp_file, x, wordsize)
            stpcommands.setupVariables(stp_file, y, wordsize)
            stpcommands.setupVariables(stp_file, z, wordsize)
            stpcommands.setupVariables(stp_file, xtmp, wordsize)
            stpcommands.setupVariables(stp_file, ytmp, wordsize)
            stpcommands.setupVariables(stp_file, ztmp, wordsize)
            stpcommands.setupVariables(stp_file, xsb, wordsize)
            stpcommands.setupVariables(stp_file, ysb, wordsize)
            stpcommands.setupVariables(stp_file, zsb, wordsize)
            stpcommands.setupVariables(stp_file, wp, wordsize)
            stpcommands.setupVariables(stp_file, w, 16)

            for rnd in range(rounds):
                stp_file.write(stpcommands.getWeightString(wp[4*rnd:4*rnd + 4], 
                               wordsize, 0, w[rnd]) + "\n")

            stpcommands.setupWeightComputationSum(stp_file, weight, w, wordsize)

            # Rounds
            for rnd in range(rounds):
                if ((rnd) & 3) == 0:
                    # Small Swap
                    for perm in range(4):
                        self.setupRound(stp_file,
                                        x[4*rnd + perm],
                                        y[4*rnd + perm],
                                        z[4*rnd + perm],
                                        xtmp[4*rnd + perm],
                                        ytmp[4*rnd + perm],
                                        ztmp[4*rnd + perm],
                                        xsb[4*rnd + perm],
                                        ysb[4*rnd + perm],
                                        zsb[4*rnd + perm],
                                        wp[4*rnd + perm],
                                        wordsize)

                    stp_file.write("ASSERT({} = {});\n".format(x[4*(rnd + 1)], xtmp[4*rnd + 1]))
                    stp_file.write("ASSERT({} = {});\n".format(y[4*(rnd + 1)], ytmp[4*rnd]))
                    stp_file.write("ASSERT({} = {});\n".format(z[4*(rnd + 1)], ztmp[4*rnd]))

                    stp_file.write("ASSERT({} = {});\n".format(x[4*(rnd + 1) + 1], xtmp[4*rnd]))
                    stp_file.write("ASSERT({} = {});\n".format(y[4*(rnd + 1) + 1], ytmp[4*rnd + 1]))
                    stp_file.write("ASSERT({} = {});\n".format(z[4*(rnd + 1) + 1], ztmp[4*rnd + 1]))

                    stp_file.write("ASSERT({} = {});\n".format(x[4*(rnd + 1) + 2], xtmp[4*rnd + 3]))
                    stp_file.write("ASSERT({} = {});\n".format(y[4*(rnd + 1) + 2], ytmp[4*rnd + 2]))
                    stp_file.write("ASSERT({} = {});\n".format(z[4*(rnd + 1) + 2], ztmp[4*rnd + 2]))

                    stp_file.write("ASSERT({} = {});\n".format(x[4*(rnd + 1) + 3], xtmp[4*rnd + 2]))
                    stp_file.write("ASSERT({} = {});\n".format(y[4*(rnd + 1) + 3], ytmp[4*rnd + 3]))
                    stp_file.write("ASSERT({} = {});\n".format(z[4*(rnd + 1) + 3], ztmp[4*rnd + 3]))

                elif ((rnd) & 3) == 2:
                    # Big Swap
                    for perm in range(4):
                        self.setupRound(stp_file,
                                        x[4*rnd + perm],
                                        y[4*rnd + perm],
                                        z[4*rnd + perm],
                                        xtmp[4*rnd + perm],
                                        ytmp[4*rnd + perm],
                                        ztmp[4*rnd + perm],
                                        xsb[4*rnd + perm],
                                        ysb[4*rnd + perm],
                                        zsb[4*rnd + perm],
                                        wp[4*rnd + perm],
                                        wordsize)

                    stp_file.write("ASSERT({} = {});\n".format(x[4*(rnd + 1)], xtmp[4*rnd + 2]))
                    stp_file.write("ASSERT({} = {});\n".format(y[4*(rnd + 1)], ytmp[4*rnd]))
                    stp_file.write("ASSERT({} = {});\n".format(z[4*(rnd + 1)], ztmp[4*rnd]))

                    stp_file.write("ASSERT({} = {});\n".format(x[4*(rnd + 1) + 1], xtmp[4*rnd + 3]))
                    stp_file.write("ASSERT({} = {});\n".format(y[4*(rnd + 1) + 1], ytmp[4*rnd + 1]))
                    stp_file.write("ASSERT({} = {});\n".format(z[4*(rnd + 1) + 1], ztmp[4*rnd + 1]))

                    stp_file.write("ASSERT({} = {});\n".format(x[4*(rnd + 1) + 2], xtmp[4*rnd]))
                    stp_file.write("ASSERT({} = {});\n".format(y[4*(rnd + 1) + 2], ytmp[4*rnd + 2]))
                    stp_file.write("ASSERT({} = {});\n".format(z[4*(rnd + 1) + 2], ztmp[4*rnd + 2]))

                    stp_file.write("ASSERT({} = {});\n".format(x[4*(rnd + 1) + 3], xtmp[4*rnd + 1]))
                    stp_file.write("ASSERT({} = {});\n".format(y[4*(rnd + 1) + 3], ytmp[4*rnd + 3]))
                    stp_file.write("ASSERT({} = {});\n".format(z[4*(rnd + 1) + 3], ztmp[4*rnd + 3]))
                else:
                    # No Swap
                    for perm in range(4):
                        self.setupRound(stp_file,
                                        x[4*rnd + perm],
                                        y[4*rnd + perm],
                                        z[4*rnd + perm],
                                        x[4*(rnd + 1) + perm],
                                        y[4*(rnd + 1) + perm],
                                        z[4*(rnd + 1) + perm],
                                        xsb[4*rnd + perm],
                                        ysb[4*rnd + perm],
                                        zsb[4*rnd + perm],
                                        wp[4*rnd + perm],
                                        wordsize)


            # No all zero characteristic
            stpcommands.assertNonZero(stp_file, x + y + z, wordsize)

            for key, value in parameters["fixedVariables"].items():
                stpcommands.assertVariableValue(stp_file, key, value)

            for char in parameters["blockedCharacteristics"]:
                stpcommands.blockCharacteristic(stp_file, char, wordsize)

            stpcommands.setupQuery(stp_file)

        return

    def setupRound(self, stp_file, xin, yin, zin, xout, yout, zout,
                   xsb, ysb, zsb, w, wordsize):
        """
        Gimli round:
            x = (x xor (z << 1) xor (y & z) << a) <<< d
            y = (y xor x xor (x | z) << b) <<< e
            z = (y xor z xor (x & y) << c) <<< f
        """
        command = ""

        # Conditions for non-linear layer
        xnl = "({} & ~({}|{}))".format(xsb, yin, zin)
        ynl = "({} & ~({}|{}))".format(ysb, xin, zin)
        znl = "({} & ~({}|{}))".format(zsb, xin, yin)

        command += "ASSERT(({} | {} | {}) = 0x{});\n".format(xnl, ynl, znl, "0" * (wordsize // 4))

        # Dependency between bits
        # (x & y & ~z) & ~(xout ^ yout)
        xcond = "(({} & {} & ~{}) & ~(BVXOR({}, {})))".format(xin, yin, zin, xsb, ysb)
        # (x & ~y & z) & (xout ^ zout)
        ycond = "(({} & ~{} & {}) & (BVXOR({}, {})))".format(xin, yin, zin, xsb, zsb)
        # (~x & y & z) & ~(yout ^ zout)
        zcond = "((~{} & {} & {}) & ~(BVXOR({}, {})))".format(xin, yin, zin, ysb, zsb)
        # (x & y & z) & (~(xout ^ yout ^ zout))
        fcond = "(({} & {} & {}) & ~(BVXOR(BVXOR({}, {}), {})))".format(xin, yin, zin, xsb, ysb, zsb)
        command += "ASSERT(({} | {} | {} | {}) = 0x{});\n".format(xcond, ycond, zcond, fcond, "0" * (wordsize // 4))

        xshift = "BVXOR({0}, BVXOR(({1} << 1)[{4}:0], ({2} << {3})[{4}:0]))".format(xin, zin, xsb, self.a, wordsize - 1)
        command += "ASSERT({} = {});\n".format(zout, rotl(xshift, self.d, wordsize))

        yshift = "BVXOR({}, BVXOR({}, ({} << {})[{}:0]))".format(yin, xin, ysb, self.b, wordsize - 1)
        command += "ASSERT({} = {});\n".format(yout, rotl(yshift, self.e, wordsize))

        zshift = "BVXOR({}, BVXOR({}, ({} << {})[{}:0]))".format(zin, yin, zsb, self.c, wordsize - 1)
        command += "ASSERT({} = {});\n".format(xout, rotl(zshift, self.f, wordsize))

        # Probability
        wxtmp = "((((({0} | {1}) << {2})[{3}:0]) >> {2})[{3}:0])".format(yin, zin, self.a, wordsize - 1)
        wytmp = "((((({0} | {1}) << {2})[{3}:0]) >> {2})[{3}:0])".format(xin, zin, self.b, wordsize - 1)
        wztmp = "((((({0} | {1}) << {2})[{3}:0]) >> {2})[{3}:0])".format(xin, yin, self.c, wordsize - 1)

        command += "ASSERT({0} = ({1} | {2} | {3}));\n".format(w, wxtmp, wytmp, wztmp)


        stp_file.write(command)
        return
