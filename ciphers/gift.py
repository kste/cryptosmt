'''
Created on Jun 28, 2017

@author: ralph
'''

from parser import stpcommands
from ciphers.cipher import AbstractCipher


class GiftCipher(AbstractCipher):
    """
    Represents the differential behaviour of GIFT and can be used
    to find differential characteristics for the given parameters.
    """

    name = "gift"

    def getFormatString(self):
        """
        Returns the print format.
        """
        return ['SC', 'PB', 'w']

    def createSTP(self, stp_filename, parameters):
        """
        Creates an STP file to find a characteristic for GIFT with
        the given parameters.
        """

        wordsize = parameters["wordsize"]
        rounds = parameters["rounds"]
        weight = parameters["sweight"]

        with open(stp_filename, 'w') as stp_file:
            header = ("% Input File for STP\n% GIFT w={}"
                      "rounds={}\n\n\n".format(wordsize, rounds))
            stp_file.write(header)

            # Setup variables
            sc = ["SC{}".format(i) for i in range(rounds + 1)]
            pb = ["PB{}".format(i) for i in range(rounds)]

            # w = weight
            w = ["w{}".format(i) for i in range(rounds)]

            stpcommands.setupVariables(stp_file, sc, wordsize)
            stpcommands.setupVariables(stp_file, pb, wordsize)
            stpcommands.setupVariables(stp_file, w, wordsize)

            stpcommands.setupWeightComputation(stp_file, weight, w, wordsize)

            for i in range(rounds):
                self.setupGiftRound(stp_file, sc[i], pb[i], sc[i+1], 
                                    w[i], wordsize)

            # No all zero characteristic
            stpcommands.assertNonZero(stp_file, sc, wordsize)

            # Iterative characteristics only
            # Input difference = Output difference
            if parameters["iterative"]:
                stpcommands.assertVariableValue(stp_file, sc[0], sc[rounds])

            for key, value in parameters["fixedVariables"].items():
                stpcommands.assertVariableValue(stp_file, key, value)

            for char in parameters["blockedCharacteristics"]:
                stpcommands.blockCharacteristic(stp_file, char, wordsize)

            stpcommands.setupQuery(stp_file)

        return

    def setupGiftRound(self, stp_file, s_in, p, s_out, w, wordsize):
        """
        Model for differential behaviour of one round GIFT
        """
        command = ""

        #Permutation Layer
        if wordsize == 64:
            command += "ASSERT({0}[0:0] = {1}[0:0]);\n".format(s_out, p)    #0
            command += "ASSERT({0}[17:17] = {1}[1:1]);\n".format(s_out, p)    #1
            command += "ASSERT({0}[34:34] = {1}[2:2]);\n".format(s_out, p)    #2
            command += "ASSERT({0}[51:51] = {1}[3:3]);\n".format(s_out, p)    #3
            command += "ASSERT({0}[48:48] = {1}[4:4]);\n".format(s_out, p)    #4
            command += "ASSERT({0}[1:1] = {1}[5:5]);\n".format(s_out, p)    #5
            command += "ASSERT({0}[18:18] = {1}[6:6]);\n".format(s_out, p)    #6
            command += "ASSERT({0}[35:35] = {1}[7:7]);\n".format(s_out, p)    #7
            command += "ASSERT({0}[32:32] = {1}[8:8]);\n".format(s_out, p)    #8
            command += "ASSERT({0}[49:49] = {1}[9:9]);\n".format(s_out, p)    #9
            command += "ASSERT({0}[2:2] = {1}[10:10]);\n".format(s_out, p)    #10
            command += "ASSERT({0}[19:19] = {1}[11:11]);\n".format(s_out, p)    #11
            command += "ASSERT({0}[16:16] = {1}[12:12]);\n".format(s_out, p)    #12
            command += "ASSERT({0}[33:33] = {1}[13:13]);\n".format(s_out, p)    #13
            command += "ASSERT({0}[50:50] = {1}[14:14]);\n".format(s_out, p)    #14
            command += "ASSERT({0}[3:3] = {1}[15:15]);\n".format(s_out, p)    #15

            command += "ASSERT({0}[4:4] = {1}[16:16]);\n".format(s_out, p)    #16
            command += "ASSERT({0}[21:21] = {1}[17:17]);\n".format(s_out, p)    #17
            command += "ASSERT({0}[38:38] = {1}[18:18]);\n".format(s_out, p)    #18
            command += "ASSERT({0}[55:55] = {1}[19:19]);\n".format(s_out, p)    #19
            command += "ASSERT({0}[52:52] = {1}[20:20]);\n".format(s_out, p)    #20
            command += "ASSERT({0}[5:5] = {1}[21:21]);\n".format(s_out, p)    #21
            command += "ASSERT({0}[22:22] = {1}[22:22]);\n".format(s_out, p)    #22
            command += "ASSERT({0}[39:39] = {1}[23:23]);\n".format(s_out, p)    #23
            command += "ASSERT({0}[36:36] = {1}[24:24]);\n".format(s_out, p)    #24
            command += "ASSERT({0}[53:53] = {1}[25:25]);\n".format(s_out, p)    #25
            command += "ASSERT({0}[6:6] = {1}[26:26]);\n".format(s_out, p)    #26
            command += "ASSERT({0}[23:23] = {1}[27:27]);\n".format(s_out, p)    #27
            command += "ASSERT({0}[20:20] = {1}[28:28]);\n".format(s_out, p)    #28
            command += "ASSERT({0}[37:37] = {1}[29:29]);\n".format(s_out, p)    #29
            command += "ASSERT({0}[54:54] = {1}[30:30]);\n".format(s_out, p)    #30
            command += "ASSERT({0}[7:7] = {1}[31:31]);\n".format(s_out, p)    #31
            
            command += "ASSERT({0}[8:8] = {1}[32:32]);\n".format(s_out, p)    #32
            command += "ASSERT({0}[25:25] = {1}[33:33]);\n".format(s_out, p)    #33
            command += "ASSERT({0}[42:42] = {1}[34:34]);\n".format(s_out, p)    #34
            command += "ASSERT({0}[59:59] = {1}[35:35]);\n".format(s_out, p)    #35
            command += "ASSERT({0}[56:56] = {1}[36:36]);\n".format(s_out, p)    #36
            command += "ASSERT({0}[9:9] = {1}[37:37]);\n".format(s_out, p)    #37
            command += "ASSERT({0}[26:26] = {1}[38:38]);\n".format(s_out, p)    #38
            command += "ASSERT({0}[43:43] = {1}[39:39]);\n".format(s_out, p)    #39
            command += "ASSERT({0}[40:40] = {1}[40:40]);\n".format(s_out, p)    #40
            command += "ASSERT({0}[57:57] = {1}[41:41]);\n".format(s_out, p)    #41
            command += "ASSERT({0}[10:10] = {1}[42:42]);\n".format(s_out, p)    #42
            command += "ASSERT({0}[27:27] = {1}[43:43]);\n".format(s_out, p)    #43
            command += "ASSERT({0}[24:24] = {1}[44:44]);\n".format(s_out, p)    #44
            command += "ASSERT({0}[41:41] = {1}[45:45]);\n".format(s_out, p)    #45
            command += "ASSERT({0}[58:58] = {1}[46:46]);\n".format(s_out, p)    #46
            command += "ASSERT({0}[11:11] = {1}[47:47]);\n".format(s_out, p)    #47

            command += "ASSERT({0}[12:12] = {1}[48:48]);\n".format(s_out, p)    #48
            command += "ASSERT({0}[29:29] = {1}[49:49]);\n".format(s_out, p)    #49
            command += "ASSERT({0}[46:46] = {1}[50:50]);\n".format(s_out, p)    #50
            command += "ASSERT({0}[63:63] = {1}[51:51]);\n".format(s_out, p)    #51
            command += "ASSERT({0}[60:60] = {1}[52:52]);\n".format(s_out, p)    #52
            command += "ASSERT({0}[13:13] = {1}[53:53]);\n".format(s_out, p)    #53
            command += "ASSERT({0}[30:30] = {1}[54:54]);\n".format(s_out, p)    #54
            command += "ASSERT({0}[47:47] = {1}[55:55]);\n".format(s_out, p)    #55
            command += "ASSERT({0}[44:44] = {1}[56:56]);\n".format(s_out, p)    #56
            command += "ASSERT({0}[61:61] = {1}[57:57]);\n".format(s_out, p)    #57
            command += "ASSERT({0}[14:14] = {1}[58:58]);\n".format(s_out, p)    #58
            command += "ASSERT({0}[31:31] = {1}[59:59]);\n".format(s_out, p)    #59
            command += "ASSERT({0}[28:28] = {1}[60:60]);\n".format(s_out, p)    #60
            command += "ASSERT({0}[45:45] = {1}[61:61]);\n".format(s_out, p)    #61
            command += "ASSERT({0}[62:62] = {1}[62:62]);\n".format(s_out, p)    #62
            command += "ASSERT({0}[15:15] = {1}[63:63]);\n".format(s_out, p)    #63
        elif wordsize == 128:
            command += "ASSERT({0}[0:0] = {1}[0:0]);\n".format(s_out, p)    #0
            command += "ASSERT({0}[33:33] = {1}[1:1]);\n".format(s_out, p)    #1
            command += "ASSERT({0}[66:66] = {1}[2:2]);\n".format(s_out, p)    #2
            command += "ASSERT({0}[99:99] = {1}[3:3]);\n".format(s_out, p)    #3
            command += "ASSERT({0}[96:96] = {1}[4:4]);\n".format(s_out, p)    #4
            command += "ASSERT({0}[1:1] = {1}[5:5]);\n".format(s_out, p)    #5
            command += "ASSERT({0}[34:34] = {1}[6:6]);\n".format(s_out, p)    #6
            command += "ASSERT({0}[67:67] = {1}[7:7]);\n".format(s_out, p)    #7
            command += "ASSERT({0}[64:64] = {1}[8:8]);\n".format(s_out, p)    #8
            command += "ASSERT({0}[97:97] = {1}[9:9]);\n".format(s_out, p)    #9
            command += "ASSERT({0}[2:2] = {1}[10:10]);\n".format(s_out, p)    #10
            command += "ASSERT({0}[35:35] = {1}[11:11]);\n".format(s_out, p)    #11
            command += "ASSERT({0}[32:32] = {1}[12:12]);\n".format(s_out, p)    #12
            command += "ASSERT({0}[65:65] = {1}[13:13]);\n".format(s_out, p)    #13
            command += "ASSERT({0}[98:98] = {1}[14:14]);\n".format(s_out, p)    #14
            command += "ASSERT({0}[3:3] = {1}[15:15]);\n".format(s_out, p)    #15

            command += "ASSERT({0}[4:4] = {1}[16:16]);\n".format(s_out, p)    #16
            command += "ASSERT({0}[37:37] = {1}[17:17]);\n".format(s_out, p)    #17
            command += "ASSERT({0}[70:70] = {1}[18:18]);\n".format(s_out, p)    #18
            command += "ASSERT({0}[103:103] = {1}[19:19]);\n".format(s_out, p)    #19
            command += "ASSERT({0}[100:100] = {1}[20:20]);\n".format(s_out, p)    #20
            command += "ASSERT({0}[5:5] = {1}[21:21]);\n".format(s_out, p)    #21
            command += "ASSERT({0}[38:38] = {1}[22:22]);\n".format(s_out, p)    #22
            command += "ASSERT({0}[71:71] = {1}[23:23]);\n".format(s_out, p)    #23
            command += "ASSERT({0}[68:68] = {1}[24:24]);\n".format(s_out, p)    #24
            command += "ASSERT({0}[101:101] = {1}[25:25]);\n".format(s_out, p)    #25
            command += "ASSERT({0}[6:6] = {1}[26:26]);\n".format(s_out, p)    #26
            command += "ASSERT({0}[39:39] = {1}[27:27]);\n".format(s_out, p)    #27
            command += "ASSERT({0}[36:36] = {1}[28:28]);\n".format(s_out, p)    #28
            command += "ASSERT({0}[69:69] = {1}[29:29]);\n".format(s_out, p)    #29
            command += "ASSERT({0}[102:102] = {1}[30:30]);\n".format(s_out, p)    #30
            command += "ASSERT({0}[7:7] = {1}[31:31]);\n".format(s_out, p)    #31
            
            command += "ASSERT({0}[8:8] = {1}[32:32]);\n".format(s_out, p)    #32
            command += "ASSERT({0}[41:41] = {1}[33:33]);\n".format(s_out, p)    #33
            command += "ASSERT({0}[74:74] = {1}[34:34]);\n".format(s_out, p)    #34
            command += "ASSERT({0}[107:107] = {1}[35:35]);\n".format(s_out, p)    #35
            command += "ASSERT({0}[104:104] = {1}[36:36]);\n".format(s_out, p)    #36
            command += "ASSERT({0}[9:9] = {1}[37:37]);\n".format(s_out, p)    #37
            command += "ASSERT({0}[42:42] = {1}[38:38]);\n".format(s_out, p)    #38
            command += "ASSERT({0}[75:75] = {1}[39:39]);\n".format(s_out, p)    #39
            command += "ASSERT({0}[72:72] = {1}[40:40]);\n".format(s_out, p)    #40
            command += "ASSERT({0}[105:105] = {1}[41:41]);\n".format(s_out, p)    #41
            command += "ASSERT({0}[10:10] = {1}[42:42]);\n".format(s_out, p)    #42
            command += "ASSERT({0}[43:43] = {1}[43:43]);\n".format(s_out, p)    #43
            command += "ASSERT({0}[40:40] = {1}[44:44]);\n".format(s_out, p)    #44
            command += "ASSERT({0}[73:73] = {1}[45:45]);\n".format(s_out, p)    #45
            command += "ASSERT({0}[106:106] = {1}[46:46]);\n".format(s_out, p)    #46
            command += "ASSERT({0}[11:11] = {1}[47:47]);\n".format(s_out, p)    #47

            command += "ASSERT({0}[12:12] = {1}[48:48]);\n".format(s_out, p)    #48
            command += "ASSERT({0}[45:45] = {1}[49:49]);\n".format(s_out, p)    #49
            command += "ASSERT({0}[78:78] = {1}[50:50]);\n".format(s_out, p)    #50
            command += "ASSERT({0}[111:111] = {1}[51:51]);\n".format(s_out, p)    #51
            command += "ASSERT({0}[108:108] = {1}[52:52]);\n".format(s_out, p)    #52
            command += "ASSERT({0}[13:13] = {1}[53:53]);\n".format(s_out, p)    #53
            command += "ASSERT({0}[46:46] = {1}[54:54]);\n".format(s_out, p)    #54
            command += "ASSERT({0}[79:79] = {1}[55:55]);\n".format(s_out, p)    #55
            command += "ASSERT({0}[76:76] = {1}[56:56]);\n".format(s_out, p)    #56
            command += "ASSERT({0}[109:109] = {1}[57:57]);\n".format(s_out, p)    #57
            command += "ASSERT({0}[14:14] = {1}[58:58]);\n".format(s_out, p)    #58
            command += "ASSERT({0}[47:47] = {1}[59:59]);\n".format(s_out, p)    #59
            command += "ASSERT({0}[44:44] = {1}[60:60]);\n".format(s_out, p)    #60
            command += "ASSERT({0}[77:77] = {1}[61:61]);\n".format(s_out, p)    #61
            command += "ASSERT({0}[110:110] = {1}[62:62]);\n".format(s_out, p)    #62
            command += "ASSERT({0}[15:15] = {1}[63:63]);\n".format(s_out, p)    #63

            command += "ASSERT({0}[16:16] = {1}[64:64]);\n".format(s_out, p)    #64
            command += "ASSERT({0}[49:49] = {1}[65:65]);\n".format(s_out, p)    #65
            command += "ASSERT({0}[82:82] = {1}[66:66]);\n".format(s_out, p)    #66
            command += "ASSERT({0}[115:115] = {1}[67:67]);\n".format(s_out, p)    #67
            command += "ASSERT({0}[112:112] = {1}[68:68]);\n".format(s_out, p)    #68
            command += "ASSERT({0}[17:17] = {1}[69:69]);\n".format(s_out, p)    #69
            command += "ASSERT({0}[50:50] = {1}[70:70]);\n".format(s_out, p)    #70
            command += "ASSERT({0}[83:83] = {1}[71:71]);\n".format(s_out, p)    #71
            command += "ASSERT({0}[80:80] = {1}[72:72]);\n".format(s_out, p)    #72
            command += "ASSERT({0}[113:113] = {1}[73:73]);\n".format(s_out, p)    #73
            command += "ASSERT({0}[18:18] = {1}[74:74]);\n".format(s_out, p)    #74
            command += "ASSERT({0}[51:51] = {1}[75:75]);\n".format(s_out, p)    #75
            command += "ASSERT({0}[48:48] = {1}[76:76]);\n".format(s_out, p)    #76
            command += "ASSERT({0}[81:81] = {1}[77:77]);\n".format(s_out, p)    #77
            command += "ASSERT({0}[114:114] = {1}[78:78]);\n".format(s_out, p)    #78
            command += "ASSERT({0}[19:19] = {1}[79:79]);\n".format(s_out, p)    #79

            command += "ASSERT({0}[20:20] = {1}[80:80]);\n".format(s_out, p)    #80
            command += "ASSERT({0}[53:53] = {1}[81:81]);\n".format(s_out, p)    #81
            command += "ASSERT({0}[86:86] = {1}[82:82]);\n".format(s_out, p)    #82
            command += "ASSERT({0}[119:119] = {1}[83:83]);\n".format(s_out, p)    #83
            command += "ASSERT({0}[116:116] = {1}[84:84]);\n".format(s_out, p)    #84
            command += "ASSERT({0}[21:21] = {1}[85:85]);\n".format(s_out, p)    #85
            command += "ASSERT({0}[54:54] = {1}[86:86]);\n".format(s_out, p)    #86
            command += "ASSERT({0}[87:87] = {1}[87:87]);\n".format(s_out, p)    #87
            command += "ASSERT({0}[84:84] = {1}[88:88]);\n".format(s_out, p)    #88
            command += "ASSERT({0}[117:117] = {1}[89:89]);\n".format(s_out, p)    #89
            command += "ASSERT({0}[22:22] = {1}[90:90]);\n".format(s_out, p)    #90
            command += "ASSERT({0}[55:55] = {1}[91:91]);\n".format(s_out, p)    #91
            command += "ASSERT({0}[52:52] = {1}[92:92]);\n".format(s_out, p)    #92
            command += "ASSERT({0}[85:85] = {1}[93:93]);\n".format(s_out, p)    #93
            command += "ASSERT({0}[118:118] = {1}[94:94]);\n".format(s_out, p)    #94
            command += "ASSERT({0}[23:23] = {1}[95:95]);\n".format(s_out, p)    #95
            
            command += "ASSERT({0}[24:24] = {1}[96:96]);\n".format(s_out, p)    #96
            command += "ASSERT({0}[57:57] = {1}[97:97]);\n".format(s_out, p)    #97
            command += "ASSERT({0}[90:90] = {1}[98:98]);\n".format(s_out, p)    #98
            command += "ASSERT({0}[123:123] = {1}[99:99]);\n".format(s_out, p)    #99
            command += "ASSERT({0}[120:120] = {1}[100:100]);\n".format(s_out, p)    #100
            command += "ASSERT({0}[25:25] = {1}[101:101]);\n".format(s_out, p)    #101
            command += "ASSERT({0}[58:58] = {1}[102:102]);\n".format(s_out, p)    #102
            command += "ASSERT({0}[91:91] = {1}[103:103]);\n".format(s_out, p)    #103
            command += "ASSERT({0}[88:88] = {1}[104:104]);\n".format(s_out, p)    #104
            command += "ASSERT({0}[121:121] = {1}[105:105]);\n".format(s_out, p)    #105
            command += "ASSERT({0}[26:26] = {1}[106:106]);\n".format(s_out, p)    #106
            command += "ASSERT({0}[59:59] = {1}[107:107]);\n".format(s_out, p)    #107
            command += "ASSERT({0}[56:56] = {1}[108:108]);\n".format(s_out, p)    #108
            command += "ASSERT({0}[89:89] = {1}[109:109]);\n".format(s_out, p)    #109
            command += "ASSERT({0}[122:122] = {1}[110:110]);\n".format(s_out, p)    #110
            command += "ASSERT({0}[27:27] = {1}[111:111]);\n".format(s_out, p)    #111

            command += "ASSERT({0}[28:28] = {1}[112:112]);\n".format(s_out, p)    #112
            command += "ASSERT({0}[61:61] = {1}[113:113]);\n".format(s_out, p)    #113
            command += "ASSERT({0}[94:94] = {1}[114:114]);\n".format(s_out, p)    #114
            command += "ASSERT({0}[127:127] = {1}[115:115]);\n".format(s_out, p)    #115
            command += "ASSERT({0}[124:124] = {1}[116:116]);\n".format(s_out, p)    #116
            command += "ASSERT({0}[29:29] = {1}[117:117]);\n".format(s_out, p)    #117
            command += "ASSERT({0}[62:62] = {1}[118:118]);\n".format(s_out, p)    #118
            command += "ASSERT({0}[95:95] = {1}[119:119]);\n".format(s_out, p)    #119
            command += "ASSERT({0}[92:92] = {1}[120:120]);\n".format(s_out, p)    #120
            command += "ASSERT({0}[125:125] = {1}[121:121]);\n".format(s_out, p)    #121
            command += "ASSERT({0}[30:30] = {1}[122:122]);\n".format(s_out, p)    #122
            command += "ASSERT({0}[63:63] = {1}[123:123]);\n".format(s_out, p)    #123
            command += "ASSERT({0}[60:60] = {1}[124:124]);\n".format(s_out, p)    #124
            command += "ASSERT({0}[93:93] = {1}[125:125]);\n".format(s_out, p)    #125
            command += "ASSERT({0}[126:126] = {1}[126:126]);\n".format(s_out, p)    #126
            command += "ASSERT({0}[31:31] = {1}[127:127]);\n".format(s_out, p)    #127
        else:
            print("Only wordsize 64/128 bit supported!")
            exit(1)


        # Substitution Layer
        gift_sbox = [0x1, 0xa, 0x4, 0xc, 0x6, 0xf, 0x3, 0x9, 0x2, 0xd, 0xb, 0x7, 0x5, 0x0, 0x8, 0xe]

        nrOfSboxes = 0
        if wordsize == 64:
            nrOfSboxes = 16
        elif wordsize == 128:
            nrOfSboxes = 32
        else:
            print("Only wordsize 64/128 bit supported!")
            exit(1)

        for i in range(nrOfSboxes):
            variables = ["{0}[{1}:{1}]".format(s_in, 4*i + 3),
                         "{0}[{1}:{1}]".format(s_in, 4*i + 2),
                         "{0}[{1}:{1}]".format(s_in, 4*i + 1),
                         "{0}[{1}:{1}]".format(s_in, 4*i + 0),
                         "{0}[{1}:{1}]".format(p, 4*i + 3),
                         "{0}[{1}:{1}]".format(p, 4*i + 2),
                         "{0}[{1}:{1}]".format(p, 4*i + 1),
                         "{0}[{1}:{1}]".format(p, 4*i + 0),
                         "{0}[{1}:{1}]".format(w, 4*i + 3),
                         "{0}[{1}:{1}]".format(w, 4*i + 2),
                         "{0}[{1}:{1}]".format(w, 4*i + 1),
                         "{0}[{1}:{1}]".format(w, 4*i + 0)]
            command += stpcommands.add4bitSbox(gift_sbox, variables)

        stp_file.write(command)
        return
