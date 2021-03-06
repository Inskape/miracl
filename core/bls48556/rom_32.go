// +build 386 amd64p32 arm armbe mips mips64p32 mips64p32le mipsle ppc riscv s390 sparc

/*
 * Copyright (c) 2012-2020 MIRACL UK Ltd.
 *
 * This file is part of MIRACL Core
 * (see https://github.com/miracl/core).
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

/* Fixed Data in ROM - Field and Curve parameters */

package bls48556

// Base Bits= 29
var Modulus = [...]Chunk{0x1CF6AC0B, 0x17B7307F, 0x19877E7B, 0x12CE0134, 0x14228402, 0x1BD4C386, 0x1DACBB04, 0x40410D0, 0x25A415, 0x980B53E, 0xDE6E250, 0x15D9AAD6, 0x5DA950, 0x1029B7A, 0x54AB351, 0x14AD90CE, 0x3729047, 0x1FE7E2D9, 0x145F610B, 0x1F}
var ROI = [...]Chunk{0x1CF6AC0A, 0x17B7307F, 0x19877E7B, 0x12CE0134, 0x14228402, 0x1BD4C386, 0x1DACBB04, 0x40410D0, 0x25A415, 0x980B53E, 0xDE6E250, 0x15D9AAD6, 0x5DA950, 0x1029B7A, 0x54AB351, 0x14AD90CE, 0x3729047, 0x1FE7E2D9, 0x145F610B, 0x1F}
var R2modp = [...]Chunk{0xD59D0FA, 0x12F01FD0, 0xDE8FD41, 0x35AAEE1, 0xB937F48, 0x50700E8, 0x1F50EFCE, 0x1019B13C, 0x3470A2F, 0x11094115, 0xF9FB72D, 0x6AD10E2, 0x1CFD9F8, 0x44F4785, 0x2B48793, 0x1148ED3, 0xF609E61, 0x1EE34BC7, 0x1735D29E, 0x0}
var SQRTm3 = [...]Chunk{0x1C809C48, 0xBADB766, 0xF42444, 0xBE2770, 0x11ED8E73, 0xD0778E1, 0x181513CC, 0x1E2CA1BF, 0x16C1D444, 0x8FA557B, 0x84DE4E8, 0xD3F7861, 0x1F82EC76, 0x1D36FF74, 0xCDB7E79, 0xC1AFE32, 0x1D0263A7, 0x17E70F58, 0x145F60DB, 0x1F}

const MConst Chunk = 0x9DA805D

var TWK = [...]Chunk{0x16F9937, 0x9133D51, 0xD89F92B, 0x17A682C, 0x16600368, 0x1830F509, 0x1531266E, 0x159D972D, 0x1C269C72, 0x46E0687, 0xCAA903, 0x1EEF4D3A, 0xED502F8, 0x1046B2AB, 0x1EC6EF4F, 0xFD93805, 0x1EEEDD57, 0xD0AFF3F, 0xC83E724, 0x8}

var Fra = [...]Chunk{0x1325BF89, 0x1311E7EC, 0xCD0A56F, 0x1A0FD46E, 0xE83BCCA, 0xCA97DD0, 0x18D1D297, 0x5F1E137, 0x7AB9F2C, 0x13FC255F, 0x1C9DECEB, 0x9DEF4A2, 0x3C0F60B, 0x1D9909E4, 0x1FF27FF7, 0x1DBF8208, 0x89BB36C, 0x40044E0, 0x62E01EE, 0x5}
var Frb = [...]Chunk{0x1325BF89, 0x1311E7EC, 0xCD0A56F, 0x1A0FD46E, 0xE83BCCA, 0xCA97DD0, 0x18D1D297, 0x5F1E137, 0x7AB9F2C, 0x13FC255F, 0x1C9DECEB, 0x9DEF4A2, 0x3C0F60B, 0x1D9909E4, 0x1FF27FF7, 0x1DBF8208, 0x89BB36C, 0x40044E0, 0x62E01EE, 0x5}

const CURVE_Cof_I int = 0
const CURVE_B_I int = 17

var CURVE_B = [...]Chunk{0x11, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0}
var CURVE_Order = [...]Chunk{0x1, 0x17FFF800, 0xA769C21, 0x8AA813C, 0x2029C21, 0xA68F58B, 0xB6307F4, 0x1184DA51, 0x6DFED78, 0x1A3C85E9, 0x571037B, 0x1637F1F9, 0x1C465FB0, 0x98354B9, 0x118DF17A, 0x1422355D, 0x43BF73E, 0x6, 0x0, 0x0}
var CURVE_Gx = [...]Chunk{0x5D71D33, 0x1943697B, 0x18CB783F, 0x1B00AA9F, 0x1711EE0B, 0x7F80B23, 0x129FD8CC, 0x1345E03F, 0x9A80F66, 0x7038173, 0xC056511, 0x142801F5, 0x42B2C3A, 0x1AF09869, 0x7924166, 0x8381264, 0x957EDD7, 0xBACAEDC, 0xA27A4A1, 0x13}
var CURVE_Gy = [...]Chunk{0xA6ED83A, 0x14D2D9FF, 0xA29C33D, 0x1B8972A9, 0x6958677, 0x19C8F547, 0x1DED7E3E, 0x14F9E3DC, 0x18FB7229, 0x27171C0, 0x1551E32D, 0xE6184CC, 0x6260E3C, 0x733D204, 0x579C437, 0x1534665C, 0x2B3349D, 0x3162FD7, 0xB634253, 0x1}
var CURVE_HTPC = [...]Chunk{0x1, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0}

var CURVE_Bnx = [...]Chunk{0x1DE40020, 0x3, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0}
var CURVE_Cof = [...]Chunk{0x1DE4001F, 0x3, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0}

//var CURVE_Cof = [...]Chunk{0x1F12ABEB, 0x516887B, 0x5, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0}
var CRu = [...]Chunk{0xCBBA429, 0x1B273F3, 0xD3DD160, 0x19C61452, 0x308093A, 0x146E1E34, 0xAE0E768, 0x1185948, 0x1B73BC2D, 0x93D855C, 0x1B1A639C, 0x118C919B, 0xFF04AE3, 0xF1CCD77, 0x91318E5, 0x10644780, 0x3A79F7, 0x1BE77919, 0x145F60F3, 0x1F}
var CURVE_Pxaaa = [...]Chunk{0x923CE4A, 0x14697474, 0xAE04F4A, 0x17AE205A, 0x1313A20C, 0x10B2EC50, 0x18DF074F, 0x15FE3FE8, 0x7C90B98, 0x959BF85, 0xE57BD37, 0x14376C96, 0xBF57375, 0xE20B625, 0x12EE2172, 0x1CBBCE85, 0x1A5D9487, 0xD0E024B, 0x195E3602, 0x1C}
var CURVE_Pxaab = [...]Chunk{0xC0A1BE1, 0x138E6E2D, 0x1DF5FDC, 0x151FC760, 0x33972C5, 0x56AA3C2, 0x2491D8C, 0x115B9FD7, 0x140A11FA, 0x1873AE35, 0x1F259C26, 0x74B0647, 0x12D18B04, 0x4672431, 0x1C27F419, 0x1CAA4D35, 0x18DB48B6, 0x13A54BDA, 0x5080497, 0x5}
var CURVE_Pxaba = [...]Chunk{0x170C5DC4, 0x11D39263, 0x16B3BCB6, 0x152C95BB, 0x19BEC736, 0x8849A12, 0x49AB2A8, 0xC7162D3, 0xC58CD55, 0x15C2659, 0x11EE8B90, 0xB40CAFC, 0xE233167, 0x7BEC8BE, 0x129335BD, 0x151C7DBB, 0x78B689B, 0x1B6B8EED, 0x14BFBE3D, 0x16}
var CURVE_Pxabb = [...]Chunk{0x1A64B740, 0x6B14B34, 0x12481578, 0x23FA931, 0x323ADD1, 0x206B82A, 0xD789E1B, 0x1FCFA666, 0x1F4EEA7, 0xF1E39E2, 0x1968610, 0xAF3EBD3, 0x590D3B, 0xDA0C35A, 0x17306AAF, 0xCF9DD2B, 0x3F63B1A, 0x96FF2F9, 0xE102A76, 0x12}
var CURVE_Pxbaa = [...]Chunk{0x12F1E01F, 0xDD8630B, 0x12C29802, 0x186239A6, 0x19218788, 0x4C87D1, 0x16AE2501, 0x775C076, 0x870C80B, 0x1A394429, 0x1637D478, 0x4A420E8, 0x1C3AD4D4, 0x10E5E713, 0x111E6AD5, 0x514FCF0, 0x7CC49D3, 0xC678A2, 0x1787BDFD, 0x1B}
var CURVE_Pxbab = [...]Chunk{0x637383D, 0x1851C11C, 0x661F866, 0x14404A7F, 0x15D3D212, 0x9AE28F6, 0x8051F25, 0x1E1CE2BF, 0x137D882F, 0xB231CEB, 0xA8DB8FC, 0x18957645, 0x5E54DA8, 0x1FF41C44, 0x1A297414, 0x17E1CBC5, 0x1014F91F, 0x4282AB7, 0xB6CE9E3, 0x10}
var CURVE_Pxbba = [...]Chunk{0x1711939C, 0xB41ED9E, 0x69066BA, 0x137CA3AD, 0xCF2F6C0, 0x5E6DAB9, 0x2CE1323, 0x946E448, 0xF353D1C, 0x14D9919F, 0x46B7046, 0x1A12015, 0x3D6070, 0x18C3E8D2, 0x1F23BA45, 0x1F1A337C, 0x435A9CC, 0x6CA1DF1, 0x8A9CE1, 0x15}
var CURVE_Pxbbb = [...]Chunk{0x56F4899, 0x196A0854, 0xA959750, 0x38A3D72, 0x190BC9BC, 0x145752BC, 0x1E9E26DA, 0x1403F88, 0x71895E3, 0x14162F5D, 0x19FEC5FF, 0x14190B16, 0x7597C, 0x19A3CF18, 0x26A4B00, 0x113D1BB6, 0x7857A32, 0xE0B78AB, 0x1DD51E0F, 0x1B}
var CURVE_Pyaaa = [...]Chunk{0x14137844, 0x1704BE7D, 0x1FD3CCDD, 0x189D8C93, 0x1C768851, 0xF5C37D5, 0xE29C659, 0x20AB1C1, 0xF8896E0, 0x1E08663E, 0x1D1D539C, 0x117E1C47, 0x156CDD39, 0x161F1017, 0x143E8C72, 0x174B22FD, 0x18706190, 0x49AA47E, 0x19BB42E1, 0xE}
var CURVE_Pyaab = [...]Chunk{0xDC83190, 0x12F19247, 0x1AA26424, 0x15D55E88, 0xC418D32, 0xB0E91DD, 0x47CBFF7, 0x2D992C1, 0xDE03C1F, 0x7694AE5, 0x5C741A2, 0x1D423AC6, 0x5E02B9E, 0x1E903F10, 0x4EA6513, 0x433A1F1, 0x8EFA1C4, 0xED54713, 0x1E72CE4F, 0x4}
var CURVE_Pyaba = [...]Chunk{0x1985C0D, 0xEE2FE82, 0x64770FA, 0x11A809B4, 0x1483ACE9, 0x18BCD2FA, 0x171F32C, 0x1612D58D, 0x1E658341, 0x1CBE2201, 0x186E971, 0x73F0E1, 0xB0A5F40, 0xAC90FB0, 0x1635E008, 0x237498B, 0x1F3140D6, 0xBF789A9, 0x1166F259, 0x1A}
var CURVE_Pyabb = [...]Chunk{0x159D42F8, 0x1B7F0540, 0x45895D7, 0x14875FA2, 0x1E9E7F2B, 0x10139D87, 0x10F3FD7D, 0x11D3717F, 0x69E5006, 0xF9BB3C4, 0x13C9ED8D, 0x16516DA, 0x102F51DE, 0x2725FEC, 0x1F125B66, 0xFFC324, 0x1ED80731, 0x1C16C4D, 0x383AAA8, 0x14}
var CURVE_Pybaa = [...]Chunk{0x1F38039F, 0x6A8959C, 0x13C68984, 0x11DD12AF, 0x58093CF, 0x1C8550A0, 0xFFA1622, 0xFF85979, 0x1F2ABB75, 0x18862E62, 0x1EB6A2C9, 0x1EC80B64, 0x8EC2F18, 0xE7BF713, 0xC36B65A, 0x19C5DD89, 0x18A1D1AB, 0xF772C8D, 0xC11927C, 0x5}
var CURVE_Pybab = [...]Chunk{0x95F7865, 0x134F0379, 0x1CE9A0E, 0x17E0EADD, 0x1DACADD7, 0x1B18F9F8, 0x181D3943, 0x186679A, 0x2505BB0, 0x1FDF1DC8, 0x11B36A49, 0x11E254E9, 0xA438576, 0x102B09AE, 0x139984F4, 0x15BC0233, 0x1B6F180E, 0x960562B, 0x48CA65B, 0x6}
var CURVE_Pybba = [...]Chunk{0x7CC1979, 0xEC1D4FB, 0x1D89E6F0, 0x955F38E, 0x1635FDA9, 0x123D8E10, 0x10076209, 0x494404A, 0xD733D7, 0x17678BCF, 0x153841F9, 0x10696FFD, 0x5BC9FE8, 0x1A20D8B2, 0xE22EC9D, 0x18449116, 0x108C86C5, 0x1B4CD720, 0x34967, 0x19}
var CURVE_Pybbb = [...]Chunk{0xFC9F25B, 0x7E44AB1, 0xE9AB5D3, 0x589F00D, 0x1C9D264F, 0xC7478B4, 0x16B24A13, 0x1D2C146B, 0xEF84D9A, 0xF47ECDE, 0x1BFEE16A, 0x1B69071E, 0x11AB4C1C, 0xBE9D9EF, 0x390F005, 0x78C8288, 0x1B9BF549, 0x9320730, 0x3D84D97, 0x14}

//var CURVE_W = [2][20]Chunk{{0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0}, {0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0}}
//var CURVE_SB = [2][2][20]Chunk{{{0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0}, {0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0}}, {{0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0}, {0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0}}}
//var CURVE_WB = [4][20]Chunk{{0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0}, {0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0}, {0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0}, {0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0}}
//var CURVE_BB = [4][4][20]Chunk{{{0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0}, {0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0}, {0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0}, {0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0}}, {{0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0}, {0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0}, {0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0}, {0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0}}, {{0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0}, {0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0}, {0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0}, {0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0}}, {{0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0}, {0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0}, {0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0}, {0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0}}}
