import "pe"
rule Win_Trojan_Ransom_Common
{
    strings:
      $ = { e8ecfbfeffe9933b01006a146868df4400e8373e010033ff897de4 }
      $ = { 4bfeffc7455cf668ce4bc745684653b55c8b }
      $ = { 60e803000000e9eb045d4555c3e801000000eb5dbbedffffff03dd81eb0000090083bd7d04000000899d7d0400000f85c00300008d858904000050ff95090f00008985810400008bf08d7d515756ff95050f0000abb000ae75fd380775ee8d457affe05669727475616c416c6c6f63005669727475616c467265650056697274 }
      $ = { 60bef1e04200bf00104000e80d21fdffb956090000e8bfffffffbf00304100e8f920fdffbf00704100b9dbb20000f3a4bf00904200e8e320fdffbf00b04200e8d920fdffbe009042008b4e0ce33a5651ff1500e0420009c0742389c58b34248b7e108b0fe311575155ff1504e042005f09c07409abebeb5e83c614ebccb8ffff }
      $ = { 558bec83ec4868fc598658ff156e16400085c074030145c068b17f29fcff156e16400085c075df6a0068060100006a036a006a04680000006068346c4100ff153a18400083f8ff8945ec0f858e0000006a006843e2e68a6823bf726cff158a1640002145c06a0068bf934b5c68ac01c21aff158a16400068856b4100ff15ca15 }
      $ = { 683c114000e8eeffffff000000000000300000004000000000000000f7fbe694f24d754290f5240ebdff2147000000000000010000000a0d0a436f6e726948517a686a45686c003d20226a6c00000000060000001c21400007000000f81a400007000000a41a400056423521f01f2a000000000000000000000000007e000000 }
      $ = { 558bec81ecd0020000c685d3fdffffc06800401a00680000001fff151c714000898540fdffff8985c4fdffff6800880200680000b800ff1538714000ff15dc704000052cda0380018540fdffff0185c4fdffff89d6c685d0fdfffff7c685d1fdfffffcc685d4fdffffc48185c4fdffff10453c808bbdc4fdffff8b078985c8fd }
      $ = { 558bec6aff6848614000689836400064a100000000506489250000000083c4c05356578965e8c745fc00000000c745d000000000eb098b45d083c0018945d0817dd0102700007d1eff150c504000a39c344100833d9c3441000075086a00ff1500504000ebd06a006a006800000400ff1510504000a39c34410068631000006a }
      $ = { 40bb4ee673716c686f73742e646c6c00536553687574646f776e50726976696c656765005c5c2e5c504859534943414c44524956453000005c737973332e6578650000005c737973746d2e747874000072756e61730000006675636b65642d75702d73686974 }
      $ = { 6d9f2261749b30726f951b73733600c001711b74436b0e726500000000480c5072611d657345001402791b744d491c756c1b3a696c1342616d1b2900003bff4478061f6e64f321766904216e6d1322000000007453ea0d696ed10c5700b1ff4272d31e7465f8266c65e1fff001f91a7446cf2365539f0a6545ae00e90488197274a3216c4100000000a21c6f633600c0036425616470196c6536002505811269745b46696c5300 }
      $ = { 686c184000e8eeffffff000000000000300000003800000000000000e320f04819417b419fb6c109d57078030000000000000100000000000084fc0062616c7a6f00fb000000000007000000e06d400007000000806d400007000000386d400007000000646b4000070000008469400007000000d465400007000000785a4000 }
      $ = { 354f465457415245000000006177747761337400326b336a3468696f753233342e646c6c }
      $ = { 558bec83ec0c568b3540069b006840069b006bf652ff15902496008b0d40069b003d02400080756c85c9756853578b3d9424960083e611bb04000080eb0f8bc6257f0000808d46ff83e00b03f06a0153ffd783f80675e7bfc0289600b900f0ffff8d5514528bc723c1ba5a4596006a402bd023d152506affff1518229600e8f1 }
      $ = { 558bec83ec18c745ecbeffdfbdc745f4bdffdfbdc745f012000000ff45f06808834000ff15ec8540006a33ff15e08540006a33ff15e48540008d }
      $ = { e8f4490000e978feffff8325a454470000e8c94a0000a3a454470033c0c3cccccccccccccccccccccccccccc558bec83ec0883e4f0dd1c24f30f7e0424e808000000c9c3660f12442404660fc5c0036625ff7f662d2038663da8080f87d7010000660f14c0660f280d10384100660f59c8f20f2dd1660f281520384100660f58 }
      $ = { 558bec892d2ce70210e8020000005dc3558bec83ec20535657c745f800000000c745e4e0140010a1201001108945f468037f00006a00ff152c1001108b4df40fb61181faff000000742a8b45f40fb60883f96a741f8b55f40fb6023d8b00000074128b4df40fb61183fa55740733c0e95d010000a1201001108945e08b0d3420 }
      $ = { 68b0144000e8f0ffffff000000000000300000003800000000000000e3e703383595d0499655c676fec77d3700000000000001000000000000000000417072696c000000000000000700000088274000070000001c27400007000000602540000700000018254000010004004421400000000000ffffffffffffffff00000000 }
      $ = { e9d6350000e97d390000e929290000e912350000e919240000e946290000e9b6380000e9062b0000e969250000e9d6350000e975260000e9482b0000e9b1390000e9d2370000e920210000e998340000e946320000e989280000e984380000e987240000e91a340000e9fd330000cccccccccccccccccccccccccccccccccccc }
      $ = { 558bec51c745fc6edd0100892d10e70310e80a0000008be55dc3cccccccccccc558bec83ec3c53c745f800000000c745e420120010a1b45000108945f4ff15bc5000108b0d14500010894dc46a00ff152050001085c0750733c0e95a0100008b1528600210c60253a128600210c64001598b0d28600210c64102538d55f852a1 }
      $ = { 6874144000e8f0ffffff00000000000030000000400053656d616e006a98f07187cc384581798af4453ad8ff0000000000000100000000010000000053656d616e6173656d6153656d616e000000000006000000f06a400001000500bc4f400000000000ffffffffffffffff000000000051400094b040000000000000008f05 }
      $ = { 558bec51c745fc80cc0000892d10170410e85a0100008be55dc3cccccccccccc558bec51c745fc54420800c745fc54420800c745fc54420800c745fc54420800c745fc54420800c745fc54420800c745fc54420800c745fc54420800c745fc54420800c745fc54420800c745fc54420800c745fc54420800c745fc54420800c7 }
      $ = { e9641a0000e9370e0000e9ad0e0000e997040000e9e2000000e9fe150000e9040d0000e9840f0000e9cf0f0000e9ff0c0000e9b1140000e9bf170000e92a050000e9a20e0000e9b4000000e95d120000e90d100000e94f150000e94e0f0000e9b0120000e9a3110000e9400c0000e970170000e947130000cccccccccccccccc }
      $ = { 8b3da82040006681e7fcffb445b0508bc8fd66f2affc8a471f502c2c720f583c55770abb02304000e9cffefffff7f10000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000008bff558bec83ec4853ff33ff33e89201000083c4085b83ec }
      $ = { 68a400000068000000006828af4000e85c30000083c40c6800000000e855300000a32caf4000680000000068001000006800000000e842300000a328af4000e8bc2f0000b8a8a04000a330af4000e8ed720000e80d710000e89a670000e8b75f0000e85d5f0000e8cf5e0000e817560000e8f6540000e8ba4e0000e88b4a0000 }
      $ = { e984140000e953090000e9630e0000e918080000e992190000e9910c0000e9c8000000e9f5100000e9c8000000e9f30f0000e982130000e941110000e9b5000000e9520b0000e964190000e91e0c0000e9490e0000e9d10a0000e91c0a0000e974090000e97e080000e99f0f0000cccccccccccccccccccccccccccccccccccc }
      $ = { 689090000068000000006880894000e85c30000083c40c6800000000e855300000a384894000680000000068001000006800000000e842300000a380894000e8bc2f0000b884814000a388894000e80d550000e825530000e82c4e0000e8fe4d0000e8033a0000e831390000e8a7380000e8c5320000e8f5300000c7058c8940 }
      $ = { e9d80b0000e967090000e947100000e9630f0000e922190000e9e60c0000e90a100000e9660c0000e9bc0a0000e9b9000000e952100000e9d9010000e99b090000e9f9180000e9f00e0000e97e120000e96b010000e9a20b0000e9b5010000e9740e0000e92c0a0000e9c90f0000cccccccccccccccccccccccccccccccccccc }
      $ = { 50006c006500610073006500200063006f006d0070006c0065007400650020007400680065002000730075007200760065007900200074006f00200075006e006c006f0063006b00200079006f0075007200200063006f006d007000750074006500720021 }
      $ = { 33f68bc681c64028400083ee6d8b4eff6a558ac58ae10fc8598bf083c08f8b444802c1e80803f08d461d8038007421b21c38107213b2c03810770dbf0030400033c00f84ccfeffff33c064892060ebf8b970000000e20083e90175f9cc000000cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc }
      $ = { 33f68bc681c6????400083ee6d8b4eff6a558ac58ae10fc8598bf083c08f8b444802c1e80803f08d461d8038007421b21c38107213b2c03810770dbf0030400033c00f84a0feffff33c064892060ebf8b970000000e20083e90175f9cc000000????????????????????????????????????????????????????????????cccc }
      $ = { 2bf68bc681f64428400083ee6d8b4eff6a2a8ac58ae10fc8598bf083c08f8b4488048acc03f18d461d8038007423b21c38107213b2e03810770dbf0030400033c00f84edfeffff6a00ff1534274000ebf6b972000000e20083e90175f9fa000b9090909090909090909090909090909090909090909090909090909090909090 }
      $ = { 2bf68bc681f64828400083ee6d8b4eff6a2a8ac58ae10fc8598bf083c08f8b4488048acc03f18d461d8038007423b21c38107213b2e03810770dbf0030400033c00f84e5feffff6a00ff1584274000ebf6b972000000e20083e90175f9fa000b9090909090909090909090909090909090909090909090909090909090909090 }
      $ = { 6818050000680000000068a8454000e81310000083c40c6800000000e812100000a3ac454000680000000068001000006800000000e8ff0f0000a3a8454000e8ec190000e8c2160000e862120000e80d110000e876100000c705b445400014000000b8201900003b05b44540007c2d8b15b8454000ff35e84c4000e8301a0000 }
      $ = { 558bec83e4f883ec4c53565768f0b340006810b4400033f656ff15ba8040006a096834b440006a09685cb440006a0468000c0000ff15c68040006890b4400068f4b44000ff15be804000688100000068890000006893080000ff15c28040008d44241c894424188d450450e823390000a3ecb3400033c066a368b64000a1ecb3 }
      $ = { 6aff5941be0431400083ee6d8b46ff8bf0c1e6106633f6680a12400081ee20ff000050648b19648921b0503806740383c6108d86ac000000b61a3830720eb538382877088d3d004040007eae9d6a07ff3574304000ff0c24ff242400004490909090909090909090909090909090558bec83ec3857ff37ff37ff3753e8590000 }
      $ = { 6a0059be0c31400083ee6d8b46ff8bd0c1e2106633d268ad11400081ea20ff000050648b19648921803a50740383c2088d82ac000000410fb6121bca7721b61a3a30731290b6383830770b8d3d004040007ea79d6a07ff357c304000ff0c24ff2424558bec83ec3457565051ff37e86b0b000083c4145f8be55d58ffd000558b }
      $ = { 558bec83e4f883ec3c53565768d0134100c7442414afdfcaffc7442418aedfcaff6820154100ff15860241006a00ff157e0241008d442424894424188d5504e825ddffffa3a4134100a1a41341008b4004a398134100a1a41341008b4008a39c134100a1a41341008b400ca3a0134100c744240c00000000a198134100a3f012 }
      $ = { 5589e583ec08c7042402000000ff157c314100e8a8feffff908db42600000000558b0da031410089e55dffe18d742600558b0d9431410089e55dffe1909090905589e5b8cd100000e8bb83000083e4f0b80000000083c00f83c00fc1e804c1e004898574efffff8b8574efffffe896830000e821830000c745f400000000c745 }
      $ = { 68903a4000e8f0ffffff000000000000300000003800000000000000e3ea7bd202008844807bc3fd7cc88f27000000000000010000000450e00570ed54686973497300a400000000ffcc310005ccedb412b420f04ab7ee3152698cad4e0c707228a1a79344af62505ec820fc7b3a4fad339966cf11b70c00aa0060d393000000 }
      $ = { b94e0e0000558bec83ec0c81052ac4400026c4400056c745f8e3eff20d68f0744000812526c4400007c54000c745f8e4eff20dff15487140008b3577c54000be003000003bc6c7052ec44000f65400000f821200000033c040c7051bc54000672c0000e9590300005381e3de6800008b1d44714000812583c540008c76000068 }
      $ = { 68883d4000e8f0ffffff000040000000300000003800000000000000334c50709658ac4c998b4fd69cf9f0b800000000000001000000000000000000614d6172650000000000000000000000000000008800000000000000020000000400000053dca641c6a8594e908b33a627d537ea0100000098000000a800000001000000 }
      $ = { 68a400000068000000006898864000e8fc2f000083c40c6800000000e8f52f0000a39c864000680000000068001000006800000000e8e22f0000a398864000e8fc3f0000e8213e0000e8a23c0000e8cc390000e8f2370000ba148140008d0dd4864000e8a02f0000ba518040008d0dcc864000e8902f0000ba898040008d0da4 }
      $ = { 2d0d180000558bec83ec105329150baa4500c745fc1beff20d2bc056c7052baa450011000000833d2baa4500000f8478000000833d2baa4500130f8500000000a12baa450048a32baa4500e9d6ffffff8125b7aa450000000000e90d0000008b1db7aa450043891db7aa4500833db7aa4500100f8332000000833db7aa450004 }
      $ = { 81e27c730000558bec83ec100d6f2d000053c745fc1beff20d8125b61e440000000000e90d0000008b1db61e440043891db61e4400833db61e44001e0f8314000000833db61e4400210f8500000000e9d4ffffff2bd856c705661e44001b000000833d661e4400000f847d000000833d661e4400070f8500000000833d661e44 }
      $ = { ff746365f6ffefffff77f6f6fff6ffefffffeffffffff6fff6ffefffffeffff6ffeffffffff6ffefffffeffffff6ffefffff546f0174735a05f6ffefffff4461490072636565656572f6fff6ffefffffefffff6e6f726973f6ffeffff6ffefffffff006f6961746765017269726524626f6df6ffefffff490075744df6ffefffff65656b6a747274f6ffeffff6ffefffffff69655372006c69f6ffefffff65637565616501576d77f6ffefffff76f6ff }
      $ = { 68c0324000e8f0ffffff0000000000003000000040000000000000009718d095d178574d8c9ecfd535de51b600000000000001000000000000000000496c5f5072616e7a6f0000000000000000000000ffcc3100073c33be2f4a1ca044bf40bbcfda18d8606cb22d8bde1af244909cdd860057b93d3a4fad339966cf11b70c00 }
      $ = { e874240000e916feffff558bec81ec28030000a3c0434200890dbc4342008915b8434200891db44342008935b0434200893dac434200668c15d8434200668c0dcc434200668c1da8434200668c05a4434200668c25a0434200668c2d9c4342009c8f05d04342008b4500a3c44342008b4504a3c84342008d4508a3d44342008b }
      $ = { bb535b0000558bec83ec0c8125a8674000702d0000c745f8f9a6bf30c745f8f8a6bf3081056c674000352800006878634000ff1510804100a16c6440003ddbb47c7fc705f0664000376a00000f85140000008105ac674000fc674000c7056c64400000000000810d04684000f46740008d45f4811df46640008c6d00008945fc }
      $ = { 6a6068f0504000e87f030000bf940000008bc7e8771000008965e88bf4893e56ff15605040008b4e10890da47340008b4604a3b07340008b56088915b47340008b760c81e6ff7f00008935a873400083f902740c81ce008000008935a8734000c1e00803c2a3ac73400033f6568b3d1c504000ffd76681384d5a751f8b483c03 }
      $ = { 683110400064ff350000000064892500000000e814050000e82d050000e8fe040000e8ff040000e80605000033db891bc3ff0d283040007401c3b81f1540002dd2104000a33a3040008d053e304000506a40ff353a30400068d2104000e8060500006800304000e802050000506800304000ff353a30400068d2104000e82900 }
      $ = { e583ec08c7042402000000ff152cf14300e8a8feffff908db42600000000558b0d44f1430089e55dffe18d742600558b0d38f1430089e55dffe1909090905589e55de9c7400000909090909090905589e583ec188b450c0faf450c89450cc7042404000000e8e44300008945fc8b55fc8b450c8902c7042400b04300e8ed4400 }
      $ = { 83C404C9C30000000000000000000000000000000000000000000000000000000000872C24558D6C24045189E981E90010000085012D001000003D001000007DEC29C1850189E089CC8B08FF60048B45ECC3E8F7FFFFFF8B008B00C3E8EDFFFFFF50E8EBFFFFFF50E8CD00000081C408000000C38B65E8E8D6FFFFFF50E8C0000000FFFFFFFFBA124000D2124000E9B7000000 }
      $ = { 740068006900730020006900730020006E006F00740020006100200058006F0072006900730074002000760061007200690061006E0074 }
      $ = "vssadmin.exe delete shadows /all" nocase
      $ = "vssadmin delete shadows /all" nocase
      $ = "files have been encrypted" nocase
      $ = "Files has been encrypted" nocase
      $ = "You cannot recover them without paying us some money."
      $ = "The price for the recovery software is "
      $ = "<h3>How to Pay</h3><p>Send"
      $ = "bcdedit /set {default} recoveryenabled no"
      $ = "To decrypt all the data"
      $ = "wmic shadowcopy delete /nointeractive" nocase
      $ = "vssadmin resize shadowstorage /for" nocase
      $ = "delete catalog -quiet" fullword wide
    condition:
        uint16(0) == 0x5a4d and any of them
}

rule Win_MSIL_Ransom
{
    meta:
        author = "LightDefender"
        date = "2021-06-28"
    strings:
        $a1 = "RijndaelManaged" ascii
        $a2 = "GetDirectories" ascii
        $a3 = "password" ascii
        $a4 = "System.IO" ascii
        $a5 = "GetFiles" ascii
        $a6 = "System.Security.Cryptography" fullword ascii
        $a7 = "encryptDirectory" fullword ascii
        $b4 = "files have been encrypted" ascii wide nocase
        $b5 = "files has been encrypted" ascii wide nocase
        $b6 = "EncryptFile" ascii
        $c1 = ".doc" fullword ascii wide
        $c2 = ".docx" fullword ascii wide
        $c3 = ".xls" fullword ascii wide
        $c4 = ".xlsx" fullword ascii wide
        $c5 = ".ppt" fullword ascii wide
        $c6 = ".pptx" fullword ascii wide
        $c7 = ".html" fullword ascii wide
        $d1 = "Windows" fullword ascii wide
        $d2 = "Program Files (x86)" fullword ascii wide
        $d3 = "GetExtension" fullword ascii wide
    condition:
        uint16(0) == 0x5a4d and (all of ($a*) or (any of ($b*) and 5 of ($a*)) or (all of ($c*) and 4 of ($a*)) or (all of ($d*) and 4 of ($a*))) and pe.imphash() == "f34d5f2d4577ed6d9ceec516c1f5a744"
}
