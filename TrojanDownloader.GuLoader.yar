rule TrojanDownloader_GuLoader {
   meta:
      description = "TrojanDownloader.GuLoader"
      author = "LightDefender"
      date = "2021-06-25"
      hash1 = "4ee78cf82b434634075e121ebbe7dce9aa4b0a18c04f54f70d84c891f7a56507"
      hash2 = "2cad3c6af2167827f44f2d53c36b8aed25c361cbe90b030a024dd13ecc649d7f"
   strings:
      $op1 = {558BEC83EC0C688613400064A100000000506489}
      $op2 = {8B450889510889953CFBFFFF8B9540FBFFFF5089}
      $op3 = {CCCCCCCCCCCCCCCCCCCCCCCC558BEC83EC0C6886}
   condition:
      uint16(0) == 0x5a4d and all of them
 }
