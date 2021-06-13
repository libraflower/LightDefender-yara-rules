rule filetour_adware {
   meta:
      description = "filetour"
      author = "LightDefender"
      date = "2021-06-13"
      hash1 = "24e73e485857368cf7ec4e1b44b5d9cf86a16fbb8eafd89626b47703256db22d"
   strings:
      $s1 = "Execute the commands..." fullword ascii
      $s2 = "@$&%04\\RunWW.exe" fullword ascii
      $s3 = "  <description>Smart Install Maker - create setup software</description>" fullword ascii
      $s4 = "This setup requires the .NET Framework version . Please install the .NET Framework and run this setup again." fullword ascii
      $s5 = "@$&%04\\Toner-Recover.exe" fullword ascii
      $s6 = "@$&%04\\Second.exe" fullword ascii
      $s7 = "@$&%04\\Uninstall.exe" fullword ascii
      $s8 = "Installation password" fullword ascii
      $s9 = "Enter the password" fullword ascii
      $s10 = "A password is required to begin the installation of Versium Research. Type the password and then click \"Next\"." fullword ascii
      $s11 = "This setup is password protected." fullword ascii
      $s12 = "        <requestedExecutionLevel level=\"requireAdministrator\"/>" fullword ascii
      $s13 = " inflate 1.1.4 Copyright 1995-2002 Mark Adler " fullword ascii
      $s14 = "    processorArchitecture=\"*\"" fullword ascii
      $s15 = "Setup is now ready to begin installing Versium Research on your computer." fullword ascii
      $s16 = "        processorArchitecture=\"*\"/>" fullword ascii
      $s17 = "7+7?7a7}7" fullword ascii /* hex encoded string 'wzw' */
      $s18 = "?\"?+?4?=?F?" fullword ascii /* hex encoded string 'O' */
      $s19 = "7 7$717?7" fullword ascii /* hex encoded string 'wqw' */
      $s20 = "        publicKeyToken=\"6595b64144ccf1df\"" fullword ascii
   condition:
      uint16(0) == 0x5a4d and filesize < 4000KB and
      8 of them
}
