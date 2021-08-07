rule BitRAT_imphash {
   meta:
      description = "Backdoor.BitRAT"
      author = "LightDefender"
      date = "2021-08-07"
   condition:
      pe.imphash() == "71955ccbbcbb24efa9f89785e7cce225"
}
