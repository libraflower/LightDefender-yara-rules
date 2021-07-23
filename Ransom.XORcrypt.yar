rule Ransom_XORcrypt_July_24 {
   meta:
      description = "Ransom.XORcrypt"
      author = "LightDefender"
      date = "2021-07-24"
      hash1 = "4d24830b93eeff7361fe72fd5c2eacfe54261e12d253f393fe3e52854681dfcc"
      hash2 = "4d1cea5df3ad85af7211fb2d4ab9748560e7d5276ef4c9060bfea97ea09b6e85"
      hash3 = "fdfcb6468c2bf733db427f5d2044070ef2bc6e7654c007e3186b3c3d2b768c3b"
      hash4 = "3ee7c5620afdd9b414ec5887d91c05e20342f230c5697aa39a3dae22f4e35ba8"
      hash5 = "95111da1fc5b52f3b05a1f1888f7e25412609e1c2a819c7a025e975e64d546d1"
      hash6 = "cb2fb6c498d3197b5c28b8df0039d2354cab65bef498e42aa4a3f822ca4d63b1"
      hash7 = "db7c89aa94e704c2a36c7ba6f1cd2cfab808e19ac30cc89345a5f7876ddfd593"
      hash8 = "710b8803c28e820b5a3d4386b56ef748de64c10d6421ecb347fda305ab6e7903"
      hash9 = "2a1ab67710bc593db4e72cc088d66ef45787968583ffd3009661f2742cacecfe"
      hash10 = "c76beb446f6676e4fffa52dbec8f1423a208a6ad50b5f5ec189ae871c52596e1"
      hash11 = "89d9c67bdba185fca71609cf37c4b4571a9e59fcc4aa441f842829b653612d37"
      hash12 = "3f8609883e7ee60435c0dff4024761a9cb134aec2dc95b4a73bf7db50deb2147"
   strings:
      $s1 = "C:\\Users" fullword ascii
      $s2 = ".data$rs" fullword ascii
      $s3 = "Please enter a number:" fullword ascii
      $s4 = "Is it a prime number?" fullword ascii
      $s5 = ".CRT$XIAC" fullword ascii
      $s6 = "__stdio_common_vfscanf" fullword ascii
      $s7 = "_set_new_mode" fullword ascii
      $s8 = "_get_initial_narrow_environment"
      $s9 = "_seh_filter_exe" fullword ascii
      $s10 = "_set_app_type" fullword ascii
      $s11 = "_register_thread_local_exe_atexit_callback" fullword ascii
   condition:
      uint16(0) == 0x5a4d and all of them
}
