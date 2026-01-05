usernames = ["root", "admin", "user", "guest", "support", "login", "zyfwp", "ZXDSL"]
passwords = ["", "root", "user", "guest", "support", "login", "password", "default", "pass",
                     "1234", "12345", "123456", "12345678", "123456789", "123123", "111111", "1111111", "ikwb",
                     "system", "smcadmin", "jiocentrum", "cxlinux", "jvbzd", "ZXDSL", "admin1234", "Admin1234",
                     "admin12345", "Admin12345", "1001chin", "PrOw!aN_fXp", "W!n0&oO7.", "", "zlxx.", "zlxx", "wyse",
                     "vizxv", "vagrant", "unitrends1", "uClinux", "tini", "timeserver", "sun123", "fidel123", "klv123",
                     "klv1234", "juantech", "oelinux123", "p@ck3tf3nc3", "qwasyx21", "sipwise", "sixaola", "stxadmin",
                     "TrippLite", "Zte521", "ahetzip8", "alpine", "anko", "anni2013", "cat1029", "ceadmin", "dreambox",
                     "admin", "Admin", "3ep5w2u", "5up", "7ujMko0admin", "7ujMko0vizxv", "GM8182", "ROOT500", "54321",
                     "1111", "00000000", "!root", "realtek", "123vidin123", "broadguam1", "warmWLspot", "Mau'dib",
                     "LSiuY7pOmZG2s", "1234567890", "nokia", "letacla", "linux", "leostream", "jvbzd", "Cisco", "888888",
                     "davox", "coolphoenix579", "cms500", "changeme", "calvin", "blender", "bananapi", "Serv4EMC",
                     "GMB182", "666666", "solokey", "zksoft3", "xc3511", "colorkey", "swsbzkgn", "zte9x15", "orion99",
                     "maxided", "hi3518", "iDirect", "qweasdzx", "hunt5759", "telecomadmin", "1234567890", "0123456789",
                     "rootroot", "h3c", "nmgx_wapia", "i826y3tz", "gwevrk7f@qwSX$fd", "hipc3518", "ipc71a", "IPCam@sw",
                     "zyad1234", "hslwificam", "huigu309", "e10adc39", "tsgoingon", "hg2x0", "grouter", "2011vsta",
                     "antslq", "20080826", "taZz@23495859", "hichiphx", "hdipc%No", "apix", "vhd1206", "059AnkJ", "xmhdipc"]

with open("combo.txt", "w") as file:
    file.writelines(f"{u}:{p}\n" for u in usernames for p in passwords)

print("combo.txt created successfully!")
