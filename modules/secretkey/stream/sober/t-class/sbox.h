WORD SBox[256] = {
    0xa3aa1887UL, 0xd75e435cUL, 0x0965c042UL, 0x830e6ef4UL,
    0xf857ee20UL, 0x4884fed3UL, 0xf666c502UL, 0xf454e8aeUL,
    0xb32ee9d9UL, 0x211f38d4UL, 0x15829b5dUL, 0x785cdf3cUL,
    0x99864249UL, 0xb12e3963UL, 0xaff4429fUL, 0xf9432c35UL,
    0xe7f40325UL, 0x2dc0dd70UL, 0x4d973dedUL, 0x8a02dc5eUL,
    0xce175b42UL, 0x4c0012bfUL, 0xca94d78cUL, 0x2eaab26bUL,
    0x52c11b9aUL, 0x95168146UL, 0xd9ea8ec5UL, 0x1e8ac28fUL,
    0x4eed5c0fUL, 0x38b4101cUL, 0x442db082UL, 0x280929e1UL,
    0x0a1843deUL, 0xdf8299fcUL, 0x022fbc4bUL, 0xa03915ddUL,
    0x17a803faUL, 0xf146b2deUL, 0x60233342UL, 0x68cee7c3UL,
    0x12d607efUL, 0xb797ebabUL, 0x7a7f859bUL, 0xc31f2e2fUL,
    0xe95b71daUL, 0xfae2269aUL, 0x3d39c3d1UL, 0x53a56b36UL,
    0x96c9def2UL, 0x84c9fc5fUL, 0x6b27b3a3UL, 0xbaa56ddfUL,
    0xf225b510UL, 0x630f85a7UL, 0x9ae82e71UL, 0x19cb8816UL,
    0x7c951e2aUL, 0xaef5f6afUL, 0xe5cbc2b3UL, 0xf54ff55dUL,
    0xf76b6214UL, 0x160b83e3UL, 0x6a9ea6f5UL, 0xa2e041afUL,
    0x392f1f17UL, 0xb63b99eeUL, 0x7ba65ec0UL, 0x0f7016c6UL,
    0xc17709a4UL, 0x93326e01UL, 0x81b280d9UL, 0x1bfb1418UL,
    0xeeaff227UL, 0xb4548203UL, 0x1a6b9d96UL, 0xea17a8c0UL,
    0xd0d5bf6eUL, 0x91ee7888UL, 0x2ffcfe64UL, 0xb8a193cdUL,
    0x550d0184UL, 0xb9ae4930UL, 0xda014f36UL, 0x85a87088UL,
    0x3fad6c2aUL, 0x4122c678UL, 0xbf204de7UL, 0xe0c2e759UL,
    0x5a00248eUL, 0x583b446bUL, 0x800d9fc2UL, 0x5f14a895UL,
    0x666cc3a1UL, 0x0bfef170UL, 0xd8c19155UL, 0x907b8a66UL,
    0x351b5e69UL, 0xd5a8623eUL, 0xc0bdfa35UL, 0xa7f068ccUL,
    0x333a6acdUL, 0x0655e936UL, 0x65602db9UL, 0x69df13c1UL,
    0x450bb16dUL, 0x0080b83cUL, 0x94b23763UL, 0x56d8a911UL,
    0x6db6bc13UL, 0x985579d7UL, 0x9b5c2fa8UL, 0x76f4196eUL,
    0x97db5476UL, 0xfc64a866UL, 0xb26e16adUL, 0xc27fc515UL,
    0xb06feb3cUL, 0xfec8a306UL, 0xdb6799d9UL, 0x201a9133UL,
    0xe12466ddUL, 0xebeb5dcdUL, 0xd6118f50UL, 0xe4afb226UL,
    0xddb9cef3UL, 0x47b36189UL, 0x4a7a19b1UL, 0x1dc73084UL,
    0x427ded5cUL, 0xed8bc58fUL, 0x9edde421UL, 0x6e1e47fbUL,
    0x49cc715eUL, 0x3cc0ff99UL, 0xcd122f0fUL, 0x43d25184UL,
    0x277a5e6cUL, 0xd2bf18bcUL, 0x07d7c6e0UL, 0xd4b7e420UL,
    0xde1f523fUL, 0xc7d9b8a2UL, 0x67da1a6bUL, 0x18888c02UL,
    0x89d1e354UL, 0xcbba7d79UL, 0x30cc7753UL, 0x1f2d9655UL,
    0x8d829da1UL, 0xc61590a7UL, 0x8fc1c149UL, 0xaa537f1cUL,
    0xc8779b69UL, 0x7471f2b7UL, 0xdc3c58faUL, 0xc9dc4418UL,
    0x5d8c8c76UL, 0x5c20d9f0UL, 0x31a80d4dUL, 0xa474c473UL,
    0x709410e9UL, 0x880e4211UL, 0x61c8082bUL, 0x2c6b334aUL,
    0x9ff68ed2UL, 0x0d43cc1bUL, 0x2b3c0ff3UL, 0x87e564a0UL,
    0x50f55a4fUL, 0x8240f8e7UL, 0x54a7f15fUL, 0x6400fe21UL,
    0x266d37d6UL, 0x7dd506f1UL, 0x03e00973UL, 0x40bbde36UL,
    0x34670fa8UL, 0x4b31ab9eUL, 0x1cdab618UL, 0x731f52f5UL,
    0xd158eb4fUL, 0xc4b9e343UL, 0xfd8d77ddUL, 0x3bb93da6UL,
    0xcc0fd52dUL, 0xfb5412f8UL, 0x7fa63360UL, 0xabe53ad0UL,
    0xe6700f1cUL, 0x3e24ed0bUL, 0x5b3dc1ecUL, 0xa5366795UL,
    0xad549d15UL, 0x04ce46d7UL, 0x237abe76UL, 0x9c48e0a0UL,
    0x14f07c02UL, 0x511249b7UL, 0x229ed6baUL, 0xf0a47f78UL,
    0x29cfffbdUL, 0x7907ca84UL, 0x7165f4daUL, 0x7e9f35daUL,
    0xffd2aa44UL, 0x8c7452acUL, 0x0ed674a7UL, 0xe261a46aUL,
    0x0c63152aUL, 0xef12b7aaUL, 0xbc615927UL, 0x724fb118UL,
    0x7551758dUL, 0x6f81687bUL, 0x3752f0b3UL, 0xa14254edUL,
    0xecc77271UL, 0xd331acabUL, 0x8ef94aecUL, 0x62e994cdUL,
    0x8b4d9e81UL, 0x86623730UL, 0x108a21e8UL, 0xe8917f0bUL,
    0x08a9b5d6UL, 0x7797adf8UL, 0x11d30431UL, 0xbecac921UL,
    0x92b35d46UL, 0x4f430a36UL, 0x24194022UL, 0xc5bca65eUL,
    0x32ec70baUL, 0x36aea8ccUL, 0x9d7bae8bUL, 0xcf2924d5UL,
    0xf3098a5aUL, 0xa6396b81UL, 0xbbde2522UL, 0xac5c1cb8UL,
    0x5eb8fe1dUL, 0x6cb3c697UL, 0xa9164f83UL, 0x13c16376UL,
    0x5719224cUL, 0x25203b35UL, 0xb53ac0feUL, 0xe366a19aUL,
    0xbdf0b24fUL, 0xa8fda998UL, 0x3ad52d71UL, 0x010896a8UL,
    0x05e6053fUL, 0x59b0d300UL, 0x2a99cbccUL, 0x465e3d40UL,
};
