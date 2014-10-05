
import unittest
import aes

class AES_tests(unittest.TestCase):
    def test_sub_key_bytes(self):
        kw = aes.key_bv('cf4f3c09')
        sub = aes.key_bv('8a84eb01')
        self.assertEqual(aes.sub_key_bytes(kw),sub,"test sub_key_bytes using keyword cf4f3c09 from FIPS-197\
                                                           appendix 2")

    def test_init_key_schedule(self):
        ntk='2b7e151628aed2a6abf7158809cf4f3c'
        q = aes.init_key_schedule(aes.key_bv(ntk))
        self.assertEqual(len(q),44,"there should be 44 elements in the key schedule")
        self.assertEqual(aes.bv_hex_str(q[0]),'2b7e1516',"random testing elements of key schedule according to\
                                                                 FIPS-197 appendix 2")
        self.assertEqual(aes.bv_hex_str(q[20]),'d4d1c6f8',"random testing elements of key schedule according to\
                                                                 FIPS-197 appendix 2")
        self.assertEqual(aes.bv_hex_str(q[43]),'b6630ca6',"random testing elements of key schedule according to\
                                                                 FIPS-197 appendix 2")

    def test_add_round_key(self):
        rk=[aes.key_bv('00010203'),aes.key_bv('04050607'),aes.key_bv('08090a0b'),\
            aes.key_bv('0c0d0e0f')]
        sa=aes.init_state_array(aes.key_bv('00112233445566778899aabbccddeeff'))
        self.assertEqual(aes.state_str(aes.add_round_key(sa,rk)),'00102030405060708090a0b0c0d0e0f0',\
            "Test add round key from FIPS-197 C.1 round[0]")

    def test_sbox_lookup(self):
        bv = aes.key_bv("ab")
        self.assertEqual(aes.bv_hex_str(aes.sbox_lookup(bv)),'62',"testing 'ab' on sbox_lookup")

    def test_inv_sbox_lookup(self):
        bv = aes.key_bv("62")
        self.assertEqual(aes.bv_hex_str(aes.inv_sbox_lookup(bv)),'ab',"testing '62' on inv_sbox_lookup")
    def test_sub_bytes(self):
        sa=aes.init_state_array(aes.key_bv('00102030405060708090a0b0c0d0e0f0'))
        self.assertEqual(aes.state_str(aes.sub_bytes(sa)),'63cab7040953d051cd60e0e7ba70e18c',\
                         "testing sub_bytes from FIPS-197 C.1 round[1]")
    def test_inv_sub_bytes(self):
        sa=aes.init_state_array(aes.key_bv('63cab7040953d051cd60e0e7ba70e18c'))
        self.assertEqual(aes.state_str(aes.inv_sub_bytes(sa)),'00102030405060708090a0b0c0d0e0f0',\
                         "testing inv_sub_bytes from FIPS-197 C.1 round[1]")
    def test_shift_bytes_left(self):
        bv = aes.key_bv("1234abcd")
        self.assertEqual(aes.bv_hex_str(aes.shift_bytes_left(bv,3)),'cd1234ab')
    def test_shift_bytes_right(self):
        bv = aes.key_bv("1234abcd")
        self.assertEqual(aes.bv_hex_str(aes.shift_bytes_right(bv,3)),'34abcd12')
    def test_shift_rows(self):
        sa=aes.init_state_array(aes.key_bv('63cab7040953d051cd60e0e7ba70e18c'))
        self.assertEqual(aes.state_str(aes.shift_rows(sa)),'6353e08c0960e104cd70b751bacad0e7',\
            "Test shift rows from FIPS-197 C.1 round[1]")
    def test_inv_shift_rows(self):
        sa=aes.init_state_array(aes.key_bv('6353e08c0960e104cd70b751bacad0e7'))
        self.assertEqual(aes.state_str(aes.inv_shift_rows(sa)),'63cab7040953d051cd60e0e7ba70e18c',\
            "Test shift rows from FIPS-197 C.1 round[1]")
    def test_gv_mult(self):
        bv_1 = aes.key_bv("63")
        bv_2 = aes.key_bv("e0")
        self.assertEqual(aes.bv_hex_str(aes.gf_mult(bv_1,2)),'c6',"testing gf_mult with 63 * 2 = c6")
        self.assertEqual(aes.bv_hex_str(aes.gf_mult(bv_2,3)),'3b',"testing gf_mult with e0 * 3 = 3b")
    def test_mix_columns(self):
        sa=aes.init_state_array(aes.key_bv('6353e08c0960e104cd70b751bacad0e7'))
        self.assertEqual(aes.state_str(aes.mix_columns(sa)),'5f72641557f5bc92f7be3b291db9f91a',\
            "Test mix columns from FIPS-197 C.1 round[1]")
    def test_inv_mix_columns(self):
        sa=aes.init_state_array(aes.key_bv('5f72641557f5bc92f7be3b291db9f91a'))
        self.assertEqual(aes.state_str(aes.inv_mix_columns(sa)),'6353e08c0960e104cd70b751bacad0e7',\
            "Test inv mix columns from FIPS-197 C.1 round[1]")
    def test_encrypt(self):
        ntk='2b7e151628aed2a6abf7158809cf4f3c'
        ntp='3243f6a8885a308d313198a2e0370734'
        ntc=aes.encrypt(ntk,ntp)
        self.assertEqual(ntc,'3925841d02dc09fbdc118597196a0b32',"sample encryption from FIPS-197 Appendix 2")
        ntk='000102030405060708090a0b0c0d0e0f'
        ntp='00112233445566778899aabbccddeeff'
        ntc=aes.encrypt(ntk,ntp)
        self.assertEqual(ntc,'69c4e0d86a7b0430d8cdb78070b4c55a',"sample encryption from FIPS-197 Appendix C.1")
    def test_decrypt(self):
        ntk='2b7e151628aed2a6abf7158809cf4f3c'
        ntc='3925841d02dc09fbdc118597196a0b32'
        ntp=aes.decrypt(ntk,ntc)
        self.assertEqual(ntp,'3243f6a8885a308d313198a2e0370734',"sample decryption from FIPS-197 Appendix 2")
        ntk='000102030405060708090a0b0c0d0e0f'
        ntc='69c4e0d86a7b0430d8cdb78070b4c55a'
        ntp=aes.decrypt(ntk,ntc)
        self.assertEqual(ntp,'00112233445566778899aabbccddeeff',"sample decryption from FIPS-197 Appendix C.1")


if __name__ == '__main__':
    unittest.main()
