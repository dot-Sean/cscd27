#CSCD27 Assignment 1 
#Eric Ren: 999661575 reneric
#Man Xu: 999586755 xuman2

import unittest
import aes

class AES_tests(unittest.TestCase):
    def test_sub_key_bytes_0(self):
        kw = aes.key_bv('cf4f3c09')
        sub = aes.key_bv('8a84eb01')
        self.assertEqual(aes.sub_key_bytes(kw),sub,"test sub_key_bytes using \
        keyword cf4f3c09 from FIPS-197 appendix 2")

    def test_sub_key_bytes_1(self):
        kw = aes.key_bv('6c76052a')
        sub = aes.key_bv('50386be5')
        self.assertEqual(aes.sub_key_bytes(kw),sub,"test sub_key_bytes using \
        keyword 6c76052a from FIPS-197 appendix 2")

    def test_sub_key_bytes_2(self):
        kw = aes.key_bv('59f67f73')
        sub = aes.key_bv('cb42d28f')
        self.assertEqual(aes.sub_key_bytes(kw),sub,"test sub_key_bytes using \
        keyword 59f67f73 from FIPS-197 appendix 2")

    def test_sub_key_bytes_3(self):
        kw = aes.key_bv('7a883b6d')
        sub = aes.key_bv('dac4e23c')
        self.assertEqual(aes.sub_key_bytes(kw),sub,"test sub_key_bytes using \
        keyword 7a883b6d from FIPS-197 appendix 2")

    def test_init_key_schedule_0(self):
        ntk='2b7e151628aed2a6abf7158809cf4f3c'
        q = aes.init_key_schedule(aes.key_bv(ntk))
        self.assertEqual(len(q),44,"there should be 44 elements in the key schedule")
        self.assertEqual(aes.bv_hex_str(q[0]),'2b7e1516',"random testing elements\
        of key schedule according to FIPS-197 appendix 2")
        self.assertEqual(aes.bv_hex_str(q[20]),'d4d1c6f8',"random testing elements\
        of key schedule according to FIPS-197 appendix 2")
        self.assertEqual(aes.bv_hex_str(q[43]),'b6630ca6',"random testing elements\
        of key schedule according to FIPS-197 appendix 2")
        self.assertEqual(aes.bv_hex_str(q[33]),'b58dbad2',"random testing elements\
        of key schedule according to FIPS-197 appendix 2")


    def test_add_round_key_0(self):
        rk=[aes.key_bv('00010203'),aes.key_bv('04050607'),aes.key_bv('08090a0b'),\
            aes.key_bv('0c0d0e0f')]

        sa=aes.init_state_array(aes.key_bv('00112233445566778899aabbccddeeff'))
        self.assertEqual(aes.state_str(aes.add_round_key(sa,rk)),\
                         '00102030405060708090a0b0c0d0e0f0',\
            "Test add round key from FIPS-197 C.1 round[0]")
        
    def test_add_round_key_1(self):
        rk=[aes.key_bv('d6aa74fd'),aes.key_bv('d2af72fa'),aes.key_bv('daa678f1'),\
            aes.key_bv('d6ab76fe')]
        

        sa=aes.init_state_array(aes.key_bv('5f72641557f5bc92f7be3b291db9f91a'))
        self.assertEqual(aes.state_str(aes.add_round_key(sa,rk)),\
                         '89d810e8855ace682d1843d8cb128fe4',\
            "Test add round key from FIPS-197 C.1 round[1]")
        
    def test_add_round_key_2(self):
        rk=[aes.key_bv('b692cf0b'),aes.key_bv('643dbdf1'),aes.key_bv('be9bc500'),\
            aes.key_bv('6830b3fe')]
    

        sa=aes.init_state_array(aes.key_bv('ff87968431d86a51645151fa773ad009'))
        self.assertEqual(aes.state_str(aes.add_round_key(sa,rk)),\
                         '4915598f55e5d7a0daca94fa1f0a63f7',\
            "Test add round key from FIPS-197 C.1 round[2]")     
    
    def test_add_round_key_3(self):
        rk=[aes.key_bv('47f7f7bc'),aes.key_bv('95353e03'),aes.key_bv('f96c32bc'),\
            aes.key_bv('fd058dfd')]
        

        sa=aes.init_state_array(aes.key_bv('6385b79ffc538df997be478e7547d691'))
        self.assertEqual(aes.state_str(aes.add_round_key(sa,rk)),\
                         '247240236966b3fa6ed2753288425b6c',\
            "Test add round key from FIPS-197 C.1 round[3]")     


    def test_sbox_lookup_0(self):
        bv = aes.key_bv("ab")
        self.assertEqual(aes.bv_hex_str(aes.sbox_lookup(bv)),'62',\
                         "testing 'ab' on sbox_lookup")
        
    def test_sbox_lookup_1(self):
        bv = aes.key_bv("60")
        self.assertEqual(aes.bv_hex_str(aes.sbox_lookup(bv)),'d0',\
                         "testing '60' on sbox_lookup")
        
    def test_sbox_lookup_2(self):
        bv = aes.key_bv("d8")
        self.assertEqual(aes.bv_hex_str(aes.sbox_lookup(bv)),'61',\
                         "testing 'd8' on sbox_lookup")
        
    def test_sbox_lookup_3(self):
        bv = aes.key_bv("66")
        self.assertEqual(aes.bv_hex_str(aes.sbox_lookup(bv)),'33',\
                         "testing '66' on sbox_lookup")
        

    def test_inv_sbox_lookup_0(self):
        bv = aes.key_bv("61")
        self.assertEqual(aes.bv_hex_str(aes.inv_sbox_lookup(bv)),'d8',\
                         "testing '61' on inv_sbox_lookup")
        
    
    def test_inv_sbox_lookup_1(self):
        bv = aes.key_bv("d0")
        self.assertEqual(aes.bv_hex_str(aes.inv_sbox_lookup(bv)),'60',\
                         "testing 'd0' on inv_sbox_lookup")    

    

    def test_inv_sbox_lookup_2(self):
        bv = aes.key_bv("62")
        self.assertEqual(aes.bv_hex_str(aes.inv_sbox_lookup(bv)),'ab',\
                         "testing '62' on inv_sbox_lookup")
    

    def test_inv_sbox_lookup_3(self):
        bv = aes.key_bv("33")
        self.assertEqual(aes.bv_hex_str(aes.inv_sbox_lookup(bv)),'66',\
                         "testing '33' on inv_sbox_lookup")

    def test_sub_bytes_0(self):
        sa=aes.init_state_array(aes.key_bv('00102030405060708090a0b0c0d0e0f0'))
        self.assertEqual(aes.state_str(aes.sub_bytes(sa)),\
                         '63cab7040953d051cd60e0e7ba70e18c',\
                         "testing sub_bytes from FIPS-197 C.1 round[1]")
    def test_sub_bytes_1(self):
        sa=aes.init_state_array(aes.key_bv('89d810e8855ace682d1843d8cb128fe4'))
        self.assertEqual(aes.state_str(aes.sub_bytes(sa)),\
                         'a761ca9b97be8b45d8ad1a611fc97369',\
                         "testing sub_bytes from FIPS-197 C.1 round[2]")
        
    def test_sub_bytes_2(self):
        sa=aes.init_state_array(aes.key_bv('4915598f55e5d7a0daca94fa1f0a63f7'))
        self.assertEqual(aes.state_str(aes.sub_bytes(sa)),\
                         '3b59cb73fcd90ee05774222dc067fb68',\
                         "testing sub_bytes from FIPS-197 C.1 round[3]")
        
    def test_sub_bytes_3(self):
        sa=aes.init_state_array(aes.key_bv('fa636a2825b339c940668a3157244d17'))
        self.assertEqual(aes.state_str(aes.sub_bytes(sa)),\
                         '2dfb02343f6d12dd09337ec75b36e3f0',\
                         "testing sub_bytes from FIPS-197 C.1 round[4]")
                
    def test_inv_sub_bytes_0(self):
        sa=aes.init_state_array(aes.key_bv('63cab7040953d051cd60e0e7ba70e18c'))
        self.assertEqual(aes.state_str(aes.inv_sub_bytes(sa)),\
                         '00102030405060708090a0b0c0d0e0f0',\
                         "testing inv_sub_bytes from FIPS-197 C.1 round[2]")
        
    def test_inv_sub_bytes_1(self):
            sa=aes.init_state_array(aes.key_bv('a761ca9b97be8b45d8ad1a611fc97369'))
            self.assertEqual(aes.state_str(aes.inv_sub_bytes(sa)),\
                             '89d810e8855ace682d1843d8cb128fe4',\
                             "testing inv_sub_bytes from FIPS-197 C.1 round[3]")
            
    def test_inv_sub_bytes_2(self):
            sa=aes.init_state_array(aes.key_bv('3b59cb73fcd90ee05774222dc067fb68'))
            self.assertEqual(aes.state_str(aes.inv_sub_bytes(sa)),\
                             '4915598f55e5d7a0daca94fa1f0a63f7',\
                             "testing inv_sub_bytes from FIPS-197 C.1 round[4]")
            
    def test_inv_sub_bytes_3(self):
            sa=aes.init_state_array(aes.key_bv('2dfb02343f6d12dd09337ec75b36e3f0'))
            self.assertEqual(aes.state_str(aes.inv_sub_bytes(sa)),\
                             'fa636a2825b339c940668a3157244d17',\
                             "testing inv_sub_bytes from FIPS-197 C.1 round[1]")
           
    def test_shift_bytes_left_0(self):
        bv = aes.key_bv("1234abcd")
        self.assertEqual(aes.bv_hex_str(aes.shift_bytes_left(bv,3)),'cd1234ab')
          
    def test_shift_bytes_left_1(self):
        bv = aes.key_bv("1234abcd")
        self.assertEqual(aes.bv_hex_str(aes.shift_bytes_left(bv,2)),'abcd1234')
        
    def test_shift_bytes_left_2(self):
        bv = aes.key_bv("1234abcd")
        self.assertEqual(aes.bv_hex_str(aes.shift_bytes_left(bv,1)),'34abcd12')
   
    def test_shift_bytes_right_0(self):
        bv = aes.key_bv("1234abcd")
        self.assertEqual(aes.bv_hex_str(aes.shift_bytes_right(bv,3)),'34abcd12')
   
    def test_shift_bytes_right_1(self):
        bv = aes.key_bv("1234abcd")
        self.assertEqual(aes.bv_hex_str(aes.shift_bytes_right(bv,2)),'abcd1234')
   
    def test_shift_bytes_right_2(self):
        bv = aes.key_bv("1234abcd")
        self.assertEqual(aes.bv_hex_str(aes.shift_bytes_right(bv,1)),'cd1234ab')       

        
    def test_shift_rows_0(self):
        sa=aes.init_state_array(aes.key_bv('63cab7040953d051cd60e0e7ba70e18c'))
        self.assertEqual(aes.state_str(aes.shift_rows(sa)),\
                         '6353e08c0960e104cd70b751bacad0e7',\
            "Test shift rows from FIPS-197 C.1 round[1]")

        
    def test_shift_rows_1(self):
        sa=aes.init_state_array(aes.key_bv('a761ca9b97be8b45d8ad1a611fc97369'))
        self.assertEqual(aes.state_str(aes.shift_rows(sa)),\
                         'a7be1a6997ad739bd8c9ca451f618b61',\
            "Test shift rows from FIPS-197 C.1 round[2]")

        
    def test_shift_rows_2(self):
        sa=aes.init_state_array(aes.key_bv('3b59cb73fcd90ee05774222dc067fb68'))
        self.assertEqual(aes.state_str(aes.shift_rows(sa)),\
                         '3bd92268fc74fb735767cbe0c0590e2d',\
            "Test shift rows from FIPS-197 C.1 round[3]")

        
    def test_shift_rows_3(self):
        sa=aes.init_state_array(aes.key_bv('2dfb02343f6d12dd09337ec75b36e3f0'))
        self.assertEqual(aes.state_str(aes.shift_rows(sa)),\
                         '2d6d7ef03f33e334093602dd5bfb12c7',\
            "Test shift rows from FIPS-197 C.1 round[4]")
                
    def test_inv_shift_rows_0(self):
        sa=aes.init_state_array(aes.key_bv('6353e08c0960e104cd70b751bacad0e7'))
        self.assertEqual(aes.state_str(aes.inv_shift_rows(sa)),\
                         '63cab7040953d051cd60e0e7ba70e18c',\
            "Test shift rows from FIPS-197 C.1 round[1]")
                
    def test_inv_shift_rows_1(self):
        sa=aes.init_state_array(aes.key_bv('a7be1a6997ad739bd8c9ca451f618b61'))
        self.assertEqual(aes.state_str(aes.inv_shift_rows(sa)),\
                         'a761ca9b97be8b45d8ad1a611fc97369',\
            "Test shift rows from FIPS-197 C.1 round[2]")

                
    def test_inv_shift_rows_2(self):
        sa=aes.init_state_array(aes.key_bv('3bd92268fc74fb735767cbe0c0590e2d'))
        self.assertEqual(aes.state_str(aes.inv_shift_rows(sa)),\
                         '3b59cb73fcd90ee05774222dc067fb68',\
            "Test shift rows from FIPS-197 C.1 round[3]")
                
    def test_inv_shift_rows_3(self):
        sa=aes.init_state_array(aes.key_bv('2d6d7ef03f33e334093602dd5bfb12c7'))
        self.assertEqual(aes.state_str(aes.inv_shift_rows(sa)),\
                         '2dfb02343f6d12dd09337ec75b36e3f0',\
            "Test shift rows from FIPS-197 C.1 round[4]")
       
        
    def test_gv_mult_0(self):        
        bv_2 = aes.key_bv("e0")
        self.assertEqual(aes.bv_hex_str(aes.gf_mult(bv_2,3)),'3b',\
                         "testing gf_mult with e0 * 3 = 3b")
        
    def test_gv_mult_1(self):
        bv_1 = aes.key_bv("63")        
        self.assertEqual(aes.bv_hex_str(aes.gf_mult(bv_1,2)),'c6',\
                         "testing gf_mult with 63 * 2 = c6")
       
        
    def test_gv_mult_2(self):
        bv_2 = aes.key_bv("e0")
        self.assertEqual(aes.bv_hex_str(aes.gf_mult(bv_2,3)),'3b',\
                         "testing gf_mult with e0 * 3 = 3b")
        
    def test_gv_mult_3(self):
        bv_1 = aes.key_bv("01")
        self.assertEqual(aes.bv_hex_str(aes.gf_mult(bv_1,1)),'01',\
                         "testing gf_mult with 63 * 2 = c6")
        
                
    def test_mix_columns_0(self):
        sa=aes.init_state_array(aes.key_bv('6353e08c0960e104cd70b751bacad0e7'))
        self.assertEqual(aes.state_str(aes.mix_columns(sa)),\
                         '5f72641557f5bc92f7be3b291db9f91a',\
            "Test mix columns from FIPS-197 C.1 round[1]")
       
    def test_mix_columns_1(self):
        sa=aes.init_state_array(aes.key_bv('a7be1a6997ad739bd8c9ca451f618b61'))
        self.assertEqual(aes.state_str(aes.mix_columns(sa)),\
                         'ff87968431d86a51645151fa773ad009',\
            "Test mix columns from FIPS-197 C.1 round[2]")
       
    def test_mix_columns_2(self):
        sa=aes.init_state_array(aes.key_bv('3bd92268fc74fb735767cbe0c0590e2d'))
        self.assertEqual(aes.state_str(aes.mix_columns(sa)),\
                         '4c9c1e66f771f0762c3f868e534df256',\
            "Test mix columns from FIPS-197 C.1 round[3]")
       
    def test_mix_columns_3(self):
        sa=aes.init_state_array(aes.key_bv('2d6d7ef03f33e334093602dd5bfb12c7'))
        self.assertEqual(aes.state_str(aes.mix_columns(sa)),\
                         '6385b79ffc538df997be478e7547d691',\
            "Test mix columns from FIPS-197 C.1 round[4]")
        
    def test_inv_mix_columns_0(self):
        sa=aes.init_state_array(aes.key_bv('5f72641557f5bc92f7be3b291db9f91a'))
        self.assertEqual(aes.state_str(aes.inv_mix_columns(sa)),\
                         '6353e08c0960e104cd70b751bacad0e7',\
            "Test inv mix columns from FIPS-197 C.1 round[1]")
        
    def test_inv_mix_columns_1(self):
        sa=aes.init_state_array(aes.key_bv('ff87968431d86a51645151fa773ad009'))
        self.assertEqual(aes.state_str(aes.inv_mix_columns(sa)),\
                         'a7be1a6997ad739bd8c9ca451f618b61',\
            "Test inv mix columns from FIPS-197 C.1 round[2]")
        
    def test_inv_mix_columns_2(self):
        sa=aes.init_state_array(aes.key_bv('4c9c1e66f771f0762c3f868e534df256'))
        self.assertEqual(aes.state_str(aes.inv_mix_columns(sa)),\
                         '3bd92268fc74fb735767cbe0c0590e2d',\
            "Test inv mix columns from FIPS-197 C.1 round[3]")
        
    def test_inv_mix_columns_3(self):
        sa=aes.init_state_array(aes.key_bv('6385b79ffc538df997be478e7547d691'))
        self.assertEqual(aes.state_str(aes.inv_mix_columns(sa)),\
                         '2d6d7ef03f33e334093602dd5bfb12c7',\
            "Test inv mix columns from FIPS-197 C.1 round[4]")
                
    def test_encrypt_0(self):
        ntk='2b7e151628aed2a6abf7158809cf4f3c'
        ntp='3243f6a8885a308d313198a2e0370734'
        ntc=aes.encrypt(ntk,ntp)
        self.assertEqual(ntc,'3925841d02dc09fbdc118597196a0b32',\
                         "sample encryption from FIPS-197 Appendix 2")
        
    def test_encrypt_1(self):
        ntk='000102030405060708090a0b0c0d0e0f'
        ntp='00112233445566778899aabbccddeeff'
        ntc=aes.encrypt(ntk,ntp)
        self.assertEqual(ntc,'69c4e0d86a7b0430d8cdb78070b4c55a',\
                         "sample encryption from FIPS-197 Appendix C.1")
    
    def test_encrypt_2(self):
        ntk='00000000000000000000000000000000'
        ntp='00000000000000000000000000000000'
        ntc=aes.encrypt(ntk,ntp)
        self.assertEqual(ntc,'66e94bd4ef8a2c3b884cfa59ca342b2e',\
                         "sample encryption all 0 case")
        
    def test_decrypt_0(self):
        ntk='2b7e151628aed2a6abf7158809cf4f3c'
        ntc='3925841d02dc09fbdc118597196a0b32'
        ntp=aes.decrypt(ntk,ntc)
        self.assertEqual(ntp,'3243f6a8885a308d313198a2e0370734',\
                         "sample decryption from FIPS-197 Appendix 2")
        
    def test_decrypt_1(self):
        ntk='000102030405060708090a0b0c0d0e0f'
        ntc='69c4e0d86a7b0430d8cdb78070b4c55a'
        ntp=aes.decrypt(ntk,ntc)
        self.assertEqual(ntp,'00112233445566778899aabbccddeeff',\
                         "sample decryption from FIPS-197 Appendix C.1")
        
    def test_decrypt_2(self):
        ntk='00000000000000000000000000000000'
        ntc='66e94bd4ef8a2c3b884cfa59ca342b2e'
        ntp=aes.decrypt(ntk,ntc)
        self.assertEqual(ntp,'00000000000000000000000000000000',\
                         "sample decryption all 0 case")


if __name__ == '__main__':
    unittest.main()
