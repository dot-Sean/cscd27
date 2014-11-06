#include <stdlib.h>
#include <stdio.h>
#include <stdarg.h>
#include <gmp.h>
/*#include "mpi.h"*/
int main (int argc, char *argv[]){
	char		sho [300];
	mpz_t		N; /* For final computation results */
	mpz_t		A,As,B,Bsq,Bsho,Bs;
	mpz_init_set_str (N, "127364267597139493540723331204339211194586014817451203830799795925196194691202462897905850883866904868892415046580817569176239367692303288839770474652109700848358432405752683726342528889678012214522325274056903064820951043366005591893083764579470069805619180603771671383915933692672583275832310594117217293261", 10);
	mpz_init(A);
	mpz_init(Bsq);
	mpz_init_set_str(Bs,"1",10);
	mpz_init(Bsho);
	mpz_init(As);
	mpz_init_set_str(B,"2",10);
	mpz_sqrt(A,N);
	while( mpz_cmp(Bs,B) != 0){
		mpz_add_ui(A,A,1);
		mpz_pow_ui(As,A,2);
		mpz_sub(B,As,N);
		mpz_sqrt(Bsq,B);
		mpz_pow_ui(Bs,Bsq,2);
	}
	mpz_sqrt(Bsq,B);
	mpz_sub(Bsho,A,Bsq);
	mpz_get_str(sho,10,Bsho);
	printf("%s\n",sho);
	mpz_cdiv_q(As,N,Bsho);
	mpz_get_str(sho,10,As);
	printf("%s\n",sho);
	return 0;
}

