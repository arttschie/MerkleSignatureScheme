#include <gmp.h>
#include <stdio.h>
#include <string.h>
#include <time.h>
#include <conio.h>
#include "gost3411-2012-core.h"

GOST34112012Context CTX;

int main() {
	printf("Welcome to program realization of Merkle digital signature scheme\n");
	printf("\n");
	gmp_randstate_t rs; // Generation algorithm declaration
	gmp_randinit_mt (rs), gmp_randseed_ui (rs, time (0)); // Algorithm initialization and seed definition 
	mpz_t keyPairs[8][2]; // Declaring a storage array 8 secret/public key pairs
	mpz_t hashedPublicKeyArray[8]; // Declaring an array of stored hash values of public keys
	mpz_t randomeNumber, h; // Declaring Integers
	int row, col, i, j;
	printf("Generating 8 pairs public/secret key:\n");
	
	for (row = 0; row < 8; row++) {
		for (col = 0; col < 2; col++) {
			mpz_inits (keyPairs[row][col], randomeNumber, 0);	
			mpz_urandomb (randomeNumber, rs, 128); 
			mpz_set (keyPairs[row][col], randomeNumber);
		}
	}
	
	for (i = 0; i < 8; i++) gmp_printf ("%ZX %ZX\n", keyPairs[i][0], keyPairs[i][1]);
	
	unsigned char H[32];
	char str[65];
	unsigned char C[64];
	
	for (i = 0; i < 8; i++) { // Caching of all public keys and array of pairs
 		GOST34112012Init (&CTX, 256);
 		mpz_inits (h, hashedPublicKeyArray[i], 0);
 		mpz_get_str (C, 16, keyPairs[i][1]);
 		GOST34112012Update (&CTX, C, strlen(C));
		GOST34112012Final (&CTX, H);
		for (j=0; j < 32; j++) sprintf (str+(2*j), "%02X", H[j]);
	    mpz_set_str (h, str, 16);
	    mpz_set (hashedPublicKeyArray[i], h); 
	}
	
	printf("\n");
	
	for (i = 0; i < 8; i++) gmp_printf ("%ZX\n", hashedPublicKeyArray[i]);
	
	printf("\n");
	
	mpz_t layer_1[4], layer_2[2], pub_key, auth0, auth1, auth2, resultedPublicKey;
	mpz_inits (pub_key, auth0, auth1, auth2, resultedPublicKey, 0);
	
	for (i=0; i<4; i++) mpz_init (layer_1[i]); 
	for (i=0; i<2; i++) mpz_init (layer_2[i]);
	
	mpz_add(layer_1[0], hashedPublicKeyArray[0], hashedPublicKeyArray[1]); // Computing the first layer of a tree
	mpz_add(layer_1[1], hashedPublicKeyArray[2], hashedPublicKeyArray[3]);
	mpz_add(layer_1[2], hashedPublicKeyArray[4], hashedPublicKeyArray[5]);
	mpz_add(layer_1[3], hashedPublicKeyArray[6], hashedPublicKeyArray[7]);
	
	mpz_add(layer_2[0], layer_1[0], layer_1[1]); // Computing the second layer of a tree
	mpz_add(layer_2[1], layer_1[2], layer_1[3]);
	
	mpz_add(pub_key, layer_2[0], layer_2[1]); // Computing the top of a tree

	printf("Signature consist of:\n");
	printf("Inital public key: ");
	gmp_printf ("%ZX\n", hashedPublicKeyArray[0]);
	printf("Authentification path:\nauth0: ");
	gmp_printf ("%ZX\n", hashedPublicKeyArray[1]);
	printf("auth1: ");
	gmp_printf ("%ZX\n", layer_1[1]);
	printf("auth2: ");
	gmp_printf ("%ZX\n", layer_2[1]);
	printf("Merkle public key: ");
	gmp_printf ("%ZX\n", pub_key);
	
	mpz_set (auth0, hashedPublicKeyArray[1]); // Assigning values to auth variables
	mpz_set (auth1, layer_1[1]);
	mpz_set (auth2, layer_2[1]);
	
	printf("\n");
	
	printf("Signature authentification:\nauth0: "); // Authentification path calculation
	gmp_printf ("%ZX\n", auth0);	
	printf("First iter: ");
	mpz_add(auth1, hashedPublicKeyArray[0], auth0);
	gmp_printf ("%ZX\n", auth1);
	printf("Second iter: ");
	mpz_add(auth2, layer_1[0], auth1);
	gmp_printf ("%ZX\n", layer_2[0]);
	printf("Resulted pub_key: ");
	mpz_add(resultedPublicKey, layer_2[0], auth2);
	gmp_printf ("%ZX\n", resultedPublicKey);
	
	if (mpz_cmp (resultedPublicKey, pub_key)) { // Signasture verifying
		printf("Hashs are equal! The message is right!\n");
		getch();
		return 0;
	}
	
	printf("Hashs are not equal! The message is wrong!\n");
	getch();
	return 0;
}
