/*
 *    Copyright (C) 1998,1999,2000 Nikos Mavroyanopoulos
 *
 *    This program is free software; you can redistribute it and/or modify
 *    it under the terms of the GNU General Public License as published by
 *    the Free Software Foundation; either version 2 of the License, or
 *    (at your option) any later version.
 *
 *    This program is distributed in the hope that it will be useful,
 *    but WITHOUT ANY WARRANTY; without even the implied warranty of
 *    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *    GNU General Public License for more details.
 *
 *    You should have received a copy of the GNU General Public License
 *    along with this program; if not, write to the Free Software
 *    Foundation, Inc., 675 Mass Ave, Cambridge, MA 02139, USA.
 */

#include "../lib/mcrypt.h"
#include <stdio.h>
#include <string.h>
#include <stdlib.h>

/* $Id$ */

/* #define DEBUG */

char test0[2][500];

int main()
{

	int i;
	int j, x = 0;
	unsigned char *keyword;
	unsigned char cipher_tmp[1024];
	unsigned char password[]="abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq";

	printf("Checking whether the key generation work normally\n");

/* Test vectors with key and plaintext == zero */
	strcpy(test0[0], "84983e441c3bd26ebaae4aa1f95129e5e54670f17eb56d121b47824bf794d1fbc880e6f74dc01a93627ddea4268da4ee41b7a74000805b64e73a9d30e9e1fc03aeff576a543e50f5c5f25d404d96248b0762c374b8ca9ee6214d55e9de2d2aefab0e3b87d67c83654d506b4730115dc98bf9fc25712d4ad40a99722c3f652307");
	strcpy(test0[1], "8215ef0796a20bcaaae116d3876c664ab5d4e00eef0f452f228d33518d1b9ebe9fecc659fd50fdfdcde8101de053c71e64e03358f3c631e05e74b2d4ec94300d02bc6461f35e7ea0fcd5793e4465ab0bf24ff5fee1fc8b901cb90b2684fafbb91f608e5a393af36f3de99fc380aa6e5f56dba13cef7fb1b01e35139f45bf6d7e");
	bzero(cipher_tmp, sizeof(cipher_tmp));

	keyword = malloc(128);

	mcrypt_gen_key("mcrypt-sha1", "../modules/keygen/.libs", keyword, 128, NULL, 0, 
			password, strlen((char*)password));

	printf("SHA-1: ");
#ifdef DEBUG
/*
	printf("\npassword:    ");
	for (j = 0; j < 128; j++)
		printf("%.2x", password[j]);
	printf("\n");
*/
#endif


	for (j = 0; j < 128; j++) {
		sprintf(&((char *) cipher_tmp)[2 * j], "%.2x", keyword[j]);
	}

#ifdef DEBUG
	printf("HASH: ");
	printf("%s\n", cipher_tmp);
#endif

	if (strcmp( cipher_tmp, test0[0]) != 0) {
		printf("failed compatibility\n");
		x = 1;
	} else {
		printf("ok\n");
	}

	mcrypt_gen_key("mcrypt-md5", "../modules/keygen/.libs", keyword, 128, NULL, 0, 
			password, strlen((char*)password));

	printf("MD5: ");
#ifdef DEBUG
/*
	printf("\npassword:    ");
	for (j = 0; j < 128; j++) {
		printf("%.2x", password[j]);
	}
	printf("\n");
*/
#endif


	for (j = 0; j < 128; j++) {
		sprintf(&((char *) cipher_tmp)[2 * j], "%.2x", keyword[j]);
	}

#ifdef DEBUG
	printf("HASH: ");
	printf("%s\n", cipher_tmp);
#endif

	if (strcmp( cipher_tmp, test0[1]) != 0) {
		printf("failed compatibility\n");
		x = 1;
	} else {
		printf("ok\n");
	}


	free(keyword);

	return x;

}
