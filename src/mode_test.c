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
#include <stdlib.h>

/* $Id$ */

/* Prints plaintext and ciphertext in hex for all the algorithms */

int main()
{

	int td, i, td2;
#ifdef DEBUG
	int j;
#endif
	int x = 0, mode;
	unsigned char *keyword = NULL;
	unsigned char *plaintext;
	unsigned char *ciphertext;
	unsigned char cipher_tmp[200];
	unsigned char *IV;
	char *name, *name2;

	printf("Checking whether the algorithm's modes work normally\n");

	for (i = 0; i <= 150; i++) {
		for (mode = 0; mode < 6; mode++) {

			if (is_ok_algorithm(i) != 0)
				continue;
			if (is_ok_mode(mode) != 0)
				continue;

			if (is_block_algorithm(i) == 0) {
				if (mode!=0) continue;

				keyword = malloc(24);
				strcpy((char*)keyword, "Ena poly megalo keyword");

				bzero(cipher_tmp, sizeof(cipher_tmp));
				td =
				    mcrypt_generic_init(MCRYPT_STREAM, i,
							keyword, 24, NULL);

				td2 =
				    mcrypt_generic_init(MCRYPT_STREAM, i,
							keyword, 24, NULL);

				if (td < 0)
					continue;

				name = mcrypt_get_algorithms_name(i);
				if (name == NULL)
					continue;
				printf("Algorithm: %s... ", name);

				printf("Mode: STREAM... ");


				ciphertext = malloc(10);
				plaintext = malloc(10);
				bzero(plaintext, 10);
				bzero(ciphertext, 10);

#ifdef DEBUG
				printf("\nplaintext:  ");
				for (j = 0; j < 10; j++) {
					printf("%.2x", ciphertext[j]);
				}
#endif

#ifdef DEBUG
				printf("\nkeyword:    ");
				for (j = 0; j < 24; j++) {
					printf("%.2x", keyword[j]);
				}
#endif

				mcrypt_generic(td, ciphertext, 10);

				mdecrypt_generic(td2, ciphertext, 10);

#ifdef DEBUG
			printf("\nplaintext:  ");
			for (j = 0; j < 10; j++) {
				printf("%.2x", ciphertext[j]);
			}
			printf("\n");
#endif

				if (memcmp(ciphertext, plaintext, 10) != 0) {
					printf("failed internally\n");
					x = 1;
					mcrypt_generic_end(td);
					mcrypt_generic_end(td2);
					free(name);
					free(keyword);
					free(ciphertext);
					free(plaintext);
					continue;
				}
				printf("ok\n");

				mcrypt_generic_end(td);
				mcrypt_generic_end(td2);
				free(name);
				free(keyword);
				free(ciphertext);
				free(plaintext);

				continue;
			}
			IV = malloc(mcrypt_get_block_size(i));
			memset(IV, '\234', mcrypt_get_block_size(i));
			memset(IV, '\123', mcrypt_get_block_size(i) / 2);
			memset(IV, '\53', mcrypt_get_block_size(i) / 4);

			keyword = malloc(mcrypt_get_key_size(i));
			memset(keyword, '\2', mcrypt_get_key_size(i));
			memset(keyword, '\3', mcrypt_get_key_size(i) / 2);
			memset(keyword, '\5', mcrypt_get_key_size(i) / 4);

			bzero(cipher_tmp, sizeof(cipher_tmp));
			td =
			    mcrypt_generic_init(mode, i, keyword,
						mcrypt_get_key_size(i),
						IV);

			if (td < 0)
				continue;

			name = mcrypt_get_algorithms_name(i);
			if (name == NULL)
				continue;
			printf("Algorithm: %s... ", name);

			name2 = mcrypt_get_modes_name(mode);
			if (name2 == NULL)
				continue;
			printf("Mode: %s... ", name2);


			ciphertext = malloc(mcrypt_get_block_size(i));
			plaintext = malloc(mcrypt_get_block_size(i));
			bzero(plaintext, mcrypt_get_block_size(i));
			bzero(ciphertext, mcrypt_get_block_size(i));

#ifdef DEBUG
			printf("plaintext:  ");
			for (j = 0; j < mcrypt_get_block_size(i); j++) {
				printf("%.2x", ciphertext[j]);
			}
#endif

#ifdef DEBUG
			printf("\nkeyword:    ");
			for (j = 0; j < mcrypt_get_key_size(i); j++) {
				printf("%.2x", keyword[j]);
			}
#endif

			mcrypt_generic(td, ciphertext,
				       mcrypt_get_block_size(i));

			mdecrypt_generic(td, ciphertext,
					 mcrypt_get_block_size(i));

			if (memcmp
			    (ciphertext, plaintext,
			     mcrypt_get_block_size(i)) != 0) {
				printf("failed internally\n");
				x = 1;
				mcrypt_generic_end(td);
				free(IV);
				free(name2);
				free(name);
				free(keyword);
				free(ciphertext);
				free(plaintext);
				continue;
			}
			printf("ok\n");

			mcrypt_generic_end(td);
			free(IV);
			free(name2);
			free(name);
			free(keyword);
			free(ciphertext);
			free(plaintext);
		}
	}
	return x;

}
