#include <string.h>
#include <stdio.h>
#include <stdlib.h>

#include "keyring.h"

char ** keyring = NULL;
int num_keys = 0;

int LoadKeyring(void)
{
    FILE * f_pkr;
    char line[200], * t_key, ** tmpkr;
    int ii, ll;

    f_pkr = fopen("pegwit.pkr", "r");
    if (!f_pkr)
        return 0;
    if (keyring)
        FreeKeyring();
    keyring = malloc(KR_SIZE * sizeof(keyring[0]));
    if (!keyring)
        return 0;
    memset(keyring, 0, KR_SIZE * sizeof(keyring[0]));
    num_keys = KR_SIZE;
    ii = 0;
    while (keyring && !feof(f_pkr)) {
        if (!fgets(line, sizeof(line), f_pkr))
            break;
        ll = strlen(line);
        while (line[ll-1] == '\r' || line[ll-1] == '\n')
            line[--ll] = 0;
        if (ll < KEYSIZE+2)
            continue;
        if (line[KEYSIZE] != ',')
            continue;
        if (ii >= num_keys) {
            tmpkr = realloc(keyring, (num_keys + KR_SIZE) * sizeof(keyring[0]));
            if (!tmpkr)
                break;
            keyring = tmpkr;
            memset(keyring + num_keys, 0, KR_SIZE * sizeof(keyring[0]));
            num_keys += KR_SIZE;
        }
        t_key = malloc(ll+1);
        if (!t_key)
            break;
        strcpy(t_key, line);
        keyring[ii++] = t_key;
    }
    fclose(f_pkr);
    return num_keys;
} // LoadKeyring


int SaveKeyring(void)
{
    FILE * f_pkr;
    int ii;

    if (!keyring) {
        num_keys = 0;
        return 0;
    }
    f_pkr = fopen("pegwit.pkx", "w");
    if (!f_pkr)
        return 0;
    for (ii=0; ii<num_keys; ii++)
        if (keyring[ii]) {
            if (fputs(keyring[ii], f_pkr) < 0)
                break;
            if (fputs("\n", f_pkr) < 0)
                break;
        }
    fclose(f_pkr);
    remove("pegwit2.bak");
    rename("pegwit1.bak", "pegwit2.bak");
    remove("pegwit1.bak");
    rename("pegwit.pkr", "pegwit1.bak");
    remove("pegwit.pkr");
    rename("pegwit.pkx", "pegwit.pkr");
    return num_keys;
} // SaveKeyring


int FreeKeyring(void)
{
    int ii;

    if (!keyring) {
        num_keys = 0;
        return 0;
    }
    for (ii=0; ii<num_keys; ii++)
        if (keyring[ii])
            free(keyring[ii]);
    free(keyring);
    keyring = NULL;
    num_keys = 0;
    return 1;
} // FreeKeyring


int DelKey(int num)
{
    if (!keyring || num>=num_keys)
        return 0;
    if (!keyring[num])
        return 0;
    if (keyring[num])
        free(keyring[num]);
    keyring[num] = NULL;
    return 1;
} // FreeKeyring


int SetDefKey(int defkey)
{
    char * t_tmp;

    if (!keyring || !defkey || defkey>=num_keys)
        return 0;
    if (!keyring[defkey])
        return 0;
    t_tmp = keyring[0];
    keyring[0] = keyring[defkey];
    keyring[defkey] = t_tmp;
    return 1;
} // SetDefKey


int FindKey(char *keyname, char *keydata)
{
    int ii;

    if (!keyring || !num_keys)
        return -1;
    for (ii=0; ii<num_keys; ii++)
        if (keyring[ii]) {
            if (keydata)
                if (!strncmp(keydata, keyring[ii], KEYSIZE)) {
                    if (!keyname)
                        return ii;
                    else
                        if (!strcmp(keyname, keyring[ii] + KEYSIZE+1))
                            return ii;
                }
            if (keyname)
                if (!strcmp(keyname, keyring[ii] + KEYSIZE+1))
                    if (!keydata)
                        return ii;
        }
    return -1;
} // FindKey


int FindKeySubstr(char *keydatasubstr)
{
    int ii;

    if (!keydatasubstr)
        return -1;
    if (!keyring || !num_keys)
        return -1;
    for (ii=0; ii<num_keys; ii++)
        if (keyring[ii]) {
            if (strstr(keyring[ii], keydatasubstr)) {
                return ii;
            }
        }
    return -1;
} // FindKey


int AddKey(char *keyname, char *keydata)
{
    int ii, found;
    char * t_key, ** tmpkr;

    if (!keyname || strlen(keydata)!=KEYSIZE)
        return 0;
    found = 0;
    if (!keyring) {
        keyring = malloc(KR_SIZE * sizeof(keyring[0]));
        if (!keyring)
            return 0;
        memset(keyring, 0, KR_SIZE * sizeof(keyring[0]));
        num_keys = KR_SIZE;
    } else {
        for (ii=0; ii<num_keys; ii++)
            if (!keyring[ii]) {
                found = ii;
                break;
            }
        if (!found) {
            found = num_keys;
            tmpkr = malloc((num_keys + KR_SIZE) * sizeof(keyring[0]));
            if (!tmpkr)
                return 0;
            memset(keyring + num_keys, 0, KR_SIZE * sizeof(keyring[0]));
            num_keys += KR_SIZE;
            keyring = tmpkr;
        }
    }
    t_key = malloc(strlen(keyname)+KEYSIZE+2);
    if (!t_key)
        return 0;
    strcpy(t_key, keydata);
    strcat(t_key, ",");
    strcat(t_key, keyname);
    keyring[found] = t_key;
    return 1;
} // AddKey

int GetNumKeys(void)
{
    if (!keyring)
        return 0;
    return num_keys;
}

char * GetKeyPtr(int num)
{
    if (!keyring)
        return NULL;
    if (num >= num_keys)
        return NULL;
    return keyring[num];
}
