package main

/*
typedef char* (*hashF)(unsigned char*, unsigned char*, unsigned char*);

hashF hash_scheme = NULL;

char* bridge_hash(unsigned char* a, unsigned char* b, unsigned char* out){
	return hash_scheme(a, b, out);
}

void init_hash_scheme(hashF f){
	hash_scheme = f;
}

*/
import "C"
