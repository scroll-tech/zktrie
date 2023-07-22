package main

/*
typedef char* (*hashF)(unsigned char*, unsigned char*, unsigned char*, unsigned char*);
typedef void (*proveWriteF)(unsigned char*, int, void*);

hashF hash_scheme = NULL;

char* bridge_hash(unsigned char* a, unsigned char* b, unsigned char* domain, unsigned char* out){
	return hash_scheme(a, b, domain, out);
}

void init_hash_scheme(hashF f){
	hash_scheme = f;
}

void bridge_prove_write(proveWriteF f, unsigned char* key, unsigned char* val, int size, void* param){
	f(val, size, param);
}


*/
import "C"
