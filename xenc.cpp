#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
static constexpr uint32_t XDELTA=0x9E3779B9,XKEY[]={0x7B2E1A4F,0xC9D83560,0x4A1F93E7,0xE8056B2C};
static void XTEA(uint32_t& v0,uint32_t& v1){uint32_t s=0xC6EF3720;for(int i=0;i<32;i++){v1-=(((v0<<4)^(v0>>5))+v0)^(s+XKEY[(s>>11)&3]);s-=XDELTA;v0-=(((v1<<4)^(v1>>5))+v1)^(s+XKEY[s&3]);}}
static void XTEACBC(uint8_t* d,size_t sz){uint32_t i0=0xDEADBEEF,i1=0xCAFEBABE;auto* b=(uint32_t*)d;for(size_t i=0;i<sz/4;i+=2){uint32_t s0=b[i],s1=b[i+1];XTEA(b[i],b[i+1]);b[i]^=i0;b[i+1]^=i1;i0=s0;i1=s1;}}
int main(int argc,char** argv){
if(argc<3){printf("Usage: enc <in> <out>\n");return 1;}
FILE* f=fopen(argv[1],"rb");if(!f){printf("ERR open\n");return 1;}
fseek(f,0,SEEK_END);size_t sz=ftell(f);fseek(f,0,SEEK_SET);
size_t pad=(sz+7)&~7;uint8_t* d=(uint8_t*)calloc(1,pad);
fread(d,1,sz,f);fclose(f);
XTEACBC(d,pad);
FILE* o=fopen(argv[2],"wb");if(!o){printf("ERR write\n");return 1;}
uint32_t s32=(uint32_t)sz;fwrite(&s32,1,4,o);
fwrite(d,1,pad,o);fclose(o);
printf("OK: %zu -> %zu bytes\n",sz,pad+4);
return 0;}
